//! Conversations : directes et de groupe, vérification des correspondants,
//! changement de clé d'identité, numéros de sécurité, messages éphémères et
//! rotation automatique des clés.
//!
//! Règle d'ordonnancement MLS : un seul membre — l'administrateur du groupe
//! (son créateur) — émet les commits. Les autres membres envoient des
//! *propositions* (rotation, départ) que l'administrateur valide. Le serveur
//! n'ordonnant pas les commits, cette règle évite les fourches d'époque.
//! L'administrateur peut transférer ce rôle à un autre membre (annonce
//! `GroupInfo` qu'il est seul autorisé à émettre) puis quitter le groupe.

use std::collections::HashMap;

use msg_crypto::app_message::{AppBody, AppMessage, AttachmentRef};
use msg_crypto::identity::DeviceCertificate;
use msg_crypto::mls::{GroupMember, Incoming, MemberIdentity};
use msg_crypto::safety;
use msg_proto::{parse_address, PublishedDevice, RemoteRecipients, SendRequest, UserDirectoryEntry};
use serde::Serialize;
use uuid::Uuid;

use crate::client::Client;
use crate::error::{ClientError, Result};
use crate::store::{status, StoredConversation, StoredMessage};

/// Rotation des clés MLS : au plus tard tous les 7 jours ou 100 messages envoyés.
pub const ROTATION_MAX_AGE_MS: i64 = 7 * 24 * 3600 * 1000;
pub const ROTATION_MAX_SENT: i64 = 100;
/// Taille maximale d'un groupe (appareils inclus, limite de la Phase 2).
pub const MAX_GROUP_MEMBERS: usize = 50;

#[derive(Debug, Clone, Serialize)]
pub struct ConversationView {
    /// Identifiant de groupe MLS (hexadécimal).
    pub id: String,
    /// `direct` ou `group`.
    pub kind: String,
    /// Titre affiché : correspondant ou nom du groupe.
    pub title: String,
    pub peer: String,
    pub members: Vec<String>,
    pub admin: Option<String>,
    pub is_admin: bool,
    /// `ok`, `identity_changed`, `removed`, `left`.
    pub status: String,
    /// Utilisateurs dont la clé d'identité a changé (décision en attente).
    pub identity_changed: Vec<String>,
    pub last_activity_ms: i64,
    pub unread: i64,
    /// Conversation directe : correspondant vérifié (numéro de sécurité).
    pub verified: bool,
    pub peer_fingerprint: String,
    /// Durée de vie des messages envoyés (secondes), si éphémères.
    pub ttl_s: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttachmentView {
    pub name: String,
    pub mime: String,
    pub size: u64,
    /// Métadonnées supprimées à l'envoi (images ré-encodées uniquement).
    pub metadata_cleaned: bool,
    /// Miniature locale (`data:image/jpeg;base64,…`), jamais distante.
    pub thumbnail_data_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MessageView {
    pub id: String,
    pub conversation_id: String,
    pub sender: String,
    pub outgoing: bool,
    pub sent_at_ms: i64,
    pub received_at_ms: i64,
    /// `text` ou `attachment`.
    pub kind: String,
    pub text: String,
    /// Rendu Markdown sûr (aucun HTML, aucune ressource distante).
    pub ast: Vec<msg_markdown::Node>,
    pub attachment: Option<AttachmentView>,
    pub expires_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SyncReport {
    pub processed: usize,
    pub new_messages: usize,
    pub changed_conversations: Vec<String>,
    /// Messages rejetés (rejeu, signature invalide, commit non autorisé…).
    pub rejected: usize,
    /// Contacts dont la clé d'identité vient de changer.
    pub identity_changes: Vec<String>,
    /// Groupes dont nous avons été retirés.
    pub removed_from: Vec<String>,
    /// Messages éphémères supprimés.
    pub expired: usize,
    /// Rotations de clés effectuées ou proposées.
    pub rotations: usize,
    /// Groupes dont les appareils membres ont été mis à jour (ajout
    /// d'appareils liés, retrait d'appareils révoqués).
    pub reconciled: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafetyNumberView {
    pub username: String,
    /// 60 chiffres par groupes de 5.
    pub number: String,
    /// Contenu du QR code.
    pub qr_payload: String,
    pub verified: bool,
    /// Le numéro affiché porte sur une **nouvelle** clé non encore acceptée.
    pub identity_changed: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum IdentityCheck {
    Trusted,
    Changed,
}

#[derive(Default)]
struct VerifyOutcome {
    others: Vec<String>,
    changed: Vec<String>,
}

#[derive(Default)]
struct Handled {
    conversation: Option<String>,
    new_message: bool,
    identity_changes: Vec<String>,
    removed: bool,
}

fn decode_id(id: &str) -> Result<Vec<u8>> {
    hex::decode(id).map_err(|_| ClientError::UnknownConversation)
}

fn usernames(members: &[GroupMember]) -> Vec<String> {
    let mut v: Vec<String> = members.iter().map(|m| m.identity.username.clone()).collect();
    v.sort();
    v.dedup();
    v
}

impl Client {
    // --- Vérification des correspondants ------------------------------------

    /// Confiance au premier usage : la première clé d'identité vue est
    /// mémorisée ; une clé différente est mise **en attente** et la
    /// conversation est suspendue jusqu'à vérification ou acceptation.
    fn check_identity(&self, username: &str, identity_key: &[u8]) -> Result<IdentityCheck> {
        if username == self.username {
            return if identity_key == self.identity_public {
                Ok(IdentityCheck::Trusted)
            } else {
                Err(ClientError::IdentityChanged(username.into()))
            };
        }
        match self.store.contact(username)? {
            None => {
                self.store.add_contact(username, identity_key, crate::now_ms())?;
                Ok(IdentityCheck::Trusted)
            }
            Some(c) if c.identity_key == identity_key => Ok(IdentityCheck::Trusted),
            Some(c) => {
                if c.pending_identity_key.as_deref() != Some(identity_key) {
                    self.store.set_pending_identity(username, identity_key)?;
                }
                Ok(IdentityCheck::Changed)
            }
        }
    }

    /// Vérifie le certificat d'un appareil : signé par la clé d'identité pour
    /// l'adresse qualifiée `nom@site` ou, pour un appareil de ce site
    /// antérieur à la fédération, pour le nom seul.
    pub(crate) fn verify_device(&self, username: &str, identity_key: &[u8], d: &PublishedDevice) -> Result<()> {
        let mut names = Vec::with_capacity(2);
        if username.contains('@') {
            names.push(username.to_owned());
        } else {
            if let Some(site) = &self.site {
                names.push(format!("{username}@{site}"));
            }
            names.push(username.to_owned());
        }
        let ok = names.into_iter().any(|name| {
            DeviceCertificate {
                username: name,
                device_id: d.device_id,
                api_key: d.api_key.clone(),
                mls_signature_key: d.mls_signature_key.clone(),
                created_at: d.cert_created_at,
            }
            .verify(identity_key, &d.cert_signature)
            .is_ok()
        });
        if ok {
            Ok(())
        } else {
            Err(ClientError::Verification(username.into(), "certificat d'appareil invalide".into()))
        }
    }

    /// Forme envoyée sur le réseau d'un nom affiché : qualifiée `nom@site`
    /// pour les utilisateurs de ce site (non ambiguë chez les autres sites).
    pub(crate) fn wire_name(&self, name: &str) -> String {
        match (&self.site, name.contains('@')) {
            (Some(site), false) => format!("{name}@{site}"),
            _ => name.to_owned(),
        }
    }

    /// Forme affichée d'un nom reçu : `nom@<ce site>` devient `nom`.
    pub(crate) fn local_name(&self, name: &str) -> String {
        match &self.site {
            Some(site) => name.strip_suffix(site.as_str()).and_then(|u| u.strip_suffix('@')).unwrap_or(name).to_owned(),
            None => name.to_owned(),
        }
    }

    /// Mémorise le site des appareils distants d'un utilisateur (routage).
    fn note_sites(&self, username: &str, devices: impl IntoIterator<Item = Uuid>) {
        if let Some(site) = self.remote_site(username).map(str::to_owned) {
            let mut map = self.device_sites.lock().unwrap_or_else(|e| e.into_inner());
            for d in devices {
                map.insert(d, site.clone());
            }
        }
    }

    /// Vérifie que chaque membre d'un groupe correspond à un appareil certifié
    /// par l'identité publiée de son utilisateur.
    async fn verify_members(&self, members: &[GroupMember]) -> Result<VerifyOutcome> {
        let mut dirs: HashMap<String, UserDirectoryEntry> = HashMap::new();
        let mut out = VerifyOutcome::default();
        for m in members {
            let name = &m.identity.username;
            if *name == self.username && m.identity.device_id == self.device_id {
                if m.signature_key != self.mls.signature_public_key() {
                    return Err(ClientError::Verification(name.clone(), "clé MLS locale inattendue".into()));
                }
                continue;
            }
            if !dirs.contains_key(name) {
                let entry = self.verified_directory(name).await?;
                if self.check_identity(name, &entry.identity_key)? == IdentityCheck::Changed {
                    out.changed.push(name.clone());
                }
                dirs.insert(name.clone(), entry);
            }
            let entry = &dirs[name];
            let dev = entry
                .devices
                .iter()
                .find(|d| d.device_id == m.identity.device_id)
                .ok_or_else(|| ClientError::Verification(name.clone(), "appareil absent de l'annuaire".into()))?;
            self.verify_device(name, &entry.identity_key, dev)?;
            if dev.mls_signature_key != m.signature_key {
                return Err(ClientError::Verification(name.clone(), "clé MLS non certifiée".into()));
            }
            if *name != self.username && !out.others.contains(name) {
                out.others.push(name.clone());
            }
        }
        Ok(out)
    }

    /// Réclame et vérifie un KeyPackage par appareil de `username`.
    async fn claim_verified(&self, username: &str) -> Result<(Vec<Vec<u8>>, Vec<Uuid>)> {
        self.claim_verified_devices(username, None).await
    }

    /// Mes autres appareils (KeyPackages réclamés), pour qu'ils participent
    /// aussi à la conversation. Aucun autre appareil : listes vides.
    async fn claim_own_devices(&self) -> Result<(Vec<Vec<u8>>, Vec<Uuid>)> {
        match self.claim_verified_devices(&self.username.clone(), None).await {
            Err(ClientError::Api { status: 404, .. }) => Ok((Vec::new(), Vec::new())),
            r => r,
        }
    }

    /// Réclame et vérifie (certificat, Key Transparency, KeyPackage) les
    /// KeyPackages des appareils de `username` (tous, ou ceux indiqués).
    /// Les appareils sans KeyPackage disponible sont ignorés.
    pub(crate) async fn claim_verified_devices(
        &self,
        username: &str,
        only: Option<&[Uuid]>,
    ) -> Result<(Vec<Vec<u8>>, Vec<Uuid>)> {
        parse_address(username).map_err(|e| ClientError::Invalid(e.into()))?;
        let entry = self.verified_claim(username, only).await?;
        if self.check_identity(username, &entry.identity_key)? == IdentityCheck::Changed {
            return Err(ClientError::IdentityChanged(username.into()));
        }
        let mut kps = Vec::new();
        let mut devices = Vec::new();
        for d in &entry.devices {
            self.verify_device(username, &entry.identity_key, d)?;
            if only.is_some_and(|o| !o.contains(&d.device_id)) || d.device_id == self.device_id {
                continue;
            }
            let Some(kp) = d.key_package.as_ref() else { continue };
            let m = self.mls.inspect_key_package(kp)?;
            if m.identity != (MemberIdentity { username: username.into(), device_id: d.device_id })
                || m.signature_key != d.mls_signature_key
            {
                return Err(ClientError::Verification(username.into(), "KeyPackage non conforme au certificat".into()));
            }
            kps.push(kp.clone());
            devices.push(d.device_id);
        }
        self.note_sites(username, devices.iter().copied());
        if kps.is_empty() {
            return Err(ClientError::Api {
                status: 404,
                code: msg_proto::ErrorCode::NotFound,
                message: "aucun appareil disponible".into(),
            });
        }
        Ok((kps, devices))
    }

    // --- Vues --------------------------------------------------------------

    /// Administrateur effectif : celui annoncé, sinon (conversations de la
    /// Phase 1) le plus petit identifiant parmi les membres — règle
    /// déterministe identique sur tous les appareils.
    pub(crate) fn effective_admin(&self, c: &StoredConversation) -> Option<String> {
        c.admin.clone().or_else(|| self.mls.members(&c.group_id).ok().and_then(|m| usernames(&m).into_iter().next()))
    }

    fn view_conversation(&self, c: StoredConversation) -> Result<ConversationView> {
        let members = self.mls.members(&c.group_id).map(|m| usernames(&m)).unwrap_or_default();
        let identity_changed: Vec<String> = members
            .iter()
            .filter(|u| **u != self.username)
            .filter(|u| matches!(self.store.contact(u), Ok(Some(ct)) if ct.pending_identity_key.is_some()))
            .cloned()
            .collect();
        let contact = if c.kind == "direct" { self.store.contact(&c.peer)? } else { None };
        let admin = self.effective_admin(&c);
        Ok(ConversationView {
            id: hex::encode(&c.group_id),
            title: if c.kind == "group" {
                c.name.clone().unwrap_or_else(|| members.join(", "))
            } else {
                c.peer.clone()
            },
            kind: c.kind,
            peer: c.peer,
            is_admin: admin.as_deref() == Some(self.username.as_str()),
            admin,
            members,
            status: c.status,
            identity_changed,
            last_activity_ms: c.last_activity_ms,
            unread: c.unread,
            verified: contact.as_ref().is_some_and(|ct| ct.verified),
            peer_fingerprint: contact.map(|ct| crate::client::fingerprint(&ct.identity_key)).unwrap_or_default(),
            ttl_s: c.ttl_s,
        })
    }

    fn view_message(m: StoredMessage) -> MessageView {
        let ast = msg_markdown::parse(&m.body);
        let attachment = m.attachment.as_deref().and_then(|j| serde_json::from_str::<AttachmentRef>(j).ok()).map(|a| {
            AttachmentView {
                metadata_cleaned: a.mime == "image/jpeg" || a.mime == "image/png",
                name: a.name,
                mime: a.mime,
                size: a.size,
                thumbnail_data_uri: a.thumbnail_b64.map(|t| format!("data:image/jpeg;base64,{t}")),
            }
        });
        MessageView {
            id: m.id,
            conversation_id: hex::encode(&m.group_id),
            sender: m.sender,
            outgoing: m.outgoing,
            sent_at_ms: m.sent_at_ms,
            received_at_ms: m.received_at_ms,
            kind: m.kind,
            text: m.body,
            ast,
            attachment,
            expires_at_ms: m.expires_at_ms,
        }
    }

    pub fn conversations(&self) -> Result<Vec<ConversationView>> {
        self.store.purge_expired(crate::now_ms())?;
        self.store.conversations()?.into_iter().map(|c| self.view_conversation(c)).collect()
    }

    pub fn conversation(&self, conversation_id: &str) -> Result<ConversationView> {
        let c = self.store.conversation(&decode_id(conversation_id)?)?.ok_or(ClientError::UnknownConversation)?;
        self.view_conversation(c)
    }

    /// Messages d'une conversation. Contenu **masqué** tant qu'un changement
    /// de clé d'identité n'a pas été vérifié ou accepté.
    pub fn messages(&self, conversation_id: &str, limit: u32) -> Result<Vec<MessageView>> {
        let gid = decode_id(conversation_id)?;
        self.store.purge_expired(crate::now_ms())?;
        let c = self.store.conversation(&gid)?.ok_or(ClientError::UnknownConversation)?;
        if c.status == status::IDENTITY_CHANGED {
            return Ok(Vec::new());
        }
        Ok(self.store.messages(&gid, limit.min(1000))?.into_iter().map(Self::view_message).collect())
    }

    /// Appareils membres d'une conversation (utilisateur, appareil).
    pub fn member_devices(&self, conversation_id: &str) -> Result<Vec<(String, Uuid)>> {
        Ok(self
            .mls
            .members(&decode_id(conversation_id)?)?
            .into_iter()
            .map(|m| (m.identity.username, m.identity.device_id))
            .collect())
    }

    pub fn mark_read(&self, conversation_id: &str) -> Result<()> {
        self.store.mark_read(&decode_id(conversation_id)?)
    }

    fn active_conversation(&self, conversation_id: &str) -> Result<StoredConversation> {
        let c = self.store.conversation(&decode_id(conversation_id)?)?.ok_or(ClientError::UnknownConversation)?;
        match c.status.as_str() {
            status::OK => Ok(c),
            status::IDENTITY_CHANGED => Err(ClientError::IdentityChanged(c.peer.clone())),
            _ => Err(ClientError::Invalid("vous ne faites plus partie de cette conversation".into())),
        }
    }

    fn require_admin(&self, c: &StoredConversation) -> Result<()> {
        if c.kind == "group" && self.effective_admin(c).as_deref() == Some(self.username.as_str()) {
            // Un seul émetteur de commits par groupe : l'appareil principal.
            if !self.is_primary() {
                return Err(ClientError::NotPrimaryDevice);
            }
            Ok(())
        } else {
            Err(ClientError::Invalid("action réservée à l'administrateur du groupe".into()))
        }
    }

    // --- Envoi -------------------------------------------------------------

    pub(crate) fn other_devices(&self, group_id: &[u8]) -> Result<Vec<Uuid>> {
        let mut out = Vec::new();
        for m in self.mls.members(group_id)? {
            if m.identity.device_id != self.device_id {
                self.note_sites(&m.identity.username, [m.identity.device_id]);
                out.push(m.identity.device_id);
            }
        }
        Ok(out)
    }

    /// Requête d'envoi : appareils de ce site d'une part, appareils d'autres
    /// sites (relayés par la fédération) d'autre part.
    fn send_request(&self, client_message_id: Uuid, devices: Vec<Uuid>, payload: Vec<u8>) -> SendRequest {
        let sites = self.device_sites.lock().unwrap_or_else(|e| e.into_inner());
        let mut recipients = Vec::new();
        let mut remote: Vec<RemoteRecipients> = Vec::new();
        for d in devices {
            match sites.get(&d) {
                None => recipients.push(d),
                Some(site) => match remote.iter_mut().find(|r| &r.site == site) {
                    Some(r) => r.devices.push(d),
                    None => remote.push(RemoteRecipients { site: site.clone(), devices: vec![d] }),
                },
            }
        }
        SendRequest { client_message_id, recipients, remote, payload }
    }

    pub(crate) async fn post(&self, recipients: Vec<Uuid>, payload: Vec<u8>) -> Result<()> {
        if recipients.is_empty() {
            return Ok(());
        }
        self.api.send(&self.send_request(Uuid::new_v4(), recipients, payload)).await?;
        Ok(())
    }

    /// Chiffre, signe et diffuse un message applicatif.
    pub(crate) async fn send_app(&self, group_id: &[u8], body: AppBody, ttl: Option<u32>) -> Result<AppMessage> {
        let app = AppMessage::with_body(body, crate::now_ms(), ttl)?;
        let ct = self.mls.encrypt(group_id, &app.encode())?;
        let recipients = self.other_devices(group_id)?;
        // L'état du ratchet a avancé : il est persisté avant l'envoi.
        self.save_mls()?;
        if !recipients.is_empty() {
            self.api.send(&self.send_request(app.id, recipients, ct)).await?;
        }
        self.store.note_sent(group_id)?;
        self.persist_tokens()?;
        Ok(app)
    }

    pub(crate) fn store_outgoing(
        &self,
        group_id: &[u8],
        app: &AppMessage,
        kind: &str,
        body: String,
        attachment: Option<String>,
    ) -> Result<MessageView> {
        let now = crate::now_ms();
        let stored = StoredMessage {
            id: format!("{}:{}", hex::encode(group_id), app.id),
            group_id: group_id.to_vec(),
            sender: self.username.clone(),
            sender_device: self.device_id.to_string(),
            kind: kind.into(),
            body,
            attachment,
            sent_at_ms: app.sent_at_ms,
            received_at_ms: now,
            outgoing: true,
            expires_at_ms: app.expires_in_s.map(|t| now + i64::from(t) * 1000),
        };
        self.store.insert_message(&stored)?;
        Ok(Self::view_message(stored))
    }

    /// Chiffre, signe et envoie un message texte (Markdown).
    pub async fn send_text(&mut self, conversation_id: &str, text: &str) -> Result<MessageView> {
        let text = text.trim_end();
        if text.trim().is_empty() {
            return Err(ClientError::Invalid("message vide".into()));
        }
        let c = self.active_conversation(conversation_id)?;
        let app = self.send_app(&c.group_id, AppBody::Text { text: text.to_owned() }, c.ttl_s).await?;
        self.store_outgoing(&c.group_id, &app, "text", text.to_owned(), None)
    }

    /// Durée de vie des prochains messages envoyés dans la conversation
    /// (`None` : messages permanents).
    pub fn set_ephemeral(&self, conversation_id: &str, ttl_s: Option<u32>) -> Result<()> {
        if ttl_s.is_some_and(|t| t == 0 || t > msg_crypto::app_message::MAX_TTL_SECS) {
            return Err(ClientError::Invalid("durée invalide".into()));
        }
        self.store.set_ttl(&decode_id(conversation_id)?, ttl_s)
    }

    // --- Création et gestion des conversations ---------------------------------

    /// Ouvre (ou retrouve) une conversation directe chiffrée avec `peer`.
    pub async fn start_conversation(&mut self, peer: &str) -> Result<ConversationView> {
        parse_address(peer).map_err(|e| ClientError::Invalid(e.into()))?;
        let peer = &self.local_name(peer);
        if *peer == self.username {
            return Err(ClientError::Invalid("impossible d'ouvrir une conversation avec soi-même".into()));
        }
        if let Some(gid) = self.store.conversation_with(peer)? {
            if let Some(c) = self.store.conversation(&gid)? {
                return self.view_conversation(c);
            }
        }
        let (mut kps, mut recipients) = self.claim_verified(peer).await?;
        let (own_kps, own_devices) = self.claim_own_devices().await?;
        kps.extend(own_kps);
        recipients.extend(own_devices);
        let created = self.mls.create_group(&kps)?;
        let now = crate::now_ms();
        let mls_state = self.mls.export_state()?;
        let conv = StoredConversation {
            group_id: created.group_id.clone(),
            kind: "direct".into(),
            peer: peer.into(),
            name: None,
            admin: Some(self.username.clone()),
            status: status::OK.into(),
            created_at_ms: now,
            last_activity_ms: now,
            unread: 0,
            ttl_s: None,
            last_rotation_ms: now,
            sent_since_rotation: 0,
        };
        self.store.transaction(|s| {
            s.set_meta(crate::client::meta::MLS_STATE, &mls_state)?;
            s.insert_conversation(&conv)
        })?;
        self.post(recipients, created.welcome).await?;
        // Annonce l'administrateur (utile à mes autres appareils, qui
        // rejoignent aussi la conversation).
        self.send_app(
            &created.group_id,
            AppBody::GroupInfo { name: String::new(), admin: self.wire_name(&self.username) },
            None,
        )
        .await?;
        self.persist_tokens()?;
        self.conversation(&hex::encode(&created.group_id))
    }

    /// Crée un groupe nommé avec les utilisateurs indiqués. Le créateur en est
    /// l'administrateur (seul émetteur de commits).
    pub async fn create_group(&mut self, name: &str, members: &[String]) -> Result<ConversationView> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > msg_crypto::app_message::MAX_NAME_CHARS {
            return Err(ClientError::Invalid("nom de groupe invalide".into()));
        }
        let mut wanted: Vec<String> =
            members.iter().map(|m| m.trim().to_lowercase()).filter(|m| *m != self.username).collect();
        wanted.sort();
        wanted.dedup();
        if wanted.is_empty() || wanted.len() + 1 > MAX_GROUP_MEMBERS {
            return Err(ClientError::Invalid(format!("un groupe compte de 2 à {MAX_GROUP_MEMBERS} membres")));
        }
        let mut kps = Vec::new();
        let mut recipients = Vec::new();
        for u in &wanted {
            let (k, d) = self.claim_verified(u).await?;
            kps.extend(k);
            recipients.extend(d);
        }
        let (own_kps, own_devices) = self.claim_own_devices().await?;
        kps.extend(own_kps);
        recipients.extend(own_devices);
        let created = self.mls.create_group(&kps)?;
        let now = crate::now_ms();
        let mls_state = self.mls.export_state()?;
        let conv = StoredConversation {
            group_id: created.group_id.clone(),
            kind: "group".into(),
            peer: String::new(),
            name: Some(name.into()),
            admin: Some(self.username.clone()),
            status: status::OK.into(),
            created_at_ms: now,
            last_activity_ms: now,
            unread: 0,
            ttl_s: None,
            last_rotation_ms: now,
            sent_since_rotation: 0,
        };
        self.store.transaction(|s| {
            s.set_meta(crate::client::meta::MLS_STATE, &mls_state)?;
            s.insert_conversation(&conv)
        })?;
        self.post(recipients, created.welcome).await?;
        self.send_app(
            &created.group_id,
            AppBody::GroupInfo { name: name.into(), admin: self.wire_name(&self.username) },
            None,
        )
        .await?;
        self.conversation(&hex::encode(&created.group_id))
    }

    /// Ajoute un utilisateur (tous ses appareils) au groupe.
    pub async fn add_member(&mut self, conversation_id: &str, username: &str) -> Result<ConversationView> {
        let c = self.active_conversation(conversation_id)?;
        self.require_admin(&c)?;
        if self.mls.members(&c.group_id)?.iter().any(|m| m.identity.username == username) {
            return Err(ClientError::Invalid("déjà membre du groupe".into()));
        }
        if self.mls.members(&c.group_id)?.len() >= MAX_GROUP_MEMBERS {
            return Err(ClientError::Invalid("groupe complet".into()));
        }
        let (kps, new_devices) = self.claim_verified(username).await?;
        let existing = self.other_devices(&c.group_id)?;
        let added = self.mls.add_members(&c.group_id, &kps)?;
        self.save_mls()?;
        self.post(existing, added.commit).await?;
        self.post(new_devices, added.welcome).await?;
        let name = c.name.clone().unwrap_or_default();
        self.send_app(&c.group_id, AppBody::GroupInfo { name, admin: self.wire_name(&self.username) }, None).await?;
        self.conversation(conversation_id)
    }

    /// Retire un utilisateur (tous ses appareils) du groupe.
    pub async fn remove_member(&mut self, conversation_id: &str, username: &str) -> Result<ConversationView> {
        let c = self.active_conversation(conversation_id)?;
        self.require_admin(&c)?;
        if username == self.username {
            return Err(ClientError::Invalid("l'administrateur ne peut pas se retirer lui-même".into()));
        }
        let devices: Vec<Uuid> = self
            .mls
            .members(&c.group_id)?
            .into_iter()
            .filter(|m| m.identity.username == username)
            .map(|m| m.identity.device_id)
            .collect();
        if devices.is_empty() {
            return Err(ClientError::Invalid("cet utilisateur n'est pas membre du groupe".into()));
        }
        // Le commit est aussi envoyé aux appareils retirés, qui constatent leur retrait.
        let recipients = self.other_devices(&c.group_id)?;
        let commit = self.mls.remove_devices(&c.group_id, &devices)?;
        self.save_mls()?;
        self.post(recipients, commit).await?;
        self.persist_tokens()?;
        self.conversation(conversation_id)
    }

    /// Transfère l'administration (seul émetteur de commits) à un autre
    /// membre. L'annonce est chiffrée dans le groupe ; chaque appareil ne
    /// l'accepte que de l'administrateur en place. L'ancien administrateur
    /// cesse aussitôt d'émettre des commits et peut ensuite quitter le groupe.
    pub async fn transfer_admin(&mut self, conversation_id: &str, username: &str) -> Result<ConversationView> {
        let c = self.active_conversation(conversation_id)?;
        self.require_admin(&c)?;
        if username == self.username {
            return Err(ClientError::Invalid("vous êtes déjà administrateur".into()));
        }
        if !usernames(&self.mls.members(&c.group_id)?).iter().any(|u| u == username) {
            return Err(ClientError::Invalid("cet utilisateur n'est pas membre du groupe".into()));
        }
        let name = c.name.clone().unwrap_or_default();
        self.send_app(&c.group_id, AppBody::GroupInfo { name: name.clone(), admin: self.wire_name(username) }, None)
            .await?;
        self.store.set_group_info(&c.group_id, &name, username)?;
        self.conversation(conversation_id)
    }

    /// Quitte un groupe : proposition de départ validée par l'administrateur.
    pub async fn leave_group(&mut self, conversation_id: &str) -> Result<()> {
        let c = self.store.conversation(&decode_id(conversation_id)?)?.ok_or(ClientError::UnknownConversation)?;
        if c.kind != "group" {
            return Err(ClientError::Invalid("seuls les groupes peuvent être quittés".into()));
        }
        if self.effective_admin(&c).as_deref() == Some(self.username.as_str()) {
            return Err(ClientError::Invalid(
                "l'administrateur doit d'abord transférer l'administration à un autre membre".into(),
            ));
        }
        let proposal = self.mls.propose_leave(&c.group_id)?;
        let recipients = self.other_devices(&c.group_id)?;
        self.save_mls()?;
        self.post(recipients, proposal).await?;
        self.store.set_status(&c.group_id, status::LEFT)?;
        self.persist_tokens()
    }

    // --- Numéros de sécurité et changement de clé ------------------------------

    fn expected_safety_number(&self, username: &str) -> Result<(String, bool, bool)> {
        let c = self.store.contact(username)?.ok_or_else(|| ClientError::Invalid("correspondant inconnu".into()))?;
        let changed = c.pending_identity_key.is_some();
        let key = c.pending_identity_key.unwrap_or(c.identity_key);
        // Entre sites, les deux côtés utilisent les adresses qualifiées (même
        // numéro des deux côtés) ; sur un même site, les noms seuls (numéros
        // inchangés depuis la Phase 2).
        let (me, them) = if username.contains('@') {
            (self.address(), username.to_owned())
        } else {
            (self.username.clone(), username.to_owned())
        };
        let n = safety::safety_number(&me, &self.identity_public, &them, &key);
        Ok((n, c.verified && !changed, changed))
    }

    /// Numéro de sécurité avec `username` (sur la nouvelle clé si elle a changé).
    pub fn safety_number(&self, username: &str) -> Result<SafetyNumberView> {
        let (n, verified, identity_changed) = self.expected_safety_number(username)?;
        Ok(SafetyNumberView {
            username: username.into(),
            number: safety::format_groups(&n),
            qr_payload: safety::qr_payload(&n),
            verified,
            identity_changed,
        })
    }

    /// Vérification : `scanned` est le contenu du QR code du correspondant ou
    /// les 60 chiffres qu'il a lus. Sans `scanned`, l'utilisateur atteste avoir
    /// comparé les chiffres de vive voix. En cas de succès, une clé en attente
    /// est acceptée et le contact est marqué vérifié.
    pub fn verify_safety_number(&self, username: &str, scanned: Option<&str>) -> Result<bool> {
        let (expected, _, changed) = self.expected_safety_number(username)?;
        if let Some(s) = scanned {
            if !safety::matches(&expected, s) {
                return Ok(false);
            }
        }
        let now = crate::now_ms();
        if changed {
            self.store.accept_pending_identity(username, true, now)?;
        } else {
            self.store.set_verified(username, true, now)?;
        }
        self.refresh_identity_status()?;
        Ok(true)
    }

    /// Accepte la nouvelle clé d'identité d'un contact **sans** vérification
    /// (le contact repasse à l'état non vérifié).
    pub fn accept_identity_change(&self, username: &str) -> Result<()> {
        if !self.store.accept_pending_identity(username, false, crate::now_ms())? {
            return Err(ClientError::Invalid("aucun changement de clé en attente".into()));
        }
        self.refresh_identity_status()
    }

    /// Réactive les conversations dont plus aucun membre n'a de changement de
    /// clé en attente (les certificats ont été vérifiés à la réception).
    fn refresh_identity_status(&self) -> Result<()> {
        for c in self.store.conversations()? {
            if c.status != status::IDENTITY_CHANGED {
                continue;
            }
            let members = self.mls.members(&c.group_id).map(|m| usernames(&m)).unwrap_or_default();
            let pending = members
                .iter()
                .any(|u| matches!(self.store.contact(u), Ok(Some(ct)) if ct.pending_identity_key.is_some()));
            if !pending {
                self.store.set_status(&c.group_id, status::OK)?;
            }
        }
        Ok(())
    }

    // --- Réception --------------------------------------------------------

    /// Récupère et traite tous les messages en attente, puis supprime les
    /// messages éphémères expirés et effectue les rotations de clés dues.
    pub async fn sync(&mut self) -> Result<SyncReport> {
        let mut report = SyncReport::default();
        loop {
            let q = self.api.queue(100).await?;
            let n = q.messages.len();
            let mut ids = Vec::with_capacity(n);
            for m in q.messages {
                report.processed += 1;
                match self.handle(&m.payload).await {
                    Ok(h) => {
                        if h.new_message {
                            report.new_messages += 1;
                        }
                        for u in h.identity_changes {
                            if !report.identity_changes.contains(&u) {
                                report.identity_changes.push(u);
                            }
                        }
                        if let Some(gid) = h.conversation {
                            if h.removed {
                                report.removed_from.push(gid.clone());
                            }
                            if !report.changed_conversations.contains(&gid) {
                                report.changed_conversations.push(gid);
                            }
                        }
                    }
                    Err(ClientError::Network(e)) => return Err(ClientError::Network(e)),
                    Err(e) => {
                        report.rejected += 1;
                        tracing::warn!(error = %e, "message entrant rejeté");
                    }
                }
                ids.push(m.id);
            }
            if !ids.is_empty() {
                self.api.ack(ids).await?;
            }
            if n < 100 {
                break;
            }
        }
        report.expired = self.store.purge_expired(crate::now_ms())?;
        report.rotations = self.rotate_due().await?;
        report.reconciled = self.reconcile_due().await?;
        self.ensure_key_packages().await?;
        Ok(report)
    }

    /// Rotation périodique (PCS) : l'administrateur émet un commit de mise à
    /// jour ; les autres membres proposent la leur.
    pub(crate) async fn rotate_due(&mut self) -> Result<usize> {
        let now = crate::now_ms();
        let mut n = 0;
        for c in self.store.rotation_due(now, ROTATION_MAX_AGE_MS, ROTATION_MAX_SENT)? {
            let recipients = self.other_devices(&c.group_id)?;
            let payload = if self.is_primary() && self.effective_admin(&c).as_deref() == Some(self.username.as_str()) {
                self.mls.self_update(&c.group_id)?
            } else {
                self.mls.propose_self_update(&c.group_id)?
            };
            self.save_mls()?;
            self.post(recipients, payload).await?;
            self.store.mark_rotated(&c.group_id, now)?;
            n += 1;
        }
        Ok(n)
    }

    /// Force la rotation immédiate des clés d'une conversation.
    pub async fn rotate_now(&mut self, conversation_id: &str) -> Result<()> {
        let c = self.active_conversation(conversation_id)?;
        self.store.mark_rotated(&c.group_id, 0)?;
        self.rotate_due().await.map(|_| ())
    }

    async fn handle(&mut self, payload: &[u8]) -> Result<Handled> {
        let incoming = {
            let store = &self.store;
            let mls = &self.mls;
            let allowed = |gid: &[u8], sender: &MemberIdentity| match store.conversation(gid) {
                Ok(Some(c)) => match c
                    .admin
                    .clone()
                    .or_else(|| mls.members(gid).ok().and_then(|m| usernames(&m).into_iter().next()))
                {
                    Some(a) => a == sender.username,
                    None => true,
                },
                _ => true,
            };
            self.mls.process_with(payload, &allowed)
        };
        // L'état MLS a pu changer (même en cas d'erreur applicative ensuite).
        self.save_mls()?;
        match incoming? {
            Incoming::Joined { group_id, members } => {
                let outcome = self.verify_members(&members).await?;
                let now = crate::now_ms();
                let direct = outcome.others.len() == 1;
                let conv = StoredConversation {
                    group_id: group_id.clone(),
                    kind: if direct { "direct" } else { "group" }.into(),
                    peer: if direct { outcome.others[0].clone() } else { String::new() },
                    name: None,
                    // Administrateur annoncé par le message GroupInfo qui suit
                    // le Welcome (le créateur peut être l'un de mes appareils).
                    admin: None,
                    status: if outcome.changed.is_empty() { status::OK } else { status::IDENTITY_CHANGED }.into(),
                    created_at_ms: now,
                    last_activity_ms: now,
                    unread: 0,
                    ttl_s: None,
                    last_rotation_ms: now,
                    sent_since_rotation: 0,
                };
                if outcome.others.is_empty() {
                    return Err(ClientError::Invalid("groupe sans autre membre".into()));
                }
                self.store.insert_conversation(&conv)?;
                self.store.rejoin_conversation(&group_id, &conv.status)?;
                Ok(Handled {
                    conversation: Some(hex::encode(group_id)),
                    identity_changes: outcome.changed,
                    ..Default::default()
                })
            }
            Incoming::Committed { group_id, members, removed_self, .. } => {
                if removed_self {
                    self.store.set_status(&group_id, status::REMOVED)?;
                    let _ = self.mls.delete_group(&group_id);
                    self.save_mls()?;
                    return Ok(Handled {
                        conversation: Some(hex::encode(group_id)),
                        removed: true,
                        ..Default::default()
                    });
                }
                let outcome = self.verify_members(&members).await?;
                if !outcome.changed.is_empty() {
                    self.store.set_status(&group_id, status::IDENTITY_CHANGED)?;
                }
                Ok(Handled {
                    conversation: Some(hex::encode(group_id)),
                    identity_changes: outcome.changed,
                    ..Default::default()
                })
            }
            Incoming::ProposalStored { group_id, .. } => {
                // L'administrateur valide aussitôt les propositions (rotation, départ).
                let c = self.store.conversation(&group_id)?;
                if let Some(c) = c
                    .filter(|c| self.is_primary() && self.effective_admin(c).as_deref() == Some(self.username.as_str()))
                {
                    let recipients = self.other_devices(&c.group_id)?;
                    if let Some(commit) = self.mls.commit_pending(&c.group_id)? {
                        self.save_mls()?;
                        self.post(recipients, commit).await?;
                    }
                }
                Ok(Handled { conversation: Some(hex::encode(group_id)), ..Default::default() })
            }
            Incoming::Application { group_id, sender, plaintext } => {
                let c = self.store.conversation(&group_id)?.ok_or(ClientError::UnknownConversation)?;
                let app = AppMessage::decode(&plaintext)?;
                let gid_hex = hex::encode(&group_id);
                let now = crate::now_ms();
                let (kind, body, attachment) = match app.body {
                    AppBody::Text { text } => ("text", text, None),
                    AppBody::GroupInfo { name, admin } => {
                        let admin = self.local_name(&admin);
                        // Seul l'administrateur en place annonce les informations
                        // du groupe : il se désigne lui-même, ou désigne un autre
                        // membre (transfert). Avant toute annonce (groupe rejoint),
                        // seul un membre se désignant lui-même est accepté.
                        let authorized = match c.admin.as_deref() {
                            Some(current) => sender.username == current,
                            None => sender.username == admin,
                        };
                        let is_member =
                            self.mls.members(&group_id).map(|m| usernames(&m).contains(&admin)).unwrap_or(false);
                        if !authorized || !is_member {
                            return Err(ClientError::Verification(
                                sender.username,
                                "informations de groupe non autorisées".into(),
                            ));
                        }
                        self.store.set_group_info(&group_id, &name, &admin)?;
                        return Ok(Handled { conversation: Some(gid_hex), ..Default::default() });
                    }
                    AppBody::Attachment { attachment, caption } => (
                        "attachment",
                        caption.unwrap_or_default(),
                        Some(serde_json::to_string(&attachment).map_err(|e| ClientError::Invalid(e.to_string()))?),
                    ),
                };
                let outgoing = sender.username == self.username;
                let stored = StoredMessage {
                    id: format!("{gid_hex}:{}", app.id),
                    group_id,
                    sender: sender.username,
                    sender_device: sender.device_id.to_string(),
                    kind: kind.into(),
                    body,
                    attachment,
                    sent_at_ms: app.sent_at_ms,
                    received_at_ms: now,
                    outgoing,
                    expires_at_ms: app.expires_in_s.map(|t| now + i64::from(t) * 1000),
                };
                let new = self.store.insert_message(&stored)?;
                Ok(Handled { conversation: Some(gid_hex), new_message: new, ..Default::default() })
            }
        }
    }
}
