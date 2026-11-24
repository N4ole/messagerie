//! Logique client de haut niveau.

use std::collections::HashMap;
use std::path::PathBuf;

use msg_crypto::app_message::{AppBody, AppMessage};
use msg_crypto::identity::{DeviceCertificate, SigningKeyPair};
use msg_crypto::keywrap::Argon2Params;
use msg_crypto::mls::{GroupMember, Incoming, MemberIdentity, MlsClient};
use msg_proto::{
    validate_username, ActivateRequest, ActivateResponse, ConfirmTotpRequest, DeviceRegistration, LoginRequest,
    PublishedDevice, SendRequest, SessionTokens, UserDirectoryEntry,
};
use serde::Serialize;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::api::{validate_server_url, ApiClient, DeviceAuth};
use crate::error::{ClientError, Result};
use crate::store::{LocalStore, StoredConversation, StoredMessage};
use crate::vault::{self, AccountPaths};

/// Seuil de réapprovisionnement des KeyPackages et taille du lot.
const KEY_PACKAGE_LOW_WATER: i64 = 10;
const KEY_PACKAGE_BATCH: usize = 50;

mod meta {
    pub const USERNAME: &str = "username";
    pub const DEVICE_ID: &str = "device_id";
    pub const IDENTITY_SECRET: &str = "identity_secret";
    pub const API_SECRET: &str = "api_secret";
    pub const MLS_PUBLIC: &str = "mls_public";
    pub const MLS_STATE: &str = "mls_state";
    pub const CERT_CREATED_AT: &str = "cert_created_at";
    pub const CERT_SIGNATURE: &str = "cert_signature";
    pub const SESSION: &str = "session";
}

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub server_url: String,
    /// Dossier de données de l'application (contient `accounts/…`).
    pub data_dir: PathBuf,
    /// Paramètres Argon2id du coffre local.
    pub argon2: Argon2Params,
    /// Autorise HTTP hors boucle locale (tests uniquement).
    pub allow_insecure_http: bool,
}

impl ClientConfig {
    pub fn new(server_url: impl Into<String>, data_dir: impl Into<PathBuf>) -> Self {
        Self {
            server_url: server_url.into(),
            data_dir: data_dir.into(),
            argon2: Argon2Params::PRODUCTION,
            allow_insecure_http: false,
        }
    }

    fn api(&self) -> Result<ApiClient> {
        ApiClient::new(validate_server_url(&self.server_url, self.allow_insecure_http)?)
    }

    fn paths(&self, username: &str) -> AccountPaths {
        AccountPaths::new(&self.data_dir, self.server_url.trim_end_matches('/'), username)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ConversationView {
    /// Identifiant de groupe MLS (hexadécimal).
    pub id: String,
    pub peer: String,
    pub last_activity_ms: i64,
    pub unread: i64,
    /// Empreinte courte de la clé d'identité du correspondant.
    pub peer_fingerprint: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MessageView {
    pub id: String,
    pub conversation_id: String,
    pub sender: String,
    pub outgoing: bool,
    pub sent_at_ms: i64,
    pub received_at_ms: i64,
    pub text: String,
    /// Rendu Markdown sûr (aucun HTML, aucune ressource distante).
    pub ast: Vec<msg_markdown::Node>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SyncReport {
    pub processed: usize,
    pub new_messages: usize,
    pub changed_conversations: Vec<String>,
    /// Messages rejetés (rejeu, signature invalide, vérification échouée…).
    pub rejected: usize,
}

/// Empreinte lisible (groupes de 4 chiffres hexadécimaux) d'une clé d'identité.
pub fn fingerprint(identity_key: &[u8]) -> String {
    let h = hex::encode_upper(&msg_crypto::sha256(identity_key)[..16]);
    h.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap_or_default()).collect::<Vec<_>>().join(" ")
}

pub struct Client {
    api: ApiClient,
    store: LocalStore,
    mls: MlsClient,
    identity: SigningKeyPair,
    username: String,
    device_id: Uuid,
}

fn get_meta(store: &LocalStore, k: &str) -> Result<Zeroizing<Vec<u8>>> {
    store.get_meta(k)?.ok_or_else(|| ClientError::Storage(format!("métadonnée « {k} » absente")))
}

impl Client {
    // --- Enrôlement et connexion ------------------------------------------

    /// Étape 1 : activation du compte avec le code remis par l'administrateur.
    pub async fn activate(
        cfg: &ClientConfig,
        username: &str,
        activation_code: &str,
        new_password: &str,
    ) -> Result<ActivateResponse> {
        validate_username(username).map_err(|e| ClientError::Invalid(e.into()))?;
        msg_proto::validate_password(new_password).map_err(|e| ClientError::Invalid(e.into()))?;
        cfg.api()?
            .activate(&ActivateRequest {
                username: username.into(),
                activation_code: activation_code.into(),
                new_password: new_password.into(),
            })
            .await
    }

    /// Étape 2 : confirmation du TOTP. Crée l'identité et l'appareil, les
    /// enregistre sur le serveur, puis crée la base locale chiffrée.
    pub async fn enroll(cfg: &ClientConfig, username: &str, password: &str, totp_code: &str) -> Result<Self> {
        validate_username(username).map_err(|e| ClientError::Invalid(e.into()))?;
        let paths = cfg.paths(username);
        if paths.exists() {
            return Err(ClientError::LocalAccountExists);
        }
        let identity = SigningKeyPair::generate()?;
        let api_key = SigningKeyPair::generate()?;
        let device_id = Uuid::new_v4();
        let mls = MlsClient::create(MemberIdentity { username: username.into(), device_id })?;
        let cert_created_at = crate::now_secs();
        let cert = DeviceCertificate {
            username: username.into(),
            device_id,
            api_key: api_key.public_bytes().to_vec(),
            mls_signature_key: mls.signature_public_key(),
            created_at: cert_created_at,
        };
        let cert_sig = cert.sign(&identity);
        let mut api = cfg.api()?;
        let reg = DeviceRegistration {
            device_id,
            identity_key: identity.public_bytes().to_vec(),
            api_key: api_key.public_bytes().to_vec(),
            mls_signature_key: mls.signature_public_key(),
            cert_created_at,
            cert_signature: cert_sig.to_vec(),
        };
        let tokens = api
            .confirm_totp(&ConfirmTotpRequest {
                username: username.into(),
                password: password.into(),
                totp_code: totp_code.into(),
                device: reg,
            })
            .await?;
        // Le serveur a accepté : création du coffre et de la base locale.
        let key = vault::create(&paths, password, cfg.argon2)?;
        let mut store = LocalStore::open(&paths.db, &key)?;
        store.transaction(|s| {
            s.set_meta(meta::USERNAME, username.as_bytes())?;
            s.set_meta(meta::DEVICE_ID, device_id.as_bytes())?;
            s.set_meta(meta::IDENTITY_SECRET, identity.secret_bytes().as_ref())?;
            s.set_meta(meta::API_SECRET, api_key.secret_bytes().as_ref())?;
            s.set_meta(meta::MLS_PUBLIC, &mls.signature_public_key())?;
            s.set_meta(meta::MLS_STATE, &mls.export_state()?)?;
            s.set_meta(meta::CERT_CREATED_AT, &cert_created_at.to_be_bytes())?;
            s.set_meta(meta::CERT_SIGNATURE, &cert_sig)?;
            Ok(())
        })?;
        api.set_device(DeviceAuth { device_id, api_key });
        let client = Self { api, store, mls, identity, username: username.into(), device_id };
        client.save_session(&tokens)?;
        client.ensure_key_packages().await?;
        Ok(client)
    }

    /// Déverrouille le compte local puis ouvre une session serveur.
    /// Sans code TOTP, tente de reprendre la session existante ; si elle a
    /// expiré, renvoie [`ClientError::TotpRequired`].
    pub async fn login(cfg: &ClientConfig, username: &str, password: &str, totp_code: Option<&str>) -> Result<Self> {
        validate_username(username).map_err(|e| ClientError::Invalid(e.into()))?;
        let paths = cfg.paths(username);
        if !paths.exists() {
            return Err(ClientError::NoLocalAccount);
        }
        let key = vault::open(&paths, password)?;
        let store = LocalStore::open(&paths.db, &key)?;
        drop(key);
        let stored_name = get_meta(&store, meta::USERNAME)?;
        if stored_name.as_slice() != username.as_bytes() {
            return Err(ClientError::Storage("compte local incohérent".into()));
        }
        let device_id =
            Uuid::from_slice(&get_meta(&store, meta::DEVICE_ID)?).map_err(|e| ClientError::Storage(e.to_string()))?;
        let identity = SigningKeyPair::from_secret_bytes(&get_meta(&store, meta::IDENTITY_SECRET)?)?;
        let api_key = SigningKeyPair::from_secret_bytes(&get_meta(&store, meta::API_SECRET)?)?;
        let mls = MlsClient::restore(
            MemberIdentity { username: username.into(), device_id },
            &get_meta(&store, meta::MLS_PUBLIC)?,
            &get_meta(&store, meta::MLS_STATE)?,
        )?;
        let mut api = cfg.api()?;
        api.set_device(DeviceAuth { device_id, api_key });
        let client = Self { api, store, mls, identity, username: username.into(), device_id };
        match totp_code.map(str::trim).filter(|c| !c.is_empty()) {
            Some(code) => {
                let reg = client.registration()?;
                let tokens = client
                    .api
                    .login(&LoginRequest {
                        username: username.into(),
                        password: password.into(),
                        totp_code: code.into(),
                        device: reg,
                    })
                    .await?;
                client.save_session(&tokens)?;
            }
            None => {
                let prev = client.load_session()?.filter(|t| t.session_expires_at > crate::now_secs() + 30);
                let Some(prev) = prev else { return Err(ClientError::TotpRequired) };
                client.api.set_tokens(Some(prev));
                match client.api.refresh().await {
                    Ok(t) => client.save_session(&t)?,
                    Err(ClientError::Api { status: 401 | 403, .. }) => {
                        client.store.delete_meta(meta::SESSION)?;
                        return Err(ClientError::TotpRequired);
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        client.ensure_key_packages().await?;
        Ok(client)
    }

    fn registration(&self) -> Result<DeviceRegistration> {
        let ts: [u8; 8] = get_meta(&self.store, meta::CERT_CREATED_AT)?
            .as_slice()
            .try_into()
            .map_err(|_| ClientError::Storage("date de certificat".into()))?;
        let api_pub = SigningKeyPair::from_secret_bytes(&get_meta(&self.store, meta::API_SECRET)?)?.public_bytes();
        Ok(DeviceRegistration {
            device_id: self.device_id,
            identity_key: self.identity.public_bytes().to_vec(),
            api_key: api_pub.to_vec(),
            mls_signature_key: self.mls.signature_public_key(),
            cert_created_at: i64::from_be_bytes(ts),
            cert_signature: get_meta(&self.store, meta::CERT_SIGNATURE)?.to_vec(),
        })
    }

    fn save_session(&self, t: &SessionTokens) -> Result<()> {
        let json = Zeroizing::new(serde_json::to_vec(t).map_err(|e| ClientError::Storage(e.to_string()))?);
        self.store.set_meta(meta::SESSION, &json)
    }

    fn load_session(&self) -> Result<Option<SessionTokens>> {
        Ok(match self.store.get_meta(meta::SESSION)? {
            Some(j) => serde_json::from_slice(&j).ok(),
            None => None,
        })
    }

    /// Enregistre les jetons courants (après un éventuel renouvellement).
    fn persist_tokens(&self) -> Result<()> {
        if let Some(t) = self.api.tokens() {
            self.save_session(&t)?;
        }
        Ok(())
    }

    fn save_mls(&self) -> Result<()> {
        self.store.set_meta(meta::MLS_STATE, &self.mls.export_state()?)
    }

    /// Réapprovisionne les KeyPackages publiés si la réserve est basse.
    pub async fn ensure_key_packages(&self) -> Result<()> {
        if self.api.key_package_count().await? < KEY_PACKAGE_LOW_WATER {
            let kps = self.mls.generate_key_packages(KEY_PACKAGE_BATCH)?;
            // Les clés privées associées doivent être persistées AVANT publication.
            self.save_mls()?;
            self.api.upload_key_packages(kps).await?;
        }
        self.persist_tokens()
    }

    pub async fn logout(self) -> Result<()> {
        let r = self.api.logout().await;
        self.store.delete_meta(meta::SESSION)?;
        r
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn device_id(&self) -> Uuid {
        self.device_id
    }

    pub fn identity_fingerprint(&self) -> String {
        fingerprint(&self.identity.public_bytes())
    }

    pub fn api(&self) -> &ApiClient {
        &self.api
    }

    // --- Vérification des correspondants ------------------------------------

    /// Confiance au premier usage : la première clé d'identité vue est
    /// mémorisée ; tout changement ultérieur bloque la conversation.
    fn check_identity(&self, username: &str, identity_key: &[u8]) -> Result<()> {
        if username == self.username {
            return if identity_key == self.identity.public_bytes() {
                Ok(())
            } else {
                Err(ClientError::IdentityChanged(username.into()))
            };
        }
        match self.store.contact_identity(username)? {
            Some(k) if k == identity_key => Ok(()),
            Some(_) => Err(ClientError::IdentityChanged(username.into())),
            None => self.store.add_contact(username, identity_key, crate::now_ms()),
        }
    }

    fn verify_device(username: &str, identity_key: &[u8], d: &PublishedDevice) -> Result<()> {
        DeviceCertificate {
            username: username.into(),
            device_id: d.device_id,
            api_key: d.api_key.clone(),
            mls_signature_key: d.mls_signature_key.clone(),
            created_at: d.cert_created_at,
        }
        .verify(identity_key, &d.cert_signature)
        .map_err(|_| ClientError::Verification(username.into(), "certificat d'appareil invalide".into()))
    }

    /// Vérifie que chaque membre d'un groupe correspond à un appareil certifié
    /// par une identité connue. Retourne les autres utilisateurs du groupe.
    async fn verify_members(&self, members: &[GroupMember]) -> Result<Vec<String>> {
        let mut dirs: HashMap<String, UserDirectoryEntry> = HashMap::new();
        let mut others = Vec::new();
        for m in members {
            let name = &m.identity.username;
            if *name == self.username && m.identity.device_id == self.device_id {
                if m.signature_key != self.mls.signature_public_key() {
                    return Err(ClientError::Verification(name.clone(), "clé MLS locale inattendue".into()));
                }
                continue;
            }
            if !dirs.contains_key(name) {
                let entry = self.api.directory(name).await?;
                self.check_identity(name, &entry.identity_key)?;
                dirs.insert(name.clone(), entry);
            }
            let entry = &dirs[name];
            let dev = entry
                .devices
                .iter()
                .find(|d| d.device_id == m.identity.device_id)
                .ok_or_else(|| ClientError::Verification(name.clone(), "appareil absent de l'annuaire".into()))?;
            Self::verify_device(name, &entry.identity_key, dev)?;
            if dev.mls_signature_key != m.signature_key {
                return Err(ClientError::Verification(name.clone(), "clé MLS non certifiée".into()));
            }
            if *name != self.username && !others.contains(name) {
                others.push(name.clone());
            }
        }
        Ok(others)
    }

    // --- Conversations ----------------------------------------------------

    fn view_conversation(&self, c: StoredConversation) -> Result<ConversationView> {
        let fp = self.store.contact_identity(&c.peer)?.map(|k| fingerprint(&k)).unwrap_or_default();
        Ok(ConversationView {
            id: hex::encode(&c.group_id),
            peer: c.peer,
            last_activity_ms: c.last_activity_ms,
            unread: c.unread,
            peer_fingerprint: fp,
        })
    }

    fn view_message(m: StoredMessage) -> MessageView {
        let ast = msg_markdown::parse(&m.body);
        MessageView {
            id: m.id,
            conversation_id: hex::encode(&m.group_id),
            sender: m.sender,
            outgoing: m.outgoing,
            sent_at_ms: m.sent_at_ms,
            received_at_ms: m.received_at_ms,
            text: m.body,
            ast,
        }
    }

    pub fn conversations(&self) -> Result<Vec<ConversationView>> {
        self.store.conversations()?.into_iter().map(|c| self.view_conversation(c)).collect()
    }

    pub fn messages(&self, conversation_id: &str, limit: u32) -> Result<Vec<MessageView>> {
        let gid = hex::decode(conversation_id).map_err(|_| ClientError::UnknownConversation)?;
        Ok(self.store.messages(&gid, limit.min(1000))?.into_iter().map(Self::view_message).collect())
    }

    pub fn mark_read(&self, conversation_id: &str) -> Result<()> {
        let gid = hex::decode(conversation_id).map_err(|_| ClientError::UnknownConversation)?;
        self.store.mark_read(&gid)
    }

    /// Ouvre (ou retrouve) une conversation chiffrée avec `peer`.
    pub async fn start_conversation(&mut self, peer: &str) -> Result<ConversationView> {
        validate_username(peer).map_err(|e| ClientError::Invalid(e.into()))?;
        if peer == self.username {
            return Err(ClientError::Invalid("impossible d'ouvrir une conversation avec soi-même".into()));
        }
        if let Some(gid) = self.store.conversation_with(peer)? {
            if let Some(c) = self.store.conversation(&gid)? {
                return self.view_conversation(c);
            }
        }
        let entry = self.api.claim(peer).await?;
        self.check_identity(peer, &entry.identity_key)?;
        let mut kps = Vec::new();
        let mut recipients = Vec::new();
        for d in &entry.devices {
            Self::verify_device(peer, &entry.identity_key, d)?;
            let kp = d
                .key_package
                .as_ref()
                .ok_or_else(|| ClientError::Verification(peer.into(), "KeyPackage manquant".into()))?;
            let m = self.mls.inspect_key_package(kp)?;
            if m.identity != (MemberIdentity { username: peer.into(), device_id: d.device_id })
                || m.signature_key != d.mls_signature_key
            {
                return Err(ClientError::Verification(peer.into(), "KeyPackage non conforme au certificat".into()));
            }
            kps.push(kp.clone());
            recipients.push(d.device_id);
        }
        let created = self.mls.create_group(&kps)?;
        let now = crate::now_ms();
        let mls_state = self.mls.export_state()?;
        self.store.transaction(|s| {
            s.set_meta(meta::MLS_STATE, &mls_state)?;
            s.upsert_conversation(&created.group_id, peer, now)
        })?;
        self.api.send(&SendRequest { client_message_id: Uuid::new_v4(), recipients, payload: created.welcome }).await?;
        self.persist_tokens()?;
        let c = self.store.conversation(&created.group_id)?.ok_or(ClientError::UnknownConversation)?;
        self.view_conversation(c)
    }

    /// Chiffre, signe et envoie un message texte (Markdown).
    pub async fn send_text(&mut self, conversation_id: &str, text: &str) -> Result<MessageView> {
        let text = text.trim_end();
        if text.trim().is_empty() {
            return Err(ClientError::Invalid("message vide".into()));
        }
        let gid = hex::decode(conversation_id).map_err(|_| ClientError::UnknownConversation)?;
        self.store.conversation(&gid)?.ok_or(ClientError::UnknownConversation)?;
        let app = AppMessage::text(text.to_owned(), crate::now_ms())?;
        let ct = self.mls.encrypt(&gid, &app.encode())?;
        let recipients: Vec<Uuid> = self
            .mls
            .members(&gid)?
            .into_iter()
            .map(|m| m.identity.device_id)
            .filter(|d| *d != self.device_id)
            .collect();
        // L'état du ratchet a avancé : il est persisté avant l'envoi.
        self.save_mls()?;
        self.api.send(&SendRequest { client_message_id: app.id, recipients, payload: ct }).await?;
        let stored = StoredMessage {
            id: format!("{}:{}", conversation_id, app.id),
            group_id: gid,
            sender: self.username.clone(),
            sender_device: self.device_id.to_string(),
            body: text.to_owned(),
            sent_at_ms: app.sent_at_ms,
            received_at_ms: crate::now_ms(),
            outgoing: true,
        };
        self.store.insert_message(&stored)?;
        self.persist_tokens()?;
        Ok(Self::view_message(stored))
    }

    // --- Réception --------------------------------------------------------

    /// Récupère et traite tous les messages en attente.
    pub async fn sync(&mut self) -> Result<SyncReport> {
        let mut report = SyncReport::default();
        loop {
            let q = self.api.queue(100).await?;
            let n = q.messages.len();
            let mut ids = Vec::with_capacity(n);
            for m in q.messages {
                report.processed += 1;
                match self.handle(&m.payload).await {
                    Ok(Some((gid, new))) => {
                        if new {
                            report.new_messages += 1;
                        }
                        if !report.changed_conversations.contains(&gid) {
                            report.changed_conversations.push(gid);
                        }
                    }
                    Ok(None) => {}
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
        self.ensure_key_packages().await?;
        Ok(report)
    }

    /// Traite un message ; retourne la conversation modifiée et si un
    /// nouveau message a été ajouté.
    async fn handle(&mut self, payload: &[u8]) -> Result<Option<(String, bool)>> {
        let incoming = self.mls.process(payload);
        // L'état MLS a pu changer (même en cas d'erreur applicative ensuite).
        self.save_mls()?;
        match incoming? {
            Incoming::Joined { group_id, members } => {
                let others = self.verify_members(&members).await?;
                let [peer] = others.as_slice() else {
                    return Err(ClientError::Invalid(
                        "seules les conversations 1-à-1 sont prises en charge en Phase 1".into(),
                    ));
                };
                self.store.upsert_conversation(&group_id, peer, crate::now_ms())?;
                Ok(Some((hex::encode(group_id), false)))
            }
            Incoming::Committed { group_id, members } => {
                self.verify_members(&members).await?;
                Ok(Some((hex::encode(group_id), false)))
            }
            Incoming::ProposalStored { .. } => Ok(None),
            Incoming::Application { group_id, sender, plaintext } => {
                if self.store.conversation(&group_id)?.is_none() {
                    return Err(ClientError::UnknownConversation);
                }
                let app = AppMessage::decode(&plaintext)?;
                let AppBody::Text { text } = app.body;
                let gid_hex = hex::encode(&group_id);
                let stored = StoredMessage {
                    id: format!("{}:{}", gid_hex, app.id),
                    group_id,
                    sender: sender.username,
                    sender_device: sender.device_id.to_string(),
                    body: text,
                    sent_at_ms: app.sent_at_ms,
                    received_at_ms: crate::now_ms(),
                    outgoing: false,
                };
                let new = self.store.insert_message(&stored)?;
                Ok(Some((gid_hex, new)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_format() {
        let f = fingerprint(&[1u8; 32]);
        assert_eq!(f.len(), 32 + 7);
        assert!(f.chars().all(|c| c.is_ascii_hexdigit() || c == ' '));
    }
}
