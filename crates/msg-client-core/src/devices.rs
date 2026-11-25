//! Appareils multiples : liaison d'un nouvel appareil, approbation par
//! l'appareil principal, révocation et réconciliation des groupes.
//!
//! Règles (voir ADR-0013) :
//! - seul l'appareil **principal** détient la clé d'identité ; il signe le
//!   certificat d'un nouvel appareil après comparaison d'une empreinte que
//!   ce dernier affiche (le serveur ne peut donc pas substituer ses clés) ;
//! - dans un groupe, seul l'appareil principal de l'administrateur émet les
//!   commits automatiques ; il ajoute les nouveaux appareils des membres et
//!   retire les appareils révoqués (« réconciliation »).

use std::collections::HashMap;

use msg_crypto::app_message::AppBody;
use msg_crypto::identity::{DeviceCertificate, SigningKeyPair};
use msg_crypto::mls::{MemberIdentity, MlsClient};
use msg_proto::{LinkApproveRequest, LinkPollRequest, LinkStartRequest, LinkStatus, OwnDevice, PendingDevice};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::account;
use crate::api::ApiClient;
use crate::client::{meta, Client, ClientConfig};
use crate::error::{ClientError, Result};
use crate::store::status;

/// Préfixe du code de liaison (affiché en QR code par le nouvel appareil).
pub const LINK_CODE_PREFIX: &str = "messagerie-link:1:";

/// Intervalle minimal entre deux réconciliations automatiques.
const RECONCILE_INTERVAL_MS: i64 = 60_000;

/// Empreinte des clés publiques d'un appareil en attente : 80 bits, en
/// groupes de 4 caractères hexadécimaux.
pub fn link_fingerprint(d: &PendingDevice) -> String {
    let mut data = b"messagerie-link-v1".to_vec();
    data.extend_from_slice(d.device_id.as_bytes());
    data.extend_from_slice(&d.api_key);
    data.extend_from_slice(&d.mls_signature_key);
    let h = hex::encode_upper(&msg_crypto::sha256(&data)[..10]);
    h.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap_or_default()).collect::<Vec<_>>().join(" ")
}

/// Code de liaison : identifiant de la demande et empreinte.
pub fn link_code(link_id: Uuid, d: &PendingDevice) -> String {
    format!("{LINK_CODE_PREFIX}{link_id}:{}", link_fingerprint(d).replace(' ', ""))
}

/// Analyse un code de liaison (saisi ou scanné).
pub fn parse_link_code(code: &str) -> Result<(Uuid, String)> {
    let bad = || ClientError::Invalid("code de liaison invalide".into());
    let rest = code.trim().strip_prefix(LINK_CODE_PREFIX).ok_or_else(bad)?;
    let (id, fp) = rest.split_once(':').ok_or_else(bad)?;
    let id = Uuid::parse_str(id).map_err(|_| bad())?;
    let fp: String = fp.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_uppercase();
    if fp.len() != 20 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(bad());
    }
    Ok((id, fp))
}

/// Demande de liaison en attente, vue par l'appareil principal.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LinkRequestInfo {
    pub link_id: Uuid,
    pub device_id: Uuid,
    /// Empreinte à comparer avec celle affichée par le nouvel appareil.
    pub fingerprint: String,
    pub created_at: i64,
    pub expires_at: i64,
}

/// Nouvel appareil en attente d'approbation.
pub struct PendingLink {
    cfg: ClientConfig,
    username: String,
    password: Zeroizing<String>,
    device: PendingDevice,
    api_key: SigningKeyPair,
    mls: MlsClient,
    link_id: Uuid,
    poll_secret: Zeroizing<String>,
    pub expires_at: i64,
}

pub enum LinkOutcome {
    Pending,
    Rejected,
    Expired,
    Linked(Box<Client>),
}

impl PendingLink {
    /// Code à afficher (texte et QR code) pour l'appareil principal.
    pub fn code(&self) -> String {
        link_code(self.link_id, &self.device)
    }

    pub fn fingerprint(&self) -> String {
        link_fingerprint(&self.device)
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    /// Consulte l'état de la demande ; une fois approuvée, crée le compte
    /// local et renvoie le client connecté.
    pub async fn poll(&self) -> Result<LinkOutcome> {
        let api = self.cfg.api()?;
        let r = api
            .link_poll(&LinkPollRequest { link_id: self.link_id, poll_secret: self.poll_secret.to_string() })
            .await?;
        match r.status {
            LinkStatus::Pending => Ok(LinkOutcome::Pending),
            LinkStatus::Rejected => Ok(LinkOutcome::Rejected),
            LinkStatus::Expired => Ok(LinkOutcome::Expired),
            LinkStatus::Approved => {
                let (Some(reg), Some(tokens)) = (r.registration, r.tokens) else {
                    return Err(ClientError::Invalid("réponse de liaison incomplète".into()));
                };
                // Le certificat doit porter exactement nos clés et être signé
                // par la clé d'identité annoncée (vérifiée ensuite par KT).
                if reg.device_id != self.device.device_id
                    || reg.api_key != self.device.api_key
                    || reg.mls_signature_key != self.device.mls_signature_key
                {
                    return Err(ClientError::Verification(self.username.clone(), "certificat d'appareil".into()));
                }
                DeviceCertificate {
                    username: self.username.clone(),
                    device_id: reg.device_id,
                    api_key: reg.api_key.clone(),
                    mls_signature_key: reg.mls_signature_key.clone(),
                    created_at: reg.cert_created_at,
                }
                .verify(&reg.identity_key, &reg.cert_signature)
                .map_err(|_| ClientError::Verification(self.username.clone(), "certificat d'appareil".into()))?;
                let identity_public: [u8; 32] = reg
                    .identity_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| ClientError::Invalid("clé d'identité invalide".into()))?;
                if account::exists(&self.cfg, &self.username) {
                    return Err(ClientError::LocalAccountExists);
                }
                let mut store = account::create(&self.cfg, &self.username, &self.password)?;
                let api_secret = self.api_key.secret_bytes();
                store.transaction(|s| {
                    s.set_meta(meta::USERNAME, self.username.as_bytes())?;
                    s.set_meta(meta::DEVICE_ID, self.device.device_id.as_bytes())?;
                    s.set_meta(meta::IDENTITY_PUBLIC, &identity_public)?;
                    s.set_meta(meta::API_SECRET, api_secret.as_ref())?;
                    s.set_meta(meta::MLS_PUBLIC, &self.mls.signature_public_key())?;
                    s.set_meta(meta::MLS_STATE, &self.mls.export_state()?)?;
                    s.set_meta(meta::CERT_CREATED_AT, &reg.cert_created_at.to_be_bytes())?;
                    s.set_meta(meta::CERT_SIGNATURE, &reg.cert_signature)?;
                    Ok(())
                })?;
                drop(store);
                // Réouverture normale : même chemin que les connexions suivantes.
                let client = Client::open_local(&self.cfg, &self.username, &self.password)?;
                client.api.set_tokens(Some(tokens.clone()));
                client.save_session(&tokens)?;
                client.ensure_key_packages().await?;
                client.kt_check_self().await?;
                Ok(LinkOutcome::Linked(Box::new(client)))
            }
        }
    }
}

impl Client {
    /// Démarre la liaison de cet appareil à un compte existant. Le mot de
    /// passe et le second facteur prouvent la connaissance du compte, mais
    /// n'accordent rien tant que l'appareil principal n'a pas approuvé.
    pub async fn link_start(
        cfg: &ClientConfig,
        username: &str,
        password: &str,
        totp_code: &str,
    ) -> Result<PendingLink> {
        msg_proto::validate_username(username).map_err(|e| ClientError::Invalid(e.into()))?;
        if account::exists(cfg, username) {
            return Err(ClientError::LocalAccountExists);
        }
        let api_key = SigningKeyPair::generate()?;
        let device_id = Uuid::new_v4();
        let mls = MlsClient::create(MemberIdentity { username: username.into(), device_id })?;
        let device = PendingDevice {
            device_id,
            api_key: api_key.public_bytes().to_vec(),
            mls_signature_key: mls.signature_public_key(),
        };
        let api: ApiClient = cfg.api()?;
        let r = api
            .link_start(&LinkStartRequest {
                username: username.into(),
                password: password.into(),
                totp_code: totp_code.trim().into(),
                webauthn: None,
                device: device.clone(),
            })
            .await?;
        Ok(PendingLink {
            cfg: cfg.clone(),
            username: username.into(),
            password: Zeroizing::new(password.into()),
            device,
            api_key,
            mls,
            link_id: r.link_id,
            poll_secret: Zeroizing::new(r.poll_secret),
            expires_at: r.expires_at,
        })
    }

    /// Demandes de liaison en attente (à approuver depuis l'appareil principal).
    pub async fn link_requests(&self) -> Result<Vec<LinkRequestInfo>> {
        let list = self.api.link_requests().await?;
        self.persist_tokens()?;
        Ok(list
            .into_iter()
            .map(|r| LinkRequestInfo {
                link_id: r.link_id,
                device_id: r.device.device_id,
                fingerprint: link_fingerprint(&r.device),
                created_at: r.created_at,
                expires_at: r.expires_at,
            })
            .collect())
    }

    /// Approuve un nouvel appareil à partir du code qu'il affiche. Le code
    /// contient l'empreinte de ses clés : si le serveur a substitué d'autres
    /// clés, l'empreinte recalculée diffère et l'approbation est refusée.
    pub async fn approve_link(&self, code: &str) -> Result<Uuid> {
        let identity = self.identity_secret.as_ref().ok_or(ClientError::NotPrimaryDevice)?;
        let (link_id, fp) = parse_link_code(code)?;
        let req = self
            .api
            .link_requests()
            .await?
            .into_iter()
            .find(|r| r.link_id == link_id)
            .ok_or_else(|| ClientError::Invalid("demande de liaison introuvable ou expirée".into()))?;
        if link_fingerprint(&req.device).replace(' ', "") != fp {
            return Err(ClientError::Verification(
                self.username.clone(),
                "l'empreinte du nouvel appareil ne correspond pas : liaison refusée".into(),
            ));
        }
        let created_at = crate::now_secs();
        let sig = DeviceCertificate {
            username: self.username.clone(),
            device_id: req.device.device_id,
            api_key: req.device.api_key.clone(),
            mls_signature_key: req.device.mls_signature_key.clone(),
            created_at,
        }
        .sign(identity);
        self.api
            .link_approve(link_id, &LinkApproveRequest { cert_created_at: created_at, cert_signature: sig.to_vec() })
            .await?;
        self.persist_tokens()?;
        Ok(req.device.device_id)
    }

    pub async fn reject_link(&self, link_id: Uuid) -> Result<()> {
        self.api.link_reject(link_id).await?;
        self.persist_tokens()
    }

    /// Appareils du compte.
    pub async fn devices(&self) -> Result<Vec<OwnDevice>> {
        let d = self.api.devices().await?;
        self.persist_tokens()?;
        Ok(d)
    }

    /// Révoque un autre appareil du compte. Il est retiré de l'annuaire (et
    /// du journal KT) immédiatement, puis de chaque groupe par le commit de
    /// l'administrateur du groupe ; à sa prochaine connexion, il efface ses
    /// données locales.
    pub async fn revoke_device(&mut self, device_id: Uuid) -> Result<()> {
        if device_id == self.device_id {
            return Err(ClientError::Invalid("impossible de révoquer l'appareil courant".into()));
        }
        self.api.revoke_device(device_id).await?;
        self.persist_tokens()?;
        self.reconcile_now().await.map(|_| ())
    }

    /// Efface les données locales d'un compte (appareil révoqué).
    pub fn wipe_local(cfg: &ClientConfig, username: &str) -> Result<()> {
        account::destroy(cfg, username)
    }

    // --- Réconciliation des membres des groupes ---------------------------

    /// Réconciliation périodique (au plus une fois par minute).
    pub(crate) async fn reconcile_due(&mut self) -> Result<usize> {
        let now = crate::now_ms();
        if now - self.last_reconcile_ms < RECONCILE_INTERVAL_MS {
            return Ok(0);
        }
        self.reconcile_now().await
    }

    /// Aligne les appareils membres de chaque groupe administré par cet
    /// appareil principal sur l'annuaire vérifié (KT) : ajoute les appareils
    /// manquants, retire ceux qui n'y figurent plus (révoqués). Renvoie le
    /// nombre de groupes modifiés.
    pub async fn reconcile_now(&mut self) -> Result<usize> {
        self.last_reconcile_ms = crate::now_ms();
        if !self.is_primary() {
            return Ok(0);
        }
        let mut dirs = HashMap::new();
        let mut changed = 0;
        for c in self.store.conversations()? {
            if c.status != status::OK || self.effective_admin(&c).as_deref() != Some(self.username.as_str()) {
                continue;
            }
            let members = self.mls.members(&c.group_id)?;
            let mut users: Vec<String> = members.iter().map(|m| m.identity.username.clone()).collect();
            users.push(self.username.clone());
            users.sort();
            users.dedup();
            let mut expected: HashMap<String, Vec<Uuid>> = HashMap::new();
            for u in &users {
                if !dirs.contains_key(u) {
                    let entry = match self.verified_directory(u).await {
                        Ok(e) => e,
                        // Compte supprimé ou réinitialisé : traité par le changement d'identité.
                        Err(ClientError::Api { status: 404, .. }) => continue,
                        Err(e) => return Err(e),
                    };
                    let mut ok = Vec::new();
                    if self.contact_identity_matches(u, &entry.identity_key)? {
                        for d in &entry.devices {
                            if Self::verify_device(u, &entry.identity_key, d).is_ok() {
                                ok.push(d.device_id);
                            }
                        }
                    }
                    dirs.insert(u.clone(), ok);
                }
                expected.insert(u.clone(), dirs[u].clone());
            }
            // Ne jamais retirer cet appareil ni les membres dont l'identité a
            // changé (la conversation est alors suspendue, pas modifiée).
            let to_remove: Vec<Uuid> = members
                .iter()
                .filter(|m| m.identity.device_id != self.device_id)
                .filter(|m| expected.get(&m.identity.username).is_some_and(|d| !d.is_empty()))
                .filter(|m| !expected[&m.identity.username].contains(&m.identity.device_id))
                .map(|m| m.identity.device_id)
                .collect();
            let mut missing: Vec<(String, Uuid)> = Vec::new();
            for (u, devs) in &expected {
                for d in devs {
                    if *d != self.device_id && !members.iter().any(|m| m.identity.device_id == *d) {
                        missing.push((u.clone(), *d));
                    }
                }
            }
            if to_remove.is_empty() && missing.is_empty() {
                continue;
            }
            if !to_remove.is_empty() {
                let recipients = self.other_devices(&c.group_id)?;
                let commit = self.mls.remove_devices(&c.group_id, &to_remove)?;
                self.save_mls()?;
                self.post(recipients, commit).await?;
            }
            if !missing.is_empty() {
                let mut kps = Vec::new();
                let mut new_devices = Vec::new();
                let mut by_user: HashMap<String, Vec<Uuid>> = HashMap::new();
                for (u, d) in missing {
                    by_user.entry(u).or_default().push(d);
                }
                for (u, devs) in by_user {
                    match self.claim_verified_devices(&u, Some(&devs)).await {
                        Ok((k, d)) => {
                            kps.extend(k);
                            new_devices.extend(d);
                        }
                        // Appareil sans KeyPackage pour l'instant : prochain passage.
                        Err(ClientError::Api { status: 404, .. }) => {}
                        Err(e) => return Err(e),
                    }
                }
                if !kps.is_empty() {
                    let existing = self.other_devices(&c.group_id)?;
                    let added = self.mls.add_members(&c.group_id, &kps)?;
                    self.save_mls()?;
                    self.post(existing, added.commit).await?;
                    self.post(new_devices, added.welcome).await?;
                    let name = c.name.clone().unwrap_or_default();
                    self.send_app(&c.group_id, AppBody::GroupInfo { name, admin: self.username.clone() }, None).await?;
                }
            }
            changed += 1;
        }
        self.persist_tokens()?;
        Ok(changed)
    }

    /// La clé d'identité publiée est-elle celle que nous connaissons ?
    fn contact_identity_matches(&self, username: &str, identity_key: &[u8]) -> Result<bool> {
        if username == self.username {
            return Ok(identity_key == self.identity_public);
        }
        Ok(self.store.contact(username)?.is_some_and(|c| c.identity_key == identity_key))
    }
}
