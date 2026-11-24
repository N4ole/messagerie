//! Logique client de haut niveau.

use std::path::PathBuf;

use msg_crypto::identity::{DeviceCertificate, SigningKeyPair};
use msg_crypto::keywrap::Argon2Params;
use msg_crypto::mls::{MemberIdentity, MlsClient};
use msg_proto::{
    validate_username, ActivateRequest, ActivateResponse, ConfirmTotpRequest, DeviceRegistration, LoginRequest,
    SessionTokens,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::api::{validate_server_url, ApiClient, DeviceAuth};
use crate::error::{ClientError, Result};
use crate::store::LocalStore;
use crate::vault::{self, AccountPaths};

/// Seuil de réapprovisionnement des KeyPackages et taille du lot.
const KEY_PACKAGE_LOW_WATER: i64 = 10;
const KEY_PACKAGE_BATCH: usize = 50;

pub(crate) mod meta {
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

/// Empreinte lisible (groupes de 4 chiffres hexadécimaux) d'une clé d'identité.
pub fn fingerprint(identity_key: &[u8]) -> String {
    let h = hex::encode_upper(&msg_crypto::sha256(identity_key)[..16]);
    h.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap_or_default()).collect::<Vec<_>>().join(" ")
}

pub struct Client {
    pub(crate) api: ApiClient,
    pub(crate) store: LocalStore,
    pub(crate) mls: MlsClient,
    pub(crate) identity: SigningKeyPair,
    pub(crate) username: String,
    pub(crate) device_id: Uuid,
}

pub(crate) fn get_meta(store: &LocalStore, k: &str) -> Result<Zeroizing<Vec<u8>>> {
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
        let client = Self::open_local(cfg, username, password)?;
        match totp_code.map(str::trim).filter(|c| !c.is_empty()) {
            Some(code) => {
                let reg = client.registration()?;
                let tokens = client
                    .api
                    .login(&LoginRequest {
                        username: username.into(),
                        password: password.into(),
                        totp_code: code.into(),
                        webauthn: None,
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

    /// Déverrouille le compte local (coffre + base) sans contacter le serveur.
    pub(crate) fn open_local(cfg: &ClientConfig, username: &str, password: &str) -> Result<Self> {
        validate_username(username).map_err(|e| ClientError::Invalid(e.into()))?;
        let paths = cfg.paths(username);
        if !paths.exists() {
            return Err(ClientError::NoLocalAccount);
        }
        let key = vault::open(&paths, password)?;
        let store = LocalStore::open(&paths.db, &key)?;
        // Renforcement opportuniste (TPM apparu depuis la création du coffre).
        if let Err(e) = vault::harden(&paths, &key, password, cfg.argon2) {
            tracing::warn!(error = %e, "renforcement TPM du coffre impossible");
        }
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
        Ok(Self { api, store, mls, identity, username: username.into(), device_id })
    }

    pub(crate) fn registration(&self) -> Result<DeviceRegistration> {
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

    pub(crate) fn save_session(&self, t: &SessionTokens) -> Result<()> {
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
    pub(crate) fn persist_tokens(&self) -> Result<()> {
        if let Some(t) = self.api.tokens() {
            self.save_session(&t)?;
        }
        Ok(())
    }

    pub(crate) fn save_mls(&self) -> Result<()> {
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

    /// Protection du coffre local (`none`, `dpapi`, `tpm+dpapi`…).
    pub fn vault_protection(&self, cfg: &ClientConfig) -> String {
        vault::protection(&cfg.paths(&self.username)).unwrap_or_else(|_| "inconnue".into())
    }

    pub fn identity_fingerprint(&self) -> String {
        fingerprint(&self.identity.public_bytes())
    }

    pub fn api(&self) -> &ApiClient {
        &self.api
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
