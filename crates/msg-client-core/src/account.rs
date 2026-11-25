//! Stockage d'un compte local : création, ouverture, protection, effacement.
//!
//! - Desktop : coffre (Argon2id + DPAPI + TPM) et base SQLCipher sur disque.
//! - Navigateur : coffre (Argon2id) et instantané chiffré de la base, tous
//!   deux confiés à l'hôte par une interface clé-valeur ([`KvStore`],
//!   implémentée sur IndexedDB par `msg-wasm`).

use crate::client::ClientConfig;
use crate::error::{ClientError, Result};
use crate::store::LocalStore;

/// Stockage clé-valeur fourni par l'hôte (navigateur). Les valeurs reçues
/// sont **déjà chiffrées** ; l'hôte n'a qu'à les conserver.
pub trait KvStore {
    fn get(&self, key: &str) -> Option<Vec<u8>>;
    fn set(&self, key: &str, value: &[u8]);
    fn delete(&self, key: &str);
}

/// Identifiant opaque d'un compte local (ni le serveur ni l'utilisateur en clair).
#[cfg(target_arch = "wasm32")]
pub(crate) fn account_id(server: &str, username: &str) -> String {
    hex::encode(&msg_crypto::sha256(format!("{}\n{username}", server.trim_end_matches('/')).as_bytes())[..12])
}

#[cfg(not(target_arch = "wasm32"))]
mod imp {
    use super::*;
    use crate::vault;

    pub fn exists(cfg: &ClientConfig, username: &str) -> bool {
        cfg.paths(username).exists()
    }

    pub fn create(cfg: &ClientConfig, username: &str, password: &str) -> Result<LocalStore> {
        let paths = cfg.paths(username);
        let key = vault::create(&paths, password, cfg.argon2)?;
        LocalStore::open(&paths.db, &key)
    }

    pub fn open(cfg: &ClientConfig, username: &str, password: &str) -> Result<LocalStore> {
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
        Ok(store)
    }

    pub fn protection(cfg: &ClientConfig, username: &str) -> String {
        vault::protection(&cfg.paths(username)).unwrap_or_else(|_| "inconnue".into())
    }

    pub fn destroy(cfg: &ClientConfig, username: &str) -> Result<()> {
        vault::destroy(&cfg.paths(username))
    }
}

#[cfg(target_arch = "wasm32")]
mod imp {
    use std::rc::Rc;

    use msg_crypto::keywrap::{self, WrappedKey};

    use super::*;

    fn kv(cfg: &ClientConfig) -> Result<Rc<dyn KvStore>> {
        cfg.kv.clone().ok_or_else(|| ClientError::Storage("stockage du navigateur indisponible".into()))
    }

    fn keys(cfg: &ClientConfig, username: &str) -> (String, String) {
        let id = account_id(&cfg.server_url, username);
        (format!("{id}/vault"), format!("{id}/db"))
    }

    fn open_store(kv: Rc<dyn KvStore>, db_key: String, key: &[u8; 32]) -> Result<LocalStore> {
        let initial = kv.get(&db_key);
        let sink = kv.clone();
        LocalStore::open(initial.as_deref(), key, Box::new(move |b: &[u8]| sink.set(&db_key, b)))
    }

    pub fn exists(cfg: &ClientConfig, username: &str) -> bool {
        let (v, d) = keys(cfg, username);
        kv(cfg).is_ok_and(|kv| kv.get(&v).is_some() && kv.get(&d).is_some())
    }

    pub fn create(cfg: &ClientConfig, username: &str, password: &str) -> Result<LocalStore> {
        let kv = kv(cfg)?;
        let (v, d) = keys(cfg, username);
        let key = msg_crypto::random_secret::<32>()?;
        let wrapped = keywrap::wrap(&key, password, cfg.argon2)?;
        kv.set(&v, &serde_json::to_vec(&wrapped).map_err(|e| ClientError::Storage(e.to_string()))?);
        open_store(kv, d, &key)
    }

    pub fn open(cfg: &ClientConfig, username: &str, password: &str) -> Result<LocalStore> {
        let kv = kv(cfg)?;
        let (v, d) = keys(cfg, username);
        let raw = kv.get(&v).ok_or(ClientError::NoLocalAccount)?;
        let wrapped: WrappedKey = serde_json::from_slice(&raw).map_err(|e| ClientError::Storage(e.to_string()))?;
        let key = keywrap::unwrap(&wrapped, password).map_err(|_| ClientError::WrongPassword)?;
        if kv.get(&d).is_none() {
            return Err(ClientError::NoLocalAccount);
        }
        open_store(kv, d, &key)
    }

    pub fn protection(_cfg: &ClientConfig, _username: &str) -> String {
        "password".into()
    }

    pub fn destroy(cfg: &ClientConfig, username: &str) -> Result<()> {
        let kv = kv(cfg)?;
        let (v, d) = keys(cfg, username);
        kv.delete(&v);
        kv.delete(&d);
        Ok(())
    }
}

pub(crate) use imp::{create, destroy, exists, open, protection};
