//! Coffre de la clé de la base locale.
//!
//! La base SQLCipher est chiffrée par une clé aléatoire de 256 bits. Cette
//! clé est enveloppée par une clé dérivée du mot de passe (Argon2id, sel local
//! jamais transmis), puis — sous Windows — protégée par DPAPI (liée à la
//! session Windows). Le TPM s'ajoutera en Phase 2 (ADR-0005).

use std::path::{Path, PathBuf};

use msg_crypto::keywrap::{self, Argon2Params, WrappedKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{ClientError, Result};

const DPAPI_ENTROPY: &[u8] = b"messagerie/vault/v1";

#[derive(Serialize, Deserialize)]
struct VaultFile {
    version: u8,
    /// `none` ou `dpapi`.
    protection: String,
    /// JSON de `WrappedKey`, éventuellement chiffré par DPAPI (hex).
    blob: String,
}

/// Emplacement des fichiers d'un compte local.
#[derive(Debug, Clone)]
pub struct AccountPaths {
    pub dir: PathBuf,
    pub vault: PathBuf,
    pub db: PathBuf,
}

impl AccountPaths {
    /// Dossier dérivé du serveur et de l'identifiant (sans les exposer en clair).
    pub fn new(data_dir: &Path, server: &str, username: &str) -> Self {
        let id = hex::encode(&msg_crypto::sha256(format!("{server}\n{username}").as_bytes())[..12]);
        let dir = data_dir.join("accounts").join(id);
        Self { vault: dir.join("vault.json"), db: dir.join("local.db"), dir }
    }

    pub fn exists(&self) -> bool {
        self.vault.exists() && self.db.exists()
    }
}

/// Crée un coffre pour une nouvelle clé de base et la retourne.
pub fn create(paths: &AccountPaths, password: &str, params: Argon2Params) -> Result<Zeroizing<[u8; 32]>> {
    std::fs::create_dir_all(&paths.dir).map_err(|e| ClientError::Storage(e.to_string()))?;
    let key = msg_crypto::random_secret::<32>()?;
    let wrapped = keywrap::wrap(&key, password, params)?;
    let json = Zeroizing::new(serde_json::to_vec(&wrapped).map_err(|e| ClientError::Storage(e.to_string()))?);
    let (protection, blob) = if msg_platform_win::dpapi_available() {
        let p =
            msg_platform_win::dpapi_protect(&json, DPAPI_ENTROPY).map_err(|e| ClientError::Storage(e.to_string()))?;
        ("dpapi", hex::encode(p))
    } else {
        ("none", hex::encode(&json[..]))
    };
    let file = VaultFile { version: 1, protection: protection.into(), blob };
    write_private(&paths.vault, &serde_json::to_vec_pretty(&file).map_err(|e| ClientError::Storage(e.to_string()))?)?;
    Ok(key)
}

/// Ouvre le coffre avec le mot de passe.
pub fn open(paths: &AccountPaths, password: &str) -> Result<Zeroizing<[u8; 32]>> {
    let raw = std::fs::read(&paths.vault).map_err(|_| ClientError::NoLocalAccount)?;
    let file: VaultFile = serde_json::from_slice(&raw).map_err(|e| ClientError::Storage(e.to_string()))?;
    if file.version != 1 {
        return Err(ClientError::Storage("version de coffre inconnue".into()));
    }
    let blob = Zeroizing::new(hex::decode(&file.blob).map_err(|e| ClientError::Storage(e.to_string()))?);
    let json = match file.protection.as_str() {
        "dpapi" => msg_platform_win::dpapi_unprotect(&blob, DPAPI_ENTROPY)
            .map_err(|e| ClientError::Storage(format!("DPAPI : {e}")))?,
        "none" => blob,
        _ => return Err(ClientError::Storage("protection de coffre inconnue".into())),
    };
    let wrapped: WrappedKey = serde_json::from_slice(&json).map_err(|e| ClientError::Storage(e.to_string()))?;
    keywrap::unwrap(&wrapped, password).map_err(|_| ClientError::WrongPassword)
}

/// Écrit un fichier lisible uniquement par l'utilisateur (Unix : 0600).
pub(crate) fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).map_err(|e| ClientError::Storage(e.to_string()))?;
        f.write_all(data).map_err(|e| ClientError::Storage(e.to_string()))?;
        f.sync_all().map_err(|e| ClientError::Storage(e.to_string()))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| ClientError::Storage(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mot de passe aléatoire (aucune valeur secrète en dur, même en test).
    fn random_password() -> String {
        hex::encode(msg_crypto::random_bytes::<16>().unwrap())
    }

    #[test]
    fn create_and_open() {
        let d = tempfile::tempdir().unwrap();
        let p = AccountPaths::new(d.path(), "https://s", "alice");
        let (good, bad) = (random_password(), random_password());
        let k = create(&p, &good, Argon2Params::INSECURE_FOR_TESTS).unwrap();
        assert_eq!(*open(&p, &good).unwrap(), *k);
        assert!(matches!(open(&p, &bad), Err(ClientError::WrongPassword)));
        // Le fichier ne contient pas la clé en clair.
        let raw = std::fs::read(&p.vault).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains(&hex::encode(*k)));
    }

    #[test]
    fn paths_do_not_leak_username() {
        let p = AccountPaths::new(Path::new("/x"), "https://s", "alice");
        assert!(!p.dir.to_string_lossy().contains("alice"));
        assert_ne!(p.dir, AccountPaths::new(Path::new("/x"), "https://s", "bob").dir);
    }
}
