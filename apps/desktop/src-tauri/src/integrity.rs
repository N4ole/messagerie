//! Vérification d'intégrité au démarrage : empreinte SHA-256 de
//! l'exécutable (à comparer au fichier `SHA256SUMS` de la Release) et
//! signature Authenticode, vérifiée sans accès réseau. Une signature
//! présente mais invalide (fichier modifié après signature) bloque
//! l'application. L'interface embarquée (HTML/JS) fait partie de
//! l'exécutable : elle est couverte par l'empreinte et la signature.

use std::io::Read;

use msg_platform_win::integrity::{verify_file, Signature};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Integrity {
    /// Empreinte SHA-256 (hexadécimal) de l'exécutable en cours.
    pub executable_sha256: String,
    /// État de la signature, en clair.
    pub signature: String,
    /// `true` : signature présente mais invalide — l'application refuse de servir.
    pub blocked: bool,
}

pub fn sha256_file(path: &std::path::Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

pub fn describe(sig: &Signature) -> (String, bool) {
    match sig {
        Signature::Valid => ("signature Authenticode valide".into(), false),
        Signature::Unsigned => ("non signé — comparez l'empreinte avec SHA256SUMS de la Release".into(), false),
        Signature::Tampered => ("SIGNATURE INVALIDE : exécutable modifié après signature".into(), true),
        Signature::Untrusted(code) => (format!("signature non approuvée par Windows (code 0x{code:08X})"), false),
        Signature::NotApplicable => ("vérification Authenticode indisponible sur ce système".into(), false),
    }
}

pub fn check() -> Integrity {
    let exe = std::env::current_exe();
    let executable_sha256 =
        exe.as_ref().ok().and_then(|p| sha256_file(p).ok()).unwrap_or_else(|| "indisponible".into());
    let sig = exe.as_ref().map(|p| verify_file(p)).unwrap_or(Signature::NotApplicable);
    let (signature, blocked) = describe(&sig);
    Integrity { executable_sha256, signature, blocked }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_files_and_blocks_only_tampered_signatures() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        std::fs::write(&p, b"abc").unwrap();
        assert_eq!(sha256_file(&p).unwrap(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert!(describe(&Signature::Tampered).1);
        for s in [Signature::Valid, Signature::Unsigned, Signature::Untrusted(1), Signature::NotApplicable] {
            assert!(!describe(&s).1);
        }
        let i = check();
        assert_eq!(i.executable_sha256.len(), 64);
    }
}
