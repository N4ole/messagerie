//! Façade cryptographique de la messagerie.
//!
//! Ce crate **n'implémente aucune primitive** : il compose des bibliothèques
//! reconnues (OpenMLS, ed25519-dalek, RustCrypto). Chaque composition est
//! listée dans `docs/conception/02-protocole-crypto.md` §8.
#![forbid(unsafe_code)]

pub mod app_message;
pub mod identity;
pub mod keywrap;
pub mod mls;
pub mod request;

use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("aléa système indisponible")]
    Rng,
    #[error("clé ou signature invalide")]
    InvalidKey,
    #[error("signature invalide")]
    BadSignature,
    #[error("déchiffrement impossible (clé incorrecte ou données altérées)")]
    Decrypt,
    #[error("format invalide : {0}")]
    Format(String),
    #[error("erreur MLS : {0}")]
    Mls(String),
    #[error("groupe inconnu")]
    UnknownGroup,
    #[error("suite cryptographique non autorisée")]
    WrongCiphersuite,
}

pub type Result<T> = std::result::Result<T, CryptoError>;

/// Remplit un tableau d'octets aléatoires issus du CSPRNG du système.
pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|_| CryptoError::Rng)?;
    Ok(b)
}

/// Comme [`random_bytes`] mais dans un tampon effacé à la libération.
pub fn random_secret<const N: usize>() -> Result<Zeroizing<[u8; N]>> {
    let mut b = Zeroizing::new([0u8; N]);
    getrandom::fill(b.as_mut()).map_err(|_| CryptoError::Rng)?;
    Ok(b)
}

/// SHA-256.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(data).into()
}
