//! Chiffrement des pièces jointes.
//!
//! Composition : clé aléatoire de 256 bits par fichier, XChaCha20-Poly1305
//! (nonce aléatoire de 192 bits, AAD fixe). Le clair est complété par des
//! zéros jusqu'au palier supérieur pour masquer la taille exacte au serveur ;
//! la taille réelle, la clé et l'empreinte voyagent dans le message MLS.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::{random_bytes, random_secret, sha256, CryptoError, Result};

const AAD: &[u8] = b"messagerie/attachment/v1";
/// Taille maximale d'une pièce jointe (en clair).
pub const MAX_ATTACHMENT_BYTES: usize = 25 * 1024 * 1024;

/// Palier de remplissage : multiples de 16 Kio jusqu'à 256 Kio, puis de 256 Kio.
pub fn padded_len(len: usize) -> usize {
    let step = if len <= 256 * 1024 { 16 * 1024 } else { 256 * 1024 };
    len.div_ceil(step).max(1) * step
}

pub struct EncryptedAttachment {
    /// `nonce ‖ texte chiffré` (à téléverser).
    pub blob: Vec<u8>,
    pub key: Zeroizing<[u8; 32]>,
    /// SHA-256 du blob chiffré (contrôle d'intégrité au téléchargement).
    pub sha256: [u8; 32],
}

pub fn encrypt(plaintext: &[u8]) -> Result<EncryptedAttachment> {
    if plaintext.len() > MAX_ATTACHMENT_BYTES {
        return Err(CryptoError::Format("pièce jointe trop volumineuse (25 Mio max.)".into()));
    }
    let key = random_secret::<32>()?;
    let nonce = random_bytes::<24>()?;
    let mut padded = Zeroizing::new(Vec::with_capacity(padded_len(plaintext.len())));
    padded.extend_from_slice(plaintext);
    padded.resize(padded_len(plaintext.len()), 0);
    let ct = XChaCha20Poly1305::new(key.as_ref().into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: &padded, aad: AAD })
        .map_err(|_| CryptoError::Decrypt)?;
    let mut blob = nonce.to_vec();
    blob.extend(ct);
    let sha256 = sha256(&blob);
    Ok(EncryptedAttachment { blob, key, sha256 })
}

/// Vérifie l'empreinte, déchiffre et retire le remplissage.
pub fn decrypt(blob: &[u8], key: &[u8; 32], expected_sha256: &[u8; 32], size: u64) -> Result<Zeroizing<Vec<u8>>> {
    if &sha256(blob) != expected_sha256 {
        return Err(CryptoError::Decrypt);
    }
    if blob.len() < 24 + 16 {
        return Err(CryptoError::Decrypt);
    }
    let (nonce, ct) = blob.split_at(24);
    let mut pt = Zeroizing::new(
        XChaCha20Poly1305::new(key.into())
            .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: AAD })
            .map_err(|_| CryptoError::Decrypt)?,
    );
    let size = usize::try_from(size).map_err(|_| CryptoError::Decrypt)?;
    if size > pt.len() {
        return Err(CryptoError::Decrypt);
    }
    pt.truncate(size);
    Ok(pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_padding_and_integrity() {
        let data = b"contenu confidentiel du fichier".to_vec();
        let e = encrypt(&data).unwrap();
        assert_eq!(e.blob.len(), 24 + 16 * 1024 + 16, "taille masquée par paliers");
        assert!(!e.blob.windows(data.len()).any(|w| w == data.as_slice()));
        let pt = decrypt(&e.blob, &e.key, &e.sha256, data.len() as u64).unwrap();
        assert_eq!(&pt[..], &data[..]);
        let mut tampered = e.blob.clone();
        tampered[40] ^= 1;
        assert!(decrypt(&tampered, &e.key, &e.sha256, data.len() as u64).is_err());
        assert!(decrypt(&tampered, &e.key, &sha256(&tampered), data.len() as u64).is_err());
        let other = random_secret::<32>().unwrap();
        assert!(decrypt(&e.blob, &other, &e.sha256, data.len() as u64).is_err());
    }

    #[test]
    fn padding_steps() {
        assert_eq!(padded_len(0), 16 * 1024);
        assert_eq!(padded_len(16 * 1024 + 1), 32 * 1024);
        assert_eq!(padded_len(300 * 1024), 512 * 1024);
        assert!(encrypt(&vec![0u8; MAX_ATTACHMENT_BYTES + 1]).is_err());
    }
}
