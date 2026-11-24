//! Clé d'identité utilisateur et certificats d'appareil.
//!
//! Composition : la clé d'identité Ed25519 de l'utilisateur signe un
//! certificat liant `(utilisateur, appareil, clé API, clé MLS, date)`.
//! Les correspondants vérifient ce certificat avant d'accepter un appareil.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{random_secret, CryptoError, Result};

const DEVICE_CERT_LABEL: &[u8] = b"messagerie/device-cert/v1";

/// Clé de signature Ed25519 (identité utilisateur ou clé API d'appareil).
/// La clé privée est effacée de la mémoire à la libération
/// (`ed25519-dalek` implémente `ZeroizeOnDrop` avec la feature `zeroize`).
pub struct SigningKeyPair(SigningKey);

impl SigningKeyPair {
    pub fn generate() -> Result<Self> {
        let seed = random_secret::<32>()?;
        Ok(Self(SigningKey::from_bytes(&seed)))
    }

    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self> {
        let arr: Zeroizing<[u8; 32]> = Zeroizing::new(bytes.try_into().map_err(|_| CryptoError::InvalidKey)?);
        Ok(Self(SigningKey::from_bytes(&arr)))
    }

    /// Octets secrets (32). À stocker uniquement dans la base locale chiffrée.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.0.sign(msg).to_bytes()
    }
}

impl std::fmt::Debug for SigningKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SigningKeyPair(pub={})", hex::encode(self.public_bytes()))
    }
}

/// Vérifie une signature Ed25519 (forme stricte, refuse les clés faibles).
pub fn verify(public_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<()> {
    let pk: [u8; 32] = public_key.try_into().map_err(|_| CryptoError::InvalidKey)?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|_| CryptoError::InvalidKey)?;
    let sig = Signature::from_slice(signature).map_err(|_| CryptoError::BadSignature)?;
    vk.verify_strict(msg, &sig).map_err(|_| CryptoError::BadSignature)
}

/// Contenu signé d'un certificat d'appareil.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCertificate {
    pub username: String,
    pub device_id: Uuid,
    pub api_key: Vec<u8>,
    pub mls_signature_key: Vec<u8>,
    pub created_at: i64,
}

fn put_lv(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

impl DeviceCertificate {
    /// Encodage canonique (longueurs préfixées, aucune ambiguïté).
    pub fn to_be_signed(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        put_lv(&mut out, DEVICE_CERT_LABEL);
        put_lv(&mut out, self.username.as_bytes());
        out.extend_from_slice(self.device_id.as_bytes());
        put_lv(&mut out, &self.api_key);
        put_lv(&mut out, &self.mls_signature_key);
        out.extend_from_slice(&self.created_at.to_be_bytes());
        out
    }

    pub fn sign(&self, identity: &SigningKeyPair) -> [u8; 64] {
        identity.sign(&self.to_be_signed())
    }

    pub fn verify(&self, identity_key: &[u8], signature: &[u8]) -> Result<()> {
        verify(identity_key, &self.to_be_signed(), signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert(api: &SigningKeyPair) -> DeviceCertificate {
        DeviceCertificate {
            username: "alice".into(),
            device_id: Uuid::from_bytes([7; 16]),
            api_key: api.public_bytes().to_vec(),
            mls_signature_key: vec![1; 32],
            created_at: 1_700_000_000,
        }
    }

    #[test]
    fn certificate_sign_verify() {
        let id = SigningKeyPair::generate().unwrap();
        let api = SigningKeyPair::generate().unwrap();
        let c = cert(&api);
        let sig = c.sign(&id);
        c.verify(&id.public_bytes(), &sig).unwrap();
    }

    #[test]
    fn certificate_rejects_tampering() {
        let id = SigningKeyPair::generate().unwrap();
        let api = SigningKeyPair::generate().unwrap();
        let c = cert(&api);
        let sig = c.sign(&id);
        let mut other = c.clone();
        other.username = "mallory".into();
        assert!(other.verify(&id.public_bytes(), &sig).is_err());
        let mut other = c.clone();
        other.mls_signature_key = vec![2; 32];
        assert!(other.verify(&id.public_bytes(), &sig).is_err());
        let wrong = SigningKeyPair::generate().unwrap();
        assert!(c.verify(&wrong.public_bytes(), &sig).is_err());
    }

    #[test]
    fn secret_roundtrip() {
        let k = SigningKeyPair::generate().unwrap();
        let k2 = SigningKeyPair::from_secret_bytes(k.secret_bytes().as_ref()).unwrap();
        assert_eq!(k.public_bytes(), k2.public_bytes());
        assert!(SigningKeyPair::from_secret_bytes(&[0u8; 31]).is_err());
    }
}
