//! Signature des requêtes API par la clé d'appareil (anti-rejeu).
//!
//! Composition inspirée de DPoP (RFC 9449) : la requête est liée à la clé
//! API de l'appareil, à un horodatage et à un nonce aléatoire à usage unique.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use uuid::Uuid;

use crate::identity::{verify, SigningKeyPair};
use crate::{random_bytes, sha256, Result};

const LABEL: &str = "messagerie/request/v1";

/// Chaîne canonique signée.
pub fn canonical(
    method: &str,
    path_and_query: &str,
    timestamp: i64,
    nonce_b64: &str,
    device_id: &Uuid,
    body: &[u8],
) -> Vec<u8> {
    format!(
        "{LABEL}\n{}\n{}\n{}\n{}\n{}\n{}",
        method.to_ascii_uppercase(),
        path_and_query,
        timestamp,
        nonce_b64,
        device_id,
        hex::encode(sha256(body))
    )
    .into_bytes()
}

/// En-têtes produits pour une requête signée.
#[derive(Debug, Clone)]
pub struct SignedHeaders {
    pub timestamp: String,
    pub nonce: String,
    pub signature: String,
    pub device: String,
}

pub fn sign_request(
    key: &SigningKeyPair,
    device_id: &Uuid,
    method: &str,
    path_and_query: &str,
    body: &[u8],
    now: i64,
) -> Result<SignedHeaders> {
    let nonce = STANDARD.encode(random_bytes::<16>()?);
    let msg = canonical(method, path_and_query, now, &nonce, device_id, body);
    Ok(SignedHeaders {
        timestamp: now.to_string(),
        nonce,
        signature: STANDARD.encode(key.sign(&msg)),
        device: device_id.to_string(),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn verify_request(
    api_key: &[u8],
    device_id: &Uuid,
    method: &str,
    path_and_query: &str,
    body: &[u8],
    timestamp: i64,
    nonce_b64: &str,
    signature_b64: &str,
) -> Result<()> {
    let sig = STANDARD.decode(signature_b64).map_err(|_| crate::CryptoError::BadSignature)?;
    let msg = canonical(method, path_and_query, timestamp, nonce_b64, device_id, body);
    verify(api_key, &msg, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let k = SigningKeyPair::generate().unwrap();
        let d = Uuid::from_bytes([1; 16]);
        let h = sign_request(&k, &d, "post", "/v1/messages", b"{}", 42).unwrap();
        verify_request(&k.public_bytes(), &d, "POST", "/v1/messages", b"{}", 42, &h.nonce, &h.signature).unwrap();
        // Tout changement invalide la signature.
        assert!(
            verify_request(&k.public_bytes(), &d, "POST", "/v1/messages", b"{ }", 42, &h.nonce, &h.signature).is_err()
        );
        assert!(verify_request(&k.public_bytes(), &d, "POST", "/v1/queue", b"{}", 42, &h.nonce, &h.signature).is_err());
        assert!(
            verify_request(&k.public_bytes(), &d, "POST", "/v1/messages", b"{}", 43, &h.nonce, &h.signature).is_err()
        );
        assert!(
            verify_request(&k.public_bytes(), &d, "GET", "/v1/messages", b"{}", 42, &h.nonce, &h.signature).is_err()
        );
        let d2 = Uuid::from_bytes([2; 16]);
        assert!(
            verify_request(&k.public_bytes(), &d2, "POST", "/v1/messages", b"{}", 42, &h.nonce, &h.signature).is_err()
        );
    }

    #[test]
    fn nonces_are_unique() {
        let k = SigningKeyPair::generate().unwrap();
        let d = Uuid::nil();
        let a = sign_request(&k, &d, "GET", "/", b"", 0).unwrap();
        let b = sign_request(&k, &d, "GET", "/", b"", 0).unwrap();
        assert_ne!(a.nonce, b.nonce);
    }
}
