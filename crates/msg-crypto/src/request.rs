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

// ---------------------------------------------------------------------------
// Fédération : requêtes et réponses signées par la clé d'un site
// ---------------------------------------------------------------------------

const SITE_REQUEST_LABEL: &str = "messagerie/federation/request/v1";
const SITE_RESPONSE_LABEL: &str = "messagerie/federation/response/v1";

fn site_canonical(
    method: &str,
    path_and_query: &str,
    timestamp: i64,
    nonce_b64: &str,
    site: &str,
    body: &[u8],
) -> Vec<u8> {
    format!(
        "{SITE_REQUEST_LABEL}\n{}\n{}\n{}\n{}\n{}\n{}",
        method.to_ascii_uppercase(),
        path_and_query,
        timestamp,
        nonce_b64,
        site,
        hex::encode(sha256(body))
    )
    .into_bytes()
}

/// Signe une requête d'un site vers un autre (même construction que les
/// requêtes d'appareil, libellé et émetteur distincts).
pub fn sign_site_request(
    key: &SigningKeyPair,
    site: &str,
    method: &str,
    path_and_query: &str,
    body: &[u8],
    now: i64,
) -> Result<SignedHeaders> {
    let nonce = STANDARD.encode(random_bytes::<16>()?);
    let msg = site_canonical(method, path_and_query, now, &nonce, site, body);
    Ok(SignedHeaders {
        timestamp: now.to_string(),
        nonce,
        signature: STANDARD.encode(key.sign(&msg)),
        device: site.to_owned(),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn verify_site_request(
    site_key: &[u8],
    site: &str,
    method: &str,
    path_and_query: &str,
    body: &[u8],
    timestamp: i64,
    nonce_b64: &str,
    signature_b64: &str,
) -> Result<()> {
    let sig = STANDARD.decode(signature_b64).map_err(|_| crate::CryptoError::BadSignature)?;
    verify(site_key, &site_canonical(method, path_and_query, timestamp, nonce_b64, site, body), &sig)
}

fn response_canonical(site: &str, request_nonce: &str, status: u16, body: &[u8]) -> Vec<u8> {
    format!("{SITE_RESPONSE_LABEL}\n{site}\n{request_nonce}\n{status}\n{}", hex::encode(sha256(body))).into_bytes()
}

/// Signature d'une réponse, liée au nonce de la requête (pas de rejeu d'une
/// ancienne réponse) : le site appelant authentifie le site appelé avec sa
/// clé épinglée, indépendamment de TLS.
pub fn sign_site_response(key: &SigningKeyPair, site: &str, request_nonce: &str, status: u16, body: &[u8]) -> String {
    STANDARD.encode(key.sign(&response_canonical(site, request_nonce, status, body)))
}

pub fn verify_site_response(
    site_key: &[u8],
    site: &str,
    request_nonce: &str,
    status: u16,
    body: &[u8],
    signature_b64: &str,
) -> Result<()> {
    let sig = STANDARD.decode(signature_b64).map_err(|_| crate::CryptoError::BadSignature)?;
    verify(site_key, &response_canonical(site, request_nonce, status, body), &sig)
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
    fn site_requests_and_responses() {
        let k = SigningKeyPair::generate().unwrap();
        let other = SigningKeyPair::generate().unwrap();
        let pk = k.public_bytes();
        let h = sign_site_request(&k, "site-a", "POST", "/v1/federation/deliver", b"{}", 7).unwrap();
        verify_site_request(&pk, "site-a", "POST", "/v1/federation/deliver", b"{}", 7, &h.nonce, &h.signature).unwrap();
        // Autre site annoncé, autre clé, autre corps : refus.
        assert!(verify_site_request(&pk, "site-c", "POST", "/v1/federation/deliver", b"{}", 7, &h.nonce, &h.signature)
            .is_err());
        assert!(verify_site_request(
            &other.public_bytes(),
            "site-a",
            "POST",
            "/v1/federation/deliver",
            b"{}",
            7,
            &h.nonce,
            &h.signature
        )
        .is_err());
        assert!(verify_site_request(
            &pk,
            "site-a",
            "POST",
            "/v1/federation/deliver",
            b"{1}",
            7,
            &h.nonce,
            &h.signature
        )
        .is_err());
        // Une signature de requête d'appareil n'est pas une signature de site.
        let d = sign_request(&k, &Uuid::nil(), "POST", "/v1/federation/deliver", b"{}", 7).unwrap();
        assert!(verify_site_request(&pk, "site-a", "POST", "/v1/federation/deliver", b"{}", 7, &d.nonce, &d.signature)
            .is_err());
        // Réponse liée au nonce et au statut.
        let r = sign_site_response(&k, "site-b", "n1", 200, b"ok");
        verify_site_response(&pk, "site-b", "n1", 200, b"ok", &r).unwrap();
        assert!(verify_site_response(&pk, "site-b", "n2", 200, b"ok", &r).is_err());
        assert!(verify_site_response(&pk, "site-b", "n1", 404, b"ok", &r).is_err());
        assert!(verify_site_response(&pk, "site-b", "n1", 200, b"ko", &r).is_err());
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
