//! Enveloppe d'une clé de 256 bits sous une clé dérivée d'un mot de passe.
//!
//! Composition : `KEK = Argon2id(mot de passe, sel aléatoire)`, puis
//! `XChaCha20-Poly1305(KEK, nonce aléatoire, clé, AAD = libellé ‖ paramètres)`.
//! Les paramètres Argon2 sont stockés avec l'enveloppe (et authentifiés).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{random_bytes, CryptoError, Result};

const AAD_LABEL: &str = "messagerie/keywrap/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Params {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Argon2Params {
    /// Paramètres de production (64 Mio, 3 passes) — au-dessus du minimum OWASP.
    pub const PRODUCTION: Self = Self { m_kib: 64 * 1024, t: 3, p: 1 };
    /// Paramètres faibles réservés aux tests automatisés.
    pub const INSECURE_FOR_TESTS: Self = Self { m_kib: 64, t: 1, p: 1 };
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedKey {
    pub version: u8,
    pub params: Argon2Params,
    #[serde(with = "hex_bytes")]
    pub salt: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub ciphertext: Vec<u8>,
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        hex::decode(String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

/// Bornes des paramètres lus depuis une enveloppe stockée : un fichier
/// modifié ne peut pas imposer un coût démesuré (déni de service à
/// l'ouverture). Les paramètres de production restent bien en deçà.
const MAX_M_KIB: u32 = 1024 * 1024; // 1 Gio
const MAX_T: u32 = 16;
const MAX_P: u32 = 16;

fn derive_kek(password: &str, salt: &[u8], p: Argon2Params) -> Result<Zeroizing<[u8; 32]>> {
    if p.m_kib > MAX_M_KIB || p.t > MAX_T || p.p > MAX_P {
        return Err(CryptoError::Format("paramètres Argon2 hors bornes".into()));
    }
    let params = argon2::Params::new(p.m_kib, p.t, p.p, Some(32)).map_err(|e| CryptoError::Format(e.to_string()))?;
    let a2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    a2.hash_password_into(password.as_bytes(), salt, out.as_mut()).map_err(|e| CryptoError::Format(e.to_string()))?;
    Ok(out)
}

fn aad(p: Argon2Params) -> Vec<u8> {
    format!("{AAD_LABEL}|{}|{}|{}", p.m_kib, p.t, p.p).into_bytes()
}

pub fn wrap(secret: &[u8; 32], password: &str, params: Argon2Params) -> Result<WrappedKey> {
    let salt = random_bytes::<16>()?;
    let nonce = random_bytes::<24>()?;
    let kek = derive_kek(password, &salt, params)?;
    let cipher = XChaCha20Poly1305::new(kek.as_ref().into());
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: secret, aad: &aad(params) })
        .map_err(|_| CryptoError::Decrypt)?;
    Ok(WrappedKey { version: 1, params, salt: salt.to_vec(), nonce: nonce.to_vec(), ciphertext })
}

pub fn unwrap(w: &WrappedKey, password: &str) -> Result<Zeroizing<[u8; 32]>> {
    if w.version != 1 || w.nonce.len() != 24 || w.salt.len() != 16 {
        return Err(CryptoError::Format("enveloppe de clé invalide".into()));
    }
    let kek = derive_kek(password, &w.salt, w.params)?;
    let cipher = XChaCha20Poly1305::new(kek.as_ref().into());
    let pt = Zeroizing::new(
        cipher
            .decrypt(XNonce::from_slice(&w.nonce), Payload { msg: &w.ciphertext, aad: &aad(w.params) })
            .map_err(|_| CryptoError::Decrypt)?,
    );
    let arr: [u8; 32] = pt.as_slice().try_into().map_err(|_| CryptoError::Decrypt)?;
    Ok(Zeroizing::new(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Clés et mots de passe aléatoires : aucune valeur secrète en dur.
    fn key() -> [u8; 32] {
        random_bytes::<32>().unwrap()
    }
    fn password() -> String {
        hex::encode(random_bytes::<16>().unwrap())
    }

    #[test]
    fn wrap_unwrap() {
        let (k, pw, bad) = (key(), password(), password());
        let w = wrap(&k, &pw, Argon2Params::INSECURE_FOR_TESTS).unwrap();
        assert_eq!(*unwrap(&w, &pw).unwrap(), k);
        assert!(matches!(unwrap(&w, &bad), Err(CryptoError::Decrypt)));
    }

    #[test]
    fn params_are_authenticated() {
        let (k, pw) = (key(), password());
        let mut w = wrap(&k, &pw, Argon2Params::INSECURE_FOR_TESTS).unwrap();
        w.params.t = 2;
        assert!(unwrap(&w, &pw).is_err());
    }

    #[test]
    fn json_roundtrip() {
        let (k, pw) = (key(), password());
        let w = wrap(&k, &pw, Argon2Params::INSECURE_FOR_TESTS).unwrap();
        let j = serde_json::to_string(&w).unwrap();
        let w2: WrappedKey = serde_json::from_str(&j).unwrap();
        assert_eq!(*unwrap(&w2, &pw).unwrap(), k);
    }
}

/// Chiffrement authentifié d'un petit secret sous une clé de 256 bits
/// (XChaCha20-Poly1305, nonce aléatoire préfixé).
pub fn seal(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let nonce = random_bytes::<24>()?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut out = nonce.to_vec();
    out.extend(
        cipher
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
            .map_err(|_| CryptoError::Decrypt)?,
    );
    Ok(out)
}

pub fn open(key: &[u8; 32], sealed: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < 24 + 16 {
        return Err(CryptoError::Decrypt);
    }
    let (nonce, ct) = sealed.split_at(24);
    let cipher = XChaCha20Poly1305::new(key.into());
    Ok(Zeroizing::new(
        cipher.decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad }).map_err(|_| CryptoError::Decrypt)?,
    ))
}

#[cfg(test)]
mod seal_tests {
    use super::*;

    #[test]
    fn seal_open() {
        let (k, other) = (random_bytes::<32>().unwrap(), random_bytes::<32>().unwrap());
        let s = seal(&k, b"donnees", b"ctx").unwrap();
        assert_eq!(&open(&k, &s, b"ctx").unwrap()[..], b"donnees");
        assert!(open(&k, &s, b"autre").is_err());
        assert!(open(&other, &s, b"ctx").is_err());
    }

    #[test]
    fn stored_parameters_are_bounded() {
        // Mot de passe aléatoire (aucune valeur secrète figée dans le code).
        let password = hex::encode(random_bytes::<16>().unwrap());
        let mut w = wrap(&random_bytes::<32>().unwrap(), &password, Argon2Params::INSECURE_FOR_TESTS).unwrap();
        w.params.m_kib = 64 * 1024 * 1024;
        assert!(matches!(unwrap(&w, &password), Err(CryptoError::Format(_))));
        w.params = Argon2Params { t: 1000, ..Argon2Params::INSECURE_FOR_TESTS };
        assert!(matches!(unwrap(&w, &password), Err(CryptoError::Format(_))));
    }
}
