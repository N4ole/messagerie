//! Hachage des mots de passe (Argon2id + pepper), TOTP, jetons, codes d'activation.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use subtle::ConstantTimeEq;
use totp_rs::{Algorithm as TotpAlg, Builder as TotpBuilder, Secret, Totp};

use crate::config::Config;

pub struct PasswordHasherCfg<'a> {
    pub pepper: &'a [u8],
    pub cfg: &'a Config,
}

impl<'a> PasswordHasherCfg<'a> {
    fn argon(&self) -> anyhow::Result<Argon2<'a>> {
        let params = Params::new(self.cfg.argon2_m_kib, self.cfg.argon2_t, self.cfg.argon2_p, None)
            .map_err(|e| anyhow::anyhow!("paramètres Argon2 : {e}"))?;
        Argon2::new_with_secret(self.pepper, Algorithm::Argon2id, Version::V0x13, params)
            .map_err(|e| anyhow::anyhow!("Argon2 : {e}"))
    }

    pub fn hash(&self, password: &str) -> anyhow::Result<String> {
        let salt_bytes = msg_crypto::random_bytes::<16>()?;
        let salt = SaltString::encode_b64(&salt_bytes).map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(self.argon()?.hash_password(password.as_bytes(), &salt).map_err(|e| anyhow::anyhow!("{e}"))?.to_string())
    }

    /// Vérifie un mot de passe. Si `stored` est `None` (compte inconnu), un
    /// hachage factice est calculé pour égaliser le temps de réponse.
    pub fn verify(&self, password: &str, stored: Option<&str>) -> anyhow::Result<bool> {
        match stored {
            Some(s) => {
                let parsed = PasswordHash::new(s).map_err(|e| anyhow::anyhow!("{e}"))?;
                Ok(self.argon()?.verify_password(password.as_bytes(), &parsed).is_ok())
            }
            None => {
                let _ = self.hash(password)?;
                Ok(false)
            }
        }
    }
}

/// Paramètres TOTP : SHA-1 / 6 chiffres / 30 s (compatibilité applis), tolérance ±1 pas.
pub fn totp(secret: &[u8], issuer: &str, account: &str) -> anyhow::Result<Totp> {
    TotpBuilder::new()
        .with_algorithm(TotpAlg::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret.to_vec())
        .with_issuer(Some(issuer))
        .with_account_name(account)
        .build()
        .map_err(|e| anyhow::anyhow!("TOTP : {e}"))
}

pub fn new_totp_secret() -> anyhow::Result<Vec<u8>> {
    Ok(msg_crypto::random_bytes::<20>()?.to_vec())
}

pub fn totp_base32(secret: &[u8]) -> String {
    Secret::from(secret.to_vec()).to_base32()
}

/// Vérifie un code TOTP et retourne le pas (step) correspondant, en refusant
/// tout pas déjà utilisé (`last_step`).
pub fn check_totp(t: &Totp, code: &str, now: i64, last_step: Option<i64>) -> Option<i64> {
    let code = code.trim();
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let step = now / 30;
    for s in [step - 1, step, step + 1] {
        if s < 0 || last_step.is_some_and(|l| s <= l) {
            continue;
        }
        let expected = t.generate((s * 30) as u64).to_string();
        if bool::from(expected.as_bytes().ct_eq(code.as_bytes())) {
            return Some(s);
        }
    }
    None
}

/// Jeton aléatoire de 256 bits (Base64 URL) et son haché SHA-256 (stocké).
pub fn new_token() -> anyhow::Result<(String, Vec<u8>)> {
    let raw = msg_crypto::random_bytes::<32>()?;
    let token = URL_SAFE_NO_PAD.encode(raw);
    Ok((token.clone(), token_hash(&token)))
}

pub fn token_hash(token: &str) -> Vec<u8> {
    msg_crypto::sha256(token.as_bytes()).to_vec()
}

/// Code d'activation lisible : 128 bits en hexadécimal par groupes de 4.
pub fn new_activation_code() -> anyhow::Result<(String, Vec<u8>)> {
    let raw = msg_crypto::random_bytes::<16>()?;
    let hex = hex::encode(raw);
    let code = hex.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("-");
    let h = activation_hash(&code);
    Ok((code, h))
}

pub fn activation_hash(code: &str) -> Vec<u8> {
    let normalized: String = code.chars().filter(|c| c.is_ascii_hexdigit()).map(|c| c.to_ascii_lowercase()).collect();
    msg_crypto::sha256(normalized.as_bytes()).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        let mut c = Config::with_secret("test".into(), [1; 32]);
        c.argon2_m_kib = 64;
        c.argon2_t = 1;
        c
    }

    fn random_string() -> String {
        hex::encode(msg_crypto::random_bytes::<16>().unwrap())
    }

    #[test]
    fn password_hash_and_pepper() {
        let c = cfg();
        let (pepper_a, pepper_b) =
            (msg_crypto::random_bytes::<32>().unwrap(), msg_crypto::random_bytes::<32>().unwrap());
        let (pw, bad) = (random_string(), random_string());
        let h = PasswordHasherCfg { pepper: &pepper_a, cfg: &c };
        let stored = h.hash(&pw).unwrap();
        assert!(stored.starts_with("$argon2id$"));
        assert!(h.verify(&pw, Some(&stored)).unwrap());
        assert!(!h.verify(&bad, Some(&stored)).unwrap());
        let other = PasswordHasherCfg { pepper: &pepper_b, cfg: &c };
        assert!(!other.verify(&pw, Some(&stored)).unwrap());
        assert!(!h.verify(&pw, None).unwrap());
    }

    #[test]
    fn totp_replay_and_window() {
        let secret = new_totp_secret().unwrap();
        let t = totp(&secret, "site", "alice").unwrap();
        let now = 1_700_000_000;
        let code = t.generate(now as u64).to_string();
        let step = check_totp(&t, &code, now, None).unwrap();
        assert_eq!(step, now / 30);
        assert!(check_totp(&t, &code, now, Some(step)).is_none(), "rejeu refusé");
        assert!(check_totp(&t, &code, now + 300, None).is_none(), "code expiré");
        assert!(check_totp(&t, "abcdef", now, None).is_none());
    }

    #[test]
    fn activation_codes() {
        let (code, h) = new_activation_code().unwrap();
        assert_eq!(code.len(), 39);
        assert_eq!(activation_hash(&code), h);
        assert_eq!(activation_hash(&code.to_uppercase().replace('-', " ")), h);
    }
}
