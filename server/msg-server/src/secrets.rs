//! Dérivation des secrets serveur et chiffrement des secrets TOTP au repos.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

pub struct ServerSecrets {
    pub pepper: Zeroizing<[u8; 32]>,
    totp_key: Zeroizing<[u8; 32]>,
    /// Graine de la clé VRF du répertoire Key Transparency.
    pub kt_vrf_seed: Zeroizing<[u8; 32]>,
    /// Graine de la clé Ed25519 de fédération du site.
    pub federation_seed: Zeroizing<[u8; 32]>,
}

impl ServerSecrets {
    /// HKDF-SHA256 avec séparation de domaine par libellé.
    pub fn derive(master: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(b"messagerie/server/v1"), master);
        let mut pepper = Zeroizing::new([0u8; 32]);
        let mut totp_key = Zeroizing::new([0u8; 32]);
        let mut kt_vrf_seed = Zeroizing::new([0u8; 32]);
        let mut federation_seed = Zeroizing::new([0u8; 32]);
        hk.expand(b"argon2-pepper", pepper.as_mut()).expect("longueur valide");
        hk.expand(b"totp-at-rest", totp_key.as_mut()).expect("longueur valide");
        hk.expand(b"kt-vrf", kt_vrf_seed.as_mut()).expect("longueur valide");
        hk.expand(b"federation-signing", federation_seed.as_mut()).expect("longueur valide");
        Self { pepper, totp_key, kt_vrf_seed, federation_seed }
    }

    /// Chiffre un secret TOTP, lié au compte par l'AAD.
    pub fn seal_totp(&self, username: &str, secret: &[u8]) -> anyhow::Result<Vec<u8>> {
        let nonce = msg_crypto::random_bytes::<24>()?;
        let c = XChaCha20Poly1305::new(self.totp_key.as_ref().into());
        let mut out = nonce.to_vec();
        out.extend(
            c.encrypt(XNonce::from_slice(&nonce), Payload { msg: secret, aad: username.as_bytes() })
                .map_err(|_| anyhow::anyhow!("chiffrement TOTP"))?,
        );
        Ok(out)
    }

    pub fn open_totp(&self, username: &str, sealed: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        if sealed.len() < 24 + 16 {
            anyhow::bail!("secret TOTP corrompu");
        }
        let (nonce, ct) = sealed.split_at(24);
        let c = XChaCha20Poly1305::new(self.totp_key.as_ref().into());
        Ok(Zeroizing::new(
            c.decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: username.as_bytes() })
                .map_err(|_| anyhow::anyhow!("déchiffrement TOTP"))?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_seal_bound_to_user() {
        let s = ServerSecrets::derive(&[3; 32]);
        let sealed = s.seal_totp("alice", b"secret-totp").unwrap();
        assert_eq!(&s.open_totp("alice", &sealed).unwrap()[..], b"secret-totp");
        assert!(s.open_totp("bob", &sealed).is_err());
        let other = ServerSecrets::derive(&[4; 32]);
        assert!(other.open_totp("alice", &sealed).is_err());
        assert_ne!(*s.pepper, *other.pepper);
    }
}
