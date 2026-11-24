//! Numéros de sécurité (*safety numbers*) pour la vérification des
//! correspondants, par comparaison de chiffres ou par QR code.
//!
//! Construction reprise de l'empreinte numérique publiquement documentée du
//! Signal Protocol (`NumericFingerprintGenerator`) : pour chaque partie,
//! `h = SHA-512(version ‖ clé ‖ identifiant)`, puis 5200 itérations de
//! `h = SHA-512(h ‖ clé)` ; les 30 premiers octets donnent 6 blocs de
//! 5 chiffres. Les deux empreintes sont concaténées dans un ordre canonique
//! (tri), si bien que les deux correspondants voient le même nombre.
//! (Clé : Ed25519 brute de 32 octets ; identifiant : nom d'utilisateur.)

use sha2::{Digest, Sha512};

const VERSION: [u8; 2] = [0, 0];
const ITERATIONS: usize = 5200;
/// Préfixe de la charge utile du QR code.
pub const QR_PREFIX: &str = "messagerie-sn:1:";

fn fingerprint_30(identity_key: &[u8], username: &str) -> String {
    let mut h = Sha512::new();
    h.update(VERSION);
    h.update(identity_key);
    h.update(username.as_bytes());
    let mut hash = h.finalize();
    for _ in 0..ITERATIONS {
        let mut h = Sha512::new();
        h.update(hash);
        h.update(identity_key);
        hash = h.finalize();
    }
    let mut out = String::with_capacity(30);
    for chunk in hash[..30].chunks(5) {
        let v = chunk.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
        out.push_str(&format!("{:05}", v % 100_000));
    }
    out
}

/// Numéro de sécurité (60 chiffres) entre deux utilisateurs.
pub fn safety_number(a_user: &str, a_key: &[u8], b_user: &str, b_key: &[u8]) -> String {
    let fa = fingerprint_30(a_key, a_user);
    let fb = fingerprint_30(b_key, b_user);
    if fa <= fb {
        fa + &fb
    } else {
        fb + &fa
    }
}

/// Présentation par groupes de 5 chiffres.
pub fn format_groups(number: &str) -> String {
    number.as_bytes().chunks(5).map(|c| std::str::from_utf8(c).unwrap_or_default()).collect::<Vec<_>>().join(" ")
}

/// Contenu du QR code à afficher.
pub fn qr_payload(number: &str) -> String {
    format!("{QR_PREFIX}{number}")
}

/// Vérifie une charge utile scannée (ou des chiffres saisis) contre le
/// numéro attendu, en ignorant espaces et préfixe.
pub fn matches(expected: &str, scanned: &str) -> bool {
    let digits: String = scanned.trim().trim_start_matches(QR_PREFIX).chars().filter(|c| c.is_ascii_digit()).collect();
    digits.len() == 60 && subtle_eq(digits.as_bytes(), expected.as_bytes())
}

fn subtle_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::SigningKeyPair;

    #[test]
    fn symmetric_and_sixty_digits() {
        let (a, b) = (SigningKeyPair::generate().unwrap(), SigningKeyPair::generate().unwrap());
        let n1 = safety_number("alice", &a.public_bytes(), "bob", &b.public_bytes());
        let n2 = safety_number("bob", &b.public_bytes(), "alice", &a.public_bytes());
        assert_eq!(n1, n2);
        assert_eq!(n1.len(), 60);
        assert!(n1.bytes().all(|c| c.is_ascii_digit()));
        assert_eq!(format_groups(&n1).len(), 60 + 11);
    }

    #[test]
    fn changes_with_any_key_or_name() {
        let (a, b, c) = (
            SigningKeyPair::generate().unwrap(),
            SigningKeyPair::generate().unwrap(),
            SigningKeyPair::generate().unwrap(),
        );
        let n = safety_number("alice", &a.public_bytes(), "bob", &b.public_bytes());
        assert_ne!(n, safety_number("alice", &a.public_bytes(), "bob", &c.public_bytes()));
        assert_ne!(n, safety_number("alice", &a.public_bytes(), "carol", &b.public_bytes()));
    }

    #[test]
    fn qr_matching() {
        let (a, b) = (SigningKeyPair::generate().unwrap(), SigningKeyPair::generate().unwrap());
        let n = safety_number("alice", &a.public_bytes(), "bob", &b.public_bytes());
        assert!(matches(&n, &qr_payload(&n)));
        assert!(matches(&n, &format_groups(&n)));
        let mut wrong = n.clone().into_bytes();
        wrong[10] = if wrong[10] == b'0' { b'1' } else { b'0' };
        assert!(!matches(&n, &String::from_utf8(wrong).unwrap()));
        assert!(!matches(&n, "123"));
    }
}
