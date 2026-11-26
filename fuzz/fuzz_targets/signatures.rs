//! En-têtes de signature arbitraires (requêtes d'appareils et de sites,
//! réponses de sites) : refus sans panique ; une signature valide ne peut
//! pas être produite sans la clé.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let parts: Vec<&str> = s.splitn(4, '\n').collect();
    let [a, b, c, d] = parts[..] else { return };
    // Clé dérivée de l'entrée (aucune valeur cryptographique figée).
    let key = [a.len() as u8 ^ 0x5a; 32];
    let id = uuid::Uuid::from_u128(1);
    assert!(msg_crypto::request::verify_request(&key, &id, a, b, d.as_bytes(), 0, c, d).is_err());
    assert!(msg_crypto::request::verify_site_request(&key, a, "POST", b, d.as_bytes(), 0, c, d).is_err());
    assert!(msg_crypto::request::verify_site_response(&key, a, b, 200, c.as_bytes(), d).is_err());
    let _ = msg_crypto::identity::verify(a.as_bytes(), b.as_bytes(), c.as_bytes());
});
