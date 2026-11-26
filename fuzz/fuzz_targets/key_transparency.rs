//! Preuves Key Transparency arbitraires (serveur malveillant) : la
//! vérification échoue proprement, ne panique jamais et n'accepte pas une
//! preuve forgée pour une valeur choisie.
#![no_main]
use libfuzzer_sys::fuzz_target;
use msg_proto::{KtAudit, KtLookup};

fuzz_target!(|data: &[u8]| {
    if data.len() < 33 {
        return;
    }
    let (key, rest) = data.split_at(32);
    if let Ok(lookup) = serde_json::from_slice::<KtLookup>(rest) {
        let _ = msg_kt::verify_lookup(key, "fuzz", &lookup, b"valeur");
    }
    if let Ok(audit) = serde_json::from_slice::<KtAudit>(rest) {
        let rt = tokio::runtime::Builder::new_current_thread().build().expect("runtime");
        let _ = rt.block_on(msg_kt::verify_audit(key, &audit));
    }
});
