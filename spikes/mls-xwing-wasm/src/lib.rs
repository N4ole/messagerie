//! Sonde de faisabilité Phase 0 : groupe MLS à 2 membres en suite X-Wing.
use openmls::prelude::{tls_codec::*, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_libcrux_crypto::Provider;

pub const CS: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

fn member(name: &str, p: &Provider) -> (CredentialWithKey, SignatureKeyPair) {
    let sk = SignatureKeyPair::new(CS.signature_algorithm()).unwrap();
    sk.store(p.storage()).unwrap();
    (CredentialWithKey { credential: BasicCredential::new(name.into()).into(), signature_key: sk.to_public_vec().into() }, sk)
}

/// Alice crée un groupe, ajoute Bob, envoie `msg` ; retourne ce que Bob déchiffre.
pub fn roundtrip(msg: &[u8]) -> Vec<u8> {
    let (pa, pb) = (Provider::new().unwrap(), Provider::new().unwrap());
    let (ca, sa) = member("alice", &pa);
    let (cb, sb) = member("bob", &pb);
    let kp_b = KeyPackage::builder().build(CS, &pb, &sb, cb).unwrap();
    let cfg = MlsGroupCreateConfig::builder().ciphersuite(CS).use_ratchet_tree_extension(true).build();
    let mut ga = MlsGroup::new(&pa, &sa, &cfg, ca).unwrap();
    let (_c, welcome, _) = ga.add_members(&pa, &sa, &[kp_b.key_package().clone()]).unwrap();
    ga.merge_pending_commit(&pa).unwrap();
    // Passage par le fil (sérialisation TLS) comme via le serveur.
    let w = MlsMessageIn::tls_deserialize_exact(welcome.tls_serialize_detached().unwrap()).unwrap();
    let MlsMessageBodyIn::Welcome(w) = w.extract() else { panic!() };
    let mut gb = StagedWelcome::new_from_welcome(&pb, &MlsGroupJoinConfig::default(), w, None).unwrap().into_group(&pb).unwrap();
    let out = ga.create_message(&pa, &sa, msg).unwrap().tls_serialize_detached().unwrap();
    assert!(!out.windows(msg.len()).any(|x| x == msg), "clair visible sur le fil");
    let inm = MlsMessageIn::tls_deserialize_exact(out).unwrap();
    let pm: ProtocolMessage = inm.try_into_protocol_message().unwrap();
    match gb.process_message(&pb, pm).unwrap().into_content() {
        ProcessedMessageContent::ApplicationMessage(m) => m.into_bytes(),
        _ => panic!(),
    }
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn probe(s: &str) -> String { String::from_utf8(roundtrip(s.as_bytes())).unwrap() }

#[cfg(test)]
mod t { #[test] fn xwing_roundtrip() { assert_eq!(super::roundtrip(b"bonjour bob"), b"bonjour bob"); } }
