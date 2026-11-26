//! Message applicatif déchiffré (texte, pièce jointe, informations de
//! groupe) : décodage et validation sans panique ; ré-encodage stable.
#![no_main]
use libfuzzer_sys::fuzz_target;
use msg_crypto::app_message::AppMessage;
use msg_crypto::mls::MemberIdentity;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = AppMessage::decode(data) {
        let again = AppMessage::decode(&m.encode()).expect("relecture");
        assert_eq!(again.id, m.id);
    }
    let _ = MemberIdentity::decode(data);
});
