//! Documents (PDF, Office, OpenDocument) : détection et nettoyage des
//! métadonnées sans panique ; un document nettoyé reste reconnu comme tel.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let kind = msg_media::detect_document(data);
    if let Ok(Some(clean)) = msg_media::sanitize_document(data) {
        assert_eq!(msg_media::detect_document(&clean), kind, "type changé par le nettoyage");
    }
});
