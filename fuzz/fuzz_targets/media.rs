//! Image reçue (pièce jointe) : détection puis nettoyage (métadonnées
//! supprimées, ré-encodage) sans panique ni allocation démesurée.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = msg_media::detect(data);
    let _ = msg_media::sanitize_image(data);
});
