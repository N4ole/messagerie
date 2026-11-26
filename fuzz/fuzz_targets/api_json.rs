//! Corps JSON reçus par le serveur (clients et sites pairs) ou par le client
//! (réponses) : désérialisation et validation sans panique.
#![no_main]
use libfuzzer_sys::fuzz_target;
use msg_proto::*;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<SendRequest>(data);
    let _ = serde_json::from_slice::<FederationDeliver>(data);
    let _ = serde_json::from_slice::<FederationAck>(data);
    let _ = serde_json::from_slice::<SignedKtHead>(data);
    let _ = serde_json::from_slice::<UserDirectoryEntry>(data);
    let _ = serde_json::from_slice::<KtAudit>(data);
    let _ = serde_json::from_slice::<SiteInfo>(data);
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = validate_username(s);
        let _ = validate_site(s);
        if let Ok((user, site)) = parse_address(s) {
            assert!(validate_username(&user).is_ok(), "nom invalide accepté : {user:?}");
            if let Some(site) = site {
                assert!(validate_site(&site).is_ok(), "site invalide accepté : {site:?}");
            }
        }
    }
});
