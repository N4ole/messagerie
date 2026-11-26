//! Message MLS entrant arbitraire (commit, proposition, Welcome, message
//! applicatif) traité par un client réel : erreur attendue, jamais de panique.
#![no_main]
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use msg_crypto::mls::{MemberIdentity, MlsClient};

fn client() -> &'static MlsClient {
    static C: OnceLock<MlsClient> = OnceLock::new();
    C.get_or_init(|| {
        let c = MlsClient::create(MemberIdentity { username: "fuzz".into(), device_id: uuid::Uuid::from_u128(1) })
            .expect("client MLS");
        c.generate_key_packages(2).expect("KeyPackages");
        c
    })
}

fuzz_target!(|data: &[u8]| {
    let c = client();
    let _ = c.process(data);
    let _ = c.inspect_key_package(data);
});
