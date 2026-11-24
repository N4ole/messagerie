//! Tests de bout en bout : serveur réel + clients réels + PostgreSQL.

mod common;

use common::*;
use msg_client_core::{Client, ClientError};
use msg_proto::{AccountStatus, ErrorCode};

/// Critère de réussite : un message échangé n'apparaît en clair ni dans la
/// base serveur (avant et après distribution), ni dans les journaux serveur,
/// ni dans la base locale chiffrée — mais il est bien lisible par le
/// destinataire (preuve que la recherche est pertinente).
#[tokio::test(flavor = "multi_thread")]
async fn message_exchange_without_plaintext_leak() {
    let mut s = spawn().await;
    let admin = s.admin().await;
    let (mut alice, alice_cfg, _) = s.user(&admin, "alice").await;
    let (mut bob, _, _) = s.user(&admin, "bob").await;

    let marker = format!("MARQUEUR-{}", uuid::Uuid::new_v4().simple());
    let conv = alice.start_conversation("bob").await.unwrap();
    assert_eq!(conv.peer, "bob");
    let sent = alice.send_text(&conv.id, &format!("**Secret** : {marker}")).await.unwrap();
    assert!(sent.outgoing);

    // Avant distribution : le blob chiffré est en base, sans clair.
    let dump = s.dump().await;
    let (blobs,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM blobs").fetch_one(&s.pool).await.unwrap();
    assert!(blobs >= 2, "Welcome + message attendus en file");
    let hex_marker = hex::encode(marker.as_bytes());
    assert!(!dump.contains(&marker), "clair trouvé dans la base serveur");
    assert!(!dump.contains(&hex_marker), "clair (hex) trouvé dans la base serveur");

    // Bob reçoit, déchiffre, vérifie l'expéditeur.
    let r = bob.sync().await.unwrap();
    assert_eq!(r.new_messages, 1);
    assert_eq!(r.rejected, 0);
    let convs = bob.conversations().unwrap();
    assert_eq!(convs.len(), 1);
    assert_eq!(convs[0].peer, "alice");
    assert_eq!(convs[0].unread, 1);
    let msgs = bob.messages(&convs[0].id, 50).unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].sender, "alice");
    assert!(msgs[0].text.contains(&marker), "le destinataire doit lire le message");
    assert!(serde_json::to_string(&msgs[0].ast).unwrap().contains("strong"));

    // Réponse de Bob.
    bob.send_text(&convs[0].id, "bien reçu").await.unwrap();
    let r = alice.sync().await.unwrap();
    assert_eq!(r.new_messages, 1);
    let msgs = alice.messages(&conv.id, 50).unwrap();
    assert_eq!(msgs.len(), 2);
    assert_eq!(msgs[1].text, "bien reçu");

    // Après distribution : les blobs sont supprimés du serveur.
    let (blobs,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM blobs").fetch_one(&s.pool).await.unwrap();
    assert_eq!(blobs, 0, "les blobs distribués doivent être supprimés");
    let dump = s.dump().await;
    assert!(!dump.contains(&marker) && !dump.contains(&hex_marker));

    // Journaux serveur (niveau TRACE, y compris sqlx).
    let logs = String::from_utf8_lossy(&logs().lock().unwrap()).to_string();
    assert!(!logs.is_empty(), "les journaux doivent être capturés");
    assert!(!logs.contains(&marker), "clair trouvé dans les journaux serveur");
    assert!(!logs.contains("/v1/users/alice") && !logs.contains("/v1/users/bob"), "chemin réel journalisé");

    // Base locale d'Alice : chiffrée sur disque.
    for entry in walk(&alice_cfg.data_dir) {
        let raw = std::fs::read(&entry).unwrap();
        assert!(!raw.windows(marker.len()).any(|w| w == marker.as_bytes()), "clair dans {}", entry.display());
    }
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn restart_resumes_session_and_mls_state() {
    let mut s = spawn().await;
    let admin = s.admin().await;
    let (mut alice, _, _) = s.user(&admin, "alice").await;
    let (bob, bob_cfg, bob_totp) = s.user(&admin, "bob").await;
    let conv = alice.start_conversation("bob").await.unwrap();
    alice.send_text(&conv.id, "avant redémarrage").await.unwrap();
    drop(bob); // fermeture de l'application

    // Mauvais mot de passe local : refus sans contacter le serveur.
    assert!(matches!(Client::login(&bob_cfg, "bob", &wrong_password(), None).await, Err(ClientError::WrongPassword)));

    // Reprise sans TOTP grâce à la session encore valide.
    let mut bob = Client::login(&bob_cfg, "bob", password(), None).await.unwrap();
    bob.sync().await.unwrap();
    let c = &bob.conversations().unwrap()[0];
    assert_eq!(bob.messages(&c.id, 10).unwrap()[0].text, "avant redémarrage");

    alice.send_text(&conv.id, "après redémarrage").await.unwrap();
    let cid = c.id.clone();
    drop(bob);
    let mut bob = Client::login(&bob_cfg, "bob", password(), None).await.unwrap();
    assert_eq!(bob.sync().await.unwrap().new_messages, 1);
    assert_eq!(bob.messages(&cid, 10).unwrap().len(), 2);

    // Déconnexion : la reprise sans TOTP n'est plus possible.
    bob.logout().await.unwrap();
    assert!(matches!(Client::login(&bob_cfg, "bob", password(), None).await, Err(ClientError::TotpRequired)));
    // Avec un nouveau code TOTP (pas suivant, l'ancien est consommé).
    let bob = Client::login(&bob_cfg, "bob", password(), Some(&totp_code(&bob_totp, 1))).await.unwrap();
    assert_eq!(bob.messages(&cid, 10).unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn authentication_rules() {
    let mut s = spawn().await;
    let admin = s.admin().await;
    let (alice, alice_cfg, alice_totp) = s.user(&admin, "alice").await;

    // Un utilisateur non administrateur ne peut pas créer de compte.
    let e = alice.api().admin_create("eve", msg_proto::Role::Admin).await.unwrap_err();
    assert_eq!(e.api_code(), Some(ErrorCode::Forbidden));

    // Code d'activation : usage unique et invalide pour un autre compte.
    let r = admin.api().admin_create("carol", msg_proto::Role::User).await.unwrap();
    let cfg = s.config();
    assert!(Client::activate(&cfg, "bob", &r.activation_code, password()).await.is_err());
    Client::activate(&cfg, "carol", &r.activation_code, password()).await.unwrap();
    assert!(Client::activate(&cfg, "carol", &r.activation_code, password()).await.is_err());
    // Mot de passe trop court refusé.
    let r = admin.api().admin_create("dave", msg_proto::Role::User).await.unwrap();
    assert!(Client::activate(&cfg, "dave", &r.activation_code, "court").await.is_err());

    // Rejeu du code TOTP déjà utilisé à l'enrôlement : refusé.
    drop(alice);
    let e = Client::login(&alice_cfg, "alice", password(), Some(&totp_code(&alice_totp, 0))).await.err().unwrap();
    assert_eq!(e.api_code(), Some(ErrorCode::InvalidCredentials));

    // Suspension : sessions révoquées, connexion refusée.
    let alice = Client::login(&alice_cfg, "alice", password(), Some(&totp_code(&alice_totp, 1))).await.unwrap();
    admin.api().admin_set_status("alice", AccountStatus::Suspended).await.unwrap();
    assert!(alice.api().key_package_count().await.is_err());
    drop(alice);
    let e = Client::login(&alice_cfg, "alice", password(), None).await.err().unwrap();
    assert!(matches!(e, ClientError::TotpRequired | ClientError::Api { .. }), "{e:?}");
    admin.api().admin_set_status("alice", AccountStatus::Active).await.unwrap();

    // Verrouillage après 5 échecs (mot de passe faux sur le serveur).
    for _ in 0..5 {
        let e = raw_login(&s.url, "alice", &wrong_password(), "000000").await;
        assert_eq!(e, 401);
    }
    assert_eq!(raw_login(&s.url, "alice", password(), "000000").await, 429);

    // Un administrateur ne peut pas se suspendre lui-même.
    assert!(admin.api().admin_set_status("admin", AccountStatus::Suspended).await.is_err());
    let list = admin.api().admin_list().await.unwrap();
    assert!(list.iter().any(|a| a.username == "alice" && a.device_count == 1));
}

async fn raw_login(url: &str, user: &str, pw: &str, totp: &str) -> u16 {
    let body = serde_json::json!({
        "username": user, "password": pw, "totp_code": totp,
        "device": { "device_id": uuid::Uuid::nil(), "identity_key": "", "api_key": "", "mls_signature_key": "",
                    "cert_created_at": 0, "cert_signature": "" }
    });
    reqwest::Client::new().post(format!("{url}/v1/auth/login")).json(&body).send().await.unwrap().status().as_u16()
}

/// Requêtes signées : rejeu d'un nonce, horodatage hors fenêtre et
/// altération du corps sont refusés.
#[tokio::test(flavor = "multi_thread")]
async fn signed_requests_resist_replay_and_tampering() {
    use msg_crypto::identity::{DeviceCertificate, SigningKeyPair};
    use msg_crypto::request::sign_request;
    use msg_proto::{headers, ConfirmTotpRequest, DeviceRegistration};

    let mut s = spawn().await;
    let admin = s.admin().await;
    let r = admin.api().admin_create("mallory", msg_proto::Role::User).await.unwrap();
    let cfg = s.config();
    let act = Client::activate(&cfg, "mallory", &r.activation_code, password()).await.unwrap();

    // Appareil construit à la main pour maîtriser la clé API.
    let identity = SigningKeyPair::generate().unwrap();
    let api_key = SigningKeyPair::generate().unwrap();
    let device_id = uuid::Uuid::new_v4();
    let mls_key = SigningKeyPair::generate().unwrap().public_bytes().to_vec();
    let cert = DeviceCertificate {
        username: "mallory".into(),
        device_id,
        api_key: api_key.public_bytes().to_vec(),
        mls_signature_key: mls_key.clone(),
        created_at: 1,
    };
    let http = reqwest::Client::new();
    let tokens: msg_proto::SessionTokens = http
        .post(format!("{}/v1/auth/confirm-totp", s.url))
        .json(&ConfirmTotpRequest {
            username: "mallory".into(),
            password: password().into(),
            totp_code: totp_code(&act.totp_secret_base32, 0),
            device: DeviceRegistration {
                device_id,
                identity_key: identity.public_bytes().to_vec(),
                api_key: api_key.public_bytes().to_vec(),
                mls_signature_key: mls_key,
                cert_created_at: 1,
                cert_signature: cert.sign(&identity).to_vec(),
            },
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let now = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let send = |h: msg_crypto::request::SignedHeaders, body: &'static str| {
        http.post(format!("{}/v1/queue/ack", s.url))
            .header(headers::DEVICE, h.device)
            .header(headers::TIMESTAMP, h.timestamp)
            .header(headers::NONCE, h.nonce)
            .header(headers::SIGNATURE, h.signature)
            .bearer_auth(&tokens.access_token)
            .header("content-type", "application/json")
            .body(body)
            .send()
    };
    let body = r#"{"ids":[]}"#;
    let h = sign_request(&api_key, &device_id, "POST", "/v1/queue/ack", body.as_bytes(), now()).unwrap();
    assert_eq!(send(h.clone(), body).await.unwrap().status(), 204);
    assert_eq!(send(h, body).await.unwrap().status(), 401, "rejeu du même nonce");

    let h = sign_request(&api_key, &device_id, "POST", "/v1/queue/ack", body.as_bytes(), now()).unwrap();
    assert_eq!(send(h, r#"{"ids":[1]}"#).await.unwrap().status(), 401, "corps altéré");

    let h = sign_request(&api_key, &device_id, "POST", "/v1/queue/ack", body.as_bytes(), now() - 600).unwrap();
    assert_eq!(send(h, body).await.unwrap().status(), 401, "horodatage trop ancien");

    let other = SigningKeyPair::generate().unwrap();
    let h = sign_request(&other, &device_id, "POST", "/v1/queue/ack", body.as_bytes(), now()).unwrap();
    assert_eq!(send(h, body).await.unwrap().status(), 401, "mauvaise clé");

    // Certificat d'appareil invalide refusé à la connexion.
    let bad = serde_json::json!({
        "username": "mallory", "password": password(), "totp_code": totp_code(&act.totp_secret_base32, 1),
        "device": { "device_id": uuid::Uuid::new_v4(),
            "identity_key": base64_32(&identity.public_bytes()), "api_key": base64_32(&api_key.public_bytes()),
            "mls_signature_key": base64_32(&[1u8; 32]), "cert_created_at": 1,
            "cert_signature": base64_64(&[0u8; 64]) }
    });
    let st = http.post(format!("{}/v1/auth/login", s.url)).json(&bad).send().await.unwrap().status();
    assert_eq!(st, 400);
}

fn base64_32(b: &[u8; 32]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}
fn base64_64(b: &[u8; 64]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// Après une réinitialisation par l'administrateur, l'identité de l'utilisateur
/// change : ses contacts existants doivent rejeter la nouvelle identité.
#[tokio::test(flavor = "multi_thread")]
async fn identity_change_is_detected() {
    let mut s = spawn().await;
    let admin = s.admin().await;
    let (mut carol, _, _) = s.user(&admin, "carol").await;
    let (bob, _, _) = s.user(&admin, "bob").await;
    let old = carol.start_conversation("bob").await.unwrap();
    drop(bob);

    let r = admin.api().admin_reset("bob").await.unwrap();
    let (mut bob2, _, _) = s.enroll("bob", &r.activation_code).await;

    // L'ancien appareil de Bob n'existe plus : l'envoi échoue.
    assert!(carol.send_text(&old.id, "test").await.is_err());

    // La nouvelle identité de Bob tente d'ouvrir une conversation : Carol,
    // qui connaît l'ancienne clé, rejette le Welcome.
    bob2.start_conversation("carol").await.unwrap();
    let report = carol.sync().await.unwrap();
    assert_eq!(report.rejected, 1, "le Welcome de la nouvelle identité doit être rejeté");
    assert_eq!(carol.conversations().unwrap().len(), 1, "aucune nouvelle conversation");

    // Un utilisateur qui n'a jamais vu Bob accepte sa nouvelle identité (TOFU).
    let (mut dave, _, _) = s.user(&admin, "dave").await;
    dave.start_conversation("bob").await.unwrap();
}
