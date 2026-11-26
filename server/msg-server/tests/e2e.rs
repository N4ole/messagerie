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
    let too_short = &password()[..11];
    assert!(Client::activate(&cfg, "dave", &r.activation_code, too_short).await.is_err());

    // Rejeu du code TOTP déjà utilisé à l'enrôlement (même pas de temps,
    // lu en base pour ne pas dépendre de l'horloge) : refusé.
    drop(alice);
    let (step,): (Option<i64>,) = sqlx::query_as("SELECT totp_last_step FROM accounts WHERE username = 'alice'")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    let used = common::totp_code_at(&alice_totp, step.unwrap() * 30);
    let e = Client::login(&alice_cfg, "alice", password(), Some(&used)).await.err().unwrap();
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
/// change : chez ses contacts, la conversation est suspendue (contenu masqué,
/// envoi bloqué) jusqu'à vérification du numéro de sécurité ou acceptation.
#[tokio::test(flavor = "multi_thread")]
async fn identity_change_suspends_until_verified() {
    let mut s = spawn().await;
    let admin = s.admin().await;
    let (mut carol, _, _) = s.user(&admin, "carol").await;
    let (bob, _, _) = s.user(&admin, "bob").await;
    let old = carol.start_conversation("bob").await.unwrap();
    let old_number = carol.safety_number("bob").unwrap().number;
    drop(bob);

    let r = admin.api().admin_reset("bob").await.unwrap();
    let (mut bob2, _, _) = s.enroll("bob", &r.activation_code).await;

    // L'ancien appareil de Bob n'existe plus : l'envoi échoue.
    assert!(carol.send_text(&old.id, "test").await.is_err());

    // La nouvelle identité de Bob ouvre une conversation et écrit.
    let conv_b = bob2.start_conversation("carol").await.unwrap();
    bob2.send_text(&conv_b.id, "c'est bien moi").await.unwrap();
    let report = carol.sync().await.unwrap();
    assert_eq!(report.identity_changes, vec!["bob".to_string()]);
    assert_eq!(report.rejected, 0);
    let suspended = carol.conversation(&conv_b.id).unwrap();
    assert_eq!(suspended.status, "identity_changed");
    assert_eq!(suspended.identity_changed, vec!["bob".to_string()]);
    assert!(carol.messages(&conv_b.id, 10).unwrap().is_empty(), "contenu masqué");
    assert!(carol.send_text(&conv_b.id, "non").await.is_err(), "envoi bloqué");

    // Numéro de sécurité : calculé sur la NOUVELLE clé, différent de l'ancien.
    let sn = carol.safety_number("bob").unwrap();
    assert!(sn.identity_changed);
    assert_ne!(sn.number, old_number);
    let bob_view = bob2.safety_number("carol").unwrap();
    assert_eq!(bob_view.number, sn.number, "les deux côtés voient le même numéro");
    // Un mauvais QR code est refusé, le bon est accepté.
    assert!(!carol.verify_safety_number("bob", Some(&old_number)).unwrap());
    assert!(carol.verify_safety_number("bob", Some(&bob_view.qr_payload)).unwrap());
    let ok = carol.conversation(&conv_b.id).unwrap();
    assert_eq!(ok.status, "ok");
    assert!(ok.verified);
    assert_eq!(carol.messages(&conv_b.id, 10).unwrap()[0].text, "c'est bien moi");
    carol.send_text(&conv_b.id, "vérifié").await.unwrap();
    assert_eq!(bob2.sync().await.unwrap().new_messages, 1);
}

/// Groupes : création, ajout, retrait (le membre retiré ne lit plus rien),
/// départ, commits réservés à l'administrateur.
#[tokio::test(flavor = "multi_thread")]
async fn group_lifecycle() {
    let mut s = spawn().await;
    let admin = s.admin().await;
    let (mut alice, _, _) = s.user(&admin, "alice").await;
    let (mut bob, _, _) = s.user(&admin, "bob").await;
    let (mut carol, _, _) = s.user(&admin, "carol").await;
    let (mut dave, _, _) = s.user(&admin, "dave").await;

    let g = alice.create_group("Équipe projet", &["bob".into(), "carol".into()]).await.unwrap();
    assert_eq!((g.kind.as_str(), g.title.as_str(), g.is_admin), ("group", "Équipe projet", true));
    assert_eq!(g.members, vec!["alice", "bob", "carol"]);
    for c in [&mut bob, &mut carol] {
        c.sync().await.unwrap();
        let v = c.conversation(&g.id).unwrap();
        assert_eq!(
            (v.kind.as_str(), v.title.as_str(), v.admin.as_deref(), v.is_admin),
            ("group", "Équipe projet", Some("alice"), false)
        );
    }
    bob.send_text(&g.id, "bonjour à tous").await.unwrap();
    assert_eq!(alice.sync().await.unwrap().new_messages, 1);
    assert_eq!(carol.sync().await.unwrap().new_messages, 1);

    // Seul l'administrateur gère les membres.
    assert!(bob.add_member(&g.id, "dave").await.is_err());
    let g2 = alice.add_member(&g.id, "dave").await.unwrap();
    assert_eq!(g2.members.len(), 4);
    for c in [&mut bob, &mut carol, &mut dave] {
        c.sync().await.unwrap();
    }
    assert_eq!(dave.conversation(&g.id).unwrap().title, "Équipe projet");
    dave.send_text(&g.id, "merci de l'invitation").await.unwrap();
    assert_eq!(carol.sync().await.unwrap().new_messages, 1);

    // Retrait de Bob : il est informé et ne peut plus rien lire.
    alice.remove_member(&g.id, "bob").await.unwrap();
    let r = bob.sync().await.unwrap();
    assert_eq!(r.removed_from, vec![g.id.clone()]);
    assert_eq!(bob.conversation(&g.id).unwrap().status, "removed");
    assert!(bob.send_text(&g.id, "encore là ?").await.is_err());
    carol.sync().await.unwrap();
    dave.sync().await.unwrap();
    alice.send_text(&g.id, "secret sans Bob").await.unwrap();
    let r = bob.sync().await.unwrap();
    assert_eq!(r.new_messages, 0, "un membre retiré ne reçoit plus rien");
    assert_eq!(carol.sync().await.unwrap().new_messages, 1);

    // Départ de Carol : proposition validée automatiquement par Alice.
    carol.leave_group(&g.id).await.unwrap();
    alice.sync().await.unwrap();
    assert_eq!(alice.conversation(&g.id).unwrap().members, vec!["alice", "dave"]);
    carol.sync().await.unwrap();
    assert_eq!(carol.conversation(&g.id).unwrap().status, "removed");
    dave.sync().await.unwrap();
    alice.send_text(&g.id, "à deux").await.unwrap();
    assert_eq!(dave.sync().await.unwrap().new_messages, 1);
    assert!(alice.leave_group(&g.id).await.is_err(), "l'administrateur ne peut pas partir");

    // Transfert d'administration : seul l'administrateur en place le peut,
    // vers un membre ; l'ancien administrateur peut alors partir et le
    // nouveau valide son départ et gère les membres.
    assert!(dave.transfer_admin(&g.id, "dave").await.is_err());
    assert!(dave.transfer_admin(&g.id, "alice").await.is_err(), "réservé à l'administrateur");
    assert!(alice.transfer_admin(&g.id, "bob").await.is_err(), "bob n'est plus membre");
    let t = alice.transfer_admin(&g.id, "dave").await.unwrap();
    assert_eq!((t.admin.as_deref(), t.is_admin), (Some("dave"), false));
    dave.sync().await.unwrap();
    let v = dave.conversation(&g.id).unwrap();
    assert_eq!((v.admin.as_deref(), v.is_admin), (Some("dave"), true));
    assert!(alice.add_member(&g.id, "bob").await.is_err(), "l'ancien administrateur ne gère plus le groupe");
    alice.leave_group(&g.id).await.unwrap();
    dave.sync().await.unwrap();
    assert_eq!(dave.conversation(&g.id).unwrap().members, vec!["dave"]);
    alice.sync().await.unwrap();
    assert_eq!(alice.conversation(&g.id).unwrap().status, "removed");
    let g3 = dave.add_member(&g.id, "carol").await.unwrap();
    assert_eq!(g3.members, vec!["carol", "dave"]);
    carol.sync().await.unwrap();
    let vc = carol.conversation(&g.id).unwrap();
    assert_eq!((vc.admin.as_deref(), vc.status.as_str()), (Some("dave"), "ok"));
    dave.send_text(&g.id, "nouvelle équipe").await.unwrap();
    assert_eq!(carol.sync().await.unwrap().new_messages, 1);
}

/// Messages éphémères et rotation des clés.
#[tokio::test(flavor = "multi_thread")]
async fn ephemeral_messages_and_key_rotation() {
    let mut s = spawn().await;
    let admin = s.admin().await;
    let (mut alice, _, _) = s.user(&admin, "alice").await;
    let (mut bob, _, _) = s.user(&admin, "bob").await;
    let c = alice.start_conversation("bob").await.unwrap();
    alice.set_ephemeral(&c.id, Some(1)).unwrap();
    let m = alice.send_text(&c.id, "disparaît vite").await.unwrap();
    assert!(m.expires_at_ms.is_some());
    bob.sync().await.unwrap();
    assert_eq!(bob.messages(&c.id, 10).unwrap().len(), 1);
    assert!(bob.messages(&c.id, 10).unwrap()[0].expires_at_ms.is_some());
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert!(bob.messages(&c.id, 10).unwrap().is_empty(), "expiré chez le destinataire");
    assert!(alice.messages(&c.id, 10).unwrap().is_empty(), "expiré chez l'expéditeur");
    alice.set_ephemeral(&c.id, None).unwrap();

    // Rotation forcée côté membre non administrateur : proposition → commit
    // par l'administrateur → les deux restent synchronisés.
    bob.rotate_now(&c.id).await.unwrap();
    alice.sync().await.unwrap(); // reçoit la proposition, émet le commit
    bob.sync().await.unwrap(); // applique le commit
    alice.rotate_now(&c.id).await.unwrap(); // commit direct de l'administrateur
    bob.sync().await.unwrap();
    bob.send_text(&c.id, "après deux rotations").await.unwrap();
    let r = alice.sync().await.unwrap();
    assert_eq!((r.new_messages, r.rejected), (1, 0));
    alice.send_text(&c.id, "toujours synchronisés").await.unwrap();
    assert_eq!(bob.sync().await.unwrap().new_messages, 1);
}

/// JPEG de test avec un segment EXIF contenant un marqueur « GPS ».
fn jpeg_with_exif(marker: &[u8]) -> Vec<u8> {
    use image::codecs::jpeg::JpegEncoder;
    let img = image::RgbImage::from_fn(64, 48, |x, y| image::Rgb([x as u8, y as u8, 100]));
    let mut plain = Vec::new();
    JpegEncoder::new_with_quality(&mut plain, 90).encode_image(&img).unwrap();
    let mut payload = b"Exif\0\0MM\0*\0\0\0\x08".to_vec();
    payload.extend_from_slice(marker);
    let mut out = vec![0xFF, 0xD8, 0xFF, 0xE1];
    out.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
    out.extend_from_slice(&payload);
    out.extend_from_slice(&plain[2..]);
    out
}

/// Pièces jointes : EXIF supprimé, nom/type/miniature invisibles du serveur,
/// intégrité vérifiée au téléchargement.
#[tokio::test(flavor = "multi_thread")]
async fn attachments_are_cleaned_and_encrypted() {
    let mut s = spawn().await;
    let admin = s.admin().await;
    let (mut alice, _, _) = s.user(&admin, "alice").await;
    let (mut bob, _, _) = s.user(&admin, "bob").await;
    let c = alice.start_conversation("bob").await.unwrap();

    let gps = format!("GPS-{}", uuid::Uuid::new_v4().simple());
    let file_name = format!("vacances-{}.jpeg", uuid::Uuid::new_v4().simple());
    let photo = jpeg_with_exif(gps.as_bytes());
    let sent = alice.send_file(&c.id, &file_name, photo, Some("la plage".into())).await.unwrap();
    let a = sent.attachment.as_ref().unwrap();
    assert_eq!((a.mime.as_str(), a.metadata_cleaned), ("image/jpeg", true));
    assert!(a.name.ends_with(".jpg"));
    assert!(a.thumbnail_data_uri.as_deref().unwrap().starts_with("data:image/jpeg;base64,"));

    // Côté serveur : ni nom de fichier, ni type, ni marqueur, ni légende.
    let dump = s.dump().await;
    let stem = file_name.trim_end_matches(".jpeg");
    for needle in [stem, gps.as_str(), "la plage", "image/jpeg"] {
        assert!(!dump.contains(needle), "« {needle} » visible côté serveur");
        assert!(!dump.contains(&hex::encode(needle)), "« {needle} » (hex) visible côté serveur");
    }

    bob.sync().await.unwrap();
    let msgs = bob.messages(&c.id, 10).unwrap();
    let m = &msgs[0];
    assert_eq!((m.kind.as_str(), m.text.as_str()), ("attachment", "la plage"));
    let file = bob.download_file(&m.id).await.unwrap();
    assert_eq!(file.mime, "image/jpeg");
    assert!(!file.data.windows(gps.len()).any(|w| w == gps.as_bytes()), "EXIF/GPS transmis au destinataire");
    assert!(!file.data.windows(4).any(|w| w == b"Exif"));
    image::load_from_memory(&file.data).expect("image valide");

    // Document Word : métadonnées supprimées avant chiffrement, contenu conservé.
    let author = format!("AUTEUR-{}", uuid::Uuid::new_v4().simple());
    let docx = docx_with_author(&author);
    let sent = alice.send_file(&c.id, "compte-rendu.docx", docx, None).await.unwrap();
    assert!(sent.attachment.unwrap().metadata_cleaned);
    bob.sync().await.unwrap();
    let m = bob.messages(&c.id, 10).unwrap().last().unwrap().clone();
    assert!(m.attachment.as_ref().unwrap().metadata_cleaned, "signalé nettoyé chez le destinataire");
    let got = bob.download_file(&m.id).await.unwrap();
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(got.data.to_vec())).expect("document valide");
    let mut all = String::new();
    for i in 0..z.len() {
        use std::io::Read;
        z.by_index(i).unwrap().read_to_string(&mut all).unwrap();
    }
    assert!(!all.contains(&author), "auteur transmis au destinataire");
    assert!(all.contains("Texte du compte rendu"), "contenu conservé");

    // Fichier de code : jamais modifié.
    let code = b"fn main() { println!(\"bonjour\"); }\n".to_vec();
    let sent = alice.send_file(&c.id, "main.rs", code.clone(), None).await.unwrap();
    assert!(!sent.attachment.unwrap().metadata_cleaned);
    bob.sync().await.unwrap();
    let id = bob.messages(&c.id, 10).unwrap().last().unwrap().id.clone();
    assert_eq!(&bob.download_file(&id).await.unwrap().data[..], &code[..]);

    // PDF illisible : impossible à nettoyer, transmis intact et signalé non nettoyé.
    let pdf = b"%PDF-1.7\n% contenu de test\n".repeat(100);
    let sent = alice.send_file(&c.id, "../../rapport.pdf", pdf.clone(), None).await.unwrap();
    let a = sent.attachment.unwrap();
    assert_eq!((a.name.as_str(), a.mime.as_str(), a.metadata_cleaned), ("rapport.pdf", "application/pdf", false));
    bob.sync().await.unwrap();
    let id = bob.messages(&c.id, 10).unwrap().last().unwrap().id.clone();
    assert_eq!(&bob.download_file(&id).await.unwrap().data[..], &pdf[..]);
}

/// Passkeys / clés de sécurité : enregistrement, connexion sans TOTP,
/// défi à usage unique, refus d'une autre clé, suppression.
#[tokio::test(flavor = "multi_thread")]
async fn passkey_second_factor() {
    use msg_client_core::passkey::soft::SoftAuthenticator;
    use std::sync::Arc;

    let mut s = spawn_webauthn().await;
    let admin = s.admin().await;
    let (alice, alice_cfg, _) = s.user(&admin, "alice").await;
    let yubikey: Arc<SoftAuthenticator> = Arc::new(SoftAuthenticator::default());

    // Pas encore de clé : le défi de connexion est refusé.
    drop(alice);
    assert!(Client::login_with_passkey(&alice_cfg, "alice", password(), yubikey.clone()).await.is_err());

    let alice = Client::login(&alice_cfg, "alice", password(), None).await.unwrap();
    let k = alice.register_passkey("YubiKey bureau", yubikey.clone()).await.unwrap();
    assert_eq!(k.name, "YubiKey bureau");
    assert_eq!(alice.passkeys().await.unwrap().len(), 1);
    alice.logout().await.unwrap();

    // Connexion mot de passe + clé, sans TOTP.
    let alice = Client::login_with_passkey(&alice_cfg, "alice", password(), yubikey.clone()).await.unwrap();
    assert!(alice.passkeys().await.unwrap()[0].last_used_at.is_some());
    alice.logout().await.unwrap();

    // Mauvais mot de passe : pas de défi (et l'échec est compté).
    assert!(Client::login_with_passkey(&alice_cfg, "alice", &wrong_password(), yubikey.clone()).await.is_err());

    // Signature altérée : refusée par le serveur (vérification webauthn-rs).
    struct Tamper(Arc<SoftAuthenticator>);
    impl msg_client_core::passkey::RawAuthenticator for Tamper {
        fn make_credential(
            &self,
            r: &msg_client_core::passkey::MakeCredentialRequest,
        ) -> msg_client_core::Result<msg_client_core::passkey::MakeCredentialResponse> {
            self.0.make_credential(r)
        }
        fn get_assertion(
            &self,
            r: &msg_client_core::passkey::GetAssertionRequest,
        ) -> msg_client_core::Result<msg_client_core::passkey::GetAssertionResponse> {
            let mut a = self.0.get_assertion(r)?;
            let n = a.signature.len();
            a.signature[n - 3] ^= 0x01;
            Ok(a)
        }
    }
    let e = Client::login_with_passkey(&alice_cfg, "alice", password(), Arc::new(Tamper(yubikey.clone()))).await;
    assert_eq!(e.err().and_then(|e| e.api_code()), Some(msg_proto::ErrorCode::InvalidCredentials));

    // Une autre clé (non enregistrée) est refusée.
    let other: Arc<SoftAuthenticator> = Arc::new(SoftAuthenticator::default());
    assert!(Client::login_with_passkey(&alice_cfg, "alice", password(), other).await.is_err());

    // Suppression : la clé ne permet plus de se connecter.
    let alice = Client::login_with_passkey(&alice_cfg, "alice", password(), yubikey.clone()).await.unwrap();
    let id = alice.passkeys().await.unwrap()[0].id;
    alice.delete_passkey(id).await.unwrap();
    alice.logout().await.unwrap();
    assert!(Client::login_with_passkey(&alice_cfg, "alice", password(), yubikey).await.is_err());
}

/// Document Word minimal dont les propriétés et un commentaire portent `author`.
fn docx_with_author(author: &str) -> Vec<u8> {
    use std::io::Write;
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let parts = [
        (
            "[Content_Types].xml",
            r#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>"#.to_owned(),
        ),
        ("docProps/core.xml", format!("<cp:coreProperties><dc:creator>{author}</dc:creator></cp:coreProperties>")),
        (
            "word/document.xml",
            "<w:document><w:body><w:p><w:r><w:t>Texte du compte rendu</w:t></w:r></w:p></w:body></w:document>"
                .to_owned(),
        ),
        ("word/comments.xml", format!(r#"<w:comments><w:comment w:id="0" w:author="{author}"/></w:comments>"#)),
    ];
    for (name, xml) in parts {
        w.start_file(name, zip::write::SimpleFileOptions::default()).unwrap();
        w.write_all(xml.as_bytes()).unwrap();
    }
    w.finish().unwrap().into_inner()
}
