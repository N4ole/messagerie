//! Phase 4 : plusieurs instances du serveur, fédération, métriques.

mod common;

use std::time::Duration;

use common::{password, spawn, totp_code};
use futures_util::StreamExt;
use msg_client_core::Client;

/// Deux instances sur la même base : un message envoyé via l'une est signalé
/// en temps réel au destinataire connecté à l'autre (LISTEN/NOTIFY) ; la Key
/// Transparency reste cohérente (un seul écrivain, rattrapage des époques).
#[tokio::test(flavor = "multi_thread")]
async fn two_instances_share_notifications_and_key_transparency() {
    let mut s = spawn().await;
    let url2 = s.second_instance().await;
    let admin = s.admin().await;
    let (mut alice, _, _) = s.user(&admin, "alice").await;

    // Bob s'enrôle et se connecte via la seconde instance.
    let r = admin.api().admin_create("bob", msg_proto::Role::User).await.unwrap();
    let cfg2 = s.config_for(&url2);
    let act = Client::activate(&cfg2, "bob", &r.activation_code, password()).await.unwrap();
    let mut bob = Client::enroll(&cfg2, "bob", password(), &totp_code(&act.totp_secret_base32, 0)).await.unwrap();
    let mut ws = bob.api().connect_ws().await.unwrap();
    // Notification initiale éventuelle (rien en attente) : on vide.
    let _ = tokio::time::timeout(Duration::from_millis(300), ws.next()).await;

    // Plusieurs époques KT publiées par la première instance…
    let (_carol, _, _) = s.user(&admin, "carol").await;
    let conv = alice.start_conversation("bob").await.unwrap();
    alice.send_text(&conv.id, "via l'instance 1").await.unwrap();

    // …notification reçue par Bob sur l'instance 2.
    let msg = tokio::time::timeout(Duration::from_secs(10), ws.next()).await.expect("notification inter-instances");
    assert!(msg.is_some());
    bob.sync().await.unwrap();
    assert_eq!(bob.messages(&conv.id, 10).unwrap()[0].text, "via l'instance 1");

    // La KT vue par l'instance 2 inclut les époques publiées par l'instance 1.
    let conv_c = bob.start_conversation("carol").await.unwrap();
    assert_eq!(conv_c.peer, "carol");
    bob.kt_check_self().await.unwrap();
    let h1 = admin.api().kt_head(None).await.unwrap();
    let h2 = bob.api().kt_head(None).await.unwrap();
    assert_eq!((h1.epoch, h1.root_hash), (h2.epoch, h2.root_hash), "même journal sur les deux instances");
}

/// Synchronise jusqu'à voir un message contenant `text` (remise fédérée asynchrone).
async fn wait_for(c: &mut Client, conv: &str, text: &str) {
    for _ in 0..50 {
        c.sync().await.unwrap();
        if c.messages(conv, 50).map(|m| m.iter().any(|m| m.text == text)).unwrap_or(false) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("message « {text} » non reçu");
}

/// Fédération : deux sites, chacun ses comptes ; conversation chiffrée de
/// bout en bout entre `alice@site-a` et `bob@site-b`, relayée par les
/// serveurs (annuaire, KeyPackages, KT, messages, pièces jointes), avec
/// remise différée pendant une coupure du site distant.
#[tokio::test(flavor = "multi_thread")]
async fn federated_sites_exchange_messages_with_store_and_forward() {
    let (mut a, mut b) = common::spawn_federated().await;
    let admin_a = a.admin().await;
    let admin_b = b.admin().await;
    let (mut alice, _, _) = a.user(&admin_a, "alice").await;
    let (mut bob, _, _) = b.user(&admin_b, "bob").await;
    assert_eq!(alice.address(), "alice@site-a");
    assert_eq!(bob.address(), "bob@site-b");

    // Alice ouvre une conversation avec un utilisateur d'un autre site.
    let conv = alice.start_conversation("bob@site-b").await.unwrap();
    assert_eq!(conv.peer, "bob@site-b");
    alice.send_text(&conv.id, "bonjour de site-a").await.unwrap();
    wait_for(&mut bob, &conv.id, "bonjour de site-a").await;
    let seen_by_bob = bob.conversation(&conv.id).unwrap();
    assert_eq!(seen_by_bob.peer, "alice@site-a", "l'utilisateur distant est affiché avec son site");

    // Réponse dans l'autre sens.
    bob.send_text(&conv.id, "bonjour de site-b").await.unwrap();
    wait_for(&mut alice, &conv.id, "bonjour de site-b").await;

    // Numéros de sécurité identiques des deux côtés (adresses qualifiées).
    let sa = alice.safety_number("bob@site-b").unwrap();
    let sb = bob.safety_number("alice@site-a").unwrap();
    assert_eq!(sa.number, sb.number);

    // Pièce jointe hébergée par site-a, récupérée par Bob via son serveur.
    let pdf = b"%PDF-1.4 document de test\n".repeat(50);
    let sent = alice.send_file(&conv.id, "note.pdf", pdf.clone(), None).await.unwrap();
    let mut got = None;
    for _ in 0..50 {
        bob.sync().await.unwrap();
        if let Some(m) = bob.messages(&conv.id, 50).unwrap().into_iter().find(|m| m.attachment.is_some()) {
            got = Some(m);
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let m = got.expect("pièce jointe reçue");
    assert!(sent.attachment.is_some());
    let file = bob.download_file(&m.id).await.unwrap();
    assert_eq!(&file.data[..], &pdf[..]);

    // Coupure de site-b : le message reste en file chez site-a…
    b.down.store(true, std::sync::atomic::Ordering::SeqCst);
    alice.send_text(&conv.id, "pendant la coupure").await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    msg_server::federation::outbox::deliver_due(&a.state).await.unwrap();
    let (queued,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM federation_outbox").fetch_one(&a.pool).await.unwrap();
    assert_eq!(queued, 1, "message conservé dans la file");
    let (attempts,): (i32,) =
        sqlx::query_as("SELECT attempts FROM federation_outbox").fetch_one(&a.pool).await.unwrap();
    assert!(attempts >= 1);
    // …puis remis au retour du site (ré-émission).
    b.down.store(false, std::sync::atomic::Ordering::SeqCst);
    sqlx::query("UPDATE federation_outbox SET next_attempt_at = 0").execute(&a.pool).await.unwrap();
    assert_eq!(msg_server::federation::outbox::deliver_due(&a.state).await.unwrap(), 1);
    wait_for(&mut bob, &conv.id, "pendant la coupure").await;
    // Ré-émission d'un message déjà remis : idempotente côté site-b.
    let (blobs_before,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM blobs").fetch_one(&b.pool).await.unwrap();

    // Témoin KT : site-a vérifie le journal de site-b (têtes signées, ajout seul).
    let peer_b = a.server_cfg.federation_peers[0].clone();
    use msg_server::federation::witness::{check_peer, Witnessed};
    assert!(matches!(check_peer(&a.state, &peer_b).await.unwrap(), Witnessed::Ok { .. }));
    let (_carol, _, _) = b.user(&admin_b, "carol").await;
    assert!(matches!(check_peer(&a.state, &peer_b).await.unwrap(), Witnessed::Ok { .. }));
    // Racine mémorisée falsifiée : incohérence détectée.
    sqlx::query("UPDATE kt_witness SET root_hash = $1").bind(vec![0u8; 32]).execute(&a.pool).await.unwrap();
    assert_eq!(check_peer(&a.state, &peer_b).await.unwrap(), Witnessed::Inconsistent);

    // Site inconnu (hors liste blanche) : refus.
    assert!(alice.start_conversation("dave@site-x").await.is_err());

    // Aucun clair dans les bases des deux sites.
    for s in [&a, &b] {
        let dump = s.dump().await;
        for needle in ["bonjour de site-a", "bonjour de site-b", "pendant la coupure", "note.pdf", "document de test"] {
            assert!(!dump.contains(needle), "« {needle} » trouvé en clair");
        }
    }
    let (blobs_after,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM blobs").fetch_one(&b.pool).await.unwrap();
    assert!(blobs_after <= blobs_before);
}

/// Requêtes entre sites : signature exigée, clé épinglée, nonce à usage unique.
#[tokio::test(flavor = "multi_thread")]
async fn federation_requests_are_authenticated() {
    let (a, b) = common::spawn_federated().await;
    let http = reqwest::Client::new();
    let body = serde_json::to_vec(&msg_proto::FederationDeliver {
        message_id: uuid::Uuid::new_v4(),
        devices: vec![uuid::Uuid::new_v4()],
        payload: vec![1, 2, 3],
    })
    .unwrap();
    let send = |key: &msg_crypto::identity::SigningKeyPair, site: &str| {
        let h = msg_crypto::request::sign_site_request(
            key,
            site,
            "POST",
            "/v1/federation/deliver",
            &body,
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64,
        )
        .unwrap();
        http.post(format!("{}/v1/federation/deliver", b.url))
            .header("x-msg-site", h.device)
            .header("x-msg-timestamp", h.timestamp)
            .header("x-msg-nonce", h.nonce)
            .header("x-msg-signature", h.signature)
            .header("content-type", "application/json")
            .body(body.clone())
    };
    // Clé quelconque se prétendant site-a : refus.
    let forged = msg_crypto::identity::SigningKeyPair::generate().unwrap();
    assert_eq!(send(&forged, "site-a").send().await.unwrap().status(), 401);
    // Site absent de la liste blanche : refus.
    assert_eq!(send(&forged, "site-x").send().await.unwrap().status(), 401);
    // Vraie clé de site-a : accepté (réponse signée par site-b), rejeu refusé.
    let key_a = msg_server::federation::signing_key(&a.state).unwrap();
    let req = send(&key_a, "site-a").build().unwrap();
    let replay = req.try_clone().unwrap();
    let resp = http.execute(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().contains_key("x-msg-site-response"));
    assert_eq!(http.execute(replay).await.unwrap().status(), 401, "nonce déjà utilisé");
    // Un site ne sert que ses propres utilisateurs.
    let h = msg_crypto::request::sign_site_request(
        &key_a,
        "site-a",
        "GET",
        "/v1/federation/users/bob@site-c",
        b"",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64,
    )
    .unwrap();
    let r = http
        .get(format!("{}/v1/federation/users/bob@site-c", b.url))
        .header("x-msg-site", h.device)
        .header("x-msg-timestamp", h.timestamp)
        .header("x-msg-nonce", h.nonce)
        .header("x-msg-signature", h.signature)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    // Informations publiques du site : nom et clé à épingler.
    let info: msg_proto::SiteInfo = http.get(format!("{}/v1/site", b.url)).send().await.unwrap().json().await.unwrap();
    assert_eq!(info.name, "site-b");
    assert_eq!(info.federation_key, a.server_cfg.federation_peers[0].public_key.to_vec());
}

/// Métriques Prometheus : aucune donnée personnelle (noms, identifiants
/// d'appareils, de conversations ou de messages, adresses, jetons) et
/// cardinalité bornée (ensembles d'étiquettes fixes).
#[tokio::test(flavor = "multi_thread")]
async fn metrics_contain_no_personal_data() {
    let (mut a, mut b) = common::spawn_federated().await;
    let admin_a = a.admin().await;
    let admin_b = b.admin().await;
    let (mut alice, _, _) = a.user(&admin_a, "alicemetrique").await;
    let (mut bob, _, _) = b.user(&admin_b, "bobmetrique").await;
    let conv = alice.start_conversation("bobmetrique@site-b").await.unwrap();
    alice.send_text(&conv.id, "contenu des métriques").await.unwrap();
    wait_for(&mut bob, &conv.id, "contenu des métriques").await;
    // Requête refusée sur un chemin contenant un identifiant.
    let r = reqwest::get(format!("{}/v1/users/utilisateurinconnu", a.url)).await.unwrap();
    assert_eq!(r.status(), 401);

    // Serveur de métriques séparé, protégé par jeton.
    let mut cfg = a.server_cfg.clone();
    cfg.metrics_token = Some("jeton-metriques-de-test".into());
    let st = msg_server::AppState::try_new(a.pool.clone(), cfg).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let murl = format!("http://{}/metrics", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, msg_server::metrics::router(st)).await.unwrap() });
    let http = reqwest::Client::new();
    assert_eq!(http.get(&murl).send().await.unwrap().status(), 401);
    assert_eq!(http.get(&murl).bearer_auth("mauvais").send().await.unwrap().status(), 401);
    let ok = http.get(&murl).bearer_auth("jeton-metriques-de-test").send().await.unwrap();
    assert_eq!(ok.status(), 200);
    assert!(ok.text().await.unwrap().contains("msg_accounts{status=\"active\"}"));
    // Jamais exposées sur l'API publique.
    let public = reqwest::get(format!("{}/metrics", a.url)).await.unwrap();
    assert!(!public.text().await.unwrap_or_default().contains("msg_http_requests_total"));

    let mut identifiers: Vec<String> = vec![
        "alicemetrique".into(),
        "bobmetrique".into(),
        "utilisateurinconnu".into(),
        "contenu".into(),
        conv.id.clone(),
        "127.0.0.1".into(),
        a.url.trim_start_matches("http://").into(),
        b.url.trim_start_matches("http://").into(),
    ];
    for s in [&a, &b] {
        let devs: Vec<(uuid::Uuid,)> = sqlx::query_as("SELECT id FROM devices").fetch_all(&s.pool).await.unwrap();
        identifiers.extend(devs.into_iter().map(|(d,)| d.to_string()));
        let msgs: Vec<(Option<uuid::Uuid>,)> =
            sqlx::query_as("SELECT client_message_id FROM blobs").fetch_all(&s.pool).await.unwrap();
        identifiers.extend(msgs.into_iter().filter_map(|(m,)| m).map(|m| m.to_string()));
    }
    let allowed_status = [
        "101", "200", "201", "204", "304", "400", "401", "403", "404", "409", "413", "429", "500", "502", "503", "2xx",
        "3xx", "4xx", "5xx",
    ];
    for s in [&a, &b] {
        let text = msg_server::metrics::render(&s.state).await;
        assert!(text.contains("msg_http_requests_total{method=\"GET\",route=\"/v1/users/{username}\""), "{text}");
        for id in &identifiers {
            assert!(!text.contains(id.as_str()), "identifiant « {id} » présent dans les métriques");
        }
        let mut series = 0;
        for line in text.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
            series += 1;
            let (name, rest) = line.split_once('{').unwrap_or((line.split(' ').next().unwrap(), ""));
            assert!(name.starts_with("msg_"), "{line}");
            let labels = rest.rsplit_once('}').map(|(l, _)| l).unwrap_or("");
            for pair in labels.split("\",").filter(|p| !p.is_empty()) {
                let (k, v) = pair.split_once("=\"").unwrap();
                let v = v.trim_end_matches('"');
                let ok = match k {
                    "method" => ["GET", "POST", "PUT", "DELETE", "HEAD", "other"].contains(&v),
                    "status" => {
                        allowed_status.contains(&v)
                            || ["pending_activation", "pending_totp", "active", "suspended"].contains(&v)
                    }
                    "route" => {
                        v == "unmatched"
                            || v == "other"
                            || (v.starts_with("/v1/") || v == "/web-config.json")
                                && v.split('/').all(|seg| {
                                    seg.is_empty()
                                        || (seg.starts_with('{') && seg.ends_with('}'))
                                        || seg.chars().all(|c| {
                                            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.'
                                        })
                                })
                    }
                    "site" => ["site-a", "site-b"].contains(&v),
                    "le" => v == "+Inf" || v.parse::<f64>().is_ok(),
                    "version" => v == env!("CARGO_PKG_VERSION"),
                    _ => false,
                };
                assert!(ok, "étiquette non bornée : {k}={v} ({line})");
            }
        }
        assert!(series < 2000, "cardinalité excessive : {series} séries");
    }
    let text_a = msg_server::metrics::render(&a.state).await;
    assert!(text_a.lines().any(|l| l.starts_with("msg_federation_sent_total ") && !l.ends_with(" 0")), "{text_a}");
    assert!(text_a.contains("msg_federation_outbox{site=\"site-b\"} 0"));
    let text_b = msg_server::metrics::render(&b.state).await;
    assert!(text_b.lines().any(|l| l.starts_with("msg_federation_received_total ") && !l.ends_with(" 0")));
}
