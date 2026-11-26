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
    let h1 = admin.api().kt_head().await.unwrap();
    let h2 = bob.api().kt_head().await.unwrap();
    assert_eq!((h1.epoch, h1.root_hash), (h2.epoch, h2.root_hash), "même journal sur les deux instances");
}
