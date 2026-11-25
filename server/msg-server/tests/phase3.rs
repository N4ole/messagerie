//! Phase 3 : appareils multiples, révocation et Key Transparency, avec un
//! serveur réel (PostgreSQL) et des clients réels.

mod common;

use common::{password, spawn, totp_code};
use msg_client_core::{Client, ClientError, LinkOutcome};

/// Lie un nouvel appareil au compte `username` (approuvé par `primary`).
async fn link(
    s: &mut common::TestServer,
    primary: &Client,
    username: &str,
    totp: &str,
    step: i64,
) -> (Client, msg_client_core::ClientConfig) {
    // Anti-rejeu TOTP : un pas déjà utilisé est refusé ; le test « avance
    // l'horloge » en oubliant le dernier pas consommé.
    sqlx::query("UPDATE accounts SET totp_last_step = NULL WHERE username = $1")
        .bind(username)
        .execute(&s.pool)
        .await
        .unwrap();
    let cfg = s.config();
    let pending = Client::link_start(&cfg, username, password(), &totp_code(totp, step)).await.unwrap();
    assert!(matches!(pending.poll().await.unwrap(), LinkOutcome::Pending));
    let reqs = primary.link_requests().await.unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].fingerprint, pending.fingerprint(), "même empreinte des deux côtés");
    primary.approve_link(&pending.code()).await.unwrap();
    match pending.poll().await.unwrap() {
        LinkOutcome::Linked(c) => (*c, cfg),
        _ => panic!("liaison non aboutie"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn linked_device_joins_conversations_and_revocation_removes_it() {
    let mut s = spawn().await;
    let admin = s.admin().await;
    let (mut alice, _, alice_totp) = s.user(&admin, "alice").await;
    let (mut bob, _, _) = s.user(&admin, "bob").await;
    let conv = alice.start_conversation("bob").await.unwrap();
    alice.send_text(&conv.id, "avant la liaison").await.unwrap();
    bob.sync().await.unwrap();

    // Un code dont l'empreinte ne correspond pas est refusé (substitution
    // de clés par le serveur ou erreur de saisie).
    let cfg_x = s.config();
    let pending = Client::link_start(&cfg_x, "alice", password(), &totp_code(&alice_totp, 1)).await.unwrap();
    let mut forged = pending.code();
    let last = forged.pop().unwrap();
    forged.push(if last == '0' { '1' } else { '0' });
    assert!(matches!(alice.approve_link(&forged).await, Err(ClientError::Verification(..))));
    let reqs = alice.link_requests().await.unwrap();
    alice.reject_link(reqs[0].link_id).await.unwrap();
    assert!(matches!(pending.poll().await.unwrap(), LinkOutcome::Rejected));
    drop(pending);

    // Liaison d'un second appareil (le « client web » d'Alice).
    let (mut alice2, alice2_cfg) = link(&mut s, &alice, "alice", &alice_totp, -1).await;
    assert!(!alice2.is_primary());
    assert_eq!(alice2.identity_fingerprint(), alice.identity_fingerprint());
    assert_eq!(alice.devices().await.unwrap().len(), 2);
    // Un appareil secondaire ne peut ni approuver ni administrer.
    assert!(matches!(alice2.approve_link("messagerie-link:1:x").await, Err(ClientError::NotPrimaryDevice)));

    // L'appareil principal (administrateur de la conversation) ajoute le
    // nouvel appareil à la conversation existante.
    assert_eq!(alice.reconcile_now().await.unwrap(), 1);
    alice2.sync().await.unwrap();
    bob.sync().await.unwrap();
    let c2 = alice2.conversations().unwrap();
    assert_eq!(c2.len(), 1);
    assert_eq!(c2[0].peer, "bob");
    assert_eq!(c2[0].admin.as_deref(), Some("alice"));
    assert!(alice2.messages(&conv.id, 10).unwrap().is_empty(), "pas d'historique antérieur à la liaison");

    // Bob écrit : les deux appareils d'Alice lisent.
    bob.send_text(&conv.id, "bonjour aux deux").await.unwrap();
    alice.sync().await.unwrap();
    alice2.sync().await.unwrap();
    assert_eq!(alice2.messages(&conv.id, 10).unwrap()[0].text, "bonjour aux deux");
    // Alice écrit depuis le second appareil : Bob et le premier appareil lisent.
    alice2.send_text(&conv.id, "depuis le web").await.unwrap();
    bob.sync().await.unwrap();
    alice.sync().await.unwrap();
    assert!(bob.messages(&conv.id, 10).unwrap().iter().any(|m| m.text == "depuis le web" && !m.outgoing));
    let mine = alice.messages(&conv.id, 10).unwrap();
    let m = mine.iter().find(|m| m.text == "depuis le web").unwrap();
    assert!(m.outgoing, "message de mon autre appareil affiché comme envoyé");

    // Une nouvelle conversation inclut d'emblée les deux appareils d'Alice.
    let (mut carol, _, _) = s.user(&admin, "carol").await;
    let conv_c = carol.start_conversation("alice").await.unwrap();
    carol.send_text(&conv_c.id, "pour alice").await.unwrap();
    alice.sync().await.unwrap();
    alice2.sync().await.unwrap();
    assert_eq!(alice2.messages(&conv_c.id, 10).unwrap()[0].text, "pour alice");

    // Révocation du second appareil depuis le premier.
    let id2 = alice2.device_id();
    alice.revoke_device(id2).await.unwrap();
    assert_eq!(alice.devices().await.unwrap().len(), 1);
    // Carol (administratrice de sa conversation) retire l'appareil révoqué
    // lors de sa synchronisation ; Bob applique le commit d'Alice.
    assert_eq!(carol.sync().await.unwrap().reconciled, 1);
    bob.sync().await.unwrap();
    assert!(!bob.member_devices(&conv.id).unwrap().iter().any(|(_, d)| *d == id2));
    assert!(!carol.member_devices(&conv_c.id).unwrap().iter().any(|(_, d)| *d == id2));
    assert_eq!(bob.member_devices(&conv.id).unwrap().len(), 2);
    // Les envois continuent sans erreur et ne sont plus distribués au révoqué.
    bob.send_text(&conv.id, "après révocation").await.unwrap();
    carol.send_text(&conv_c.id, "après révocation").await.unwrap();
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM deliveries WHERE device_id = $1")
        .bind(id2)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
    alice.sync().await.unwrap();
    assert!(alice.messages(&conv.id, 10).unwrap().iter().any(|m| m.text == "après révocation"));

    // L'appareil révoqué l'apprend et efface ses données locales.
    let err = alice2.sync().await.unwrap_err();
    assert!(err.is_device_revoked(), "{err:?}");
    drop(alice2);
    Client::wipe_local(&alice2_cfg, "alice").unwrap();
    assert!(matches!(Client::login(&alice2_cfg, "alice", password(), None).await, Err(ClientError::NoLocalAccount)));
}

/// Key Transparency : un serveur qui modifie l'annuaire sans le publier, ou
/// qui publie une autre clé d'identité, est détecté.
#[tokio::test(flavor = "multi_thread")]
async fn key_transparency_detects_unpublished_and_substituted_keys() {
    let mut s = spawn().await;
    let admin = s.admin().await;
    let (mut alice, _, _) = s.user(&admin, "alice").await;
    let (bob, _, _) = s.user(&admin, "bob").await;
    let (mut carol, _, _) = s.user(&admin, "carol").await;
    alice.start_conversation("bob").await.unwrap();

    // Une nouvelle instance (même secret) rejoue le journal à l'identique.
    let head = admin.api().kt_head().await.unwrap();
    let restarted = msg_server::AppState::try_new(s.pool.clone(), s.server_cfg.clone()).unwrap();
    let replayed = msg_server::kt::head(&restarted).await.unwrap();
    assert_eq!((replayed.epoch, replayed.root_hash), (head.epoch, head.root_hash.clone()));
    // Autre secret serveur ⇒ autre clé VRF ⇒ rejeu refusé (racines différentes).
    let mut other = s.server_cfg.clone();
    other.server_secret = zeroize::Zeroizing::new([9u8; 32]);
    assert!(msg_server::kt::head(&msg_server::AppState::try_new(s.pool.clone(), other).unwrap()).await.is_err());

    // Le serveur (ou sa base) remplace la clé d'identité de Bob sans publier.
    let fake = msg_crypto::identity::SigningKeyPair::generate().unwrap();
    sqlx::query("UPDATE accounts SET identity_key = $1 WHERE username = 'bob'")
        .bind(fake.public_bytes().to_vec())
        .execute(&s.pool)
        .await
        .unwrap();
    let err = carol.start_conversation("bob").await.unwrap_err();
    assert!(matches!(err, ClientError::KeyTransparency(_)), "{err:?}");

    // S'il publie la fausse clé, la preuve est valide… mais Bob, en
    // vérifiant sa propre entrée, détecte la substitution.
    sqlx::query("INSERT INTO kt_dirty (username) VALUES ('bob')").execute(&s.pool).await.unwrap();
    let err = bob.kt_check_self().await.unwrap_err();
    assert!(matches!(err, ClientError::KeyTransparency(_)), "{err:?}");
    // Alice, qui connaissait l'ancienne clé, constate le changement d'identité.
    let err = alice.create_group("équipe", &["bob".into()]).await.unwrap_err();
    assert!(matches!(err, ClientError::IdentityChanged(_)), "{err:?}");

    // Le journal a avancé de façon vérifiable (preuves d'ajout seul).
    let head2 = admin.api().kt_head().await.unwrap();
    assert!(head2.epoch > head.epoch);
    let audit = admin.api().kt_audit(head.epoch, head2.epoch).await.unwrap();
    assert_eq!(msg_kt::verify_audit(&head.root_hash, &audit).await.unwrap(), head2.root_hash);

    // Une base dont le journal a été altéré n'est pas servie.
    sqlx::query("UPDATE kt_log SET root_hash = $1 WHERE epoch = 1").bind(vec![0u8; 32]).execute(&s.pool).await.unwrap();
    let st3 = msg_server::AppState::try_new(s.pool.clone(), s.server_cfg.clone()).unwrap();
    assert!(msg_server::kt::head(&st3).await.is_err());
}
