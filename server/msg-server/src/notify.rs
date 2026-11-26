//! Notifications « nouveaux messages » entre instances du serveur.
//!
//! Chaque distribution est signalée par `pg_notify` sur un canal PostgreSQL
//! écouté par toutes les instances ; chacune relaie le signal à ses
//! WebSocket locaux. Le signal ne contient que l'identifiant de l'appareil
//! destinataire (jamais de contenu). Si l'écoute est interrompue, toutes les
//! connexions locales sont invitées à se synchroniser (signal « tous »).

use std::time::Duration;

use sqlx::postgres::PgListener;
use uuid::Uuid;

use crate::state::AppState;

/// Canal PostgreSQL des notifications.
pub const CHANNEL: &str = "msg_deliveries";

/// Signal adressé à toutes les connexions (reprise après coupure).
pub const EVERYONE: Uuid = Uuid::nil();

/// Signale de nouvelles distributions à toutes les instances.
pub async fn deliveries(st: &AppState, devices: &[Uuid]) {
    if devices.is_empty() {
        return;
    }
    // Plusieurs identifiants par notification (charge utile < 8 000 octets).
    for chunk in devices.chunks(200) {
        let payload = chunk.iter().map(Uuid::to_string).collect::<Vec<_>>().join(",");
        if let Err(e) = sqlx::query("SELECT pg_notify($1, $2)").bind(CHANNEL).bind(payload).execute(st.db()).await {
            // Repli local : au moins les connexions de cette instance.
            tracing::warn!(error = %e, "pg_notify indisponible");
            for d in chunk {
                let _ = st.inner.hub.send(*d);
            }
        }
    }
}

/// Écoute le canal et relaie vers les connexions de cette instance
/// (reconnexion avec attente exponentielle).
pub fn spawn_listener(st: AppState) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else { return };
    handle.spawn(async move {
        let mut backoff = 1u64;
        loop {
            match PgListener::connect_with(st.db()).await {
                Ok(mut l) => match l.listen(CHANNEL).await {
                    Ok(()) => {
                        backoff = 1;
                        // Notifications éventuellement manquées pendant la coupure.
                        let _ = st.inner.hub.send(EVERYONE);
                        loop {
                            match l.recv().await {
                                Ok(n) => {
                                    for id in n.payload().split(',').filter_map(|s| s.parse::<Uuid>().ok()) {
                                        let _ = st.inner.hub.send(id);
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "écoute des notifications interrompue");
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, "LISTEN impossible"),
                },
                Err(e) => tracing::warn!(error = %e, "connexion d'écoute impossible"),
            }
            tokio::time::sleep(Duration::from_secs(backoff)).await;
            backoff = (backoff * 2).min(30);
        }
    });
}
