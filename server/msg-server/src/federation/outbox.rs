//! File persistante (store-and-forward) des messages destinés à d'autres
//! sites : ré-émission avec attente exponentielle (plafonnée à une heure),
//! suppression à l'accusé de réception signé ou après la rétention maximale.

use msg_proto::{FederationAck, FederationDeliver, FEDERATION_RETENTION_SECS};
use uuid::Uuid;

use super::peer;
use crate::error::AppResult;
use crate::state::AppState;

/// Bail pendant lequel une instance traite une entrée (les autres l'ignorent).
const LEASE_SECS: i64 = 120;
/// Attente maximale entre deux tentatives.
const MAX_BACKOFF_SECS: i64 = 3600;

/// Met en file un message pour un site pair, puis tente la remise aussitôt.
pub async fn enqueue(st: &AppState, site: &str, message_id: Uuid, devices: &[Uuid], payload: &[u8]) -> AppResult<()> {
    let now = crate::now();
    sqlx::query(
        "INSERT INTO federation_outbox (site, message_id, devices, payload, next_attempt_at, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $5, $6) ON CONFLICT (site, message_id) DO NOTHING",
    )
    .bind(site)
    .bind(message_id)
    .bind(devices)
    .bind(payload)
    .bind(now)
    .bind(now + FEDERATION_RETENTION_SECS)
    .execute(st.db())
    .await?;
    let st = st.clone();
    tokio::spawn(async move {
        if let Err(e) = deliver_due(&st).await {
            tracing::warn!(error = %e.message, "remise fédérée différée");
        }
    });
    Ok(())
}

/// (id, site, message, appareils, blob chiffré, tentatives)
type OutboxRow = (i64, String, Uuid, Vec<Uuid>, Vec<u8>, i32);

/// Remet les messages dont l'échéance est atteinte. Renvoie le nombre de
/// messages remis.
pub async fn deliver_due(st: &AppState) -> AppResult<usize> {
    let now = crate::now();
    let expired =
        sqlx::query("DELETE FROM federation_outbox WHERE expires_at <= $1").bind(now).execute(st.db()).await?;
    if expired.rows_affected() > 0 {
        tracing::warn!(nombre = expired.rows_affected(), "messages fédérés expirés sans accusé de réception");
    }
    // Prise de bail atomique : plusieurs instances peuvent traiter la file.
    let rows: Vec<OutboxRow> = sqlx::query_as(
        "UPDATE federation_outbox SET next_attempt_at = $2
          WHERE id IN (SELECT id FROM federation_outbox WHERE next_attempt_at <= $1
                        ORDER BY next_attempt_at LIMIT 50 FOR UPDATE SKIP LOCKED)
          RETURNING id, site, message_id, devices, payload, attempts",
    )
    .bind(now)
    .bind(now + LEASE_SECS)
    .fetch_all(st.db())
    .await?;
    let mut delivered = 0;
    for (id, site, message_id, devices, payload, attempts) in rows {
        let result = match peer(st, &site) {
            Ok(p) => {
                let req = FederationDeliver { message_id, devices, payload };
                super::client::post_json::<_, FederationAck>(st, &p, "/v1/federation/deliver", &req).await
            }
            Err(e) => Err(e),
        };
        match result {
            Ok(ack) if ack.message_id == message_id => {
                sqlx::query("DELETE FROM federation_outbox WHERE id = $1").bind(id).execute(st.db()).await?;
                delivered += 1;
                st.inner.metrics.federation_sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            _ => {
                st.inner.metrics.federation_send_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let wait = (1i64 << attempts.clamp(0, 12)).min(MAX_BACKOFF_SECS);
                sqlx::query("UPDATE federation_outbox SET attempts = attempts + 1, next_attempt_at = $2 WHERE id = $1")
                    .bind(id)
                    .bind(crate::now() + wait)
                    .execute(st.db())
                    .await?;
            }
        }
    }
    Ok(delivered)
}
