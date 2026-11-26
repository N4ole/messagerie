//! Service de distribution : files de blobs chiffrés par appareil.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use msg_proto::{AckRequest, ErrorCode, QueueResponse, QueuedMessage, SendRequest, SendResponse, MAX_PAYLOAD_BYTES};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::AuthContext;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

const MAX_RECIPIENTS: usize = 1000;

pub async fn send(
    State(st): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Json(req): Json<SendRequest>,
) -> AppResult<Json<SendResponse>> {
    let now = crate::now();
    if !st.allow_send(ctx.device_id, now) {
        return Err(AppError::new(StatusCode::TOO_MANY_REQUESTS, ErrorCode::RateLimited, "trop d'envois"));
    }
    if req.payload.is_empty() || req.payload.len() > MAX_PAYLOAD_BYTES {
        return Err(AppError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::PayloadTooLarge,
            "message trop volumineux",
        ));
    }
    let mut recipients = req.recipients.clone();
    recipients.sort();
    recipients.dedup();
    if recipients.is_empty() || recipients.len() > MAX_RECIPIENTS {
        return Err(AppError::bad_request("destinataires invalides"));
    }
    let mut tx = st.db().begin().await?;
    // Les appareils révoqués (encore membres d'un groupe jusqu'au commit de
    // retrait) sont ignorés : leur révocation ne doit pas bloquer les envois.
    let known: Vec<(Uuid,)> =
        sqlx::query_as("SELECT id FROM devices WHERE id = ANY($1)").bind(&recipients).fetch_all(&mut *tx).await?;
    let recipients: Vec<Uuid> = known.into_iter().map(|(d,)| d).collect();
    if recipients.is_empty() {
        return Err(AppError::bad_request("appareil destinataire inconnu"));
    }
    let blob: Option<(i64,)> = sqlx::query_as(
        "INSERT INTO blobs (sender_device, client_message_id, payload, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT (sender_device, client_message_id) DO NOTHING RETURNING id",
    )
    .bind(ctx.device_id)
    .bind(req.client_message_id)
    .bind(&req.payload)
    .bind(now)
    .bind(now + st.cfg().blob_retention_secs)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((blob_id,)) = blob else {
        // Renvoi idempotent d'un message déjà accepté.
        return Ok(Json(SendResponse { accepted: recipients.len() }));
    };
    sqlx::query(
        "INSERT INTO deliveries (blob_id, device_id, created_at) SELECT $1, r, $3 FROM UNNEST($2::uuid[]) AS r",
    )
    .bind(blob_id)
    .bind(&recipients)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    crate::notify::deliveries(&st, &recipients).await;
    Ok(Json(SendResponse { accepted: recipients.len() }))
}

#[derive(Deserialize)]
pub struct QueueParams {
    pub limit: Option<i64>,
}

pub async fn queue(
    State(st): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Query(p): Query<QueueParams>,
) -> AppResult<Json<QueueResponse>> {
    let limit = p.limit.unwrap_or(50).clamp(1, 100);
    let rows: Vec<(i64, i64, Vec<u8>)> = sqlx::query_as(
        "SELECT d.id, d.created_at, b.payload FROM deliveries d JOIN blobs b ON b.id = d.blob_id
          WHERE d.device_id = $1 ORDER BY d.id LIMIT $2",
    )
    .bind(ctx.device_id)
    .bind(limit)
    .fetch_all(st.db())
    .await?;
    Ok(Json(QueueResponse {
        messages: rows
            .into_iter()
            .map(|(id, received_at, payload)| QueuedMessage { id, received_at, payload })
            .collect(),
    }))
}

/// Accusé de réception : la livraison est supprimée, puis le blob s'il n'a
/// plus aucun destinataire en attente.
pub async fn ack(
    State(st): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Json(req): Json<AckRequest>,
) -> AppResult<StatusCode> {
    if req.ids.len() > 1000 {
        return Err(AppError::bad_request("trop d'accusés"));
    }
    let mut tx = st.db().begin().await?;
    let blobs: Vec<(i64,)> =
        sqlx::query_as("DELETE FROM deliveries WHERE device_id = $1 AND id = ANY($2) RETURNING blob_id")
            .bind(ctx.device_id)
            .bind(&req.ids)
            .fetch_all(&mut *tx)
            .await?;
    let ids: Vec<i64> = blobs.into_iter().map(|(b,)| b).collect();
    sqlx::query(
        "DELETE FROM blobs b WHERE b.id = ANY($1) AND NOT EXISTS (SELECT 1 FROM deliveries d WHERE d.blob_id = b.id)",
    )
    .bind(&ids)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Utilisé par le WebSocket : y a-t-il des messages en attente ?
pub async fn has_pending(st: &AppState, device: Uuid) -> Result<bool, sqlx::Error> {
    let (b,): (bool,) = sqlx::query_as("SELECT EXISTS (SELECT 1 FROM deliveries WHERE device_id = $1)")
        .bind(device)
        .fetch_one(st.db())
        .await?;
    Ok(b)
}
