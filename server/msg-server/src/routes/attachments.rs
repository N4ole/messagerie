//! Stockage des pièces jointes chiffrées. L'identifiant aléatoire (128 bits)
//! sert de capacité : seul un destinataire du message MLS le connaît.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::{Extension, Json};
use msg_proto::{AttachmentUploadResponse, ErrorCode, MAX_ATTACHMENT_BLOB_BYTES};
use uuid::Uuid;

use crate::auth::AuthContext;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

pub async fn upload(
    State(st): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    body: Bytes,
) -> AppResult<Json<AttachmentUploadResponse>> {
    if body.len() < 40 || body.len() > MAX_ATTACHMENT_BLOB_BYTES {
        return Err(AppError::new(StatusCode::PAYLOAD_TOO_LARGE, ErrorCode::PayloadTooLarge, "pièce jointe invalide"));
    }
    let now = crate::now();
    let mut tx = st.db().begin().await?;
    let (used,): (Option<i64>,) = sqlx::query_as("SELECT SUM(size)::BIGINT FROM attachments WHERE owner_device = $1")
        .bind(ctx.device_id)
        .fetch_one(&mut *tx)
        .await?;
    if used.unwrap_or(0) + body.len() as i64 > st.cfg().attachment_quota_bytes {
        return Err(AppError::new(
            StatusCode::INSUFFICIENT_STORAGE,
            ErrorCode::RateLimited,
            "quota de pièces jointes atteint",
        ));
    }
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO attachments (id, owner_device, data, size, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(ctx.device_id)
    .bind(body.as_ref())
    .bind(body.len() as i64)
    .bind(now)
    .bind(now + st.cfg().attachment_retention_secs)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(AttachmentUploadResponse { blob_id: id }))
}

/// Pièce jointe chiffrée hébergée par ce site.
pub(crate) async fn load(st: &AppState, id: Uuid) -> AppResult<Vec<u8>> {
    let row: Option<(Vec<u8>,)> = sqlx::query_as("SELECT data FROM attachments WHERE id = $1 AND expires_at > $2")
        .bind(id)
        .bind(crate::now())
        .fetch_optional(st.db())
        .await?;
    Ok(row.ok_or_else(AppError::not_found)?.0)
}

#[derive(serde::Deserialize)]
pub struct DownloadQuery {
    /// Site qui héberge la pièce jointe (fédération) ; par défaut ce site.
    site: Option<String>,
}

pub async fn download(
    State(st): State<AppState>,
    Extension(_ctx): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Query(q): Query<DownloadQuery>,
) -> AppResult<impl IntoResponse> {
    let data = match q.site.as_deref().filter(|s| *s != st.cfg().site_name) {
        None => load(&st, id).await?,
        // Pièce jointe d'un expéditeur d'un autre site : relayée par ce serveur.
        Some(site) => {
            let peer = crate::federation::peer(&st, site)?;
            crate::federation::client::get_bytes(&st, &peer, &format!("/v1/federation/attachments/{id}")).await?
        }
    };
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], data))
}
