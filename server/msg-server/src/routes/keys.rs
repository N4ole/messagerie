//! Annuaire : KeyPackages MLS et appareils publiés.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use msg_proto::{
    KeyPackageCount, PublishedDevice, UploadKeyPackagesRequest, UserDirectoryEntry, MAX_KEY_PACKAGES_PER_UPLOAD,
};
use uuid::Uuid;

use crate::auth::AuthContext;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

const MAX_KEY_PACKAGE_BYTES: usize = 16 * 1024;
const MAX_STORED_PER_DEVICE: i64 = 200;

pub async fn upload(
    State(st): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Json(req): Json<UploadKeyPackagesRequest>,
) -> AppResult<StatusCode> {
    if req.key_packages.is_empty()
        || req.key_packages.len() > MAX_KEY_PACKAGES_PER_UPLOAD
        || req.key_packages.iter().any(|k| k.is_empty() || k.len() > MAX_KEY_PACKAGE_BYTES)
    {
        return Err(AppError::bad_request("KeyPackages invalides"));
    }
    let mut tx = st.db().begin().await?;
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM key_packages WHERE device_id = $1")
        .bind(ctx.device_id)
        .fetch_one(&mut *tx)
        .await?;
    if n + req.key_packages.len() as i64 > MAX_STORED_PER_DEVICE {
        return Err(AppError::conflict("trop de KeyPackages en réserve"));
    }
    sqlx::query(
        "INSERT INTO key_packages (device_id, data, created_at) SELECT $1, d, $3 FROM UNNEST($2::bytea[]) AS d",
    )
    .bind(ctx.device_id)
    .bind(&req.key_packages)
    .bind(crate::now())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn count(
    State(st): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
) -> AppResult<Json<KeyPackageCount>> {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM key_packages WHERE device_id = $1")
        .bind(ctx.device_id)
        .fetch_one(st.db())
        .await?;
    Ok(Json(KeyPackageCount { count }))
}

#[derive(sqlx::FromRow)]
struct DeviceRow {
    id: Uuid,
    api_key: Vec<u8>,
    mls_signature_key: Vec<u8>,
    cert_created_at: i64,
    cert_signature: Vec<u8>,
}

async fn load_user(st: &AppState, username: &str) -> AppResult<(Vec<u8>, Vec<DeviceRow>)> {
    let acc: Option<(i64, Option<Vec<u8>>)> =
        sqlx::query_as("SELECT id, identity_key FROM accounts WHERE username = $1 AND status = 'active'")
            .bind(username)
            .fetch_optional(st.db())
            .await?;
    let (id, identity) = acc.ok_or_else(AppError::not_found)?;
    let identity = identity.ok_or_else(AppError::not_found)?;
    let devices = sqlx::query_as::<_, DeviceRow>(
        "SELECT id, api_key, mls_signature_key, cert_created_at, cert_signature FROM devices WHERE account_id = $1 ORDER BY created_at",
    )
    .bind(id)
    .fetch_all(st.db())
    .await?;
    Ok((identity, devices))
}

fn publish(d: DeviceRow, key_package: Option<Vec<u8>>) -> PublishedDevice {
    PublishedDevice {
        device_id: d.id,
        api_key: d.api_key,
        mls_signature_key: d.mls_signature_key,
        cert_created_at: d.cert_created_at,
        cert_signature: d.cert_signature,
        key_package,
    }
}

/// Consultation de l'annuaire (sans consommer de KeyPackage).
pub async fn directory(
    State(st): State<AppState>,
    Extension(_ctx): Extension<AuthContext>,
    Path(username): Path<String>,
) -> AppResult<Json<UserDirectoryEntry>> {
    let (identity_key, devices) = load_user(&st, &username).await?;
    Ok(Json(UserDirectoryEntry {
        username,
        identity_key,
        devices: devices.into_iter().map(|d| publish(d, None)).collect(),
    }))
}

/// Réclame un KeyPackage par appareil de l'utilisateur. Chaque KeyPackage est
/// à usage unique et supprimé à la distribution, sauf le dernier (« dernier
/// recours », RFC 9420 §16.8) qui est conservé pour ne jamais bloquer
/// l'établissement d'une conversation.
pub async fn claim(
    State(st): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(username): Path<String>,
) -> AppResult<Json<UserDirectoryEntry>> {
    let (identity_key, devices) = load_user(&st, &username).await?;
    let mut out = Vec::with_capacity(devices.len());
    for d in devices {
        if d.id == ctx.device_id {
            continue;
        }
        let mut tx = st.db().begin().await?;
        let rows: Vec<(i64, Vec<u8>)> =
            sqlx::query_as("SELECT id, data FROM key_packages WHERE device_id = $1 ORDER BY id LIMIT 2 FOR UPDATE")
                .bind(d.id)
                .fetch_all(&mut *tx)
                .await?;
        let kp = match rows.as_slice() {
            [] => None,
            [(_, data)] => Some(data.clone()),
            [(id, data), ..] => {
                sqlx::query("DELETE FROM key_packages WHERE id = $1").bind(id).execute(&mut *tx).await?;
                Some(data.clone())
            }
        };
        tx.commit().await?;
        if kp.is_some() {
            out.push(publish(d, kp));
        }
    }
    if out.is_empty() {
        return Err(AppError::not_found());
    }
    Ok(Json(UserDirectoryEntry { username, identity_key, devices: out }))
}
