//! Authentification des requêtes : signature par la clé d'appareil (anti-rejeu)
//! puis jeton de session lié à cet appareil.

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use msg_proto::{headers, AccountStatus, ErrorCode, Role, REQUEST_MAX_SKEW_SECS};
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::passwords::token_hash;
use crate::state::AppState;

/// Taille maximale d'un corps de requête authentifiée.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Appareil dont la signature de requête a été vérifiée.
#[derive(Debug, Clone)]
pub struct SignedDevice {
    pub device_id: Uuid,
    pub account_id: i64,
    pub username: String,
    pub role: Role,
    pub status: AccountStatus,
}

/// Contexte d'une requête authentifiée (signature + session valide).
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub device_id: Uuid,
    pub account_id: i64,
    pub username: String,
    pub role: Role,
}

impl AuthContext {
    pub fn require_admin(&self) -> AppResult<()> {
        if self.role == Role::Admin {
            Ok(())
        } else {
            Err(AppError::forbidden())
        }
    }
}

fn header_str<'a>(req: &'a axum::http::request::Parts, name: &str) -> AppResult<&'a str> {
    req.headers.get(name).and_then(|v| v.to_str().ok()).ok_or_else(AppError::unauthorized)
}

async fn verify_signed(st: &AppState, parts: &axum::http::request::Parts, body: &[u8]) -> AppResult<SignedDevice> {
    let device_id: Uuid = header_str(parts, headers::DEVICE)?.parse().map_err(|_| AppError::unauthorized())?;
    let ts: i64 = header_str(parts, headers::TIMESTAMP)?.parse().map_err(|_| AppError::unauthorized())?;
    let nonce = header_str(parts, headers::NONCE)?;
    let sig = header_str(parts, headers::SIGNATURE)?;
    let now = crate::now();
    if (now - ts).abs() > REQUEST_MAX_SKEW_SECS || nonce.is_empty() || nonce.len() > 64 {
        return Err(AppError::unauthorized());
    }
    let row: Option<(Vec<u8>, i64, String, String, String)> = sqlx::query_as(
        "SELECT d.api_key, a.id, a.username, a.role, a.status
           FROM devices d JOIN accounts a ON a.id = d.account_id WHERE d.id = $1",
    )
    .bind(device_id)
    .fetch_optional(st.db())
    .await?;
    let (api_key, account_id, username, role, status) = row.ok_or_else(AppError::unauthorized)?;
    let path = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    msg_crypto::request::verify_request(&api_key, &device_id, parts.method.as_str(), path, body, ts, nonce, sig)
        .map_err(|_| AppError::unauthorized())?;
    // Anti-rejeu : un nonce ne peut servir qu'une fois par appareil.
    let inserted = sqlx::query(
        "INSERT INTO request_nonces (device_id, nonce, seen_at) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
    .bind(device_id)
    .bind(nonce)
    .bind(now)
    .execute(st.db())
    .await?
    .rows_affected();
    if inserted == 0 {
        return Err(AppError::unauthorized());
    }
    // Dernière activité à l'heure près seulement (minimisation des métadonnées).
    sqlx::query("UPDATE devices SET last_seen_at = $2 WHERE id = $1 AND (last_seen_at IS NULL OR last_seen_at < $2)")
        .bind(device_id)
        .bind(now - now % 3600)
        .execute(st.db())
        .await?;
    Ok(SignedDevice {
        device_id,
        account_id,
        username,
        role: Role::parse(&role).ok_or_else(AppError::internal)?,
        status: AccountStatus::parse(&status).ok_or_else(AppError::internal)?,
    })
}

async fn buffer(req: Request) -> AppResult<(axum::http::request::Parts, axum::body::Bytes)> {
    let (parts, body) = req.into_parts();
    let bytes = axum::body::to_bytes(body, MAX_BODY_BYTES).await.map_err(|_| {
        AppError::new(StatusCode::PAYLOAD_TOO_LARGE, ErrorCode::PayloadTooLarge, "requête trop volumineuse")
    })?;
    Ok((parts, bytes))
}

/// Middleware : signature d'appareil seule (renouvellement de session).
pub async fn signed_only(State(st): State<AppState>, req: Request, next: Next) -> AppResult<Response> {
    let (mut parts, bytes) = buffer(req).await?;
    let dev = verify_signed(&st, &parts, &bytes).await?;
    if dev.status != AccountStatus::Active {
        return Err(AppError::new(StatusCode::FORBIDDEN, ErrorCode::AccountSuspended, "compte inactif"));
    }
    parts.extensions.insert(dev);
    Ok(next.run(Request::from_parts(parts, Body::from(bytes))).await)
}

/// Middleware : signature d'appareil + jeton d'accès valide lié à l'appareil.
pub async fn authenticated(State(st): State<AppState>, req: Request, next: Next) -> AppResult<Response> {
    let (mut parts, bytes) = buffer(req).await?;
    let dev = verify_signed(&st, &parts, &bytes).await?;
    let token = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(AppError::unauthorized)?;
    let now = crate::now();
    let ok: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM sessions WHERE access_hash = $1 AND device_id = $2
            AND access_expires_at > $3 AND session_expires_at > $3",
    )
    .bind(token_hash(token))
    .bind(dev.device_id)
    .bind(now)
    .fetch_optional(st.db())
    .await?;
    if ok.is_none() {
        return Err(AppError::unauthorized());
    }
    if dev.status != AccountStatus::Active {
        return Err(AppError::new(StatusCode::FORBIDDEN, ErrorCode::AccountSuspended, "compte inactif"));
    }
    parts.extensions.insert(AuthContext {
        device_id: dev.device_id,
        account_id: dev.account_id,
        username: dev.username,
        role: dev.role,
    });
    Ok(next.run(Request::from_parts(parts, Body::from(bytes))).await)
}
