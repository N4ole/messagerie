//! Routes HTTP de l'API v1.

pub mod account;
pub mod admin;
pub mod attachments;
pub mod keys;
pub mod messages;
pub mod webauthn;
pub mod ws;

use axum::extract::DefaultBodyLimit;
use axum::middleware::from_fn_with_state;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use msg_proto::HealthResponse;

use crate::auth::{authenticated, signed_only, MAX_BODY_BYTES};
use crate::state::AppState;

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok".into(), version: env!("CARGO_PKG_VERSION").into() })
}

pub fn router(st: AppState) -> Router {
    let public = Router::new()
        .route("/v1/health", get(health))
        .route("/v1/auth/activate", post(account::activate))
        .route("/v1/auth/confirm-totp", post(account::confirm_totp))
        .route("/v1/auth/login", post(account::login))
        .route("/v1/auth/webauthn/challenge", post(webauthn::login_challenge));

    let signed = Router::new()
        .route("/v1/auth/refresh", post(account::refresh))
        .route_layer(from_fn_with_state(st.clone(), signed_only));

    let protected = Router::new()
        .route("/v1/auth/logout", post(account::logout))
        .route("/v1/keypackages", post(keys::upload))
        .route("/v1/keypackages/count", get(keys::count))
        .route("/v1/users/{username}", get(keys::directory))
        .route("/v1/users/{username}/claim", post(keys::claim))
        .route("/v1/messages", post(messages::send))
        .route("/v1/queue", get(messages::queue))
        .route("/v1/queue/ack", post(messages::ack))
        .route(
            "/v1/attachments",
            post(attachments::upload).layer(DefaultBodyLimit::max(msg_proto::MAX_ATTACHMENT_BLOB_BYTES + 1024)),
        )
        .route("/v1/attachments/{id}", get(attachments::download))
        .route("/v1/ws", get(ws::handler))
        .route("/v1/webauthn/register/start", post(webauthn::register_start))
        .route("/v1/webauthn/register/finish", post(webauthn::register_finish))
        .route("/v1/webauthn/credentials", get(webauthn::list))
        .route("/v1/webauthn/credentials/{id}", delete(webauthn::delete))
        .route("/v1/admin/accounts", get(admin::list).post(admin::create))
        .route("/v1/admin/accounts/{username}/status", put(admin::set_status))
        .route("/v1/admin/accounts/{username}/role", put(admin::set_role))
        .route("/v1/admin/accounts/{username}/reset", post(admin::reset))
        .route("/v1/admin/accounts/{username}/devices", get(admin::devices))
        .route("/v1/admin/accounts/{username}/devices/{device_id}", delete(admin::revoke_device))
        .route_layer(from_fn_with_state(st.clone(), authenticated));

    Router::new()
        .merge(public)
        .merge(signed)
        .merge(protected)
        .layer(axum::middleware::from_fn(crate::logging::access_log))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(st)
}
