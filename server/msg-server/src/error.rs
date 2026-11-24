//! Erreurs HTTP. Les messages renvoyés sont génériques : aucun détail interne
//! n'est exposé, et les erreurs internes sont journalisées sans données
//! utilisateur.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use msg_proto::{ApiError, ErrorCode};

#[derive(Debug)]
pub struct AppError {
    pub status: StatusCode,
    pub code: ErrorCode,
    pub message: String,
}

pub type AppResult<T> = Result<T, AppError>;

impl AppError {
    pub fn new(status: StatusCode, code: ErrorCode, message: impl Into<String>) -> Self {
        Self { status, code, message: message.into() }
    }
    pub fn bad_request(m: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, ErrorCode::BadRequest, m)
    }
    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, ErrorCode::Unauthorized, "authentification requise")
    }
    pub fn invalid_credentials() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, ErrorCode::InvalidCredentials, "identifiants invalides")
    }
    pub fn forbidden() -> Self {
        Self::new(StatusCode::FORBIDDEN, ErrorCode::Forbidden, "accès refusé")
    }
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, ErrorCode::NotFound, "introuvable")
    }
    pub fn conflict(m: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, ErrorCode::Conflict, m)
    }
    pub fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::Internal, "erreur interne")
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        // Les erreurs SQL ne contiennent pas de contenu utilisateur (requêtes paramétrées).
        tracing::error!(error = %e, "erreur base de données");
        Self::internal()
    }
}

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!(error = %e, "erreur interne");
        Self::internal()
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.status, Json(ApiError { code: self.code, message: self.message })).into_response()
    }
}
