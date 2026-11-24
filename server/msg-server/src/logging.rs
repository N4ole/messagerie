//! Journalisation respectueuse de la vie privée : on ne journalise que la
//! méthode, le **modèle** de route (jamais le chemin réel, qui peut contenir
//! un identifiant), le statut et la durée. Jamais d'IP, d'en-tête, de corps.

use std::time::Instant;

use axum::extract::{MatchedPath, Request};
use axum::middleware::Next;
use axum::response::Response;

pub async fn access_log(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let route =
        req.extensions().get::<MatchedPath>().map(|p| p.as_str().to_owned()).unwrap_or_else(|| "<inconnue>".into());
    let start = Instant::now();
    let resp = next.run(req).await;
    tracing::info!(
        method = %method,
        route = %route,
        status = resp.status().as_u16(),
        ms = start.elapsed().as_millis() as u64,
        "requête"
    );
    resp
}

/// Initialise `tracing` (format JSON si `MSG_LOG_JSON=1`).
pub fn init() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_env("MSG_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let json = std::env::var("MSG_LOG_JSON").map(|v| v == "1").unwrap_or(false);
    let builder = tracing_subscriber::fmt().with_env_filter(filter).with_target(false);
    if json {
        builder.json().init();
    } else {
        builder.init();
    }
}
