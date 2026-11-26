//! Serveur de messagerie « aveugle » : il authentifie des appareils et relaie
//! des blobs chiffrés de bout en bout, sans jamais disposer des clés.
#![forbid(unsafe_code)]

pub mod auth;
pub mod config;
pub mod error;
pub mod federation;
pub mod kt;
pub mod logging;
pub mod notify;
pub mod passwords;
pub mod routes;
pub mod secrets;
pub mod state;
pub mod tasks;

use std::time::{SystemTime, UNIX_EPOCH};

pub use config::Config;
pub use state::AppState;

/// Heure courante en secondes Unix.
pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Applique les migrations SQL embarquées.
pub async fn migrate(pool: &sqlx::PgPool) -> anyhow::Result<()> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}

pub use routes::router;
