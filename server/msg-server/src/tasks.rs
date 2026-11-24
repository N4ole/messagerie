//! Tâches de maintenance périodiques (purge des données expirées).

use std::time::Duration;

use crate::state::AppState;

pub async fn cleanup_once(st: &AppState) -> Result<(), sqlx::Error> {
    let now = crate::now();
    let db = st.db();
    sqlx::query("DELETE FROM request_nonces WHERE seen_at < $1").bind(now - 600).execute(db).await?;
    sqlx::query("DELETE FROM sessions WHERE session_expires_at < $1").bind(now).execute(db).await?;
    // Rétention maximale des blobs non retirés.
    sqlx::query("DELETE FROM blobs WHERE expires_at < $1").bind(now).execute(db).await?;
    sqlx::query("DELETE FROM attachments WHERE expires_at < $1").bind(now).execute(db).await?;
    sqlx::query("DELETE FROM webauthn_challenges WHERE expires_at < $1").bind(now).execute(db).await?;
    sqlx::query("DELETE FROM blobs b WHERE NOT EXISTS (SELECT 1 FROM deliveries d WHERE d.blob_id = b.id)")
        .execute(db)
        .await?;
    Ok(())
}

pub fn spawn(st: AppState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(300));
        loop {
            tick.tick().await;
            if let Err(e) = cleanup_once(&st).await {
                tracing::error!(error = %e, "purge périodique échouée");
            }
        }
    });
}
