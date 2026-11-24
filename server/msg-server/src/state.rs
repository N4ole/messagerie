//! État partagé du serveur.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use sqlx::PgPool;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::config::Config;
use crate::secrets::ServerSecrets;

#[derive(Clone)]
pub struct AppState {
    pub inner: Arc<Inner>,
}

pub struct Inner {
    pub db: PgPool,
    pub cfg: Config,
    pub secrets: ServerSecrets,
    /// Notifications « nouveaux messages » par appareil (instance unique en
    /// Phase 1 ; un bus inter-instances viendra en Phase 4).
    pub hub: broadcast::Sender<Uuid>,
    send_rate: Mutex<HashMap<Uuid, (i64, u32)>>,
}

impl AppState {
    pub fn new(db: PgPool, cfg: Config) -> Self {
        let secrets = ServerSecrets::derive(&cfg.server_secret);
        let (hub, _) = broadcast::channel(4096);
        Self { inner: Arc::new(Inner { db, cfg, secrets, hub, send_rate: Mutex::new(HashMap::new()) }) }
    }

    pub fn db(&self) -> &PgPool {
        &self.inner.db
    }

    pub fn cfg(&self) -> &Config {
        &self.inner.cfg
    }

    /// Limitation de débit des envois par appareil (fenêtre fixe de 10 s).
    pub fn allow_send(&self, device: Uuid, now: i64) -> bool {
        let mut map = self.inner.send_rate.lock().unwrap_or_else(|e| e.into_inner());
        let window = now / 10;
        if map.len() > 100_000 {
            map.retain(|_, (w, _)| *w == window);
        }
        let entry = map.entry(device).or_insert((window, 0));
        if entry.0 != window {
            *entry = (window, 0);
        }
        entry.1 += 1;
        entry.1 <= self.inner.cfg.send_rate_per_10s
    }
}
