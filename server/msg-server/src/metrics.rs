//! Métriques Prometheus **sans données personnelles**.
//!
//! Règles (vérifiées par `tests/phase4.rs::metrics_contain_no_personal_data`) :
//! - aucune étiquette ne contient d'identifiant (nom d'utilisateur, appareil,
//!   message, IP, jeton) : les routes sont étiquetées par leur **modèle**
//!   (`/v1/users/{username}`), jamais par le chemin réel ;
//! - cardinalité bornée : méthode et statut ramenés à des ensembles fixes,
//!   routes limitées aux modèles déclarés, sites limités à la liste blanche ;
//! - seules des valeurs agrégées (comptes, files, tailles totales).
//!
//! Exposées sur un port séparé (`MSG_METRICS_BIND`), jamais sur l'API
//! publique ; jeton porteur facultatif (`MSG_METRICS_TOKEN`).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use axum::extract::{MatchedPath, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use subtle::ConstantTimeEq;

use crate::state::AppState;

/// Bornes des histogrammes de durée (secondes).
const BUCKETS: [f64; 10] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 10.0];
/// Nombre maximal de séries HTTP (garde-fou de cardinalité).
const MAX_HTTP_SERIES: usize = 512;

#[derive(Default)]
struct HttpStat {
    count: u64,
    sum: f64,
    buckets: [u64; BUCKETS.len()],
}

/// Compteurs en mémoire de l'instance.
#[derive(Default)]
pub struct Metrics {
    http: Mutex<BTreeMap<(&'static str, String, &'static str), HttpStat>>,
    pub ws_connections: AtomicI64,
    pub federation_sent: AtomicU64,
    pub federation_send_failures: AtomicU64,
    pub federation_received: AtomicU64,
    pub kt_witness_inconsistent: AtomicU64,
}

fn method_label(m: &axum::http::Method) -> &'static str {
    match m.as_str() {
        "GET" => "GET",
        "POST" => "POST",
        "PUT" => "PUT",
        "DELETE" => "DELETE",
        "HEAD" => "HEAD",
        _ => "other",
    }
}

fn status_label(s: StatusCode) -> &'static str {
    match s.as_u16() {
        200 => "200",
        201 => "201",
        204 => "204",
        101 => "101",
        304 => "304",
        400 => "400",
        401 => "401",
        403 => "403",
        404 => "404",
        409 => "409",
        413 => "413",
        429 => "429",
        500 => "500",
        502 => "502",
        503 => "503",
        c if c < 300 => "2xx",
        c if c < 400 => "3xx",
        c if c < 500 => "4xx",
        _ => "5xx",
    }
}

/// Modèle de route sûr : uniquement des segments littéraux ou `{param}`.
fn route_label(p: Option<&MatchedPath>) -> String {
    match p.map(MatchedPath::as_str) {
        Some(r) if r.len() <= 96 && r.chars().all(|c| c.is_ascii_alphanumeric() || "/{}_-.".contains(c)) => r.into(),
        Some(_) => "other".into(),
        // Fichiers statiques du client web et chemins inconnus : regroupés.
        None => "unmatched".into(),
    }
}

impl Metrics {
    fn observe(&self, method: &'static str, route: String, status: &'static str, secs: f64) {
        let Ok(mut m) = self.http.lock() else { return };
        let key = (method, route, status);
        let key =
            if m.len() >= MAX_HTTP_SERIES && !m.contains_key(&key) { (method, "other".into(), status) } else { key };
        let s = m.entry(key).or_default();
        s.count += 1;
        s.sum += secs;
        for (i, b) in BUCKETS.iter().enumerate() {
            if secs <= *b {
                s.buckets[i] += 1;
            }
        }
    }
}

/// Middleware : compte les requêtes HTTP par modèle de route.
pub async fn track(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let method = method_label(req.method());
    let route = route_label(req.extensions().get::<MatchedPath>());
    let start = Instant::now();
    let resp = next.run(req).await;
    st.inner.metrics.observe(method, route, status_label(resp.status()), start.elapsed().as_secs_f64());
    resp
}

/// Décrément automatique du nombre de connexions WebSocket.
pub struct WsGuard(AppState);

impl WsGuard {
    pub fn new(st: &AppState) -> Self {
        st.inner.metrics.ws_connections.fetch_add(1, Ordering::Relaxed);
        Self(st.clone())
    }
}

impl Drop for WsGuard {
    fn drop(&mut self) {
        self.0.inner.metrics.ws_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

fn esc(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

fn metric(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
}

async fn scalar(st: &AppState, sql: &'static str) -> i64 {
    sqlx::query_scalar::<_, Option<i64>>(sql).fetch_one(st.db()).await.ok().flatten().unwrap_or(0)
}

/// Rendu au format texte Prometheus 0.0.4.
pub async fn render(st: &AppState) -> String {
    let mut out = String::new();
    let m = &st.inner.metrics;

    metric(&mut out, "msg_build_info", "gauge", "Version du serveur.");
    let _ = writeln!(out, "msg_build_info{{version=\"{}\"}} 1", esc(env!("CARGO_PKG_VERSION")));

    metric(&mut out, "msg_http_requests_total", "counter", "Requêtes HTTP par modèle de route.");
    let mut hist = String::new();
    metric(&mut hist, "msg_http_request_duration_seconds", "histogram", "Durée des requêtes HTTP.");
    if let Ok(map) = m.http.lock() {
        for ((method, route, status), s) in map.iter() {
            let l = format!("method=\"{method}\",route=\"{}\",status=\"{status}\"", esc(route));
            let _ = writeln!(out, "msg_http_requests_total{{{l}}} {}", s.count);
            for (i, b) in BUCKETS.iter().enumerate() {
                let _ = writeln!(hist, "msg_http_request_duration_seconds_bucket{{{l},le=\"{b}\"}} {}", s.buckets[i]);
            }
            let _ = writeln!(hist, "msg_http_request_duration_seconds_bucket{{{l},le=\"+Inf\"}} {}", s.count);
            let _ = writeln!(hist, "msg_http_request_duration_seconds_sum{{{l}}} {}", s.sum);
            let _ = writeln!(hist, "msg_http_request_duration_seconds_count{{{l}}} {}", s.count);
        }
    }
    out.push_str(&hist);

    metric(&mut out, "msg_websocket_connections", "gauge", "Connexions WebSocket ouvertes sur cette instance.");
    let _ = writeln!(out, "msg_websocket_connections {}", m.ws_connections.load(Ordering::Relaxed));

    let counters = [
        ("msg_federation_sent_total", "Messages remis à des sites pairs.", &m.federation_sent),
        ("msg_federation_send_failures_total", "Tentatives de remise fédérée échouées.", &m.federation_send_failures),
        ("msg_federation_received_total", "Messages reçus de sites pairs.", &m.federation_received),
        ("msg_kt_witness_inconsistent_total", "Incohérences KT détectées chez des pairs.", &m.kt_witness_inconsistent),
    ];
    for (name, help, c) in counters {
        metric(&mut out, name, "counter", help);
        let _ = writeln!(out, "{name} {}", c.load(Ordering::Relaxed));
    }

    // Valeurs agrégées lues en base (communes à toutes les instances).
    metric(&mut out, "msg_accounts", "gauge", "Comptes par statut.");
    let rows: Vec<(String, i64)> = sqlx::query_as("SELECT status, COUNT(*) FROM accounts GROUP BY status")
        .fetch_all(st.db())
        .await
        .unwrap_or_default();
    for status in ["pending_activation", "pending_totp", "active", "suspended"] {
        let n = rows.iter().find(|(s, _)| s == status).map(|(_, n)| *n).unwrap_or(0);
        let _ = writeln!(out, "msg_accounts{{status=\"{status}\"}} {n}");
    }
    let gauges = [
        ("msg_devices", "Appareils enregistrés.", "SELECT COUNT(*) FROM devices"),
        ("msg_pending_deliveries", "Remises en attente de retrait.", "SELECT COUNT(*) FROM deliveries"),
        ("msg_stored_blobs", "Messages chiffrés stockés.", "SELECT COUNT(*) FROM blobs"),
        (
            "msg_attachments_bytes",
            "Taille totale des pièces jointes chiffrées.",
            "SELECT SUM(size)::BIGINT FROM attachments",
        ),
        ("msg_kt_epoch", "Dernière époque du journal Key Transparency.", "SELECT MAX(epoch) FROM kt_log"),
        ("msg_kt_pending_updates", "Comptes en attente de publication KT.", "SELECT COUNT(*) FROM kt_dirty"),
    ];
    for (name, help, sql) in gauges {
        metric(&mut out, name, "gauge", help);
        let _ = writeln!(out, "{name} {}", scalar(st, sql).await);
    }

    // Par site pair : uniquement les noms de la liste blanche (infrastructure).
    let peers = &st.cfg().federation_peers;
    metric(&mut out, "msg_federation_outbox", "gauge", "Messages en file vers un site pair.");
    let queued: Vec<(String, i64)> = sqlx::query_as("SELECT site, COUNT(*) FROM federation_outbox GROUP BY site")
        .fetch_all(st.db())
        .await
        .unwrap_or_default();
    for p in peers {
        let n = queued.iter().find(|(s, _)| *s == p.name).map(|(_, n)| *n).unwrap_or(0);
        let _ = writeln!(out, "msg_federation_outbox{{site=\"{}\"}} {n}", esc(&p.name));
    }
    metric(&mut out, "msg_federation_outbox_oldest_seconds", "gauge", "Âge du plus ancien message en file.");
    let oldest: i64 = sqlx::query_scalar::<_, Option<i64>>("SELECT MIN(created_at) FROM federation_outbox")
        .fetch_one(st.db())
        .await
        .ok()
        .flatten()
        .map(|t| (crate::now() - t).max(0))
        .unwrap_or(0);
    let _ = writeln!(out, "msg_federation_outbox_oldest_seconds {oldest}");
    metric(&mut out, "msg_kt_witness_epoch", "gauge", "Dernière époque KT vérifiée chez un site pair.");
    metric(&mut out, "msg_kt_witness_age_seconds", "gauge", "Ancienneté de la dernière vérification KT d'un pair.");
    let seen: Vec<(String, i64, i64)> =
        sqlx::query_as("SELECT site, epoch, checked_at FROM kt_witness").fetch_all(st.db()).await.unwrap_or_default();
    for p in peers {
        if let Some((_, epoch, at)) = seen.iter().find(|(s, _, _)| *s == p.name) {
            let site = esc(&p.name);
            let _ = writeln!(out, "msg_kt_witness_epoch{{site=\"{site}\"}} {epoch}");
            let _ = writeln!(out, "msg_kt_witness_age_seconds{{site=\"{site}\"}} {}", (crate::now() - at).max(0));
        }
    }
    out
}

async fn handler(State(st): State<AppState>, req: Request) -> Response {
    if let Some(token) = &st.cfg().metrics_token {
        let given = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        if !bool::from(given.as_bytes().ct_eq(token.as_bytes())) {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")], render(&st).await).into_response()
}

/// Routeur dédié, à servir sur une adresse séparée (réseau d'administration).
pub fn router(st: AppState) -> Router {
    Router::new().route("/metrics", get(handler)).with_state(st)
}
