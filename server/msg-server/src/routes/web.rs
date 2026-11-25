//! Client web : fichiers statiques et en-têtes de sécurité.
//!
//! Le client web est servi par le serveur lui-même (même origine que l'API) :
//! aucune ressource tierce, aucun CORS. Limite fondamentale du chiffrement de
//! bout en bout sur le web : le code est fourni par le serveur à chaque
//! visite ; un serveur compromis peut servir un client piégé (voir la
//! documentation de la Phase 3). Le client desktop n'a pas cette limite.

use axum::extract::{Request, State};
use axum::http::{header, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use axum::Json;
use msg_proto::WebConfig;
use tower_http::services::ServeDir;

use crate::state::AppState;

/// Politique de sécurité du contenu : uniquement des ressources du site,
/// WebAssembly autorisé, aucun script en ligne, aucun cadre.
pub const CSP: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; \
img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; worker-src 'self'; \
manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

pub fn static_files(dir: std::path::PathBuf) -> ServeDir {
    ServeDir::new(dir).append_index_html_on_directories(true)
}

pub async fn config(State(st): State<AppState>) -> Json<WebConfig> {
    Json(WebConfig { onion_only: st.cfg().web_onion_only })
}

/// En-têtes de sécurité sur toutes les réponses (API comprise).
pub async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    let set = |h: &mut axum::http::HeaderMap, k: header::HeaderName, v: &'static str| {
        h.entry(k).or_insert(HeaderValue::from_static(v));
    };
    set(h, header::CONTENT_SECURITY_POLICY, CSP);
    set(h, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(h, header::REFERRER_POLICY, "no-referrer");
    set(h, header::X_FRAME_OPTIONS, "DENY");
    set(h, header::CACHE_CONTROL, "no-store");
    set(h, header::HeaderName::from_static("cross-origin-opener-policy"), "same-origin");
    set(h, header::HeaderName::from_static("cross-origin-resource-policy"), "same-origin");
    set(
        h,
        header::HeaderName::from_static("permissions-policy"),
        "camera=(self), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
    );
    resp
}
