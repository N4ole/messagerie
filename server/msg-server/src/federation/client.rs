//! Appels sortants vers les sites pairs : requête signée par la clé de ce
//! site, réponse exigée signée par la clé épinglée du site appelé.

use std::time::Duration;

use axum::http::StatusCode;
use msg_proto::{headers, ErrorCode};
use serde::de::DeserializeOwned;
use serde::Serialize;

use super::{bad_peer, signing_key};
use crate::config::FederationPeer;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

/// Taille maximale d'une réponse d'un site pair (pièces jointes comprises).
const MAX_RESPONSE_BYTES: usize = msg_proto::MAX_ATTACHMENT_BLOB_BYTES + 64 * 1024;

/// Client HTTP de fédération (proxy SOCKS facultatif, aucune redirection).
pub fn http_client(proxy: Option<&str>) -> anyhow::Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .user_agent("messagerie-federation")
        .timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy();
    if let Some(p) = proxy {
        b = b.proxy(reqwest::Proxy::all(p)?);
    }
    Ok(b.build()?)
}

fn unreachable(e: impl std::fmt::Display) -> AppError {
    tracing::warn!(error = %e, "site pair injoignable");
    AppError::new(StatusCode::BAD_GATEWAY, ErrorCode::Internal, "site distant injoignable")
}

/// Appel signé ; renvoie le corps d'une réponse 2xx authentifiée.
pub async fn call(
    st: &AppState,
    peer: &FederationPeer,
    method: reqwest::Method,
    path: &str,
    body: Vec<u8>,
) -> AppResult<Vec<u8>> {
    let onion = peer.url.contains(".onion");
    if onion && st.cfg().federation_proxy.is_none() {
        return Err(unreachable("adresse .onion sans MSG_FEDERATION_PROXY"));
    }
    let url = format!("{}{}", peer.url.trim_end_matches('/'), path);
    let key = signing_key(st)?;
    let h =
        msg_crypto::request::sign_site_request(&key, &st.cfg().site_name, method.as_str(), path, &body, crate::now())
            .map_err(|_| AppError::internal())?;
    let mut rb = st
        .inner
        .federation_http
        .request(method, url)
        .header(headers::SITE, &h.device)
        .header(headers::TIMESTAMP, &h.timestamp)
        .header(headers::NONCE, &h.nonce)
        .header(headers::SIGNATURE, &h.signature);
    if !body.is_empty() {
        rb = rb.header(reqwest::header::CONTENT_TYPE, "application/json").body(body);
    }
    let resp = rb.send().await.map_err(unreachable)?;
    let status = resp.status().as_u16();
    let sig = resp.headers().get(headers::SITE_RESPONSE_SIGNATURE).and_then(|v| v.to_str().ok()).map(str::to_owned);
    if resp.content_length().is_some_and(|l| l as usize > MAX_RESPONSE_BYTES) {
        return Err(bad_peer("réponse trop volumineuse"));
    }
    let bytes = resp.bytes().await.map_err(unreachable)?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(bad_peer("réponse trop volumineuse"));
    }
    let Some(sig) = sig else { return Err(bad_peer("réponse non signée")) };
    msg_crypto::request::verify_site_response(&peer.public_key, &peer.name, &h.nonce, status, &bytes, &sig)
        .map_err(|_| bad_peer("signature de réponse invalide"))?;
    match status {
        200..=299 => Ok(bytes.to_vec()),
        404 => Err(AppError::not_found()),
        _ => {
            Err(AppError::new(StatusCode::BAD_GATEWAY, ErrorCode::Internal, format!("site distant : statut {status}")))
        }
    }
}

pub async fn get_json<T: DeserializeOwned>(st: &AppState, peer: &FederationPeer, path: &str) -> AppResult<T> {
    let b = call(st, peer, reqwest::Method::GET, path, Vec::new()).await?;
    serde_json::from_slice(&b).map_err(|_| bad_peer("réponse mal formée"))
}

pub async fn post_json<B: Serialize, T: DeserializeOwned>(
    st: &AppState,
    peer: &FederationPeer,
    path: &str,
    body: &B,
) -> AppResult<T> {
    let body = serde_json::to_vec(body).map_err(|_| AppError::internal())?;
    let b = call(st, peer, reqwest::Method::POST, path, body).await?;
    serde_json::from_slice(&b).map_err(|_| bad_peer("réponse mal formée"))
}

pub async fn get_bytes(st: &AppState, peer: &FederationPeer, path: &str) -> AppResult<Vec<u8>> {
    call(st, peer, reqwest::Method::GET, path, Vec::new()).await
}
