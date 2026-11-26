//! Fédération entre sites (ADR-0009, révisé en Phase 4).
//!
//! - Chaque site a une clé Ed25519 de fédération (dérivée du secret serveur)
//!   et une **liste blanche** de sites pairs avec leur clé épinglée.
//! - Les requêtes entre sites sont **signées** par la clé du site appelant
//!   (horodatage, nonce à usage unique) et les réponses par la clé du site
//!   appelé, liées au nonce de la requête : authentification mutuelle par
//!   clés épinglées, indépendante de TLS (qui reste exigé, sauf `.onion`).
//! - Un site ne répond que pour **ses** utilisateurs ; il ne relaie que des
//!   blobs chiffrés de bout en bout.
//! - Les clients ne contactent jamais un site distant : leur propre serveur
//!   relaie annuaire, KeyPackages, journal KT et pièces jointes.

pub mod client;
pub mod outbox;
pub mod routes;
pub mod witness;

use axum::http::StatusCode;
use msg_crypto::identity::SigningKeyPair;
use msg_proto::{ErrorCode, KtHead, SignedKtHead, SiteInfo};

use crate::config::FederationPeer;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

const KT_HEAD_LABEL: &str = "messagerie/federation/kt-head/v1";

/// Destination d'une adresse `nom` ou `nom@site`.
pub enum Route {
    Local(String),
    Remote(FederationPeer, String),
}

/// Résout une adresse : utilisateur de ce site, ou d'un site de la liste blanche.
pub fn route(st: &AppState, address: &str) -> AppResult<Route> {
    let (user, site) = msg_proto::parse_address(address).map_err(AppError::bad_request)?;
    match site {
        None => Ok(Route::Local(user.to_owned())),
        Some(s) if s == st.cfg().site_name => Ok(Route::Local(user.to_owned())),
        Some(s) => Ok(Route::Remote(peer(st, s)?, user.to_owned())),
    }
}

/// Site pair de la liste blanche (introuvable sinon).
pub fn peer(st: &AppState, site: &str) -> AppResult<FederationPeer> {
    st.cfg()
        .federation_peers
        .iter()
        .find(|p| p.name == site)
        .cloned()
        .ok_or_else(|| AppError::new(StatusCode::NOT_FOUND, ErrorCode::NotFound, "site inconnu ou non autorisé"))
}

/// Clé de fédération de ce site.
pub fn signing_key(st: &AppState) -> AppResult<SigningKeyPair> {
    SigningKeyPair::from_secret_bytes(st.inner.secrets.federation_seed.as_ref()).map_err(|_| AppError::internal())
}

pub fn site_info(st: &AppState) -> AppResult<SiteInfo> {
    Ok(SiteInfo { name: st.cfg().site_name.clone(), federation_key: signing_key(st)?.public_bytes().to_vec() })
}

fn head_message(site: &str, h: &KtHead) -> Vec<u8> {
    format!("{KT_HEAD_LABEL}\n{site}\n{}\n{}\n{}", h.epoch, hex::encode(&h.root_hash), hex::encode(&h.vrf_public_key))
        .into_bytes()
}

/// Tête du journal KT de ce site, signée par sa clé de site.
pub fn sign_head(st: &AppState, head: KtHead) -> AppResult<SignedKtHead> {
    let site = st.cfg().site_name.clone();
    let signature = signing_key(st)?.sign(&head_message(&site, &head)).to_vec();
    Ok(SignedKtHead { site, head, signature })
}

/// Vérifie qu'une tête de journal a bien été signée par le site pair.
pub fn verify_signed_head(peer: &FederationPeer, s: &SignedKtHead) -> AppResult<()> {
    if s.site != peer.name {
        return Err(bad_peer("tête de journal d'un autre site"));
    }
    msg_crypto::identity::verify(&peer.public_key, &head_message(&s.site, &s.head), &s.signature)
        .map_err(|_| bad_peer("signature de la tête de journal invalide"))
}

pub(crate) fn bad_peer(msg: &str) -> AppError {
    tracing::warn!(raison = msg, "réponse refusée d'un site pair");
    AppError::new(StatusCode::BAD_GATEWAY, ErrorCode::Internal, format!("site distant : {msg}"))
}
