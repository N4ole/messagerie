//! Routes appelées par les sites pairs (authentifiées par signature de site).

use axum::body::Body;
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use msg_proto::{
    headers, FederationAck, FederationDeliver, KtAudit, SignedKtHead, SiteInfo, UserDirectoryEntry, MAX_PAYLOAD_BYTES,
    REQUEST_MAX_SKEW_SECS,
};
use uuid::Uuid;

use super::{peer, signing_key, site_info};
use crate::error::{AppError, AppResult};
use crate::routes::keys::{claim_entry, directory_entry, parse_devices, AuditQuery, ClaimQuery};
use crate::state::AppState;

/// Site pair authentifié pour la requête en cours.
#[derive(Clone, Debug)]
pub struct PeerSite(pub String);

/// Nombre maximal d'appareils par distribution fédérée.
const MAX_FEDERATED_RECIPIENTS: usize = 500;

/// Informations publiques de ce site (nom, clé de fédération à épingler).
pub async fn site(State(st): State<AppState>) -> AppResult<Json<SiteInfo>> {
    Ok(Json(site_info(&st)?))
}

fn header_str<'a>(req: &'a Request, name: &str) -> AppResult<&'a str> {
    req.headers().get(name).and_then(|v| v.to_str().ok()).ok_or_else(AppError::unauthorized)
}

/// Middleware : authentifie le site appelant (liste blanche, signature,
/// horodatage, nonce à usage unique) puis signe la réponse, liée au nonce.
pub async fn authenticate(State(st): State<AppState>, req: Request, next: Next) -> AppResult<Response> {
    let site = header_str(&req, headers::SITE)?.to_owned();
    let ts: i64 = header_str(&req, headers::TIMESTAMP)?.parse().map_err(|_| AppError::unauthorized())?;
    let nonce = header_str(&req, headers::NONCE)?.to_owned();
    let sig = header_str(&req, headers::SIGNATURE)?.to_owned();
    let now = crate::now();
    if (now - ts).abs() > REQUEST_MAX_SKEW_SECS || nonce.is_empty() || nonce.len() > 64 {
        return Err(AppError::unauthorized());
    }
    let peer = peer(&st, &site).map_err(|_| AppError::unauthorized())?;
    let (mut parts, body) = req.into_parts();
    let bytes = axum::body::to_bytes(body, MAX_PAYLOAD_BYTES + 64 * 1024)
        .await
        .map_err(|_| AppError::bad_request("requête trop volumineuse"))?;
    let path = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    msg_crypto::request::verify_site_request(
        &peer.public_key,
        &site,
        parts.method.as_str(),
        path,
        &bytes,
        ts,
        &nonce,
        &sig,
    )
    .map_err(|_| AppError::unauthorized())?;
    let fresh =
        sqlx::query("INSERT INTO federation_nonces (site, nonce, seen_at) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
            .bind(&site)
            .bind(&nonce)
            .bind(now)
            .execute(st.db())
            .await?
            .rows_affected();
    if fresh == 0 {
        return Err(AppError::unauthorized());
    }
    parts.extensions.insert(PeerSite(site));
    let resp = next.run(Request::from_parts(parts, Body::from(bytes))).await;
    // Signature de la réponse (corps complet, statut, nonce de la requête).
    let (mut rparts, rbody) = resp.into_parts();
    let rbytes = axum::body::to_bytes(rbody, msg_proto::MAX_ATTACHMENT_BLOB_BYTES + 64 * 1024)
        .await
        .map_err(|_| AppError::internal())?;
    let key = signing_key(&st)?;
    let signature =
        msg_crypto::request::sign_site_response(&key, &st.cfg().site_name, &nonce, rparts.status.as_u16(), &rbytes);
    rparts
        .headers
        .insert(headers::SITE_RESPONSE_SIGNATURE, HeaderValue::from_str(&signature).map_err(|_| AppError::internal())?);
    Ok(Response::from_parts(rparts, Body::from(rbytes)))
}

fn local_user(user: &str) -> AppResult<&str> {
    msg_proto::validate_username(user).map_err(AppError::bad_request)?;
    Ok(user)
}

pub async fn directory(
    State(st): State<AppState>,
    Extension(_p): Extension<PeerSite>,
    Path(user): Path<String>,
) -> AppResult<Json<UserDirectoryEntry>> {
    Ok(Json(directory_entry(&st, local_user(&user)?).await?))
}

pub async fn claim(
    State(st): State<AppState>,
    Extension(_p): Extension<PeerSite>,
    Path(user): Path<String>,
    Query(q): Query<ClaimQuery>,
) -> AppResult<Json<UserDirectoryEntry>> {
    let wanted = parse_devices(q.devices.as_deref())?;
    Ok(Json(claim_entry(&st, local_user(&user)?, None, wanted).await?))
}

/// Distribution d'un message à des appareils de ce site.
pub async fn deliver(
    State(st): State<AppState>,
    Extension(PeerSite(site)): Extension<PeerSite>,
    Json(req): Json<FederationDeliver>,
) -> AppResult<Json<FederationAck>> {
    if req.payload.is_empty() || req.payload.len() > MAX_PAYLOAD_BYTES {
        return Err(AppError::bad_request("message invalide"));
    }
    let mut devices = req.devices.clone();
    devices.sort();
    devices.dedup();
    if devices.is_empty() || devices.len() > MAX_FEDERATED_RECIPIENTS {
        return Err(AppError::bad_request("destinataires invalides"));
    }
    let mut tx = st.db().begin().await?;
    // Seuls les appareils de ce site sont servis ; les autres sont ignorés.
    let known: Vec<(Uuid,)> =
        sqlx::query_as("SELECT id FROM devices WHERE id = ANY($1)").bind(&devices).fetch_all(&mut *tx).await?;
    let devices: Vec<Uuid> = known.into_iter().map(|(d,)| d).collect();
    let now = crate::now();
    let blob: Option<(i64,)> = sqlx::query_as(
        "INSERT INTO blobs (sender_device, origin_site, client_message_id, payload, created_at, expires_at)
         VALUES (NULL, $1, $2, $3, $4, $5)
         ON CONFLICT (origin_site, client_message_id) WHERE origin_site IS NOT NULL DO NOTHING RETURNING id",
    )
    .bind(&site)
    .bind(req.message_id)
    .bind(&req.payload)
    .bind(now)
    .bind(now + st.cfg().blob_retention_secs)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((blob_id,)) = blob else {
        // Ré-émission d'un message déjà accepté : accusé identique.
        return Ok(Json(FederationAck { message_id: req.message_id, accepted: devices.len() }));
    };
    if !devices.is_empty() {
        sqlx::query(
            "INSERT INTO deliveries (blob_id, device_id, created_at) SELECT $1, r, $3 FROM UNNEST($2::uuid[]) AS r",
        )
        .bind(blob_id)
        .bind(&devices)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    st.inner.metrics.federation_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    crate::notify::deliveries(&st, &devices).await;
    Ok(Json(FederationAck { message_id: req.message_id, accepted: devices.len() }))
}

/// Pièce jointe chiffrée hébergée par ce site (demandée par le site d'un destinataire).
pub async fn attachment(
    State(st): State<AppState>,
    Extension(_p): Extension<PeerSite>,
    Path(id): Path<Uuid>,
) -> AppResult<impl IntoResponse> {
    let data = crate::routes::attachments::load(&st, id).await?;
    Ok((StatusCode::OK, [(header::CONTENT_TYPE, "application/octet-stream")], data))
}

pub async fn kt_head(State(st): State<AppState>, Extension(_p): Extension<PeerSite>) -> AppResult<Json<SignedKtHead>> {
    let head = crate::kt::head(&st).await?;
    Ok(Json(super::sign_head(&st, head)?))
}

pub async fn kt_audit(
    State(st): State<AppState>,
    Extension(_p): Extension<PeerSite>,
    Query(q): Query<AuditQuery>,
) -> AppResult<Json<KtAudit>> {
    Ok(Json(crate::kt::audit(&st, q.from, q.to).await?))
}
