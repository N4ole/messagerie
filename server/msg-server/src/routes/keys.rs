//! Annuaire : KeyPackages MLS et appareils publiés.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use msg_proto::{
    KeyPackageCount, KtAudit, KtHead, PublishedDevice, UploadKeyPackagesRequest, UserDirectoryEntry,
    MAX_KEY_PACKAGES_PER_UPLOAD,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::AuthContext;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

const MAX_KEY_PACKAGE_BYTES: usize = 16 * 1024;
const MAX_STORED_PER_DEVICE: i64 = 200;

pub async fn upload(
    State(st): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Json(req): Json<UploadKeyPackagesRequest>,
) -> AppResult<StatusCode> {
    if req.key_packages.is_empty()
        || req.key_packages.len() > MAX_KEY_PACKAGES_PER_UPLOAD
        || req.key_packages.iter().any(|k| k.is_empty() || k.len() > MAX_KEY_PACKAGE_BYTES)
    {
        return Err(AppError::bad_request("KeyPackages invalides"));
    }
    let mut tx = st.db().begin().await?;
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM key_packages WHERE device_id = $1")
        .bind(ctx.device_id)
        .fetch_one(&mut *tx)
        .await?;
    if n + req.key_packages.len() as i64 > MAX_STORED_PER_DEVICE {
        return Err(AppError::conflict("trop de KeyPackages en réserve"));
    }
    sqlx::query(
        "INSERT INTO key_packages (device_id, data, created_at) SELECT $1, d, $3 FROM UNNEST($2::bytea[]) AS d",
    )
    .bind(ctx.device_id)
    .bind(&req.key_packages)
    .bind(crate::now())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn count(
    State(st): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
) -> AppResult<Json<KeyPackageCount>> {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM key_packages WHERE device_id = $1")
        .bind(ctx.device_id)
        .fetch_one(st.db())
        .await?;
    Ok(Json(KeyPackageCount { count }))
}

#[derive(sqlx::FromRow)]
struct DeviceRow {
    id: Uuid,
    api_key: Vec<u8>,
    mls_signature_key: Vec<u8>,
    cert_created_at: i64,
    cert_signature: Vec<u8>,
}

async fn load_user(st: &AppState, username: &str) -> AppResult<(Vec<u8>, Vec<DeviceRow>)> {
    let acc: Option<(i64, Option<Vec<u8>>)> =
        sqlx::query_as("SELECT id, identity_key FROM accounts WHERE username = $1 AND status = 'active'")
            .bind(username)
            .fetch_optional(st.db())
            .await?;
    let (id, identity) = acc.ok_or_else(AppError::not_found)?;
    let identity = identity.ok_or_else(AppError::not_found)?;
    let devices = sqlx::query_as::<_, DeviceRow>(
        "SELECT id, api_key, mls_signature_key, cert_created_at, cert_signature FROM devices WHERE account_id = $1 ORDER BY created_at",
    )
    .bind(id)
    .fetch_all(st.db())
    .await?;
    Ok((identity, devices))
}

fn publish(d: DeviceRow, key_package: Option<Vec<u8>>) -> PublishedDevice {
    PublishedDevice {
        device_id: d.id,
        api_key: d.api_key,
        mls_signature_key: d.mls_signature_key,
        cert_created_at: d.cert_created_at,
        cert_signature: d.cert_signature,
        key_package,
    }
}

/// Entrée d'annuaire d'un utilisateur de ce site (avec preuve KT).
pub(crate) async fn directory_entry(st: &AppState, username: &str) -> AppResult<UserDirectoryEntry> {
    let kt = crate::kt::lookup(st, username).await?;
    let (identity_key, devices) = load_user(st, username).await?;
    Ok(UserDirectoryEntry {
        username: username.to_owned(),
        identity_key,
        devices: devices.into_iter().map(|d| publish(d, None)).collect(),
        kt,
    })
}

/// Consultation de l'annuaire (sans consommer de KeyPackage). Une adresse
/// `nom@site` d'un autre site est relayée au site concerné (fédération) :
/// le client ne contacte jamais lui-même un site distant.
pub async fn directory(
    State(st): State<AppState>,
    Extension(_ctx): Extension<AuthContext>,
    Path(address): Path<String>,
) -> AppResult<Json<UserDirectoryEntry>> {
    match crate::federation::route(&st, &address)? {
        crate::federation::Route::Local(user) => Ok(Json(directory_entry(&st, &user).await?)),
        crate::federation::Route::Remote(peer, user) => {
            Ok(Json(crate::federation::client::get_json(&st, &peer, &format!("/v1/federation/users/{user}")).await?))
        }
    }
}

pub(crate) fn parse_devices(list: Option<&str>) -> AppResult<Option<Vec<Uuid>>> {
    match list {
        Some(list) => Ok(Some(
            list.split(',')
                .map(|d| d.trim().parse::<Uuid>())
                .collect::<Result<_, _>>()
                .map_err(|_| AppError::bad_request("liste d'appareils invalide"))?,
        )),
        None => Ok(None),
    }
}

#[derive(Deserialize)]
pub struct ClaimQuery {
    /// Appareils visés (séparés par des virgules) ; par défaut tous.
    pub(crate) devices: Option<String>,
}

#[derive(Deserialize)]
pub struct AuditQuery {
    pub(crate) from: u64,
    pub(crate) to: u64,
}

#[derive(Deserialize)]
pub struct SiteQuery {
    /// Site dont on veut le journal (fédération) ; par défaut ce site.
    site: Option<String>,
}

pub async fn kt_head(
    State(st): State<AppState>,
    Extension(_ctx): Extension<AuthContext>,
    Query(q): Query<SiteQuery>,
) -> AppResult<Json<KtHead>> {
    match q.site.as_deref().filter(|s| *s != st.cfg().site_name) {
        None => Ok(Json(crate::kt::head(&st).await?)),
        Some(site) => {
            let peer = crate::federation::peer(&st, site)?;
            let signed: msg_proto::SignedKtHead =
                crate::federation::client::get_json(&st, &peer, "/v1/federation/kt/head").await?;
            crate::federation::verify_signed_head(&peer, &signed)?;
            Ok(Json(signed.head))
        }
    }
}

pub async fn kt_audit(
    State(st): State<AppState>,
    Extension(_ctx): Extension<AuthContext>,
    Query(q): Query<AuditQuery>,
    Query(site): Query<SiteQuery>,
) -> AppResult<Json<KtAudit>> {
    match site.site.as_deref().filter(|s| *s != st.cfg().site_name) {
        None => Ok(Json(crate::kt::audit(&st, q.from, q.to).await?)),
        Some(s) => {
            let peer = crate::federation::peer(&st, s)?;
            let path = format!("/v1/federation/kt/audit?from={}&to={}", q.from, q.to);
            Ok(Json(crate::federation::client::get_json(&st, &peer, &path).await?))
        }
    }
}

/// Réclame un KeyPackage par appareil de l'utilisateur (ou par appareil
/// demandé). La réponse liste tous les appareils, pour la vérification Key
/// Transparency ; seuls ceux qui ont reçu un KeyPackage sont à ajouter.
/// Chaque KeyPackage est
/// à usage unique et supprimé à la distribution, sauf le dernier (« dernier
/// recours », RFC 9420 §16.8) qui est conservé pour ne jamais bloquer
/// l'établissement d'une conversation.
pub async fn claim(
    State(st): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(address): Path<String>,
    Query(q): Query<ClaimQuery>,
) -> AppResult<Json<UserDirectoryEntry>> {
    let wanted = parse_devices(q.devices.as_deref())?;
    match crate::federation::route(&st, &address)? {
        crate::federation::Route::Local(user) => Ok(Json(claim_entry(&st, &user, Some(ctx.device_id), wanted).await?)),
        crate::federation::Route::Remote(peer, user) => {
            let mut path = format!("/v1/federation/users/{user}/claim");
            if let Some(d) = &q.devices {
                path.push_str(&format!("?devices={d}"));
            }
            Ok(Json(crate::federation::client::post_json(&st, &peer, &path, &()).await?))
        }
    }
}

/// Réclamation de KeyPackages pour un utilisateur de ce site.
pub(crate) async fn claim_entry(
    st: &AppState,
    username: &str,
    requester: Option<Uuid>,
    wanted: Option<Vec<Uuid>>,
) -> AppResult<UserDirectoryEntry> {
    let username = username.to_owned();
    let kt = crate::kt::lookup(st, &username).await?;
    let (identity_key, devices) = load_user(st, &username).await?;
    let mut out = Vec::with_capacity(devices.len());
    let mut claimed = 0;
    for d in devices {
        if Some(d.id) == requester || wanted.as_ref().is_some_and(|w| !w.contains(&d.id)) {
            out.push(publish(d, None));
            continue;
        }
        let mut tx = st.db().begin().await?;
        let rows: Vec<(i64, Vec<u8>)> =
            sqlx::query_as("SELECT id, data FROM key_packages WHERE device_id = $1 ORDER BY id LIMIT 2 FOR UPDATE")
                .bind(d.id)
                .fetch_all(&mut *tx)
                .await?;
        let kp = match rows.as_slice() {
            [] => None,
            [(_, data)] => Some(data.clone()),
            [(id, data), ..] => {
                sqlx::query("DELETE FROM key_packages WHERE id = $1").bind(id).execute(&mut *tx).await?;
                Some(data.clone())
            }
        };
        tx.commit().await?;
        if kp.is_some() {
            claimed += 1;
        }
        out.push(publish(d, kp));
    }
    if claimed == 0 {
        return Err(AppError::not_found());
    }
    Ok(UserDirectoryEntry { username, identity_key, devices: out, kt })
}
