//! Appareils d'un compte : liaison d'un nouvel appareil et révocation.
//!
//! Liaison (aucune clé privée ne quitte un appareil) :
//! 1. le nouvel appareil s'authentifie (mot de passe + second facteur) et
//!    publie ses clés **publiques** : une demande en attente est créée ;
//! 2. un appareil détenteur de la clé d'identité compare l'empreinte
//!    affichée par le nouvel appareil, puis signe son certificat ;
//! 3. le serveur vérifie ce certificat avec la clé d'identité du compte,
//!    enregistre l'appareil, et le nouvel appareil récupère (une seule fois)
//!    son certificat et une session.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use msg_crypto::identity::DeviceCertificate;
use msg_proto::{
    AccountStatus, DeviceRegistration, LinkApproveRequest, LinkPollRequest, LinkPollResponse, LinkRequestView,
    LinkStartRequest, LinkStartResponse, LinkStatus, OwnDevice, PendingDevice,
};
use sqlx::{Postgres, Transaction};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use super::account::{check_credentials, check_len, new_session, SecondFactor, MAX_DEVICES};
use crate::auth::AuthContext;
use crate::error::{AppError, AppResult};
use crate::passwords::{new_token, token_hash};
use crate::state::AppState;

/// Durée de validité d'une demande de liaison.
pub const LINK_TTL_SECS: i64 = 600;
/// Demandes en attente simultanées par compte.
const MAX_PENDING_LINKS: i64 = 3;

/// Révoque un appareil : il disparaît de l'annuaire (ses KeyPackages, sa
/// session et sa file sont supprimés en cascade) et sa clé API est conservée
/// pour qu'il apprenne sa révocation à sa prochaine requête.
pub(crate) async fn revoke(tx: &mut Transaction<'_, Postgres>, account_id: i64, device_id: Uuid) -> AppResult<bool> {
    let row: Option<(Vec<u8>,)> =
        sqlx::query_as("DELETE FROM devices WHERE id = $1 AND account_id = $2 RETURNING api_key")
            .bind(device_id)
            .bind(account_id)
            .fetch_optional(&mut **tx)
            .await?;
    let Some((api_key,)) = row else { return Ok(false) };
    sqlx::query(
        "INSERT INTO revoked_devices (device_id, account_id, api_key, revoked_at) VALUES ($1, $2, $3, $4)
         ON CONFLICT (device_id) DO NOTHING",
    )
    .bind(device_id)
    .bind(account_id)
    .bind(api_key)
    .bind(crate::now())
    .execute(&mut **tx)
    .await?;
    crate::kt::mark_dirty(&mut **tx, account_id).await?;
    Ok(true)
}

/// Publie aussitôt les changements dans le journal Key Transparency. En cas
/// d'échec, la publication aura lieu avant la prochaine consultation de
/// l'annuaire (les comptes restent marqués « à publier »).
pub(crate) async fn publish_now(st: &AppState) {
    if let Err(e) = crate::kt::flush(st).await {
        tracing::warn!(error = %e.message, "publication Key Transparency différée");
    }
}

/// Étape 1 (publique) : le nouvel appareil demande sa liaison.
pub async fn link_start(
    State(st): State<AppState>,
    Json(req): Json<LinkStartRequest>,
) -> AppResult<Json<LinkStartResponse>> {
    check_len(&req.device.api_key, 32, "clé API")?;
    check_len(&req.device.mls_signature_key, 32, "clé MLS")?;
    let mut tx = st.db().begin().await?;
    let second = match &req.webauthn {
        Some(a) => SecondFactor::Webauthn(a),
        None => SecondFactor::Totp(&req.totp_code),
    };
    let acc = match check_credentials(&st, &mut tx, &req.username, &req.password, second, AccountStatus::Active).await {
        Ok(a) => a,
        Err(e) => {
            tx.commit().await?; // conserve le compteur d'échecs
            return Err(e);
        }
    };
    if acc.identity_key.is_none() {
        return Err(AppError::conflict("aucun appareil principal : terminez d'abord l'activation"));
    }
    let now = crate::now();
    sqlx::query("DELETE FROM link_requests WHERE expires_at <= $1").bind(now).execute(&mut *tx).await?;
    let taken: (bool,) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM devices WHERE id = $1)
             OR EXISTS (SELECT 1 FROM revoked_devices WHERE device_id = $1)
             OR EXISTS (SELECT 1 FROM link_requests WHERE device_id = $1)",
    )
    .bind(req.device.device_id)
    .fetch_one(&mut *tx)
    .await?;
    if taken.0 {
        return Err(AppError::conflict("identifiant d'appareil déjà utilisé"));
    }
    let (pending,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM link_requests WHERE account_id = $1 AND status = 'pending'")
            .bind(acc.id)
            .fetch_one(&mut *tx)
            .await?;
    let (devices,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM devices WHERE account_id = $1").bind(acc.id).fetch_one(&mut *tx).await?;
    if pending >= MAX_PENDING_LINKS {
        return Err(AppError::conflict("trop de demandes de liaison en attente"));
    }
    if devices >= MAX_DEVICES {
        return Err(AppError::conflict("nombre maximal d'appareils atteint"));
    }
    let link_id = Uuid::new_v4();
    let (poll_secret, poll_hash) = new_token()?;
    let expires_at = now + LINK_TTL_SECS;
    sqlx::query(
        "INSERT INTO link_requests (id, account_id, device_id, api_key, mls_signature_key, poll_hash, status, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8)",
    )
    .bind(link_id)
    .bind(acc.id)
    .bind(req.device.device_id)
    .bind(&req.device.api_key)
    .bind(&req.device.mls_signature_key)
    .bind(poll_hash)
    .bind(now)
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(LinkStartResponse { link_id, poll_secret, expires_at }))
}

#[derive(sqlx::FromRow)]
struct LinkRow {
    id: Uuid,
    account_id: i64,
    device_id: Uuid,
    api_key: Vec<u8>,
    mls_signature_key: Vec<u8>,
    poll_hash: Vec<u8>,
    status: String,
    created_at: i64,
    expires_at: i64,
}

/// Étape 3 (publique, authentifiée par le secret de consultation).
pub async fn link_poll(
    State(st): State<AppState>,
    Json(req): Json<LinkPollRequest>,
) -> AppResult<Json<LinkPollResponse>> {
    let mut tx = st.db().begin().await?;
    let row: Option<LinkRow> = sqlx::query_as(
        "SELECT id, account_id, device_id, api_key, mls_signature_key, poll_hash, status, created_at, expires_at
           FROM link_requests WHERE id = $1 FOR UPDATE",
    )
    .bind(req.link_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else { return Err(AppError::not_found()) };
    if !bool::from(token_hash(&req.poll_secret).ct_eq(&row.poll_hash)) {
        return Err(AppError::not_found());
    }
    let done = |status| Json(LinkPollResponse { status, registration: None, tokens: None });
    let now = crate::now();
    match row.status.as_str() {
        "pending" if row.expires_at > now => return Ok(done(LinkStatus::Pending)),
        "pending" => {
            sqlx::query("DELETE FROM link_requests WHERE id = $1").bind(req.link_id).execute(&mut *tx).await?;
            tx.commit().await?;
            return Ok(done(LinkStatus::Expired));
        }
        "rejected" => {
            sqlx::query("DELETE FROM link_requests WHERE id = $1").bind(req.link_id).execute(&mut *tx).await?;
            tx.commit().await?;
            return Ok(done(LinkStatus::Rejected));
        }
        _ => {}
    }
    // Approuvée : l'appareil a été enregistré lors de l'approbation.
    let dev: Option<(i64, Vec<u8>, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT d.cert_created_at, d.cert_signature, a.identity_key
           FROM devices d JOIN accounts a ON a.id = d.account_id WHERE d.id = $1 AND d.account_id = $2",
    )
    .bind(row.device_id)
    .bind(row.account_id)
    .fetch_optional(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM link_requests WHERE id = $1").bind(req.link_id).execute(&mut *tx).await?;
    let Some((cert_created_at, cert_signature, Some(identity_key))) = dev else {
        // Appareil révoqué entre l'approbation et la consultation.
        tx.commit().await?;
        return Ok(done(LinkStatus::Rejected));
    };
    let tokens = new_session(&st, &mut tx, row.device_id).await?;
    tx.commit().await?;
    Ok(Json(LinkPollResponse {
        status: LinkStatus::Approved,
        registration: Some(DeviceRegistration {
            device_id: row.device_id,
            identity_key,
            api_key: row.api_key,
            mls_signature_key: row.mls_signature_key,
            cert_created_at,
            cert_signature,
        }),
        tokens: Some(tokens),
    }))
}

/// Demandes de liaison en attente pour le compte courant.
pub async fn link_requests(
    State(st): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
) -> AppResult<Json<Vec<LinkRequestView>>> {
    let rows: Vec<LinkRow> = sqlx::query_as(
        "SELECT id, account_id, device_id, api_key, mls_signature_key, poll_hash, status, created_at, expires_at
           FROM link_requests WHERE account_id = $1 AND status = 'pending' AND expires_at > $2 ORDER BY created_at",
    )
    .bind(ctx.account_id)
    .bind(crate::now())
    .fetch_all(st.db())
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| LinkRequestView {
                link_id: r.id,
                device: PendingDevice {
                    device_id: r.device_id,
                    api_key: r.api_key,
                    mls_signature_key: r.mls_signature_key,
                },
                created_at: r.created_at,
                expires_at: r.expires_at,
            })
            .collect(),
    ))
}

/// Étape 2 : approbation par un appareil détenteur de la clé d'identité.
/// Le serveur ne fait confiance qu'à la signature du certificat.
pub async fn link_approve(
    State(st): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(link_id): Path<Uuid>,
    Json(req): Json<LinkApproveRequest>,
) -> AppResult<StatusCode> {
    let mut tx = st.db().begin().await?;
    let row: Option<LinkRow> = sqlx::query_as(
        "SELECT id, account_id, device_id, api_key, mls_signature_key, poll_hash, status, created_at, expires_at
           FROM link_requests WHERE id = $1 AND account_id = $2 FOR UPDATE",
    )
    .bind(link_id)
    .bind(ctx.account_id)
    .fetch_optional(&mut *tx)
    .await?;
    let row = row.filter(|r| r.status == "pending" && r.expires_at > crate::now()).ok_or_else(AppError::not_found)?;
    let (identity_key,): (Option<Vec<u8>>,) =
        sqlx::query_as("SELECT identity_key FROM accounts WHERE id = $1 FOR UPDATE")
            .bind(ctx.account_id)
            .fetch_one(&mut *tx)
            .await?;
    let identity_key = identity_key.ok_or_else(AppError::forbidden)?;
    let cert = DeviceCertificate {
        username: ctx.username.clone(),
        device_id: row.device_id,
        api_key: row.api_key.clone(),
        mls_signature_key: row.mls_signature_key.clone(),
        created_at: req.cert_created_at,
    };
    super::account::verify_device_cert((&ctx.username, &st.cfg().site_name), cert, &identity_key, &req.cert_signature)?;
    let (devices,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM devices WHERE account_id = $1")
        .bind(ctx.account_id)
        .fetch_one(&mut *tx)
        .await?;
    if devices >= MAX_DEVICES {
        return Err(AppError::conflict("nombre maximal d'appareils atteint"));
    }
    sqlx::query(
        "INSERT INTO devices (id, account_id, api_key, mls_signature_key, cert_created_at, cert_signature, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(row.device_id)
    .bind(ctx.account_id)
    .bind(&row.api_key)
    .bind(&row.mls_signature_key)
    .bind(req.cert_created_at)
    .bind(&req.cert_signature)
    .bind(crate::now())
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE link_requests SET status = 'approved' WHERE id = $1").bind(link_id).execute(&mut *tx).await?;
    crate::kt::mark_dirty(&mut *tx, ctx.account_id).await?;
    tx.commit().await?;
    publish_now(&st).await;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn link_reject(
    State(st): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(link_id): Path<Uuid>,
) -> AppResult<StatusCode> {
    let r = sqlx::query(
        "UPDATE link_requests SET status = 'rejected' WHERE id = $1 AND account_id = $2 AND status = 'pending'",
    )
    .bind(link_id)
    .bind(ctx.account_id)
    .execute(st.db())
    .await?;
    if r.rows_affected() == 0 {
        return Err(AppError::not_found());
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Appareils du compte courant.
pub async fn list(
    State(st): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
) -> AppResult<Json<Vec<OwnDevice>>> {
    let rows: Vec<(Uuid, i64, Option<i64>)> =
        sqlx::query_as("SELECT id, created_at, last_seen_at FROM devices WHERE account_id = $1 ORDER BY created_at")
            .bind(ctx.account_id)
            .fetch_all(st.db())
            .await?;
    Ok(Json(
        rows.into_iter()
            .map(|(device_id, created_at, last_seen_at)| OwnDevice {
                device_id,
                created_at,
                last_seen_at,
                current: device_id == ctx.device_id,
            })
            .collect(),
    ))
}

/// Révocation d'un autre appareil du compte (appareil perdu ou volé).
pub async fn revoke_own(
    State(st): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(device_id): Path<Uuid>,
) -> AppResult<StatusCode> {
    if device_id == ctx.device_id {
        return Err(AppError::bad_request("utilisez la déconnexion pour l'appareil courant"));
    }
    let mut tx = st.db().begin().await?;
    if !revoke(&mut tx, ctx.account_id, device_id).await? {
        return Err(AppError::not_found());
    }
    tx.commit().await?;
    publish_now(&st).await;
    Ok(StatusCode::NO_CONTENT)
}
