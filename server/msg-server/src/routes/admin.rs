//! Administration des comptes. Aucune route ne permet d'accéder au contenu
//! des messages : c'est cryptographiquement impossible pour le serveur.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use msg_proto::{
    validate_username, AccountStatus, AccountSummary, ActivationCodeResponse, CreateAccountRequest, DeviceSummary,
    Role, SetRoleRequest, SetStatusRequest,
};
use uuid::Uuid;

use crate::auth::AuthContext;
use crate::error::{AppError, AppResult};
use crate::passwords::new_activation_code;
use crate::state::AppState;

async fn audit<'e, E: sqlx::PgExecutor<'e>>(db: E, actor: &str, action: &str, target: &str) -> AppResult<()> {
    sqlx::query("INSERT INTO admin_audit (at, actor, action, target) VALUES ($1, $2, $3, $4)")
        .bind(crate::now())
        .bind(actor)
        .bind(action)
        .bind(target)
        .execute(db)
        .await?;
    Ok(())
}

/// Création directe en base, réservée à l'amorçage du premier administrateur
/// (`msg-server bootstrap-admin`). Refuse s'il existe déjà un administrateur.
pub async fn bootstrap_admin(
    db: &sqlx::PgPool,
    username: &str,
    activation_ttl: i64,
) -> anyhow::Result<ActivationCodeResponse> {
    validate_username(username).map_err(|e| anyhow::anyhow!(e))?;
    let mut tx = db.begin().await?;
    sqlx::query("LOCK TABLE accounts IN EXCLUSIVE MODE").execute(&mut *tx).await?;
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM accounts WHERE role = 'admin'").fetch_one(&mut *tx).await?;
    if n > 0 {
        anyhow::bail!("un administrateur existe déjà : utilisez msg-admin");
    }
    let (code, hash) = new_activation_code()?;
    let now = crate::now();
    sqlx::query(
        "INSERT INTO accounts (username, role, status, activation_code_hash, activation_expires_at, created_at)
         VALUES ($1, 'admin', 'pending_activation', $2, $3, $4)",
    )
    .bind(username)
    .bind(hash)
    .bind(now + activation_ttl)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    audit(&mut *tx, "<bootstrap>", "create_admin", username).await.map_err(|e| anyhow::anyhow!(e.message))?;
    tx.commit().await?;
    Ok(ActivationCodeResponse { username: username.into(), activation_code: code, expires_at: now + activation_ttl })
}

pub async fn create(
    State(st): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Json(req): Json<CreateAccountRequest>,
) -> AppResult<Json<ActivationCodeResponse>> {
    ctx.require_admin()?;
    validate_username(&req.username).map_err(AppError::bad_request)?;
    let (code, hash) = new_activation_code()?;
    let now = crate::now();
    let exp = now + st.cfg().activation_ttl_secs;
    let mut tx = st.db().begin().await?;
    let r = sqlx::query(
        "INSERT INTO accounts (username, role, status, activation_code_hash, activation_expires_at, created_at)
         VALUES ($1, $2, 'pending_activation', $3, $4, $5) ON CONFLICT (username) DO NOTHING",
    )
    .bind(&req.username)
    .bind(req.role.as_str())
    .bind(hash)
    .bind(exp)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    if r.rows_affected() == 0 {
        return Err(AppError::conflict("identifiant déjà utilisé"));
    }
    audit(&mut *tx, &ctx.username, &format!("create_{}", req.role.as_str()), &req.username).await?;
    tx.commit().await?;
    Ok(Json(ActivationCodeResponse { username: req.username, activation_code: code, expires_at: exp }))
}

pub async fn list(
    State(st): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
) -> AppResult<Json<Vec<AccountSummary>>> {
    ctx.require_admin()?;
    let rows: Vec<(String, String, String, i64, i64)> = sqlx::query_as(
        "SELECT a.username, a.role, a.status, a.created_at,
                (SELECT COUNT(*) FROM devices d WHERE d.account_id = a.id)
           FROM accounts a ORDER BY a.username",
    )
    .fetch_all(st.db())
    .await?;
    rows.into_iter()
        .map(|(username, role, status, created_at, device_count)| {
            Ok(AccountSummary {
                username,
                role: Role::parse(&role).ok_or_else(AppError::internal)?,
                status: AccountStatus::parse(&status).ok_or_else(AppError::internal)?,
                created_at,
                device_count,
            })
        })
        .collect::<AppResult<Vec<_>>>()
        .map(Json)
}

fn not_self(ctx: &AuthContext, username: &str) -> AppResult<()> {
    if ctx.username == username {
        Err(AppError::bad_request("un administrateur ne peut pas modifier son propre compte par cette route"))
    } else {
        Ok(())
    }
}

pub async fn set_status(
    State(st): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(username): Path<String>,
    Json(req): Json<SetStatusRequest>,
) -> AppResult<StatusCode> {
    ctx.require_admin()?;
    not_self(&ctx, &username)?;
    let mut tx = st.db().begin().await?;
    let (from, to) = match req.status {
        AccountStatus::Suspended => ("active", "suspended"),
        AccountStatus::Active => ("suspended", "active"),
        _ => return Err(AppError::bad_request("statut cible invalide")),
    };
    let row: Option<(i64,)> =
        sqlx::query_as("UPDATE accounts SET status = $3 WHERE username = $1 AND status = $2 RETURNING id")
            .bind(&username)
            .bind(from)
            .bind(to)
            .fetch_optional(&mut *tx)
            .await?;
    let (id,) = row.ok_or_else(|| AppError::conflict("transition de statut impossible"))?;
    if to == "suspended" {
        // Révocation immédiate des sessions.
        sqlx::query("DELETE FROM sessions s USING devices d WHERE s.device_id = d.id AND d.account_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    audit(&mut *tx, &ctx.username, &format!("set_status_{to}"), &username).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn set_role(
    State(st): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(username): Path<String>,
    Json(req): Json<SetRoleRequest>,
) -> AppResult<StatusCode> {
    ctx.require_admin()?;
    not_self(&ctx, &username)?;
    let mut tx = st.db().begin().await?;
    let r = sqlx::query("UPDATE accounts SET role = $2 WHERE username = $1")
        .bind(&username)
        .bind(req.role.as_str())
        .execute(&mut *tx)
        .await?;
    if r.rows_affected() == 0 {
        return Err(AppError::not_found());
    }
    audit(&mut *tx, &ctx.username, &format!("set_role_{}", req.role.as_str()), &username).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Réinitialisation complète : nouveau code d'activation, suppression du mot
/// de passe, du TOTP, de la clé d'identité et de tous les appareils. Les
/// correspondants verront un **changement de clé d'identité**.
pub async fn reset(
    State(st): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(username): Path<String>,
) -> AppResult<Json<ActivationCodeResponse>> {
    ctx.require_admin()?;
    not_self(&ctx, &username)?;
    let (code, hash) = new_activation_code()?;
    let exp = crate::now() + st.cfg().activation_ttl_secs;
    let mut tx = st.db().begin().await?;
    let row: Option<(i64,)> = sqlx::query_as(
        "UPDATE accounts SET status = 'pending_activation', password_hash = NULL, totp_secret_enc = NULL,
                totp_last_step = NULL, identity_key = NULL, activation_code_hash = $2,
                activation_expires_at = $3, failed_logins = 0, locked_until = NULL
          WHERE username = $1 RETURNING id",
    )
    .bind(&username)
    .bind(hash)
    .bind(exp)
    .fetch_optional(&mut *tx)
    .await?;
    let (id,) = row.ok_or_else(AppError::not_found)?;
    sqlx::query("DELETE FROM devices WHERE account_id = $1").bind(id).execute(&mut *tx).await?;
    audit(&mut *tx, &ctx.username, "reset", &username).await?;
    tx.commit().await?;
    Ok(Json(ActivationCodeResponse { username, activation_code: code, expires_at: exp }))
}

pub async fn devices(
    State(st): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(username): Path<String>,
) -> AppResult<Json<Vec<DeviceSummary>>> {
    ctx.require_admin()?;
    let rows: Vec<(Uuid, i64, Option<i64>)> = sqlx::query_as(
        "SELECT d.id, d.created_at, d.last_seen_at FROM devices d JOIN accounts a ON a.id = d.account_id
          WHERE a.username = $1 ORDER BY d.created_at",
    )
    .bind(&username)
    .fetch_all(st.db())
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|(device_id, created_at, last_seen_at)| DeviceSummary { device_id, created_at, last_seen_at })
            .collect(),
    ))
}

/// Révocation d'un appareil : sessions, KeyPackages et files supprimés.
/// (Le retrait cryptographique des groupes MLS arrive en Phase 3.)
pub async fn revoke_device(
    State(st): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path((username, device_id)): Path<(String, Uuid)>,
) -> AppResult<StatusCode> {
    ctx.require_admin()?;
    let mut tx = st.db().begin().await?;
    let r = sqlx::query(
        "DELETE FROM devices d USING accounts a WHERE d.account_id = a.id AND a.username = $1 AND d.id = $2",
    )
    .bind(&username)
    .bind(device_id)
    .execute(&mut *tx)
    .await?;
    if r.rows_affected() == 0 {
        return Err(AppError::not_found());
    }
    audit(&mut *tx, &ctx.username, "revoke_device", &format!("{username}/{device_id}")).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
