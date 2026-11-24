//! Passkeys et clés de sécurité FIDO2 (YubiKey) : enregistrement par un
//! utilisateur connecté, défi de connexion délivré après le mot de passe.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use msg_proto::{
    AccountStatus, ErrorCode, WebauthnChallenge, WebauthnChallengeRequest, WebauthnCredentialSummary,
    WebauthnRegisterFinish,
};
use uuid::Uuid;
use webauthn_rs::prelude::{Passkey, PasskeyRegistration, RegisterPublicKeyCredential};
use webauthn_rs::Webauthn;

use crate::auth::AuthContext;
use crate::error::{AppError, AppResult};
use crate::routes::account::{check_credentials, SecondFactor};
use crate::state::AppState;

const CHALLENGE_TTL_SECS: i64 = 300;
const MAX_CREDENTIALS: i64 = 10;

fn wa(st: &AppState) -> AppResult<&Webauthn> {
    st.inner.webauthn.as_ref().ok_or_else(|| {
        AppError::new(StatusCode::NOT_IMPLEMENTED, ErrorCode::BadRequest, "WebAuthn n'est pas configuré sur ce serveur")
    })
}

fn json_err<E: std::fmt::Display>(e: E) -> AppError {
    AppError::from(anyhow::anyhow!("{e}"))
}

async fn passkeys(st: &AppState, account_id: i64) -> AppResult<Vec<Passkey>> {
    let rows: Vec<(String,)> = sqlx::query_as("SELECT passkey FROM webauthn_credentials WHERE account_id = $1")
        .bind(account_id)
        .fetch_all(st.db())
        .await?;
    rows.into_iter().map(|(p,)| serde_json::from_str(&p).map_err(json_err)).collect()
}

async fn store_challenge(st: &AppState, account_id: i64, kind: &str, state: String) -> AppResult<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO webauthn_challenges (id, account_id, kind, state, expires_at) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(account_id)
    .bind(kind)
    .bind(state)
    .bind(crate::now() + CHALLENGE_TTL_SECS)
    .execute(st.db())
    .await?;
    Ok(id)
}

pub async fn register_start(
    State(st): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
) -> AppResult<Json<WebauthnChallenge>> {
    let wa = wa(&st)?;
    let existing = passkeys(&st, ctx.account_id).await?;
    if existing.len() as i64 >= MAX_CREDENTIALS {
        return Err(AppError::conflict("nombre maximal de clés atteint"));
    }
    // Identifiant WebAuthn opaque et stable de l'utilisateur.
    let (user_id,): (Uuid,) = sqlx::query_as(
        "UPDATE accounts SET webauthn_user_id = COALESCE(webauthn_user_id, $2) WHERE id = $1 RETURNING webauthn_user_id",
    )
    .bind(ctx.account_id)
    .bind(Uuid::new_v4())
    .fetch_one(st.db())
    .await?;
    let exclude = existing.iter().map(|p| p.cred_id().clone()).collect::<Vec<_>>();
    let (options, state) =
        wa.start_passkey_registration(user_id, &ctx.username, &ctx.username, Some(exclude)).map_err(json_err)?;
    let id = store_challenge(&st, ctx.account_id, "register", serde_json::to_string(&state).map_err(json_err)?).await?;
    Ok(Json(WebauthnChallenge { challenge_id: id, options: serde_json::to_value(options).map_err(json_err)? }))
}

pub async fn register_finish(
    State(st): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Json(req): Json<WebauthnRegisterFinish>,
) -> AppResult<Json<WebauthnCredentialSummary>> {
    let wa = wa(&st)?;
    let name = req.name.trim();
    if name.is_empty() || name.chars().count() > 64 {
        return Err(AppError::bad_request("nom de clé invalide (1 à 64 caractères)"));
    }
    let row: Option<(String,)> = sqlx::query_as(
        "DELETE FROM webauthn_challenges WHERE id = $1 AND account_id = $2 AND kind = 'register' AND expires_at > $3
         RETURNING state",
    )
    .bind(req.challenge_id)
    .bind(ctx.account_id)
    .bind(crate::now())
    .fetch_optional(st.db())
    .await?;
    let (state,) = row.ok_or_else(|| AppError::bad_request("défi inconnu ou expiré"))?;
    let state: PasskeyRegistration = serde_json::from_str(&state).map_err(json_err)?;
    let cred: RegisterPublicKeyCredential = serde_json::from_value(req.credential)
        .map_err(|_| AppError::bad_request("réponse d'authentificateur invalide"))?;
    let passkey = wa
        .finish_passkey_registration(&cred, &state)
        .map_err(|e| AppError::bad_request(format!("enregistrement refusé : {e}")))?;
    let now = crate::now();
    let cred_id: &[u8] = passkey.cred_id().as_ref();
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO webauthn_credentials (account_id, credential_id, name, passkey, created_at) VALUES ($1, $2, $3, $4, $5)
         RETURNING id",
    )
    .bind(ctx.account_id)
    .bind(cred_id)
    .bind(name)
    .bind(serde_json::to_string(&passkey).map_err(json_err)?)
    .bind(now)
    .fetch_one(st.db())
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(d) if d.is_unique_violation() => AppError::conflict("clé déjà enregistrée"),
        e => AppError::from(e),
    })?;
    Ok(Json(WebauthnCredentialSummary { id, name: name.into(), created_at: now, last_used_at: None }))
}

pub async fn list(
    State(st): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
) -> AppResult<Json<Vec<WebauthnCredentialSummary>>> {
    let rows: Vec<(i64, String, i64, Option<i64>)> = sqlx::query_as(
        "SELECT id, name, created_at, last_used_at FROM webauthn_credentials WHERE account_id = $1 ORDER BY created_at",
    )
    .bind(ctx.account_id)
    .fetch_all(st.db())
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|(id, name, created_at, last_used_at)| WebauthnCredentialSummary {
                id,
                name,
                created_at,
                last_used_at,
            })
            .collect(),
    ))
}

pub async fn delete(
    State(st): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> AppResult<StatusCode> {
    let r = sqlx::query("DELETE FROM webauthn_credentials WHERE id = $1 AND account_id = $2")
        .bind(id)
        .bind(ctx.account_id)
        .execute(st.db())
        .await?;
    if r.rows_affected() == 0 {
        return Err(AppError::not_found());
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Défi de connexion : délivré seulement après vérification du mot de passe
/// (avec le même compteur d'échecs que la connexion).
pub async fn login_challenge(
    State(st): State<AppState>,
    Json(req): Json<WebauthnChallengeRequest>,
) -> AppResult<Json<WebauthnChallenge>> {
    let wa = wa(&st)?;
    let mut tx = st.db().begin().await?;
    let res = check_credentials(
        &st,
        &mut tx,
        &req.username,
        &req.password,
        SecondFactor::PasswordOnly,
        AccountStatus::Active,
    )
    .await;
    let acc = match res {
        Ok(a) => a,
        Err(e) => {
            tx.commit().await?;
            return Err(e);
        }
    };
    tx.commit().await?;
    let creds = passkeys(&st, acc.id).await?;
    if creds.is_empty() {
        return Err(AppError::bad_request("aucune clé de sécurité enregistrée pour ce compte"));
    }
    let (options, state) = wa.start_passkey_authentication(&creds).map_err(json_err)?;
    let id = store_challenge(&st, acc.id, "authenticate", serde_json::to_string(&state).map_err(json_err)?).await?;
    Ok(Json(WebauthnChallenge { challenge_id: id, options: serde_json::to_value(options).map_err(json_err)? }))
}
