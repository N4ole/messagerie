//! Activation, connexion, renouvellement et fermeture de session.

use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use msg_crypto::identity::DeviceCertificate;
use msg_proto::{
    validate_password, AccountStatus, ActivateRequest, ActivateResponse, ConfirmTotpRequest, DeviceRegistration,
    ErrorCode, LoginRequest, RefreshRequest, SessionTokens, WebauthnAssertion,
};
use sqlx::{Postgres, Transaction};
use subtle::ConstantTimeEq;
use webauthn_rs::prelude::{Passkey, PasskeyAuthentication, PublicKeyCredential};

use crate::auth::{AuthContext, SignedDevice};
use crate::error::{AppError, AppResult};
use crate::passwords::{self, activation_hash, new_token, token_hash, PasswordHasherCfg};
use crate::state::AppState;

/// Nombre maximal d'appareils par compte.
const MAX_DEVICES: i64 = 10;

#[derive(sqlx::FromRow)]
pub(crate) struct AccountRow {
    pub(crate) id: i64,
    status: String,
    password_hash: Option<String>,
    totp_secret_enc: Option<Vec<u8>>,
    totp_last_step: Option<i64>,
    identity_key: Option<Vec<u8>>,
    activation_code_hash: Option<Vec<u8>>,
    activation_expires_at: Option<i64>,
    failed_logins: i32,
    locked_until: Option<i64>,
}

async fn lock_account(tx: &mut Transaction<'_, Postgres>, username: &str) -> AppResult<Option<AccountRow>> {
    Ok(sqlx::query_as::<_, AccountRow>(
        "SELECT id, status, password_hash, totp_secret_enc, totp_last_step, identity_key,
                activation_code_hash, activation_expires_at, failed_logins, locked_until
           FROM accounts WHERE username = $1 FOR UPDATE",
    )
    .bind(username)
    .fetch_optional(&mut **tx)
    .await?)
}

/// Vérification Argon2id hors du runtime asynchrone (calcul coûteux).
async fn verify_password(st: &AppState, password: String, stored: Option<String>) -> AppResult<bool> {
    let st = st.clone();
    tokio::task::spawn_blocking(move || {
        let h = PasswordHasherCfg { pepper: st.inner.secrets.pepper.as_ref(), cfg: st.cfg() };
        h.verify(&password, stored.as_deref())
    })
    .await
    .map_err(|_| AppError::internal())?
    .map_err(AppError::from)
}

async fn hash_password(st: &AppState, password: String) -> AppResult<String> {
    let st = st.clone();
    tokio::task::spawn_blocking(move || {
        let h = PasswordHasherCfg { pepper: st.inner.secrets.pepper.as_ref(), cfg: st.cfg() };
        h.hash(&password)
    })
    .await
    .map_err(|_| AppError::internal())?
    .map_err(AppError::from)
}

pub async fn activate(
    State(st): State<AppState>,
    Json(req): Json<ActivateRequest>,
) -> AppResult<Json<ActivateResponse>> {
    validate_password(&req.new_password).map_err(AppError::bad_request)?;
    let now = crate::now();
    let mut tx = st.db().begin().await?;
    let acc = lock_account(&mut tx, &req.username).await?;
    let valid = match &acc {
        Some(a) => {
            a.status == AccountStatus::PendingActivation.as_str()
                && a.activation_expires_at.is_some_and(|e| e > now)
                && a.activation_code_hash
                    .as_deref()
                    .is_some_and(|h| bool::from(h.ct_eq(&activation_hash(&req.activation_code))))
        }
        None => false,
    };
    let Some(acc) = acc.filter(|_| valid) else {
        return Err(AppError::invalid_credentials());
    };
    let hash = hash_password(&st, req.new_password.clone()).await?;
    let secret = passwords::new_totp_secret()?;
    let sealed = st.inner.secrets.seal_totp(&req.username, &secret)?;
    sqlx::query(
        "UPDATE accounts SET password_hash = $2, totp_secret_enc = $3, totp_last_step = NULL,
                status = 'pending_totp', activation_code_hash = NULL, activation_expires_at = NULL
          WHERE id = $1",
    )
    .bind(acc.id)
    .bind(hash)
    .bind(sealed)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let t = passwords::totp(&secret, &st.cfg().site_name, &req.username)?;
    Ok(Json(ActivateResponse { totp_secret_base32: passwords::totp_base32(&secret), otpauth_uri: t.get_url() }))
}

/// Second facteur présenté avec le mot de passe.
pub(crate) enum SecondFactor<'a> {
    Totp(&'a str),
    Webauthn(&'a WebauthnAssertion),
    /// Mot de passe seul : uniquement pour délivrer un défi WebAuthn.
    PasswordOnly,
}

async fn record_failure(st: &AppState, tx: &mut Transaction<'_, Postgres>, acc: &AccountRow) -> AppResult<()> {
    let now = crate::now();
    let failed = acc.failed_logins + 1;
    let (failed, locked) =
        if failed >= st.cfg().max_failed_logins { (0, Some(now + st.cfg().lockout_secs)) } else { (failed, None) };
    sqlx::query("UPDATE accounts SET failed_logins = $2, locked_until = COALESCE($3, locked_until) WHERE id = $1")
        .bind(acc.id)
        .bind(failed)
        .bind(locked)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Vérifie l'assertion WebAuthn d'un défi d'authentification (usage unique).
async fn verify_webauthn(
    st: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    account_id: i64,
    a: &WebauthnAssertion,
) -> AppResult<bool> {
    let Some(wa) = st.inner.webauthn.as_ref() else { return Ok(false) };
    let row: Option<(String,)> = sqlx::query_as(
        "DELETE FROM webauthn_challenges WHERE id = $1 AND account_id = $2 AND kind = 'authenticate' AND expires_at > $3
         RETURNING state",
    )
    .bind(a.challenge_id)
    .bind(account_id)
    .bind(crate::now())
    .fetch_optional(&mut **tx)
    .await?;
    let Some((state,)) = row else { return Ok(false) };
    let Ok(state) = serde_json::from_str::<PasskeyAuthentication>(&state) else { return Ok(false) };
    let Ok(cred) = serde_json::from_value::<PublicKeyCredential>(a.credential.clone()) else { return Ok(false) };
    let Ok(result) = wa.finish_passkey_authentication(&cred, &state) else { return Ok(false) };
    let cred_id: &[u8] = result.cred_id().as_ref();
    let stored: Option<(i64, String)> = sqlx::query_as(
        "SELECT id, passkey FROM webauthn_credentials WHERE account_id = $1 AND credential_id = $2 FOR UPDATE",
    )
    .bind(account_id)
    .bind(cred_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((id, pk)) = stored else { return Ok(false) };
    let mut passkey: Passkey = serde_json::from_str(&pk).map_err(|e| anyhow::anyhow!(e))?;
    passkey.update_credential(&result);
    sqlx::query("UPDATE webauthn_credentials SET passkey = $2, last_used_at = $3 WHERE id = $1")
        .bind(id)
        .bind(serde_json::to_string(&passkey).map_err(|e| anyhow::anyhow!(e))?)
        .bind(crate::now())
        .execute(&mut **tx)
        .await?;
    Ok(true)
}

/// Vérifie mot de passe + second facteur, avec verrouillage progressif.
pub(crate) async fn check_credentials(
    st: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    username: &str,
    password: &str,
    second: SecondFactor<'_>,
    expected_status: AccountStatus,
) -> AppResult<AccountRow> {
    let now = crate::now();
    let acc = lock_account(tx, username).await?;
    if let Some(a) = &acc {
        if a.locked_until.is_some_and(|l| l > now) {
            return Err(AppError::new(
                StatusCode::TOO_MANY_REQUESTS,
                ErrorCode::AccountLocked,
                "compte temporairement verrouillé",
            ));
        }
    }
    let pw_ok = verify_password(st, password.to_owned(), acc.as_ref().and_then(|a| a.password_hash.clone())).await?;
    let Some(acc) = acc else {
        return Err(AppError::invalid_credentials());
    };
    // (vérifié, pas TOTP consommé)
    let outcome: Option<Option<i64>> = if !pw_ok {
        None
    } else {
        match second {
            SecondFactor::Totp(code) => match acc.totp_secret_enc.as_deref() {
                Some(sealed) => {
                    let secret = st.inner.secrets.open_totp(username, sealed)?;
                    let t = passwords::totp(&secret, &st.cfg().site_name, username)?;
                    passwords::check_totp(&t, code, now, acc.totp_last_step).map(Some)
                }
                None => None,
            },
            SecondFactor::Webauthn(a) => verify_webauthn(st, tx, acc.id, a).await?.then_some(None),
            SecondFactor::PasswordOnly => Some(None),
        }
    };
    let Some(step) = outcome else {
        record_failure(st, tx, &acc).await?;
        // Pas de distinction mot de passe / second facteur dans la réponse.
        return Err(AppError::invalid_credentials());
    };
    if acc.status == AccountStatus::Suspended.as_str() {
        return Err(AppError::new(StatusCode::FORBIDDEN, ErrorCode::AccountSuspended, "compte suspendu"));
    }
    if acc.status != expected_status.as_str() {
        return Err(AppError::new(StatusCode::FORBIDDEN, ErrorCode::AccountNotActive, "compte non activé"));
    }
    if matches!(second, SecondFactor::PasswordOnly) {
        // Authentification partielle : le compteur d'échecs n'est pas remis à zéro.
        return Ok(acc);
    }
    sqlx::query(
        "UPDATE accounts SET failed_logins = 0, locked_until = NULL, totp_last_step = COALESCE($2, totp_last_step) WHERE id = $1",
    )
    .bind(acc.id)
    .bind(step)
    .execute(&mut **tx)
    .await?;
    Ok(acc)
}

fn check_len(v: &[u8], n: usize, what: &str) -> AppResult<()> {
    if v.len() == n {
        Ok(())
    } else {
        Err(AppError::bad_request(format!("{what} invalide")))
    }
}

/// Enregistre (ou reconnaît) l'appareil après vérification de son certificat.
async fn register_device(
    tx: &mut Transaction<'_, Postgres>,
    acc: &AccountRow,
    username: &str,
    reg: &DeviceRegistration,
) -> AppResult<()> {
    check_len(&reg.identity_key, 32, "clé d'identité")?;
    check_len(&reg.api_key, 32, "clé API")?;
    check_len(&reg.mls_signature_key, 32, "clé MLS")?;
    let cert = DeviceCertificate {
        username: username.to_owned(),
        device_id: reg.device_id,
        api_key: reg.api_key.clone(),
        mls_signature_key: reg.mls_signature_key.clone(),
        created_at: reg.cert_created_at,
    };
    cert.verify(&reg.identity_key, &reg.cert_signature)
        .map_err(|_| AppError::bad_request("certificat d'appareil invalide"))?;
    match &acc.identity_key {
        None => {
            sqlx::query("UPDATE accounts SET identity_key = $2 WHERE id = $1")
                .bind(acc.id)
                .bind(&reg.identity_key)
                .execute(&mut **tx)
                .await?;
        }
        Some(k) if k == &reg.identity_key => {}
        Some(_) => {
            return Err(AppError::new(
                StatusCode::CONFLICT,
                ErrorCode::IdentityMismatch,
                "clé d'identité différente de celle du compte (réinitialisation par un administrateur requise)",
            ))
        }
    }
    let existing: Option<(i64, Vec<u8>, Vec<u8>)> =
        sqlx::query_as("SELECT account_id, api_key, mls_signature_key FROM devices WHERE id = $1")
            .bind(reg.device_id)
            .fetch_optional(&mut **tx)
            .await?;
    match existing {
        Some((aid, api, mls)) if aid == acc.id && api == reg.api_key && mls == reg.mls_signature_key => Ok(()),
        Some(_) => Err(AppError::conflict("identifiant d'appareil déjà utilisé")),
        None => {
            let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM devices WHERE account_id = $1")
                .bind(acc.id)
                .fetch_one(&mut **tx)
                .await?;
            if n >= MAX_DEVICES {
                return Err(AppError::conflict("nombre maximal d'appareils atteint"));
            }
            sqlx::query(
                "INSERT INTO devices (id, account_id, api_key, mls_signature_key, cert_created_at, cert_signature, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(reg.device_id)
            .bind(acc.id)
            .bind(&reg.api_key)
            .bind(&reg.mls_signature_key)
            .bind(reg.cert_created_at)
            .bind(&reg.cert_signature)
            .bind(crate::now())
            .execute(&mut **tx)
            .await?;
            Ok(())
        }
    }
}

async fn new_session(
    st: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    device: uuid::Uuid,
) -> AppResult<SessionTokens> {
    let now = crate::now();
    let (access, access_h) = new_token()?;
    let (refresh, refresh_h) = new_token()?;
    let session_exp = now + st.cfg().session_ttl_secs;
    let access_exp = (now + st.cfg().access_ttl_secs).min(session_exp);
    // Une seule session par appareil.
    sqlx::query("DELETE FROM sessions WHERE device_id = $1").bind(device).execute(&mut **tx).await?;
    sqlx::query(
        "INSERT INTO sessions (device_id, access_hash, access_expires_at, refresh_hash, session_expires_at, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(device)
    .bind(access_h)
    .bind(access_exp)
    .bind(refresh_h)
    .bind(session_exp)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    Ok(SessionTokens {
        access_token: access,
        access_expires_at: access_exp,
        refresh_token: refresh,
        session_expires_at: session_exp,
    })
}

pub async fn confirm_totp(
    State(st): State<AppState>,
    Json(req): Json<ConfirmTotpRequest>,
) -> AppResult<Json<SessionTokens>> {
    let mut tx = st.db().begin().await?;
    let second = SecondFactor::Totp(&req.totp_code);
    let res = check_credentials(&st, &mut tx, &req.username, &req.password, second, AccountStatus::PendingTotp).await;
    let acc = match res {
        Ok(a) => a,
        Err(e) => {
            tx.commit().await?; // conserve le compteur d'échecs
            return Err(e);
        }
    };
    sqlx::query("UPDATE accounts SET status = 'active' WHERE id = $1").bind(acc.id).execute(&mut *tx).await?;
    register_device(&mut tx, &acc, &req.username, &req.device).await?;
    let s = new_session(&st, &mut tx, req.device.device_id).await?;
    tx.commit().await?;
    Ok(Json(s))
}

pub async fn login(State(st): State<AppState>, Json(req): Json<LoginRequest>) -> AppResult<Json<SessionTokens>> {
    let mut tx = st.db().begin().await?;
    let second = match &req.webauthn {
        Some(a) => SecondFactor::Webauthn(a),
        None => SecondFactor::Totp(&req.totp_code),
    };
    let res = check_credentials(&st, &mut tx, &req.username, &req.password, second, AccountStatus::Active).await;
    let acc = match res {
        Ok(a) => a,
        Err(e) => {
            tx.commit().await?;
            return Err(e);
        }
    };
    register_device(&mut tx, &acc, &req.username, &req.device).await?;
    let s = new_session(&st, &mut tx, req.device.device_id).await?;
    tx.commit().await?;
    Ok(Json(s))
}

pub async fn refresh(
    State(st): State<AppState>,
    Extension(dev): Extension<SignedDevice>,
    Json(req): Json<RefreshRequest>,
) -> AppResult<Json<SessionTokens>> {
    if req.device_id != dev.device_id {
        return Err(AppError::unauthorized());
    }
    let now = crate::now();
    let mut tx = st.db().begin().await?;
    let row: Option<(i64, i64)> = sqlx::query_as(
        "SELECT id, session_expires_at FROM sessions
          WHERE refresh_hash = $1 AND device_id = $2 AND session_expires_at > $3 FOR UPDATE",
    )
    .bind(token_hash(&req.refresh_token))
    .bind(dev.device_id)
    .bind(now)
    .fetch_optional(&mut *tx)
    .await?;
    let (id, session_exp) = row.ok_or_else(AppError::unauthorized)?;
    let (access, access_h) = new_token()?;
    let (refresh, refresh_h) = new_token()?;
    let access_exp = (now + st.cfg().access_ttl_secs).min(session_exp);
    sqlx::query("UPDATE sessions SET access_hash = $2, access_expires_at = $3, refresh_hash = $4 WHERE id = $1")
        .bind(id)
        .bind(access_h)
        .bind(access_exp)
        .bind(refresh_h)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(SessionTokens {
        access_token: access,
        access_expires_at: access_exp,
        refresh_token: refresh,
        session_expires_at: session_exp,
    }))
}

pub async fn logout(State(st): State<AppState>, Extension(ctx): Extension<AuthContext>) -> AppResult<StatusCode> {
    sqlx::query("DELETE FROM sessions WHERE device_id = $1").bind(ctx.device_id).execute(st.db()).await?;
    Ok(StatusCode::NO_CONTENT)
}
