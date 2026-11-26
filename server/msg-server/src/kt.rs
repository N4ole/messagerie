//! Journal Key Transparency : publication des entrées d'annuaire dans akd.
//!
//! Toute modification de l'identité ou des appareils d'un compte marque le
//! compte « à publier » dans la même transaction ; la publication (nouvelle
//! époque) a lieu juste après la validation, et au plus tard avant toute
//! réponse d'annuaire concernant ce compte.

use msg_kt::{directory_value, KtDirectory};
use msg_proto::{KtAudit, KtHead, KtLookup, KtRoot, PublishedDevice, KT_MAX_AUDIT_EPOCHS};
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::state::AppState;

/// Marque le compte comme devant être republié dans le journal.
pub async fn mark_dirty<'e, E: sqlx::PgExecutor<'e>>(db: E, account_id: i64) -> AppResult<()> {
    sqlx::query("INSERT INTO kt_dirty (username) SELECT username FROM accounts WHERE id = $1 ON CONFLICT DO NOTHING")
        .bind(account_id)
        .execute(db)
        .await?;
    Ok(())
}

fn kt_err(e: msg_kt::KtError) -> AppError {
    tracing::error!(error = %e, "Key Transparency");
    AppError::internal()
}

/// Clé du verrou consultatif PostgreSQL qui sérialise les publications
/// entre instances du serveur (un seul écrivain du journal à la fois).
const KT_LOCK_KEY: i64 = 0x6b74_5f6c_6f67; // « kt_log »

/// Met le répertoire en mémoire à jour avec le journal en base : création
/// (premier usage) puis rejeu des époques publiées depuis, éventuellement
/// par une autre instance. Chaque racine recalculée doit égaler la racine
/// journalisée, sinon le journal est refusé.
async fn sync_dir(st: &AppState, slot: &mut Option<KtDirectory>) -> AppResult<()> {
    if slot.is_none() {
        let dir = KtDirectory::new(*st.inner.secrets.kt_vrf_seed).await.map_err(kt_err)?;
        let (logged,): (bool,) = sqlx::query_as("SELECT EXISTS (SELECT 1 FROM kt_log)").fetch_one(st.db()).await?;
        if !logged {
            // Premier démarrage (ou base de Phase 2) : publier tous les comptes.
            sqlx::query(
                "INSERT INTO kt_dirty (username) SELECT username FROM accounts WHERE identity_key IS NOT NULL
                 ON CONFLICT DO NOTHING",
            )
            .execute(st.db())
            .await?;
        }
        *slot = Some(dir);
    }
    let dir = slot.as_ref().ok_or_else(AppError::internal)?;
    let (current, _) = dir.head().await.map_err(kt_err)?;
    let rows: Vec<(i64, String, Vec<u8>)> =
        sqlx::query_as("SELECT epoch, entries, root_hash FROM kt_log WHERE epoch > $1 ORDER BY epoch")
            .bind(current as i64)
            .fetch_all(st.db())
            .await?;
    for (epoch, entries, root) in rows {
        let batch: Vec<(String, String)> = serde_json::from_str(&entries).map_err(|e| anyhow::anyhow!(e))?;
        let batch: Vec<(String, Vec<u8>)> = batch
            .into_iter()
            .map(|(u, v)| hex::decode(v).map(|v| (u, v)))
            .collect::<Result<_, _>>()
            .map_err(|e| anyhow::anyhow!(e))?;
        let replayed = dir.publish(&batch).await.map_err(kt_err);
        match replayed {
            Ok((e, r)) if e == epoch as u64 && r == root => {}
            _ => {
                tracing::error!(epoch, "journal Key Transparency incohérent : rejeu refusé");
                *slot = None;
                return Err(AppError::internal());
            }
        }
    }
    Ok(())
}

/// (appareil, clé API, clé MLS, date du certificat, signature du certificat)
type DeviceRow = (Uuid, Vec<u8>, Vec<u8>, i64, Vec<u8>);

async fn current_value(st: &AppState, username: &str) -> AppResult<Vec<u8>> {
    let acc: Option<(i64, Option<Vec<u8>>)> =
        sqlx::query_as("SELECT id, identity_key FROM accounts WHERE username = $1")
            .bind(username)
            .fetch_optional(st.db())
            .await?;
    let Some((id, identity)) = acc else { return Ok(directory_value(None, &[])) };
    let devices: Vec<DeviceRow> = sqlx::query_as(
        "SELECT id, api_key, mls_signature_key, cert_created_at, cert_signature FROM devices WHERE account_id = $1",
    )
    .bind(id)
    .fetch_all(st.db())
    .await?;
    let devices: Vec<PublishedDevice> = devices
        .into_iter()
        .map(|(device_id, api_key, mls_signature_key, cert_created_at, cert_signature)| PublishedDevice {
            device_id,
            api_key,
            mls_signature_key,
            cert_created_at,
            cert_signature,
            key_package: None,
        })
        .collect();
    Ok(directory_value(identity.as_deref(), &devices))
}

/// Publie dans une nouvelle époque tous les comptes en attente.
pub async fn flush(st: &AppState) -> AppResult<()> {
    let mut guard = st.inner.kt.lock().await;
    let mut tx = st.db().begin().await?;
    // Un seul écrivain parmi toutes les instances ; le verrou est libéré à
    // la fin de la transaction.
    sqlx::query("SELECT pg_advisory_xact_lock($1)").bind(KT_LOCK_KEY).execute(&mut *tx).await?;
    sync_dir(st, &mut guard).await?;
    let dir = guard.as_ref().ok_or_else(AppError::internal)?;
    let dirty: Vec<(String,)> =
        sqlx::query_as("SELECT username FROM kt_dirty ORDER BY username FOR UPDATE").fetch_all(&mut *tx).await?;
    if dirty.is_empty() {
        return Ok(());
    }
    let mut updates = Vec::with_capacity(dirty.len());
    for (u,) in &dirty {
        updates.push((u.clone(), current_value(st, u).await?));
    }
    let (epoch, root) = dir.publish(&updates).await.map_err(kt_err)?;
    let entries: Vec<(&str, String)> = updates.iter().map(|(u, v)| (u.as_str(), hex::encode(v))).collect();
    let names: Vec<String> = dirty.into_iter().map(|(u,)| u).collect();
    let res = async {
        sqlx::query("INSERT INTO kt_log (epoch, entries, root_hash, created_at) VALUES ($1, $2, $3, $4)")
            .bind(epoch as i64)
            .bind(serde_json::to_string(&entries).map_err(|e| anyhow::anyhow!(e))?)
            .bind(&root)
            .bind(crate::now())
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM kt_dirty WHERE username = ANY($1)").bind(&names).execute(&mut *tx).await?;
        tx.commit().await?;
        AppResult::Ok(())
    }
    .await;
    if res.is_err() {
        // L'époque n'a pas été journalisée : le répertoire en mémoire est
        // abandonné et sera reconstruit depuis la base.
        *guard = None;
    }
    res
}

/// Preuve de la valeur courante d'un utilisateur (publiée au besoin).
pub async fn lookup(st: &AppState, username: &str) -> AppResult<Option<KtLookup>> {
    let (pending,): (bool,) = sqlx::query_as("SELECT EXISTS (SELECT 1 FROM kt_dirty WHERE username = $1)")
        .bind(username)
        .fetch_one(st.db())
        .await?;
    if pending {
        flush(st).await?;
    }
    let mut guard = st.inner.kt.lock().await;
    sync_dir(st, &mut guard).await?;
    let dir = guard.as_ref().ok_or_else(AppError::internal)?;
    Ok(dir.lookup(username).await.ok())
}

pub async fn head(st: &AppState) -> AppResult<KtHead> {
    flush(st).await?;
    let mut guard = st.inner.kt.lock().await;
    sync_dir(st, &mut guard).await?;
    let dir = guard.as_ref().ok_or_else(AppError::internal)?;
    let (epoch, root_hash) = dir.head().await.map_err(kt_err)?;
    Ok(KtHead { epoch, root_hash, vrf_public_key: dir.vrf_public_key().to_vec() })
}

pub async fn audit(st: &AppState, from: u64, to: u64) -> AppResult<KtAudit> {
    if from == 0 || to <= from || to - from > KT_MAX_AUDIT_EPOCHS {
        return Err(AppError::bad_request("intervalle d'époques invalide"));
    }
    let roots: Vec<(Vec<u8>,)> =
        sqlx::query_as("SELECT root_hash FROM kt_log WHERE epoch BETWEEN $1 AND $2 ORDER BY epoch")
            .bind(from as i64)
            .bind(to as i64)
            .fetch_all(st.db())
            .await?;
    if roots.len() as u64 != to - from + 1 {
        return Err(AppError::not_found());
    }
    let mut guard = st.inner.kt.lock().await;
    sync_dir(st, &mut guard).await?;
    let dir = guard.as_ref().ok_or_else(AppError::internal)?;
    let proof = dir.audit(from, to).await.map_err(kt_err)?;
    Ok(KtAudit { from_epoch: from, to_epoch: to, roots: roots.into_iter().map(|(r,)| KtRoot(r)).collect(), proof })
}
