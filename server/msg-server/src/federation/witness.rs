//! Témoin Key Transparency des sites pairs : ce site suit le journal de
//! chaque pair (têtes signées par la clé du pair) et vérifie qu'il ne fait
//! que croître (preuves d'ajout seul). Une incohérence est journalisée : le
//! pair présente un historique réécrit ou des vues différentes.

use msg_proto::{KtAudit, SignedKtHead, KT_MAX_AUDIT_EPOCHS};

use super::{client, verify_signed_head};
use crate::config::FederationPeer;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

/// Résultat d'une vérification.
#[derive(Debug, PartialEq, Eq)]
pub enum Witnessed {
    /// Première observation, ou nouvelle époque prouvée cohérente.
    Ok { epoch: u64 },
    /// Le journal du pair n'est pas cohérent avec ce qui a été vu.
    Inconsistent,
}

pub async fn check_peer(st: &AppState, peer: &FederationPeer) -> AppResult<Witnessed> {
    let signed: SignedKtHead = client::get_json(st, peer, "/v1/federation/kt/head").await?;
    verify_signed_head(peer, &signed)?;
    let head = signed.head;
    let known: Option<(i64, Vec<u8>)> = sqlx::query_as("SELECT epoch, root_hash FROM kt_witness WHERE site = $1")
        .bind(&peer.name)
        .fetch_optional(st.db())
        .await?;
    let consistent = match &known {
        None => true,
        Some((e, root)) if *e as u64 == head.epoch => *root == head.root_hash,
        Some((e, _)) if *e as u64 > head.epoch => false,
        Some((e, root)) => {
            let mut from = *e as u64;
            let mut from_root = root.clone();
            let mut ok = true;
            while from < head.epoch {
                let to = head.epoch.min(from + KT_MAX_AUDIT_EPOCHS);
                let audit: KtAudit =
                    client::get_json(st, peer, &format!("/v1/federation/kt/audit?from={from}&to={to}")).await?;
                match msg_kt::verify_audit(&from_root, &audit).await {
                    Ok(r) => {
                        from_root = r;
                        from = to;
                    }
                    Err(_) => {
                        ok = false;
                        break;
                    }
                }
            }
            ok && from_root == head.root_hash
        }
    };
    if !consistent {
        tracing::error!(site = %peer.name, "ALERTE : journal Key Transparency incohérent chez un site pair");
        return Ok(Witnessed::Inconsistent);
    }
    sqlx::query(
        "INSERT INTO kt_witness (site, epoch, root_hash, checked_at) VALUES ($1, $2, $3, $4)
         ON CONFLICT (site) DO UPDATE SET epoch = $2, root_hash = $3, checked_at = $4",
    )
    .bind(&peer.name)
    .bind(head.epoch as i64)
    .bind(&head.root_hash)
    .bind(crate::now())
    .execute(st.db())
    .await?;
    Ok(Witnessed::Ok { epoch: head.epoch })
}

/// Vérifie tous les pairs (tâche périodique) ; renvoie les sites incohérents.
pub async fn check_all(st: &AppState) -> Vec<String> {
    let mut bad = Vec::new();
    for p in st.cfg().federation_peers.clone() {
        match check_peer(st, &p).await {
            Ok(Witnessed::Inconsistent) => bad.push(p.name.clone()),
            Ok(_) => {}
            Err(AppError { message, .. }) => tracing::warn!(site = %p.name, error = %message, "témoin KT indisponible"),
        }
    }
    bad
}
