//! Key Transparency fondée sur `akd` (Auditable Key Directory, Meta).
//!
//! Le serveur publie, pour chaque utilisateur, une **valeur** qui résume son
//! identité et la liste de ses appareils certifiés ([`directory_value`]).
//! Chaque modification crée une nouvelle époque du journal akd. Le client :
//!
//! 1. vérifie que l'entrée d'annuaire reçue correspond à la valeur prouvée
//!    dans le journal pour l'époque annoncée ([`verify_lookup`]) ;
//! 2. vérifie que le journal n'a fait que croître depuis la dernière époque
//!    qu'il a vue ([`verify_audit`]) — un serveur qui présenterait des vues
//!    différentes à deux clients devrait maintenir deux historiques, ce que
//!    des auditeurs (ou les clients qui comparent leurs racines) détectent.
//!
//! Aucune construction cryptographique n'est ajoutée : preuves, VRF et
//! engagements sont ceux d'akd (configuration « expérimentale », BLAKE3) ;
//! la valeur publiée est un simple haché SHA-256 d'un encodage canonique.

use akd::configuration::{DomainLabel, ExperimentalConfiguration};
use akd::{AkdLabel, AkdValue, AppendOnlyProof, LookupProof};
use msg_proto::{KtAudit, KtLookup, PublishedDevice};
use protobuf::Message;
use sha2::{Digest as _, Sha256};

#[cfg(feature = "server")]
mod server;
#[cfg(feature = "server")]
pub use server::KtDirectory;

/// Séparation de domaine des hachés akd de ce projet.
#[derive(Clone)]
pub struct MessagerieLabel;

impl DomainLabel for MessagerieLabel {
    fn domain_label() -> &'static [u8] {
        b"messagerie-kt-v1"
    }
}

/// Configuration akd utilisée par le serveur et les clients.
pub type KtConfig = ExperimentalConfiguration<MessagerieLabel>;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KtError {
    #[error("preuve Key Transparency mal formée : {0}")]
    Malformed(String),
    #[error("preuve Key Transparency invalide : {0}")]
    Invalid(String),
    #[error("l'annuaire ne correspond pas à la valeur publiée dans le journal")]
    ValueMismatch,
    #[error("le journal Key Transparency n'est pas cohérent avec la dernière version vue")]
    Inconsistent,
    #[error("erreur du répertoire : {0}")]
    Directory(String),
}

pub type Result<T> = std::result::Result<T, KtError>;

const VALUE_DOMAIN: &[u8] = b"messagerie-kt-value-v1";

fn put(h: &mut Sha256, bytes: &[u8]) {
    h.update((bytes.len() as u32).to_be_bytes());
    h.update(bytes);
}

/// Valeur publiée pour un utilisateur : haché d'un encodage canonique (champs
/// préfixés par leur longueur, appareils triés) de sa clé d'identité et de
/// ses appareils certifiés. Sans identité (compte réinitialisé), la valeur
/// encode l'absence de clé.
pub fn directory_value(identity_key: Option<&[u8]>, devices: &[PublishedDevice]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(VALUE_DOMAIN);
    match identity_key {
        None => h.update([0u8]),
        Some(k) => {
            h.update([1u8]);
            put(&mut h, k);
            let mut ds: Vec<&PublishedDevice> = devices.iter().collect();
            ds.sort_by_key(|d| d.device_id);
            h.update((ds.len() as u32).to_be_bytes());
            for d in ds {
                h.update(d.device_id.as_bytes());
                put(&mut h, &d.api_key);
                put(&mut h, &d.mls_signature_key);
                h.update(d.cert_created_at.to_be_bytes());
                put(&mut h, &d.cert_signature);
            }
        }
    }
    h.finalize().to_vec()
}

fn label(username: &str) -> AkdLabel {
    AkdLabel::from(username)
}

fn digest(bytes: &[u8]) -> Result<akd::Digest> {
    bytes.try_into().map_err(|_| KtError::Malformed("racine de 32 octets attendue".into()))
}

#[cfg(feature = "server")]
pub(crate) fn encode_lookup(p: &LookupProof) -> Vec<u8> {
    akd::proto::specs::types::LookupProof::from(p).write_to_bytes().unwrap_or_default()
}

#[cfg(feature = "server")]
pub(crate) fn encode_audit(p: &AppendOnlyProof) -> Vec<u8> {
    akd::proto::specs::types::AppendOnlyProof::from(p).write_to_bytes().unwrap_or_default()
}

/// Vérifie qu'une preuve de recherche établit, pour `username` à l'époque et
/// à la racine annoncées, exactement la valeur `expected_value`.
pub fn verify_lookup(vrf_public_key: &[u8], username: &str, lookup: &KtLookup, expected_value: &[u8]) -> Result<()> {
    let pb = akd::proto::specs::types::LookupProof::parse_from_bytes(&lookup.proof)
        .map_err(|e| KtError::Malformed(e.to_string()))?;
    let proof = LookupProof::try_from(&pb).map_err(|e| KtError::Malformed(format!("{e:?}")))?;
    let root = digest(&lookup.root_hash)?;
    let res = akd::client::lookup_verify::<KtConfig>(vrf_public_key, root, lookup.epoch, label(username), proof)
        .map_err(|e| KtError::Invalid(format!("{e:?}")))?;
    if res.value != AkdValue(expected_value.to_vec()) {
        return Err(KtError::ValueMismatch);
    }
    Ok(())
}

/// Vérifie qu'entre `audit.from_epoch` et `audit.to_epoch` le journal n'a
/// fait que croître, et que la chaîne de racines part de `known_root`.
/// Renvoie la racine de la dernière époque.
pub async fn verify_audit(known_root: &[u8], audit: &KtAudit) -> Result<Vec<u8>> {
    let span = audit.to_epoch.checked_sub(audit.from_epoch).ok_or(KtError::Inconsistent)?;
    if span == 0 || span > msg_proto::KT_MAX_AUDIT_EPOCHS || audit.roots.len() as u64 != span + 1 {
        return Err(KtError::Malformed("nombre de racines incohérent".into()));
    }
    if audit.roots[0].0 != known_root {
        return Err(KtError::Inconsistent);
    }
    let hashes = audit.roots.iter().map(|r| digest(&r.0)).collect::<Result<Vec<_>>>()?;
    let pb = akd::proto::specs::types::AppendOnlyProof::parse_from_bytes(&audit.proof)
        .map_err(|e| KtError::Malformed(e.to_string()))?;
    let proof = AppendOnlyProof::try_from(&pb).map_err(|e| KtError::Malformed(format!("{e:?}")))?;
    akd::auditor::audit_verify::<KtConfig>(hashes, proof).await.map_err(|_| KtError::Inconsistent)?;
    Ok(audit.roots[span as usize].0.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn dev(n: u8) -> PublishedDevice {
        PublishedDevice {
            device_id: Uuid::from_bytes([n; 16]),
            api_key: vec![n; 32],
            mls_signature_key: vec![n + 1; 32],
            cert_created_at: i64::from(n),
            cert_signature: vec![n; 64],
            key_package: Some(vec![9; 10]),
        }
    }

    #[test]
    fn value_is_canonical() {
        let id = [7u8; 32];
        let a = directory_value(Some(&id), &[dev(1), dev(2)]);
        // Ordre des appareils et KeyPackages sans effet.
        let mut d2 = dev(2);
        d2.key_package = None;
        assert_eq!(a, directory_value(Some(&id), &[d2, dev(1)]));
        // Toute modification change la valeur.
        assert_ne!(a, directory_value(Some(&id), &[dev(1)]));
        assert_ne!(a, directory_value(Some(&[8u8; 32]), &[dev(1), dev(2)]));
        let mut d3 = dev(2);
        d3.mls_signature_key = vec![0; 32];
        assert_ne!(a, directory_value(Some(&id), &[dev(1), d3]));
        assert_ne!(directory_value(None, &[]), directory_value(Some(&id), &[]));
    }
}
