//! Répertoire akd côté serveur.
//!
//! Le répertoire est tenu en mémoire ; sa persistance est assurée par le
//! serveur, qui journalise chaque lot publié et le **rejoue** au démarrage.
//! Le rejeu est déterministe (VRF et engagements dérivés de la même clé),
//! ce que le serveur vérifie en comparant chaque racine recalculée à la
//! racine journalisée.

use akd::directory::Directory;
use akd::ecvrf::{VRFKeyStorage, VrfError};
use akd::storage::memory::AsyncInMemoryDatabase;
use akd::storage::StorageManager;
use akd::{AkdLabel, AkdValue, AzksParallelismConfig, EpochHash};
use msg_proto::KtLookup;
use zeroize::Zeroizing;

use crate::{encode_audit, encode_lookup, label, KtConfig, KtError, Result};

/// Clé VRF du répertoire (graine Ed25519 de 32 octets).
#[derive(Clone)]
struct VrfKey(Zeroizing<[u8; 32]>);

#[async_trait::async_trait]
impl VRFKeyStorage for VrfKey {
    async fn retrieve(&self) -> std::result::Result<Vec<u8>, VrfError> {
        Ok(self.0.to_vec())
    }
}

type Dir = Directory<KtConfig, AsyncInMemoryDatabase, VrfKey>;

pub struct KtDirectory {
    dir: Dir,
    vrf_public_key: Vec<u8>,
}

fn err(e: impl std::fmt::Debug) -> KtError {
    KtError::Directory(format!("{e:?}"))
}

impl KtDirectory {
    /// Crée un répertoire vide (époque 0).
    pub async fn new(vrf_seed: [u8; 32]) -> Result<Self> {
        let vrf = VrfKey(Zeroizing::new(vrf_seed));
        let db = AsyncInMemoryDatabase::new();
        let dir =
            Dir::new(StorageManager::new_no_cache(db), vrf, AzksParallelismConfig::disabled()).await.map_err(err)?;
        let vrf_public_key = dir.get_public_key().await.map_err(err)?.as_bytes().to_vec();
        Ok(Self { dir, vrf_public_key })
    }

    pub fn vrf_public_key(&self) -> &[u8] {
        &self.vrf_public_key
    }

    /// Époque et racine courantes.
    pub async fn head(&self) -> Result<(u64, Vec<u8>)> {
        let h = self.dir.get_epoch_hash().await.map_err(err)?;
        Ok((h.epoch(), h.hash().to_vec()))
    }

    /// Publie un lot de valeurs (une par utilisateur) : nouvelle époque.
    pub async fn publish(&self, updates: &[(String, Vec<u8>)]) -> Result<(u64, Vec<u8>)> {
        if updates.is_empty() {
            return Err(KtError::Directory("lot vide".into()));
        }
        let batch = updates.iter().map(|(u, v)| (label(u), AkdValue(v.clone()))).collect();
        let EpochHash(epoch, root) = self.dir.publish(batch).await.map_err(err)?;
        Ok((epoch, root.to_vec()))
    }

    /// Preuve de la valeur courante de `username` (erreur si jamais publiée).
    pub async fn lookup(&self, username: &str) -> Result<KtLookup> {
        let (proof, h) = self.dir.lookup(AkdLabel::from(username)).await.map_err(err)?;
        Ok(KtLookup { epoch: h.epoch(), root_hash: h.hash().to_vec(), proof: encode_lookup(&proof) })
    }

    /// Preuve d'ajout seul entre deux époques.
    pub async fn audit(&self, from_epoch: u64, to_epoch: u64) -> Result<Vec<u8>> {
        let p = self.dir.audit(from_epoch, to_epoch).await.map_err(err)?;
        Ok(encode_audit(&p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{directory_value, verify_audit, verify_lookup};
    use msg_proto::{KtAudit, KtRoot};

    /// Graine VRF de test aléatoire (jamais de clé codée en dur).
    fn seed() -> [u8; 32] {
        let mut s = [0u8; 32];
        getrandom::fill(&mut s).unwrap();
        s
    }

    #[tokio::test]
    async fn lookup_and_audit_roundtrip() {
        let d = KtDirectory::new(seed()).await.unwrap();
        let v1 = directory_value(Some(&[1u8; 32]), &[]);
        let v2 = directory_value(Some(&[2u8; 32]), &[]);
        let (e1, r1) = d.publish(&[("alice".into(), v1.clone()), ("bob".into(), v2.clone())]).await.unwrap();
        let l = d.lookup("alice").await.unwrap();
        assert_eq!((l.epoch, l.root_hash.clone()), (e1, r1.clone()));
        verify_lookup(d.vrf_public_key(), "alice", &l, &v1).unwrap();
        // Une autre valeur, un autre utilisateur ou une autre clé VRF : refus.
        assert_eq!(verify_lookup(d.vrf_public_key(), "alice", &l, &v2), Err(KtError::ValueMismatch));
        assert!(verify_lookup(d.vrf_public_key(), "bob", &l, &v1).is_err());
        let other = KtDirectory::new(seed()).await.unwrap();
        assert!(verify_lookup(other.vrf_public_key(), "alice", &l, &v1).is_err());
        // Racine altérée : refus.
        let mut bad = l.clone();
        bad.root_hash[0] ^= 1;
        assert!(verify_lookup(d.vrf_public_key(), "alice", &bad, &v1).is_err());

        // Nouvelle époque : alice ajoute un appareil.
        let v1b = directory_value(Some(&[1u8; 32]), &[]).into_iter().rev().collect::<Vec<_>>();
        let (e2, r2) = d.publish(&[("alice".into(), v1b.clone())]).await.unwrap();
        let (e3, r3) = d.publish(&[("carol".into(), v2.clone())]).await.unwrap();
        assert_eq!((e2, e3), (e1 + 1, e1 + 2));
        let audit = KtAudit {
            from_epoch: e1,
            to_epoch: e3,
            roots: vec![KtRoot(r1.clone()), KtRoot(r2.clone()), KtRoot(r3.clone())],
            proof: d.audit(e1, e3).await.unwrap(),
        };
        assert_eq!(verify_audit(&r1, &audit).await.unwrap(), r3);
        // Point de départ différent de la racine connue : incohérent.
        assert_eq!(verify_audit(&r2, &audit).await, Err(KtError::Inconsistent));
        // Racine intermédiaire falsifiée : la preuve ne tient plus.
        let mut forged = audit.clone();
        forged.roots[1].0[0] ^= 1;
        assert!(verify_audit(&r1, &forged).await.is_err());
        verify_lookup(d.vrf_public_key(), "alice", &d.lookup("alice").await.unwrap(), &v1b).unwrap();
    }

    /// Le rejeu des mêmes lots avec la même clé redonne les mêmes racines :
    /// c'est ce qui permet de reconstruire le répertoire au démarrage.
    #[tokio::test]
    async fn replay_is_deterministic() {
        let batches: Vec<Vec<(String, Vec<u8>)>> = vec![
            vec![("alice".into(), vec![1; 32]), ("bob".into(), vec![2; 32])],
            vec![("alice".into(), vec![3; 32])],
            vec![("carol".into(), vec![4; 32]), ("bob".into(), vec![5; 32])],
        ];
        let mut roots = Vec::new();
        let seed = seed();
        for _ in 0..2 {
            let d = KtDirectory::new(seed).await.unwrap();
            let mut r = Vec::new();
            for b in &batches {
                r.push(d.publish(b).await.unwrap());
            }
            roots.push(r);
        }
        assert_eq!(roots[0], roots[1]);
    }
}
