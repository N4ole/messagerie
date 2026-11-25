//! Vérification Key Transparency côté client.
//!
//! Toute entrée d'annuaire (consultation ou réclamation de KeyPackages) doit
//! être accompagnée d'une preuve akd que sa valeur est celle publiée dans le
//! journal. Le client mémorise la clé VRF du répertoire (au premier usage),
//! la dernière époque et la dernière racine vérifiées, et exige une preuve
//! d'ajout seul (append-only) pour toute époque plus récente.

use msg_proto::UserDirectoryEntry;
use uuid::Uuid;

use crate::client::{meta, Client};
use crate::error::{ClientError, Result};

fn kt_err(e: msg_kt::KtError) -> ClientError {
    ClientError::KeyTransparency(e.to_string())
}

impl Client {
    async fn kt_vrf(&self) -> Result<Vec<u8>> {
        if let Some(k) = self.store.get_meta(meta::KT_VRF)? {
            return Ok(k.to_vec());
        }
        // Confiance au premier usage, comme pour les clés d'identité.
        let head = self.api.kt_head().await?;
        if head.vrf_public_key.len() != 32 {
            return Err(ClientError::KeyTransparency("clé VRF invalide".into()));
        }
        self.store.set_meta(meta::KT_VRF, &head.vrf_public_key)?;
        Ok(head.vrf_public_key)
    }

    /// Dernière vue vérifiée : époque (8 octets) suivie de la racine, en une
    /// seule métadonnée (écriture atomique).
    fn kt_state(&self) -> Result<Option<(u64, Vec<u8>)>> {
        let Some(v) = self.store.get_meta(meta::KT_STATE)? else { return Ok(None) };
        if v.len() != 8 + 32 {
            return Err(ClientError::Storage("état Key Transparency".into()));
        }
        let e: [u8; 8] = v[..8].try_into().map_err(|_| ClientError::Storage("époque KT".into()))?;
        Ok(Some((u64::from_be_bytes(e), v[8..].to_vec())))
    }

    fn kt_store(&self, epoch: u64, root: &[u8]) -> Result<()> {
        if root.len() != 32 {
            return Err(ClientError::KeyTransparency("racine invalide".into()));
        }
        let mut v = epoch.to_be_bytes().to_vec();
        v.extend_from_slice(root);
        self.store.set_meta(meta::KT_STATE, &v)
    }

    /// Fait avancer la vue locale du journal jusqu'à `(epoch, root)` en
    /// exigeant une preuve d'ajout seul ; refuse tout retour en arrière et
    /// toute racine différente pour une époque déjà vue.
    async fn kt_advance(&self, epoch: u64, root: &[u8]) -> Result<()> {
        match self.kt_state()? {
            None => self.kt_store(epoch, root),
            Some((known, known_root)) if known == epoch => {
                if known_root == root {
                    Ok(())
                } else {
                    Err(kt_err(msg_kt::KtError::Inconsistent))
                }
            }
            Some((known, _)) if known > epoch => Err(ClientError::KeyTransparency(
                "le serveur présente une version du journal antérieure à celle déjà vérifiée".into(),
            )),
            Some((mut from, mut from_root)) => {
                while from < epoch {
                    let to = epoch.min(from + msg_proto::KT_MAX_AUDIT_EPOCHS);
                    let audit = self.api.kt_audit(from, to).await?;
                    if audit.from_epoch != from || audit.to_epoch != to {
                        return Err(kt_err(msg_kt::KtError::Inconsistent));
                    }
                    from_root = msg_kt::verify_audit(&from_root, &audit).await.map_err(kt_err)?;
                    from = to;
                }
                if from_root != root {
                    return Err(kt_err(msg_kt::KtError::Inconsistent));
                }
                self.kt_store(epoch, root)
            }
        }
    }

    /// Vérifie qu'une entrée d'annuaire est exactement celle publiée.
    pub(crate) async fn kt_verify(&self, entry: &UserDirectoryEntry) -> Result<()> {
        let lookup = entry
            .kt
            .as_ref()
            .ok_or_else(|| ClientError::KeyTransparency("preuve absente de la réponse du serveur".into()))?;
        let vrf = self.kt_vrf().await?;
        let value = msg_kt::directory_value(Some(&entry.identity_key), &entry.devices);
        msg_kt::verify_lookup(&vrf, &entry.username, lookup, &value).map_err(kt_err)?;
        self.kt_advance(lookup.epoch, &lookup.root_hash).await
    }

    /// Consultation vérifiée de l'annuaire. Une seule nouvelle tentative en
    /// cas de valeur différente (modification concurrente de l'annuaire).
    pub(crate) async fn verified_directory(&self, username: &str) -> Result<UserDirectoryEntry> {
        let entry = self.api.directory(username).await?;
        match self.kt_verify(&entry).await {
            Err(ClientError::KeyTransparency(_)) => {
                let entry = self.api.directory(username).await?;
                self.kt_verify(&entry).await?;
                Ok(entry)
            }
            Err(e) => Err(e),
            Ok(()) => Ok(entry),
        }
    }

    /// Réclamation vérifiée de KeyPackages (tous les appareils ou certains).
    pub(crate) async fn verified_claim(&self, username: &str, devices: Option<&[Uuid]>) -> Result<UserDirectoryEntry> {
        let entry = match devices {
            Some(d) => self.api.claim_devices(username, d).await?,
            None => self.api.claim(username).await?,
        };
        self.kt_verify(&entry).await?;
        Ok(entry)
    }

    /// Vérifie que le journal publie bien **notre** clé d'identité : un
    /// serveur qui présenterait une autre clé à nos correspondants devrait
    /// la publier, et nous le verrions ici.
    pub async fn kt_check_self(&self) -> Result<()> {
        let entry = self.verified_directory(&self.username).await?;
        if entry.identity_key != self.identity_public {
            return Err(ClientError::KeyTransparency(
                "le journal publie pour votre compte une clé d'identité qui n'est pas la vôtre".into(),
            ));
        }
        if !entry.devices.iter().any(|d| d.device_id == self.device_id) {
            return Err(ClientError::KeyTransparency("cet appareil est absent de votre entrée publiée".into()));
        }
        Ok(())
    }
}
