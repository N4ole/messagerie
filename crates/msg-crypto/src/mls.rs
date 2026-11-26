//! Client MLS (RFC 9420) basé sur OpenMLS.
//!
//! Une conversation 1-à-1 est un groupe MLS contenant les appareils des deux
//! utilisateurs (ADR-0002). Chaque message applicatif est un `PrivateMessage` :
//! chiffré (AEAD) et signé par la clé de feuille de l'expéditeur.
//!
//! L'état OpenMLS (arbres, secrets d'époque, clés privées HPKE) est conservé
//! dans un `MemoryStorage` dont le contenu est exporté/importé en bloc vers la
//! base locale chiffrée (SQLCipher) par `msg-client-core`.

use std::collections::HashMap;
use std::io::Read;

use openmls::prelude::{tls_codec::*, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_memory_storage::MemoryStorage;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{CryptoError, Result};

/// Suite par défaut : KEM hybride ML-KEM-768 + X25519 (post-quantique et
/// classique), AES-128-GCM, SHA-256, Ed25519 — draft-ietf-mls-pq-ciphersuites
/// (point de code provisoire 0x004F). Implémentation RustCrypto (pure Rust,
/// compatible WASM) via `openmls_rust_crypto`.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519;

/// Remplissage des messages applicatifs (masque la longueur exacte).
const PADDING_SIZE: usize = 256;
/// Tolérance aux messages hors ordre et distance maximale d'avance.
const OUT_OF_ORDER_TOLERANCE: u32 = 100;
const MAX_FORWARD_DISTANCE: u32 = 1000;
/// Nombre d'époques passées dont on garde les secrets (messages retardés).
const MAX_PAST_EPOCHS: usize = 1;

const STATE_MAGIC: &[u8; 8] = b"MSGMLS01";

fn mls_err<E: std::fmt::Debug>(e: E) -> CryptoError {
    CryptoError::Mls(format!("{e:?}"))
}

/// Fournisseur OpenMLS : crypto RustCrypto + stockage mémoire persistable.
pub struct MsgProvider {
    crypto: RustCrypto,
    storage: MemoryStorage,
}

impl MsgProvider {
    fn new() -> Result<Self> {
        Ok(Self { crypto: RustCrypto::default(), storage: MemoryStorage::default() })
    }
}

impl OpenMlsProvider for MsgProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }
    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }
    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

/// Identité d'un membre telle qu'encodée dans son `BasicCredential` MLS.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemberIdentity {
    pub username: String,
    pub device_id: Uuid,
}

impl MemberIdentity {
    /// Encodage : `username ‖ 0x00 ‖ device_id (16 octets)`.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = self.username.as_bytes().to_vec();
        v.push(0);
        v.extend_from_slice(self.device_id.as_bytes());
        v
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let pos =
            bytes.iter().position(|b| *b == 0).ok_or_else(|| CryptoError::Format("identité MLS invalide".into()))?;
        let username = std::str::from_utf8(&bytes[..pos])
            .map_err(|_| CryptoError::Format("identité MLS invalide".into()))?
            .to_owned();
        let id: [u8; 16] =
            bytes[pos + 1..].try_into().map_err(|_| CryptoError::Format("identité MLS invalide".into()))?;
        Ok(Self { username, device_id: Uuid::from_bytes(id) })
    }

    fn from_credential(c: &Credential) -> Result<Self> {
        let basic = BasicCredential::try_from(c.clone()).map_err(mls_err)?;
        Self::decode(basic.identity())
    }
}

/// Membre d'un groupe avec sa clé de signature (à confronter à l'annuaire).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMember {
    pub identity: MemberIdentity,
    pub signature_key: Vec<u8>,
}

/// Résultat du traitement d'un message entrant.
#[derive(Debug)]
pub enum Incoming {
    /// Nous avons été ajoutés à un groupe (message `Welcome`).
    Joined { group_id: Vec<u8>, members: Vec<GroupMember> },
    /// Message applicatif déchiffré et dont la signature a été vérifiée.
    Application { group_id: Vec<u8>, sender: MemberIdentity, plaintext: Zeroizing<Vec<u8>> },
    /// Commit appliqué : nouvelle époque. `removed_self` : nous avons été
    /// retirés du groupe par ce commit.
    Committed { group_id: Vec<u8>, sender: MemberIdentity, members: Vec<GroupMember>, removed_self: bool },
    /// Proposition (mise à jour, départ…) mise en attente d'un commit.
    ProposalStored { group_id: Vec<u8>, sender: MemberIdentity },
}

/// Résultat de l'ajout de membres à un groupe existant.
#[derive(Debug)]
pub struct AddedMembers {
    /// Commit à diffuser aux membres déjà présents.
    pub commit: Vec<u8>,
    /// Welcome à distribuer aux nouveaux appareils.
    pub welcome: Vec<u8>,
    pub members: Vec<GroupMember>,
}

/// Groupe nouvellement créé.
#[derive(Debug)]
pub struct CreatedGroup {
    pub group_id: Vec<u8>,
    /// Message `Welcome` sérialisé, à distribuer aux appareils ajoutés.
    pub welcome: Vec<u8>,
    pub members: Vec<GroupMember>,
}

/// Client MLS d'un appareil.
pub struct MlsClient {
    provider: MsgProvider,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    identity: MemberIdentity,
    /// Site de cet appareil (fédération) : les identités `nom@site` de ce
    /// site sont rendues sous leur forme courte `nom` ; celles des autres
    /// sites restent qualifiées. Les credentials sans site (appareils
    /// antérieurs à la fédération) désignent des utilisateurs de ce site.
    home_site: Option<String>,
}

impl MlsClient {
    /// Crée un nouvel état MLS pour l'appareil (nouvelle clé de signature).
    pub fn create(identity: MemberIdentity) -> Result<Self> {
        let provider = MsgProvider::new()?;
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).map_err(mls_err)?;
        signer.store(provider.storage()).map_err(mls_err)?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(identity.encode()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        Ok(Self { provider, signer, credential, identity, home_site: None })
    }

    /// Restaure un état exporté par [`MlsClient::export_state`].
    pub fn restore(identity: MemberIdentity, signature_public_key: &[u8], state: &[u8]) -> Result<Self> {
        let provider = MsgProvider::new()?;
        {
            let map = decode_state(state)?;
            let mut values = provider.storage.values.write().map_err(|_| CryptoError::Mls("verrou".into()))?;
            *values = map;
        }
        let signer =
            SignatureKeyPair::read(provider.storage(), signature_public_key, CIPHERSUITE.signature_algorithm())
                .ok_or_else(|| CryptoError::Mls("clé de signature MLS absente de l'état".into()))?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(identity.encode()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        Ok(Self { provider, signer, credential, identity, home_site: None })
    }

    /// Exporte l'intégralité de l'état (contient des secrets : à stocker
    /// uniquement chiffré). Encodage déterministe (clés triées).
    pub fn export_state(&self) -> Result<Zeroizing<Vec<u8>>> {
        let values = self.provider.storage.values.read().map_err(|_| CryptoError::Mls("verrou".into()))?;
        let mut entries: Vec<(&Vec<u8>, &Vec<u8>)> = values.iter().collect();
        entries.sort();
        let mut out = Zeroizing::new(Vec::with_capacity(4096));
        out.extend_from_slice(STATE_MAGIC);
        out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        for (k, v) in entries {
            out.extend_from_slice(&(k.len() as u32).to_be_bytes());
            out.extend_from_slice(k);
            out.extend_from_slice(&(v.len() as u32).to_be_bytes());
            out.extend_from_slice(v);
        }
        Ok(out)
    }

    pub fn identity(&self) -> &MemberIdentity {
        &self.identity
    }

    /// Déclare le site de cet appareil (normalisation des identités).
    pub fn set_home_site(&mut self, site: Option<String>) {
        self.home_site = site;
    }

    /// Forme locale d'une identité : `nom@<ce site>` → `nom`.
    pub fn normalize(&self, mut id: MemberIdentity) -> MemberIdentity {
        if let Some(site) = &self.home_site {
            if let Some(local) = id.username.strip_suffix(site.as_str()).and_then(|u| u.strip_suffix('@')) {
                id.username = local.to_owned();
            }
        }
        id
    }

    fn normalize_members(&self, members: Vec<GroupMember>) -> Vec<GroupMember> {
        members.into_iter().map(|m| GroupMember { identity: self.normalize(m.identity), ..m }).collect()
    }

    /// Clé publique de signature MLS de cet appareil.
    pub fn signature_public_key(&self) -> Vec<u8> {
        self.signer.to_public_vec()
    }

    /// Génère `n` KeyPackages sérialisés (à publier sur le serveur).
    pub fn generate_key_packages(&self, n: usize) -> Result<Vec<Vec<u8>>> {
        (0..n)
            .map(|_| {
                let bundle = KeyPackage::builder()
                    .build(CIPHERSUITE, &self.provider, &self.signer, self.credential.clone())
                    .map_err(mls_err)?;
                bundle.key_package().tls_serialize_detached().map_err(mls_err)
            })
            .collect()
    }

    fn create_config() -> MlsGroupCreateConfig {
        MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .padding_size(PADDING_SIZE)
            .max_past_epochs(MAX_PAST_EPOCHS)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(OUT_OF_ORDER_TOLERANCE, MAX_FORWARD_DISTANCE))
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .build()
    }

    fn join_config() -> MlsGroupJoinConfig {
        MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .padding_size(PADDING_SIZE)
            .max_past_epochs(MAX_PAST_EPOCHS)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(OUT_OF_ORDER_TOLERANCE, MAX_FORWARD_DISTANCE))
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .build()
    }

    /// Valide un KeyPackage reçu de l'annuaire (signature, durée de vie,
    /// suite) et retourne l'identité et la clé de signature qu'il annonce.
    pub fn inspect_key_package(&self, bytes: &[u8]) -> Result<GroupMember> {
        let kp = self.validate_key_package(bytes)?;
        Ok(GroupMember {
            identity: self.normalize(MemberIdentity::from_credential(kp.leaf_node().credential())?),
            signature_key: kp.leaf_node().signature_key().as_slice().to_vec(),
        })
    }

    fn validate_key_package(&self, bytes: &[u8]) -> Result<KeyPackage> {
        let kp_in = KeyPackageIn::tls_deserialize_exact(bytes).map_err(mls_err)?;
        let kp = kp_in.validate(self.provider.crypto(), ProtocolVersion::Mls10).map_err(mls_err)?;
        if kp.ciphersuite() != CIPHERSUITE {
            return Err(CryptoError::WrongCiphersuite);
        }
        Ok(kp)
    }

    /// Crée un groupe et y ajoute les appareils correspondant aux KeyPackages.
    pub fn create_group(&self, key_packages: &[Vec<u8>]) -> Result<CreatedGroup> {
        if key_packages.is_empty() {
            return Err(CryptoError::Mls("aucun appareil à ajouter".into()));
        }
        let kps = key_packages.iter().map(|b| self.validate_key_package(b)).collect::<Result<Vec<_>>>()?;
        let mut group = MlsGroup::new(&self.provider, &self.signer, &Self::create_config(), self.credential.clone())
            .map_err(mls_err)?;
        let (_commit, welcome, _group_info) = group.add_members(&self.provider, &self.signer, &kps).map_err(mls_err)?;
        group.merge_pending_commit(&self.provider).map_err(mls_err)?;
        Ok(CreatedGroup {
            group_id: group.group_id().as_slice().to_vec(),
            welcome: welcome.tls_serialize_detached().map_err(mls_err)?,
            members: self.normalize_members(members_of(&group)?),
        })
    }

    fn load(&self, group_id: &[u8]) -> Result<MlsGroup> {
        MlsGroup::load(self.provider.storage(), &GroupId::from_slice(group_id))
            .map_err(mls_err)?
            .ok_or(CryptoError::UnknownGroup)
    }

    /// Membres actuels d'un groupe.
    pub fn members(&self, group_id: &[u8]) -> Result<Vec<GroupMember>> {
        Ok(self.normalize_members(members_of(&self.load(group_id)?)?))
    }

    /// Chiffre et signe un message applicatif.
    pub fn encrypt(&self, group_id: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut group = self.load(group_id)?;
        let msg = group.create_message(&self.provider, &self.signer, plaintext).map_err(mls_err)?;
        msg.tls_serialize_detached().map_err(mls_err)
    }

    /// Émet un commit de mise à jour (rotation de la clé de chemin : PCS).
    /// Retourne le commit à diffuser aux autres membres.
    pub fn self_update(&self, group_id: &[u8]) -> Result<Vec<u8>> {
        let mut group = self.load(group_id)?;
        let bundle = group.self_update(&self.provider, &self.signer, LeafNodeParameters::default()).map_err(mls_err)?;
        let commit = bundle.commit().tls_serialize_detached().map_err(mls_err)?;
        group.merge_pending_commit(&self.provider).map_err(mls_err)?;
        Ok(commit)
    }

    /// Ajoute des appareils (KeyPackages validés) à un groupe existant.
    pub fn add_members(&self, group_id: &[u8], key_packages: &[Vec<u8>]) -> Result<AddedMembers> {
        if key_packages.is_empty() {
            return Err(CryptoError::Mls("aucun appareil à ajouter".into()));
        }
        let kps = key_packages.iter().map(|b| self.validate_key_package(b)).collect::<Result<Vec<_>>>()?;
        let mut group = self.load(group_id)?;
        let (commit, welcome, _) = group.add_members(&self.provider, &self.signer, &kps).map_err(mls_err)?;
        group.merge_pending_commit(&self.provider).map_err(mls_err)?;
        Ok(AddedMembers {
            commit: commit.tls_serialize_detached().map_err(mls_err)?,
            welcome: welcome.tls_serialize_detached().map_err(mls_err)?,
            members: self.normalize_members(members_of(&group)?),
        })
    }

    /// Retire du groupe les appareils indiqués. Retourne le commit à diffuser
    /// (y compris aux appareils retirés, pour qu'ils constatent leur retrait).
    pub fn remove_devices(&self, group_id: &[u8], devices: &[Uuid]) -> Result<Vec<u8>> {
        let mut group = self.load(group_id)?;
        let mut leaves = Vec::new();
        for m in group.members() {
            if devices.contains(&MemberIdentity::from_credential(&m.credential)?.device_id) {
                leaves.push(m.index);
            }
        }
        if leaves.is_empty() {
            return Err(CryptoError::Mls("aucun appareil correspondant dans le groupe".into()));
        }
        let (commit, _, _) = group.remove_members(&self.provider, &self.signer, &leaves).map_err(mls_err)?;
        group.merge_pending_commit(&self.provider).map_err(mls_err)?;
        commit.tls_serialize_detached().map_err(mls_err)
    }

    /// Propose une mise à jour de notre feuille (rotation de clés), à valider
    /// par le committer du groupe.
    pub fn propose_self_update(&self, group_id: &[u8]) -> Result<Vec<u8>> {
        let mut group = self.load(group_id)?;
        let (msg, _) =
            group.propose_self_update(&self.provider, &self.signer, LeafNodeParameters::default()).map_err(mls_err)?;
        msg.tls_serialize_detached().map_err(mls_err)
    }

    /// Propose notre départ du groupe (à valider par le committer).
    pub fn propose_leave(&self, group_id: &[u8]) -> Result<Vec<u8>> {
        let mut group = self.load(group_id)?;
        let msg = group.leave_group(&self.provider, &self.signer).map_err(mls_err)?;
        msg.tls_serialize_detached().map_err(mls_err)
    }

    /// Valide les propositions en attente par un commit (s'il y en a).
    pub fn commit_pending(&self, group_id: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut group = self.load(group_id)?;
        if group.pending_proposals().next().is_none() {
            return Ok(None);
        }
        let (commit, _, _) = group.commit_to_pending_proposals(&self.provider, &self.signer).map_err(mls_err)?;
        group.merge_pending_commit(&self.provider).map_err(mls_err)?;
        Ok(Some(commit.tls_serialize_detached().map_err(mls_err)?))
    }

    /// Supprime l'état local d'un groupe (après départ ou retrait).
    pub fn delete_group(&self, group_id: &[u8]) -> Result<()> {
        let mut group = self.load(group_id)?;
        group.delete(self.provider.storage()).map_err(mls_err)
    }

    /// Traite un message reçu en acceptant tout commit (voir [`MlsClient::process_with`]).
    pub fn process(&self, bytes: &[u8]) -> Result<Incoming> {
        self.process_with(bytes, &|_, _| true)
    }

    /// Traite un message reçu (Welcome, commit, proposition ou message
    /// applicatif). `commit_allowed(group_id, émetteur)` décide si un commit
    /// peut être appliqué : il est rejeté **avant** toute modification d'état.
    pub fn process_with(
        &self,
        bytes: &[u8],
        commit_allowed: &dyn Fn(&[u8], &MemberIdentity) -> bool,
    ) -> Result<Incoming> {
        let msg = MlsMessageIn::tls_deserialize_exact(bytes).map_err(mls_err)?;
        match msg.extract() {
            MlsMessageBodyIn::Welcome(welcome) => {
                let group = StagedWelcome::new_from_welcome(&self.provider, &Self::join_config(), welcome, None)
                    .map_err(mls_err)?
                    .into_group(&self.provider)
                    .map_err(mls_err)?;
                if group.ciphersuite() != CIPHERSUITE {
                    return Err(CryptoError::WrongCiphersuite);
                }
                Ok(Incoming::Joined {
                    group_id: group.group_id().as_slice().to_vec(),
                    members: self.normalize_members(members_of(&group)?),
                })
            }
            MlsMessageBodyIn::PrivateMessage(pm) => self.process_protocol(pm.into(), commit_allowed),
            MlsMessageBodyIn::PublicMessage(pm) => self.process_protocol(pm.into(), commit_allowed),
            _ => Err(CryptoError::Mls("type de message MLS inattendu".into())),
        }
    }

    fn process_protocol(
        &self,
        pm: ProtocolMessage,
        commit_allowed: &dyn Fn(&[u8], &MemberIdentity) -> bool,
    ) -> Result<Incoming> {
        let group_id = pm.group_id().as_slice().to_vec();
        let mut group = self.load(&group_id)?;
        let processed = group.process_message(&self.provider, pm).map_err(mls_err)?;
        let sender = self.normalize(MemberIdentity::from_credential(processed.credential())?);
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => {
                Ok(Incoming::Application { group_id, sender, plaintext: Zeroizing::new(app.into_bytes()) })
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                if !commit_allowed(&group_id, &sender) {
                    return Err(CryptoError::CommitRejected);
                }
                let removed_self = staged.self_removed();
                group.merge_staged_commit(&self.provider, *staged).map_err(mls_err)?;
                let members = if removed_self { Vec::new() } else { self.normalize_members(members_of(&group)?) };
                Ok(Incoming::Committed { group_id, sender, members, removed_self })
            }
            ProcessedMessageContent::ProposalMessage(p) => {
                group.store_pending_proposal(self.provider.storage(), *p).map_err(mls_err)?;
                Ok(Incoming::ProposalStored { group_id, sender })
            }
            ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                Err(CryptoError::Mls("adhésion externe non autorisée".into()))
            }
            #[allow(unreachable_patterns)]
            _ => Err(CryptoError::Mls("contenu MLS non pris en charge".into())),
        }
    }
}

fn members_of(group: &MlsGroup) -> Result<Vec<GroupMember>> {
    group
        .members()
        .map(|m| {
            Ok(GroupMember {
                identity: MemberIdentity::from_credential(&m.credential)?,
                signature_key: m.signature_key,
            })
        })
        .collect()
}

fn decode_state(state: &[u8]) -> Result<HashMap<Vec<u8>, Vec<u8>>> {
    let bad = || CryptoError::Format("état MLS corrompu".into());
    let mut r = state;
    let mut magic = [0u8; 8];
    r.read_exact(&mut magic).map_err(|_| bad())?;
    if &magic != STATE_MAGIC {
        return Err(bad());
    }
    let read_u32 = |r: &mut &[u8]| -> Result<usize> {
        let mut b = [0u8; 4];
        r.read_exact(&mut b).map_err(|_| bad())?;
        Ok(u32::from_be_bytes(b) as usize)
    };
    let read_vec = |r: &mut &[u8], n: usize| -> Result<Vec<u8>> {
        if n > r.len() {
            return Err(bad());
        }
        let (a, b) = r.split_at(n);
        *r = b;
        Ok(a.to_vec())
    };
    let count = read_u32(&mut r)?;
    let mut map = HashMap::with_capacity(count.min(1 << 16));
    for _ in 0..count {
        let kl = read_u32(&mut r)?;
        let k = read_vec(&mut r, kl)?;
        let vl = read_u32(&mut r)?;
        let v = read_vec(&mut r, vl)?;
        map.insert(k, v);
    }
    if !r.is_empty() {
        return Err(bad());
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(name: &str) -> MlsClient {
        MlsClient::create(MemberIdentity { username: name.into(), device_id: Uuid::new_v4() }).unwrap()
    }

    fn pair() -> (MlsClient, MlsClient, Vec<u8>) {
        let alice = client("alice");
        let bob = client("bob");
        let kp = bob.generate_key_packages(1).unwrap().remove(0);
        let g = alice.create_group(&[kp]).unwrap();
        match bob.process(&g.welcome).unwrap() {
            Incoming::Joined { group_id, members } => {
                assert_eq!(group_id, g.group_id);
                assert_eq!(members.len(), 2);
            }
            other => panic!("{other:?}"),
        }
        (alice, bob, g.group_id)
    }

    #[test]
    fn identity_encoding() {
        let id = MemberIdentity { username: "alice".into(), device_id: Uuid::new_v4() };
        assert_eq!(MemberIdentity::decode(&id.encode()).unwrap(), id);
        // Normalisation selon le site de l'appareil.
        let mut c =
            MlsClient::create(MemberIdentity { username: "bob@site-a".into(), device_id: Uuid::new_v4() }).unwrap();
        let q = |u: &str| MemberIdentity { username: u.into(), device_id: id.device_id };
        assert_eq!(c.normalize(q("alice@site-a")).username, "alice@site-a", "sans site déclaré : inchangé");
        c.set_home_site(Some("site-a".into()));
        assert_eq!(c.normalize(q("alice@site-a")).username, "alice");
        assert_eq!(c.normalize(q("alice@site-b")).username, "alice@site-b");
        assert_eq!(c.normalize(q("alice@xsite-a")).username, "alice@xsite-a");
        assert_eq!(c.normalize(q("alice")).username, "alice");
        assert!(MemberIdentity::decode(b"sans-separateur").is_err());
    }

    #[test]
    fn roundtrip_both_directions_and_no_plaintext_on_wire() {
        let (alice, bob, gid) = pair();
        let secret = b"rendez-vous a 18h";
        let ct = alice.encrypt(&gid, secret).unwrap();
        assert!(!ct.windows(secret.len()).any(|w| w == secret));
        match bob.process(&ct).unwrap() {
            Incoming::Application { sender, plaintext, .. } => {
                assert_eq!(sender.username, "alice");
                assert_eq!(&plaintext[..], secret);
            }
            other => panic!("{other:?}"),
        }
        let ct = bob.encrypt(&gid, b"ok").unwrap();
        assert!(matches!(alice.process(&ct).unwrap(), Incoming::Application { .. }));
    }

    #[test]
    fn replay_is_rejected() {
        let (alice, bob, gid) = pair();
        let ct = alice.encrypt(&gid, b"une fois").unwrap();
        bob.process(&ct).unwrap();
        assert!(bob.process(&ct).is_err(), "un rejeu doit être refusé");
    }

    #[test]
    fn tampering_is_rejected() {
        let (alice, bob, gid) = pair();
        let mut ct = alice.encrypt(&gid, b"integre").unwrap();
        let n = ct.len();
        ct[n - 5] ^= 0x01;
        assert!(bob.process(&ct).is_err());
    }

    #[test]
    fn padding_hides_exact_length() {
        let (alice, _bob, gid) = pair();
        let a = alice.encrypt(&gid, b"a").unwrap();
        let b = alice.encrypt(&gid, &[b'b'; 100]).unwrap();
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn state_export_restore() {
        let (alice, bob, gid) = pair();
        let state = bob.export_state().unwrap();
        let pk = bob.signature_public_key();
        let id = bob.identity().clone();
        drop(bob);
        let bob = MlsClient::restore(id, &pk, &state).unwrap();
        let ct = alice.encrypt(&gid, b"apres redemarrage").unwrap();
        assert!(matches!(bob.process(&ct).unwrap(), Incoming::Application { .. }));
        assert!(MlsClient::restore(bob.identity().clone(), &pk, b"garbage").is_err());
    }

    #[test]
    fn self_update_rotates_epoch() {
        let (alice, bob, gid) = pair();
        let commit = alice.self_update(&gid).unwrap();
        assert!(matches!(bob.process(&commit).unwrap(), Incoming::Committed { .. }));
        let ct = bob.encrypt(&gid, b"nouvelle epoque").unwrap();
        assert!(matches!(alice.process(&ct).unwrap(), Incoming::Application { .. }));
    }

    #[test]
    fn third_party_cannot_decrypt() {
        let (alice, _bob, gid) = pair();
        let eve = client("eve");
        let ct = alice.encrypt(&gid, b"secret").unwrap();
        assert!(matches!(eve.process(&ct), Err(CryptoError::UnknownGroup)));
    }

    #[test]
    fn key_package_inspection() {
        let alice = client("alice");
        let bob = client("bob");
        let kp = bob.generate_key_packages(1).unwrap().remove(0);
        let m = alice.inspect_key_package(&kp).unwrap();
        assert_eq!(m.identity, *bob.identity());
        assert_eq!(m.signature_key, bob.signature_public_key());
        assert!(alice.inspect_key_package(&kp[..kp.len() - 1]).is_err());
    }
}

#[cfg(test)]
mod group_tests {
    use super::*;

    fn client(name: &str) -> MlsClient {
        MlsClient::create(MemberIdentity { username: name.into(), device_id: Uuid::new_v4() }).unwrap()
    }

    fn join(c: &MlsClient, welcome: &[u8]) {
        assert!(matches!(c.process(welcome).unwrap(), Incoming::Joined { .. }));
    }

    #[test]
    fn group_add_remove_and_removed_member_locked_out() {
        let (alice, bob, carol) = (client("alice"), client("bob"), client("carol"));
        let g = alice.create_group(&[bob.generate_key_packages(1).unwrap().remove(0)]).unwrap();
        join(&bob, &g.welcome);
        // Ajout de Carol : commit pour Bob, Welcome pour Carol.
        let add = alice.add_members(&g.group_id, &[carol.generate_key_packages(1).unwrap().remove(0)]).unwrap();
        assert_eq!(add.members.len(), 3);
        assert!(matches!(bob.process(&add.commit).unwrap(), Incoming::Committed { removed_self: false, .. }));
        join(&carol, &add.welcome);
        let m = carol.encrypt(&g.group_id, b"salut le groupe").unwrap();
        assert!(matches!(alice.process(&m).unwrap(), Incoming::Application { .. }));
        assert!(matches!(bob.process(&m).unwrap(), Incoming::Application { .. }));
        // Retrait de Bob.
        let rm = alice.remove_devices(&g.group_id, &[bob.identity().device_id]).unwrap();
        match bob.process(&rm).unwrap() {
            Incoming::Committed { removed_self, .. } => assert!(removed_self),
            other => panic!("{other:?}"),
        }
        assert!(matches!(carol.process(&rm).unwrap(), Incoming::Committed { removed_self: false, .. }));
        // Nouvelle époque : Bob ne peut plus déchiffrer.
        let secret = alice.encrypt(&g.group_id, b"apres retrait").unwrap();
        assert!(bob.process(&secret).is_err());
        assert!(matches!(carol.process(&secret).unwrap(), Incoming::Application { .. }));
    }

    #[test]
    fn proposals_committed_by_admin_only() {
        let (alice, bob) = (client("alice"), client("bob"));
        let g = alice.create_group(&[bob.generate_key_packages(1).unwrap().remove(0)]).unwrap();
        join(&bob, &g.welcome);
        // Bob propose une rotation ; Alice (committer) la valide.
        let prop = bob.propose_self_update(&g.group_id).unwrap();
        assert!(matches!(alice.process(&prop).unwrap(), Incoming::ProposalStored { .. }));
        let commit = alice.commit_pending(&g.group_id).unwrap().expect("commit");
        assert!(alice.commit_pending(&g.group_id).unwrap().is_none());
        assert!(matches!(bob.process(&commit).unwrap(), Incoming::Committed { .. }));
        let m = bob.encrypt(&g.group_id, b"apres rotation").unwrap();
        assert!(matches!(alice.process(&m).unwrap(), Incoming::Application { .. }));
        // Un commit d'un membre non autorisé est rejeté sans modifier l'état.
        let rogue = bob.self_update(&g.group_id).unwrap();
        let only_alice = |_: &[u8], s: &MemberIdentity| s.username == "alice";
        assert!(matches!(alice.process_with(&rogue, &only_alice), Err(CryptoError::CommitRejected)));
        // Alice est restée à l'époque précédente : un message de Bob émis dans
        // l'époque qu'il a créée seul est illisible pour elle.
        let m = bob.encrypt(&g.group_id, b"epoque non reconnue").unwrap();
        assert!(alice.process(&m).is_err());
    }

    #[test]
    fn leave_via_proposal() {
        let (alice, bob) = (client("alice"), client("bob"));
        let g = alice.create_group(&[bob.generate_key_packages(1).unwrap().remove(0)]).unwrap();
        join(&bob, &g.welcome);
        let leave = bob.propose_leave(&g.group_id).unwrap();
        assert!(matches!(alice.process(&leave).unwrap(), Incoming::ProposalStored { .. }));
        let commit = alice.commit_pending(&g.group_id).unwrap().unwrap();
        assert!(matches!(bob.process(&commit).unwrap(), Incoming::Committed { removed_self: true, .. }));
        assert_eq!(alice.members(&g.group_id).unwrap().len(), 1);
    }
}
