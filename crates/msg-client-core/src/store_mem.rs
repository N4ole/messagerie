//! Base locale du client web : même interface que la base SQLCipher du
//! desktop, données tenues en mémoire et persistées sous forme d'un
//! instantané **chiffré** (XChaCha20-Poly1305, clé de 256 bits enveloppée
//! par le mot de passe) que l'hôte conserve (IndexedDB dans le navigateur).
//!
//! SQLCipher n'existe pas dans le navigateur : c'est l'adaptation prévue par
//! la conception (document 01, « BDD locale web »). Le volume de données
//! d'un client web d'appoint reste modeste ; l'instantané est réécrit après
//! chaque modification (ou à la fin d'une transaction).

use std::cell::RefCell;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{ClientError, Result};
use crate::store::{status, Contact, StoredConversation, StoredMessage};

/// Données associées de l'instantané chiffré (séparation de domaine).
const SNAPSHOT_AAD: &[u8] = b"messagerie/web-store/v1";

/// Fonction de persistance fournie par l'hôte (reçoit l'instantané chiffré).
pub type Persist = Box<dyn Fn(&[u8])>;

#[derive(Default, Serialize, Deserialize)]
struct MemContact {
    identity_key: Vec<u8>,
    pending_identity_key: Option<Vec<u8>>,
    verified: bool,
}

#[derive(Serialize, Deserialize)]
struct MemMessage {
    seq: u64,
    unread: bool,
    m: StoredMessage,
}

#[derive(Default, Serialize, Deserialize)]
struct State {
    meta: BTreeMap<String, Vec<u8>>,
    contacts: BTreeMap<String, MemContact>,
    conversations: BTreeMap<Vec<u8>, StoredConversation>,
    messages: BTreeMap<String, MemMessage>,
    next_seq: u64,
}

impl Drop for State {
    fn drop(&mut self) {
        for v in self.meta.values_mut() {
            v.zeroize();
        }
    }
}

pub struct MemStore {
    state: RefCell<State>,
    key: Zeroizing<[u8; 32]>,
    persist: Persist,
    /// Profondeur de transaction : la persistance est différée jusqu'au commit.
    in_tx: RefCell<u32>,
}

fn storage<E: std::fmt::Display>(e: E) -> ClientError {
    ClientError::Storage(e.to_string())
}

impl MemStore {
    /// Ouvre la base à partir de l'instantané chiffré `initial` (ou crée une
    /// base vide). Une clé incorrecte ou un instantané altéré est refusé.
    pub fn open(initial: Option<&[u8]>, key: &[u8; 32], persist: Persist) -> Result<Self> {
        let state = match initial {
            Some(blob) => {
                let plain = msg_crypto::keywrap::open(key, blob, SNAPSHOT_AAD).map_err(|_| {
                    ClientError::Storage("base locale illisible (clé incorrecte ou données altérées)".into())
                })?;
                ciborium::from_reader::<State, _>(plain.as_slice()).map_err(storage)?
            }
            None => State::default(),
        };
        let s = Self { state: RefCell::new(state), key: Zeroizing::new(*key), persist, in_tx: RefCell::new(0) };
        if initial.is_none() {
            s.save()?;
        }
        Ok(s)
    }

    fn save(&self) -> Result<()> {
        if *self.in_tx.borrow() > 0 {
            return Ok(());
        }
        let mut plain = Zeroizing::new(Vec::new());
        ciborium::into_writer(&*self.state.borrow(), &mut *plain).map_err(storage)?;
        let sealed = msg_crypto::keywrap::seal(&self.key, &plain, SNAPSHOT_AAD)?;
        (self.persist)(&sealed);
        Ok(())
    }

    /// Applique une modification puis persiste.
    fn update<T>(&self, f: impl FnOnce(&mut State) -> T) -> Result<T> {
        let r = f(&mut self.state.borrow_mut());
        self.save()?;
        Ok(r)
    }

    pub fn schema_version(&self) -> Result<i64> {
        Ok(2)
    }

    // --- Métadonnées --------------------------------------------------------

    pub fn get_meta(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(self.state.borrow().meta.get(key).map(|v| Zeroizing::new(v.clone())))
    }

    pub fn set_meta(&self, key: &str, value: &[u8]) -> Result<()> {
        self.update(|s| {
            if let Some(mut old) = s.meta.insert(key.into(), value.to_vec()) {
                old.zeroize();
            }
        })
    }

    pub fn delete_meta(&self, key: &str) -> Result<()> {
        self.update(|s| {
            if let Some(mut old) = s.meta.remove(key) {
                old.zeroize();
            }
        })
    }

    // --- Contacts -------------------------------------------------------------

    pub fn contact(&self, username: &str) -> Result<Option<Contact>> {
        Ok(self.state.borrow().contacts.get(username).map(|c| Contact {
            identity_key: c.identity_key.clone(),
            pending_identity_key: c.pending_identity_key.clone(),
            verified: c.verified,
        }))
    }

    pub fn contact_identity(&self, username: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.contact(username)?.map(|c| c.identity_key))
    }

    pub fn add_contact(&self, username: &str, identity_key: &[u8], _now_ms: i64) -> Result<()> {
        self.update(|s| {
            s.contacts
                .entry(username.into())
                .or_insert_with(|| MemContact { identity_key: identity_key.to_vec(), ..Default::default() });
        })
    }

    pub fn set_pending_identity(&self, username: &str, key: &[u8]) -> Result<()> {
        self.update(|s| {
            if let Some(c) = s.contacts.get_mut(username) {
                c.pending_identity_key = Some(key.to_vec());
            }
        })
    }

    pub fn accept_pending_identity(&self, username: &str, verified: bool, _now_ms: i64) -> Result<bool> {
        self.update(|s| match s.contacts.get_mut(username) {
            Some(c) => match c.pending_identity_key.take() {
                Some(k) => {
                    c.identity_key = k;
                    c.verified = verified;
                    true
                }
                None => false,
            },
            None => false,
        })
    }

    pub fn set_verified(&self, username: &str, verified: bool, _now_ms: i64) -> Result<()> {
        self.update(|s| {
            if let Some(c) = s.contacts.get_mut(username) {
                c.verified = verified;
            }
        })
    }

    // --- Conversations ------------------------------------------------------

    pub fn insert_conversation(&self, c: &StoredConversation) -> Result<()> {
        self.update(|s| {
            s.conversations.entry(c.group_id.clone()).or_insert_with(|| StoredConversation {
                last_activity_ms: c.created_at_ms,
                last_rotation_ms: c.created_at_ms,
                sent_since_rotation: 0,
                unread: 0,
                ..c.clone()
            });
        })
    }

    fn with_conv(&self, group_id: &[u8], f: impl FnOnce(&mut StoredConversation)) -> Result<()> {
        self.update(|s| {
            if let Some(c) = s.conversations.get_mut(group_id) {
                f(c);
            }
        })
    }

    pub fn set_status(&self, group_id: &[u8], status: &str) -> Result<()> {
        self.with_conv(group_id, |c| c.status = status.into())
    }

    /// Un nom vide (conversation directe) ne fixe que l'administrateur.
    pub fn set_group_info(&self, group_id: &[u8], name: &str, admin: &str) -> Result<()> {
        self.with_conv(group_id, |c| {
            if !name.is_empty() {
                c.kind = "group".into();
                c.name = Some(name.into());
            }
            c.admin = Some(admin.into());
        })
    }

    pub fn set_ttl(&self, group_id: &[u8], ttl_s: Option<u32>) -> Result<()> {
        self.with_conv(group_id, |c| c.ttl_s = ttl_s)
    }

    pub fn note_sent(&self, group_id: &[u8]) -> Result<()> {
        self.with_conv(group_id, |c| c.sent_since_rotation += 1)
    }

    pub fn mark_rotated(&self, group_id: &[u8], now_ms: i64) -> Result<()> {
        self.with_conv(group_id, |c| {
            c.last_rotation_ms = now_ms;
            c.sent_since_rotation = 0;
        })
    }

    pub fn rotation_due(&self, now_ms: i64, max_age_ms: i64, max_sent: i64) -> Result<Vec<StoredConversation>> {
        Ok(self
            .conversations()?
            .into_iter()
            .filter(|c| {
                c.status == status::OK
                    && (now_ms - c.last_rotation_ms >= max_age_ms || c.sent_since_rotation >= max_sent)
            })
            .collect())
    }

    pub fn conversation_with(&self, peer: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .conversations()?
            .into_iter()
            .find(|c| {
                c.kind == "direct" && c.peer == peer && (c.status == status::OK || c.status == status::IDENTITY_CHANGED)
            })
            .map(|c| c.group_id))
    }

    fn unread(s: &State, group_id: &[u8]) -> i64 {
        s.messages.values().filter(|m| m.unread && m.m.group_id == group_id).count() as i64
    }

    pub fn conversation(&self, group_id: &[u8]) -> Result<Option<StoredConversation>> {
        let s = self.state.borrow();
        Ok(s.conversations
            .get(group_id)
            .map(|c| StoredConversation { unread: Self::unread(&s, group_id), ..c.clone() }))
    }

    pub fn conversations(&self) -> Result<Vec<StoredConversation>> {
        let s = self.state.borrow();
        let mut v: Vec<StoredConversation> = s
            .conversations
            .values()
            .map(|c| StoredConversation { unread: Self::unread(&s, &c.group_id), ..c.clone() })
            .collect();
        v.sort_by_key(|c| std::cmp::Reverse(c.last_activity_ms));
        Ok(v)
    }

    pub fn mark_read(&self, group_id: &[u8]) -> Result<()> {
        self.update(|s| {
            for m in s.messages.values_mut().filter(|m| m.m.group_id == group_id) {
                m.unread = false;
            }
        })
    }

    // --- Messages -------------------------------------------------------------

    pub fn insert_message(&self, m: &StoredMessage) -> Result<bool> {
        self.update(|s| {
            if s.messages.contains_key(&m.id) {
                return false;
            }
            s.next_seq += 1;
            let seq = s.next_seq;
            s.messages.insert(m.id.clone(), MemMessage { seq, unread: !m.outgoing, m: m.clone() });
            if let Some(c) = s.conversations.get_mut(&m.group_id) {
                c.last_activity_ms = c.last_activity_ms.max(m.received_at_ms);
            }
            true
        })
    }

    pub fn messages(&self, group_id: &[u8], limit: u32) -> Result<Vec<StoredMessage>> {
        let s = self.state.borrow();
        let mut v: Vec<&MemMessage> = s.messages.values().filter(|m| m.m.group_id == group_id).collect();
        // Les plus récents (réception, puis ordre d'insertion), rendus du plus ancien au plus récent.
        v.sort_by_key(|m| std::cmp::Reverse((m.m.received_at_ms, m.seq)));
        v.truncate(limit as usize);
        v.reverse();
        Ok(v.into_iter().map(|m| m.m.clone()).collect())
    }

    pub fn message(&self, id: &str) -> Result<Option<StoredMessage>> {
        Ok(self.state.borrow().messages.get(id).map(|m| m.m.clone()))
    }

    pub fn purge_expired(&self, now_ms: i64) -> Result<usize> {
        self.update(|s| {
            let before = s.messages.len();
            s.messages.retain(|_, m| m.m.expires_at_ms.is_none_or(|e| e > now_ms));
            before - s.messages.len()
        })
    }

    /// Exécute plusieurs opérations de manière atomique : en cas d'erreur,
    /// l'état antérieur est restauré ; la persistance n'a lieu qu'au commit.
    pub fn transaction<T>(&mut self, f: impl FnOnce(&MemStore) -> Result<T>) -> Result<T> {
        let mut backup = Vec::new();
        ciborium::into_writer(&*self.state.borrow(), &mut backup).map_err(storage)?;
        let backup = Zeroizing::new(backup);
        *self.in_tx.borrow_mut() += 1;
        let r = f(self);
        *self.in_tx.borrow_mut() -= 1;
        match r {
            Ok(v) => {
                self.save()?;
                Ok(v)
            }
            Err(e) => {
                let restored: State = ciborium::from_reader(backup.as_slice()).map_err(storage)?;
                *self.state.borrow_mut() = restored;
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use super::*;

    fn msg(id: &str, gid: &[u8], received: i64, outgoing: bool) -> StoredMessage {
        StoredMessage {
            id: id.into(),
            group_id: gid.to_vec(),
            sender: "bob".into(),
            sender_device: "d".into(),
            kind: "text".into(),
            body: format!("corps {id}"),
            attachment: None,
            sent_at_ms: 1,
            received_at_ms: received,
            outgoing,
            expires_at_ms: None,
        }
    }

    fn conv(gid: &[u8], peer: &str) -> StoredConversation {
        StoredConversation {
            group_id: gid.to_vec(),
            kind: "direct".into(),
            peer: peer.into(),
            name: None,
            admin: None,
            status: status::OK.into(),
            created_at_ms: 10,
            last_activity_ms: 10,
            unread: 0,
            ttl_s: None,
            last_rotation_ms: 10,
            sent_since_rotation: 0,
        }
    }

    type Disk = Rc<RefCell<Option<Vec<u8>>>>;

    /// Clé de test aléatoire (jamais de clé codée en dur).
    fn key() -> [u8; 32] {
        msg_crypto::random_bytes::<32>().unwrap()
    }

    fn sink(disk: &Disk) -> Persist {
        let d = disk.clone();
        Box::new(move |b: &[u8]| *d.borrow_mut() = Some(b.to_vec()))
    }

    #[test]
    fn persisted_snapshot_is_encrypted_and_reloads() {
        let disk: Disk = Rc::new(RefCell::new(None));
        let key = key();
        let s = MemStore::open(None, &key, sink(&disk)).unwrap();
        s.set_meta("identity_secret", b"secret-tres-sensible").unwrap();
        s.insert_conversation(&conv(b"g1", "bob")).unwrap();
        assert!(s.insert_message(&msg("m1", b"g1", 20, false)).unwrap());
        assert!(!s.insert_message(&msg("m1", b"g1", 20, false)).unwrap(), "doublon refusé");
        drop(s);
        let blob = disk.borrow().clone().unwrap();
        // Rien de lisible dans l'instantané.
        for needle in [&b"secret-tres-sensible"[..], b"corps m1", b"bob"] {
            assert!(!blob.windows(needle.len()).any(|w| w == needle));
        }
        // Mauvaise clé ou instantané altéré : refus.
        assert!(MemStore::open(Some(&blob), &self::key(), sink(&disk)).is_err());
        let mut bad = blob.clone();
        let n = bad.len() - 1;
        bad[n] ^= 1;
        assert!(MemStore::open(Some(&bad), &key, sink(&disk)).is_err());
        let s = MemStore::open(Some(&blob), &key, sink(&disk)).unwrap();
        assert_eq!(s.get_meta("identity_secret").unwrap().unwrap().as_slice(), b"secret-tres-sensible");
        let c = s.conversation(b"g1").unwrap().unwrap();
        assert_eq!((c.unread, c.last_activity_ms), (1, 20));
        assert_eq!(s.conversation_with("bob").unwrap().unwrap(), b"g1".to_vec());
    }

    #[test]
    fn ordering_limit_expiry_and_transactions() {
        let disk: Disk = Rc::new(RefCell::new(None));
        let mut s = MemStore::open(None, &key(), sink(&disk)).unwrap();
        s.insert_conversation(&conv(b"g", "bob")).unwrap();
        for (i, t) in [(1, 30), (2, 10), (3, 20), (4, 20)] {
            s.insert_message(&msg(&format!("m{i}"), b"g", t, i == 4)).unwrap();
        }
        let ids: Vec<String> = s.messages(b"g", 3).unwrap().into_iter().map(|m| m.id).collect();
        assert_eq!(ids, ["m3", "m4", "m1"], "trois plus récents, du plus ancien au plus récent");
        assert_eq!(s.conversation(b"g").unwrap().unwrap().unread, 3, "messages envoyés non comptés");
        s.mark_read(b"g").unwrap();
        assert_eq!(s.conversation(b"g").unwrap().unwrap().unread, 0);

        let mut e = msg("e", b"g", 40, false);
        e.expires_at_ms = Some(100);
        s.insert_message(&e).unwrap();
        assert_eq!(s.purge_expired(99).unwrap(), 0);
        assert_eq!(s.purge_expired(100).unwrap(), 1);

        // Transaction annulée : aucune trace ; validée : persistée une fois.
        let saved_before = disk.borrow().clone();
        let r: Result<()> = s.transaction(|t| {
            t.set_meta("a", b"1")?;
            Err(ClientError::Invalid("échec".into()))
        });
        assert!(r.is_err());
        assert!(s.get_meta("a").unwrap().is_none());
        assert_eq!(*disk.borrow(), saved_before);
        s.transaction(|t| {
            t.set_meta("a", b"1")?;
            t.set_group_info(b"g", "Équipe", "alice")
        })
        .unwrap();
        let c = s.conversation(b"g").unwrap().unwrap();
        assert_eq!((c.kind.as_str(), c.name.as_deref(), c.admin.as_deref()), ("group", Some("Équipe"), Some("alice")));
        assert_ne!(*disk.borrow(), saved_before);
    }
}
