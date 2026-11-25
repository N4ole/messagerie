//! Base locale chiffrée (SQLCipher).

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{params, Connection, OptionalExtension};
use zeroize::Zeroizing;

use crate::error::{ClientError, Result};

/// La connexion est protégée par un verrou pour que le client soit `Sync`
/// (partage entre tâches asynchrones). Chaque opération est courte et
/// synchrone : le verrou n'est jamais tenu pendant une attente réseau.
pub struct LocalStore {
    conn: Mutex<Connection>,
}

/// Message stocké localement.
#[derive(Debug, Clone)]
pub struct StoredMessage {
    pub id: String,
    pub group_id: Vec<u8>,
    pub sender: String,
    pub sender_device: String,
    /// `text` ou `attachment`.
    pub kind: String,
    /// Texte (ou légende d'une pièce jointe).
    pub body: String,
    /// Référence de pièce jointe (JSON), chiffrée avec la base.
    pub attachment: Option<String>,
    pub sent_at_ms: i64,
    pub received_at_ms: i64,
    pub outgoing: bool,
    /// Suppression automatique (message éphémère).
    pub expires_at_ms: Option<i64>,
}

/// Statut d'une conversation.
pub mod status {
    pub const OK: &str = "ok";
    /// La clé d'identité d'un membre a changé : contenu masqué, envoi bloqué.
    pub const IDENTITY_CHANGED: &str = "identity_changed";
    /// Nous avons été retirés du groupe.
    pub const REMOVED: &str = "removed";
    /// Nous avons quitté le groupe.
    pub const LEFT: &str = "left";
}

#[derive(Debug, Clone)]
pub struct StoredConversation {
    pub group_id: Vec<u8>,
    /// `direct` ou `group`.
    pub kind: String,
    /// Correspondant (conversation directe).
    pub peer: String,
    pub name: Option<String>,
    /// Seul membre autorisé à émettre des commits MLS (évite les fourches).
    pub admin: Option<String>,
    pub status: String,
    pub created_at_ms: i64,
    pub last_activity_ms: i64,
    pub unread: i64,
    /// Durée de vie par défaut des messages envoyés (éphémères).
    pub ttl_s: Option<u32>,
    pub last_rotation_ms: i64,
    pub sent_since_rotation: i64,
}

#[derive(Debug, Clone)]
pub struct Contact {
    pub identity_key: Vec<u8>,
    pub pending_identity_key: Option<Vec<u8>>,
    pub verified: bool,
}

const SCHEMA_V1: &str = r#"
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS contacts (
    username TEXT PRIMARY KEY,
    identity_key BLOB NOT NULL,
    first_seen_ms INTEGER NOT NULL,
    verified INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS conversations (
    group_id BLOB PRIMARY KEY,
    peer TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    last_activity_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS conversations_peer ON conversations (peer);
CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    group_id BLOB NOT NULL,
    sender TEXT NOT NULL,
    sender_device TEXT NOT NULL,
    body TEXT NOT NULL,
    sent_at_ms INTEGER NOT NULL,
    received_at_ms INTEGER NOT NULL,
    outgoing INTEGER NOT NULL,
    unread INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS messages_group ON messages (group_id, received_at_ms);
"#;

/// Phase 2 : groupes, changement de clé, éphémères, pièces jointes, rotation.
const SCHEMA_V2: &str = r#"
ALTER TABLE contacts ADD COLUMN pending_identity_key BLOB;
ALTER TABLE contacts ADD COLUMN verified_at_ms INTEGER;
ALTER TABLE conversations ADD COLUMN kind TEXT NOT NULL DEFAULT 'direct';
ALTER TABLE conversations ADD COLUMN name TEXT;
ALTER TABLE conversations ADD COLUMN admin TEXT;
ALTER TABLE conversations ADD COLUMN status TEXT NOT NULL DEFAULT 'ok';
ALTER TABLE conversations ADD COLUMN ttl_s INTEGER;
ALTER TABLE conversations ADD COLUMN last_rotation_ms INTEGER NOT NULL DEFAULT 0;
ALTER TABLE conversations ADD COLUMN sent_since_rotation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE messages ADD COLUMN kind TEXT NOT NULL DEFAULT 'text';
ALTER TABLE messages ADD COLUMN attachment TEXT;
ALTER TABLE messages ADD COLUMN expires_at_ms INTEGER;
CREATE INDEX IF NOT EXISTS messages_expiry ON messages (expires_at_ms) WHERE expires_at_ms IS NOT NULL;
"#;

const SCHEMA_VERSION: i64 = 2;

const CONV_COLUMNS: &str = "c.group_id, c.kind, c.peer, c.name, c.admin, c.status, c.created_at_ms, c.last_activity_ms,
    (SELECT COUNT(*) FROM messages m WHERE m.group_id = c.group_id AND m.unread = 1),
    c.ttl_s, c.last_rotation_ms, c.sent_since_rotation";

const MSG_COLUMNS: &str =
    "id, group_id, sender, sender_device, kind, body, attachment, sent_at_ms, received_at_ms, outgoing, expires_at_ms";

impl LocalStore {
    /// Ouvre (ou crée) la base avec une clé brute de 256 bits, puis applique
    /// les migrations de schéma.
    pub fn open(path: &Path, key: &[u8; 32]) -> Result<Self> {
        let conn = Connection::open(path)?;
        let pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", hex::encode(key)));
        conn.execute_batch(&pragma)?;
        // Vérifie la clé : échoue avec « file is not a database » si incorrecte.
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0))
            .map_err(|_| ClientError::Storage("base locale illisible (clé incorrecte ou fichier altéré)".into()))?;
        conn.execute_batch(
            "PRAGMA cipher_memory_security = ON;
             PRAGMA secure_delete = ON;
             PRAGMA journal_mode = DELETE;
             PRAGMA foreign_keys = ON;",
        )?;
        conn.execute_batch(SCHEMA_V1)?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version < 2 {
            conn.execute_batch(&format!("BEGIN; {SCHEMA_V2} PRAGMA user_version = {SCHEMA_VERSION}; COMMIT;"))?;
        }
        Ok(Self { conn: Mutex::new(conn) })
    }

    fn c(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn schema_version(&self) -> Result<i64> {
        Ok(self.c().query_row("PRAGMA user_version", [], |r| r.get(0))?)
    }

    // --- Métadonnées (identités, clés, état MLS) ---------------------------

    pub fn get_meta(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(self
            .c()
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get::<_, Vec<u8>>(0))
            .optional()?
            .map(Zeroizing::new))
    }

    pub fn set_meta(&self, key: &str, value: &[u8]) -> Result<()> {
        self.c().execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn delete_meta(&self, key: &str) -> Result<()> {
        self.c().execute("DELETE FROM meta WHERE key = ?1", [key])?;
        Ok(())
    }

    // --- Contacts (confiance au premier usage + vérification) --------------

    pub fn contact(&self, username: &str) -> Result<Option<Contact>> {
        Ok(self
            .c()
            .query_row(
                "SELECT identity_key, pending_identity_key, verified FROM contacts WHERE username = ?1",
                [username],
                |r| {
                    Ok(Contact {
                        identity_key: r.get(0)?,
                        pending_identity_key: r.get(1)?,
                        verified: r.get::<_, i64>(2)? != 0,
                    })
                },
            )
            .optional()?)
    }

    pub fn contact_identity(&self, username: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.contact(username)?.map(|c| c.identity_key))
    }

    pub fn add_contact(&self, username: &str, identity_key: &[u8], now_ms: i64) -> Result<()> {
        self.c().execute(
            "INSERT INTO contacts (username, identity_key, first_seen_ms) VALUES (?1, ?2, ?3) ON CONFLICT DO NOTHING",
            params![username, identity_key, now_ms],
        )?;
        Ok(())
    }

    /// Mémorise une nouvelle clé d'identité observée, en attente de décision.
    pub fn set_pending_identity(&self, username: &str, key: &[u8]) -> Result<()> {
        self.c()
            .execute("UPDATE contacts SET pending_identity_key = ?2 WHERE username = ?1", params![username, key])?;
        Ok(())
    }

    /// Remplace la clé d'identité par la clé en attente.
    pub fn accept_pending_identity(&self, username: &str, verified: bool, now_ms: i64) -> Result<bool> {
        let n = self.c().execute(
            "UPDATE contacts SET identity_key = pending_identity_key, pending_identity_key = NULL,
                    verified = ?2, verified_at_ms = CASE WHEN ?2 = 1 THEN ?3 ELSE NULL END
              WHERE username = ?1 AND pending_identity_key IS NOT NULL",
            params![username, verified as i64, now_ms],
        )?;
        Ok(n > 0)
    }

    pub fn set_verified(&self, username: &str, verified: bool, now_ms: i64) -> Result<()> {
        self.c().execute(
            "UPDATE contacts SET verified = ?2, verified_at_ms = CASE WHEN ?2 = 1 THEN ?3 ELSE NULL END WHERE username = ?1",
            params![username, verified as i64, now_ms],
        )?;
        Ok(())
    }

    // --- Conversations ----------------------------------------------------

    pub fn insert_conversation(&self, c: &StoredConversation) -> Result<()> {
        self.c().execute(
            "INSERT INTO conversations (group_id, kind, peer, name, admin, status, created_at_ms, last_activity_ms,
                                        ttl_s, last_rotation_ms, sent_since_rotation)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?8, ?7, 0) ON CONFLICT(group_id) DO NOTHING",
            params![c.group_id, c.kind, c.peer, c.name, c.admin, c.status, c.created_at_ms, c.ttl_s],
        )?;
        Ok(())
    }

    pub fn set_status(&self, group_id: &[u8], status: &str) -> Result<()> {
        self.c().execute("UPDATE conversations SET status = ?2 WHERE group_id = ?1", params![group_id, status])?;
        Ok(())
    }

    /// Informations annoncées par l'administrateur. Un nom vide (conversation
    /// directe) ne fixe que l'administrateur.
    pub fn set_group_info(&self, group_id: &[u8], name: &str, admin: &str) -> Result<()> {
        self.c().execute(
            "UPDATE conversations SET kind = CASE WHEN ?2 = '' THEN kind ELSE 'group' END,
                    name = CASE WHEN ?2 = '' THEN name ELSE ?2 END, admin = ?3 WHERE group_id = ?1",
            params![group_id, name, admin],
        )?;
        Ok(())
    }

    pub fn set_ttl(&self, group_id: &[u8], ttl_s: Option<u32>) -> Result<()> {
        self.c().execute("UPDATE conversations SET ttl_s = ?2 WHERE group_id = ?1", params![group_id, ttl_s])?;
        Ok(())
    }

    pub fn note_sent(&self, group_id: &[u8]) -> Result<()> {
        self.c().execute(
            "UPDATE conversations SET sent_since_rotation = sent_since_rotation + 1 WHERE group_id = ?1",
            [group_id],
        )?;
        Ok(())
    }

    pub fn mark_rotated(&self, group_id: &[u8], now_ms: i64) -> Result<()> {
        self.c().execute(
            "UPDATE conversations SET last_rotation_ms = ?2, sent_since_rotation = 0 WHERE group_id = ?1",
            params![group_id, now_ms],
        )?;
        Ok(())
    }

    /// Conversations actives dont les clés doivent être renouvelées.
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
            .c()
            .query_row(
                "SELECT group_id FROM conversations WHERE kind = 'direct' AND peer = ?1 AND status IN ('ok', 'identity_changed')
                  ORDER BY last_activity_ms DESC LIMIT 1",
                [peer],
                |r| r.get(0),
            )
            .optional()?)
    }

    pub fn conversation(&self, group_id: &[u8]) -> Result<Option<StoredConversation>> {
        Ok(self
            .c()
            .query_row(
                &format!("SELECT {CONV_COLUMNS} FROM conversations c WHERE c.group_id = ?1"),
                [group_id],
                Self::row_conv,
            )
            .optional()?)
    }

    fn row_conv(r: &rusqlite::Row<'_>) -> rusqlite::Result<StoredConversation> {
        Ok(StoredConversation {
            group_id: r.get(0)?,
            kind: r.get(1)?,
            peer: r.get(2)?,
            name: r.get(3)?,
            admin: r.get(4)?,
            status: r.get(5)?,
            created_at_ms: r.get(6)?,
            last_activity_ms: r.get(7)?,
            unread: r.get(8)?,
            ttl_s: r.get(9)?,
            last_rotation_ms: r.get(10)?,
            sent_since_rotation: r.get(11)?,
        })
    }

    pub fn conversations(&self) -> Result<Vec<StoredConversation>> {
        let c = self.c();
        let mut st =
            c.prepare(&format!("SELECT {CONV_COLUMNS} FROM conversations c ORDER BY c.last_activity_ms DESC"))?;
        let rows = st.query_map([], Self::row_conv)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn mark_read(&self, group_id: &[u8]) -> Result<()> {
        self.c().execute("UPDATE messages SET unread = 0 WHERE group_id = ?1", [group_id])?;
        Ok(())
    }

    // --- Messages ---------------------------------------------------------

    /// Insère un message ; retourne `false` s'il existait déjà (doublon/rejeu).
    pub fn insert_message(&self, m: &StoredMessage) -> Result<bool> {
        let c = self.c();
        let n = c.execute(
            "INSERT INTO messages (id, group_id, sender, sender_device, kind, body, attachment, sent_at_ms,
                                   received_at_ms, outgoing, unread, expires_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) ON CONFLICT(id) DO NOTHING",
            params![
                m.id,
                m.group_id,
                m.sender,
                m.sender_device,
                m.kind,
                m.body,
                m.attachment,
                m.sent_at_ms,
                m.received_at_ms,
                m.outgoing as i64,
                (!m.outgoing) as i64,
                m.expires_at_ms
            ],
        )?;
        if n > 0 {
            c.execute(
                "UPDATE conversations SET last_activity_ms = MAX(last_activity_ms, ?2) WHERE group_id = ?1",
                params![m.group_id, m.received_at_ms],
            )?;
        }
        Ok(n > 0)
    }

    fn row_msg(r: &rusqlite::Row<'_>) -> rusqlite::Result<StoredMessage> {
        Ok(StoredMessage {
            id: r.get(0)?,
            group_id: r.get(1)?,
            sender: r.get(2)?,
            sender_device: r.get(3)?,
            kind: r.get(4)?,
            body: r.get(5)?,
            attachment: r.get(6)?,
            sent_at_ms: r.get(7)?,
            received_at_ms: r.get(8)?,
            outgoing: r.get::<_, i64>(9)? != 0,
            expires_at_ms: r.get(10)?,
        })
    }

    pub fn messages(&self, group_id: &[u8], limit: u32) -> Result<Vec<StoredMessage>> {
        let c = self.c();
        let mut st = c.prepare(&format!(
            "SELECT {MSG_COLUMNS} FROM (
                SELECT * FROM messages WHERE group_id = ?1 ORDER BY received_at_ms DESC, rowid DESC LIMIT ?2
             ) ORDER BY received_at_ms ASC"
        ))?;
        let rows = st.query_map(params![group_id, limit], Self::row_msg)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn message(&self, id: &str) -> Result<Option<StoredMessage>> {
        Ok(self
            .c()
            .query_row(&format!("SELECT {MSG_COLUMNS} FROM messages WHERE id = ?1"), [id], Self::row_msg)
            .optional()?)
    }

    /// Supprime les messages éphémères expirés (effacement sécurisé :
    /// `secure_delete` écrase les pages libérées).
    pub fn purge_expired(&self, now_ms: i64) -> Result<usize> {
        Ok(self
            .c()
            .execute("DELETE FROM messages WHERE expires_at_ms IS NOT NULL AND expires_at_ms <= ?1", [now_ms])?)
    }

    /// Exécute plusieurs opérations de manière atomique.
    /// `&mut self` garantit qu'aucune autre opération ne s'intercale.
    pub fn transaction<T>(&mut self, f: impl FnOnce(&LocalStore) -> Result<T>) -> Result<T> {
        self.c().execute_batch("BEGIN IMMEDIATE")?;
        match f(self) {
            Ok(v) => {
                self.c().execute_batch("COMMIT")?;
                Ok(v)
            }
            Err(e) => {
                let _ = self.c().execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        msg_crypto::random_bytes::<32>().unwrap()
    }

    fn msg(id: &str, gid: &[u8], body: &str) -> StoredMessage {
        StoredMessage {
            id: id.into(),
            group_id: gid.to_vec(),
            sender: "bob".into(),
            sender_device: "d".into(),
            kind: "text".into(),
            body: body.into(),
            attachment: None,
            sent_at_ms: 1,
            received_at_ms: 2,
            outgoing: false,
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
            created_at_ms: 1,
            last_activity_ms: 1,
            unread: 0,
            ttl_s: None,
            last_rotation_ms: 1,
            sent_since_rotation: 0,
        }
    }

    #[test]
    fn encrypted_at_rest_and_wrong_key_rejected() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("t.db");
        let marker = "MARQUEUR-CLAIR-7f3a9c";
        let (k, other) = (key(), key());
        {
            let s = LocalStore::open(&path, &k).unwrap();
            s.insert_conversation(&conv(b"g1", "bob")).unwrap();
            assert!(s.insert_message(&msg("m1", b"g1", marker)).unwrap());
        }
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(marker.len()).any(|w| w == marker.as_bytes()), "clair trouvé dans le fichier");
        assert!(!raw.starts_with(b"SQLite format 3"), "en-tête SQLite en clair");
        assert!(LocalStore::open(&path, &other).is_err());
        let plain = Connection::open(&path).unwrap();
        assert!(plain.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0)).is_err());
        let s = LocalStore::open(&path, &k).unwrap();
        assert_eq!(s.messages(b"g1", 10).unwrap()[0].body, marker);
    }

    #[test]
    fn migrates_phase1_database() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("v1.db");
        let k = key();
        {
            // Base telle que créée par la Phase 1 (schéma v1, user_version 0).
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", hex::encode(k))).unwrap();
            conn.execute_batch(SCHEMA_V1).unwrap();
            conn.execute("INSERT INTO conversations VALUES (x'01', 'bob', 1, 1)", []).unwrap();
            conn.execute("INSERT INTO messages (id, group_id, sender, sender_device, body, sent_at_ms, received_at_ms, outgoing) VALUES ('m', x'01', 'bob', 'd', 'ancien', 1, 1, 0)", []).unwrap();
        }
        let s = LocalStore::open(&path, &k).unwrap();
        assert_eq!(s.schema_version().unwrap(), 2);
        let c = s.conversation(&[1]).unwrap().unwrap();
        assert_eq!((c.kind.as_str(), c.status.as_str()), ("direct", "ok"));
        assert_eq!(s.messages(&[1], 10).unwrap()[0].body, "ancien");
        drop(s);
        // Réouverture : migration idempotente.
        assert_eq!(LocalStore::open(&path, &k).unwrap().schema_version().unwrap(), 2);
    }

    #[test]
    fn duplicates_unread_and_expiry() {
        let d = tempfile::tempdir().unwrap();
        let s = LocalStore::open(&d.path().join("t.db"), &key()).unwrap();
        s.insert_conversation(&conv(b"g", "bob")).unwrap();
        assert!(s.insert_message(&msg("m", b"g", "x")).unwrap());
        assert!(!s.insert_message(&msg("m", b"g", "y")).unwrap());
        assert_eq!(s.conversation(b"g").unwrap().unwrap().unread, 1);
        s.mark_read(b"g").unwrap();
        assert_eq!(s.conversations().unwrap()[0].unread, 0);
        assert_eq!(s.conversation_with("bob").unwrap().unwrap(), b"g".to_vec());
        let mut e = msg("e", b"g", "éphémère");
        e.expires_at_ms = Some(100);
        s.insert_message(&e).unwrap();
        assert_eq!(s.purge_expired(99).unwrap(), 0);
        assert_eq!(s.purge_expired(100).unwrap(), 1);
        assert!(s.message("e").unwrap().is_none());
        assert!(s.message("m").unwrap().is_some());
    }

    #[test]
    fn contacts_tofu_and_pending_identity() {
        let d = tempfile::tempdir().unwrap();
        let s = LocalStore::open(&d.path().join("t.db"), &key()).unwrap();
        s.add_contact("bob", &[1; 32], 0).unwrap();
        s.add_contact("bob", &[2; 32], 0).unwrap();
        assert_eq!(s.contact_identity("bob").unwrap().unwrap(), vec![1; 32]);
        s.set_pending_identity("bob", &[3; 32]).unwrap();
        assert_eq!(s.contact("bob").unwrap().unwrap().pending_identity_key, Some(vec![3; 32]));
        assert!(s.accept_pending_identity("bob", true, 5).unwrap());
        let c = s.contact("bob").unwrap().unwrap();
        assert_eq!((c.identity_key, c.pending_identity_key, c.verified), (vec![3; 32], None, true));
        assert!(!s.accept_pending_identity("bob", false, 6).unwrap());
    }

    #[test]
    fn rotation_due_selection() {
        let d = tempfile::tempdir().unwrap();
        let s = LocalStore::open(&d.path().join("t.db"), &key()).unwrap();
        s.insert_conversation(&conv(b"a", "bob")).unwrap();
        assert!(s.rotation_due(10, 100, 5).unwrap().is_empty());
        assert_eq!(s.rotation_due(101, 100, 5).unwrap().len(), 1);
        for _ in 0..5 {
            s.note_sent(b"a").unwrap();
        }
        assert_eq!(s.rotation_due(10, 100, 5).unwrap().len(), 1);
        s.mark_rotated(b"a", 10).unwrap();
        assert!(s.rotation_due(20, 100, 5).unwrap().is_empty());
        s.set_status(b"a", status::REMOVED).unwrap();
        assert!(s.rotation_due(1000, 100, 5).unwrap().is_empty());
    }
}
