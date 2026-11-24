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
    pub body: String,
    pub sent_at_ms: i64,
    pub received_at_ms: i64,
    pub outgoing: bool,
}

#[derive(Debug, Clone)]
pub struct StoredConversation {
    pub group_id: Vec<u8>,
    pub peer: String,
    pub created_at_ms: i64,
    pub last_activity_ms: i64,
    pub unread: i64,
}

const SCHEMA: &str = r#"
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

impl LocalStore {
    /// Ouvre (ou crée) la base avec une clé brute de 256 bits.
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
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    fn c(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
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

    // --- Contacts (confiance au premier usage) ----------------------------

    pub fn contact_identity(&self, username: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .c()
            .query_row("SELECT identity_key FROM contacts WHERE username = ?1", [username], |r| r.get(0))
            .optional()?)
    }

    pub fn add_contact(&self, username: &str, identity_key: &[u8], now_ms: i64) -> Result<()> {
        self.c().execute(
            "INSERT INTO contacts (username, identity_key, first_seen_ms) VALUES (?1, ?2, ?3) ON CONFLICT DO NOTHING",
            params![username, identity_key, now_ms],
        )?;
        Ok(())
    }

    // --- Conversations ----------------------------------------------------

    pub fn upsert_conversation(&self, group_id: &[u8], peer: &str, now_ms: i64) -> Result<()> {
        self.c().execute(
            "INSERT INTO conversations (group_id, peer, created_at_ms, last_activity_ms) VALUES (?1, ?2, ?3, ?3)
             ON CONFLICT(group_id) DO NOTHING",
            params![group_id, peer, now_ms],
        )?;
        Ok(())
    }

    pub fn conversation_with(&self, peer: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .c()
            .query_row(
                "SELECT group_id FROM conversations WHERE peer = ?1 ORDER BY last_activity_ms DESC LIMIT 1",
                [peer],
                |r| r.get(0),
            )
            .optional()?)
    }

    pub fn conversation(&self, group_id: &[u8]) -> Result<Option<StoredConversation>> {
        Ok(self
            .c()
            .query_row(
                "SELECT c.group_id, c.peer, c.created_at_ms, c.last_activity_ms,
                        (SELECT COUNT(*) FROM messages m WHERE m.group_id = c.group_id AND m.unread = 1)
                   FROM conversations c WHERE c.group_id = ?1",
                [group_id],
                Self::row_conv,
            )
            .optional()?)
    }

    fn row_conv(r: &rusqlite::Row<'_>) -> rusqlite::Result<StoredConversation> {
        Ok(StoredConversation {
            group_id: r.get(0)?,
            peer: r.get(1)?,
            created_at_ms: r.get(2)?,
            last_activity_ms: r.get(3)?,
            unread: r.get(4)?,
        })
    }

    pub fn conversations(&self) -> Result<Vec<StoredConversation>> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT c.group_id, c.peer, c.created_at_ms, c.last_activity_ms,
                    (SELECT COUNT(*) FROM messages m WHERE m.group_id = c.group_id AND m.unread = 1)
               FROM conversations c ORDER BY c.last_activity_ms DESC",
        )?;
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
        let n = self.c().execute(
            "INSERT INTO messages (id, group_id, sender, sender_device, body, sent_at_ms, received_at_ms, outgoing, unread)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) ON CONFLICT(id) DO NOTHING",
            params![
                m.id,
                m.group_id,
                m.sender,
                m.sender_device,
                m.body,
                m.sent_at_ms,
                m.received_at_ms,
                m.outgoing as i64,
                (!m.outgoing) as i64
            ],
        )?;
        if n > 0 {
            self.c().execute(
                "UPDATE conversations SET last_activity_ms = MAX(last_activity_ms, ?2) WHERE group_id = ?1",
                params![m.group_id, m.received_at_ms],
            )?;
        }
        Ok(n > 0)
    }

    pub fn messages(&self, group_id: &[u8], limit: u32) -> Result<Vec<StoredMessage>> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT id, group_id, sender, sender_device, body, sent_at_ms, received_at_ms, outgoing FROM (
                SELECT * FROM messages WHERE group_id = ?1 ORDER BY received_at_ms DESC, rowid DESC LIMIT ?2
             ) ORDER BY received_at_ms ASC",
        )?;
        let rows = st.query_map(params![group_id, limit], |r| {
            Ok(StoredMessage {
                id: r.get(0)?,
                group_id: r.get(1)?,
                sender: r.get(2)?,
                sender_device: r.get(3)?,
                body: r.get(4)?,
                sent_at_ms: r.get(5)?,
                received_at_ms: r.get(6)?,
                outgoing: r.get::<_, i64>(7)? != 0,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
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

    fn msg(id: &str, gid: &[u8], body: &str) -> StoredMessage {
        StoredMessage {
            id: id.into(),
            group_id: gid.to_vec(),
            sender: "bob".into(),
            sender_device: "d".into(),
            body: body.into(),
            sent_at_ms: 1,
            received_at_ms: 2,
            outgoing: false,
        }
    }

    #[test]
    fn encrypted_at_rest_and_wrong_key_rejected() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("t.db");
        let marker = "MARQUEUR-CLAIR-7f3a9c";
        {
            let s = LocalStore::open(&path, &[7u8; 32]).unwrap();
            s.upsert_conversation(b"g1", "bob", 1).unwrap();
            assert!(s.insert_message(&msg("m1", b"g1", marker)).unwrap());
        }
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(marker.len()).any(|w| w == marker.as_bytes()), "clair trouvé dans le fichier");
        assert!(!raw.starts_with(b"SQLite format 3"), "en-tête SQLite en clair");
        assert!(LocalStore::open(&path, &[8u8; 32]).is_err());
        // Sans clé du tout : illisible.
        let plain = Connection::open(&path).unwrap();
        assert!(plain.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0)).is_err());
        let s = LocalStore::open(&path, &[7u8; 32]).unwrap();
        assert_eq!(s.messages(b"g1", 10).unwrap()[0].body, marker);
    }

    #[test]
    fn duplicates_and_unread() {
        let d = tempfile::tempdir().unwrap();
        let s = LocalStore::open(&d.path().join("t.db"), &[1u8; 32]).unwrap();
        s.upsert_conversation(b"g", "bob", 1).unwrap();
        assert!(s.insert_message(&msg("m", b"g", "x")).unwrap());
        assert!(!s.insert_message(&msg("m", b"g", "y")).unwrap());
        assert_eq!(s.conversation(b"g").unwrap().unwrap().unread, 1);
        s.mark_read(b"g").unwrap();
        assert_eq!(s.conversations().unwrap()[0].unread, 0);
        assert_eq!(s.conversation_with("bob").unwrap().unwrap(), b"g".to_vec());
    }

    #[test]
    fn contacts_tofu() {
        let d = tempfile::tempdir().unwrap();
        let s = LocalStore::open(&d.path().join("t.db"), &[1u8; 32]).unwrap();
        s.add_contact("bob", &[1; 32], 0).unwrap();
        s.add_contact("bob", &[2; 32], 0).unwrap();
        assert_eq!(s.contact_identity("bob").unwrap().unwrap(), vec![1; 32]);
    }
}
