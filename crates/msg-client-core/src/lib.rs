//! Cœur du client de messagerie (desktop ; la cible WASM arrive en Phase 3).
//!
//! - [`api`] : client HTTP dont chaque requête est signée par la clé d'appareil ;
//! - [`vault`] / [`store`] : base locale SQLCipher, clé enveloppée par le mot
//!   de passe (Argon2id) et, sous Windows, par DPAPI ;
//! - [`client`] : établissement des conversations MLS, envoi, synchronisation.
#![forbid(unsafe_code)]

pub mod api;
pub mod attachments;
pub mod client;
pub mod conversations;
pub mod error;
pub mod store;
pub mod vault;

pub use attachments::DownloadedFile;
pub use client::{Client, ClientConfig};
pub use conversations::{AttachmentView, ConversationView, MessageView, SafetyNumberView, SyncReport};
pub use error::{ClientError, Result};

pub(crate) fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}
