//! Cœur du client de messagerie, commun au desktop (natif) et au client web (WASM).
//!
//! - [`api`] : client HTTP dont chaque requête est signée par la clé d'appareil ;
//! - [`vault`] / [`store`] : base locale SQLCipher, clé enveloppée par le mot
//!   de passe (Argon2id) et, sous Windows, par DPAPI ;
//! - [`client`] : établissement des conversations MLS, envoi, synchronisation.
#![forbid(unsafe_code)]

pub mod account;
pub mod api;
pub mod attachments;
pub mod client;
pub mod conversations;
pub mod devices;
pub mod error;
pub mod kt;
#[cfg(not(target_arch = "wasm32"))]
pub mod net;
#[cfg(not(target_arch = "wasm32"))]
pub mod passkey;
pub mod store;
pub mod store_mem;
#[cfg(not(target_arch = "wasm32"))]
pub mod vault;

pub use attachments::DownloadedFile;
pub use client::{Client, ClientConfig};
pub use conversations::{AttachmentView, ConversationView, MessageView, SafetyNumberView, SyncReport};
pub use devices::{LinkOutcome, LinkRequestInfo, PendingLink};
pub use error::{ClientError, Result};

pub(crate) fn now_secs() -> i64 {
    now_ms() / 1000
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// Dans le navigateur, l'horloge système de Rust n'existe pas : `Date.now()`.
#[cfg(target_arch = "wasm32")]
pub(crate) fn now_ms() -> i64 {
    js_sys::Date::now() as i64
}
