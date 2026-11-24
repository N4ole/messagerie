//! Contenu applicatif transporté **à l'intérieur** des messages MLS chiffrés.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{CryptoError, Result};

/// Taille maximale du texte d'un message (octets UTF-8).
pub const MAX_TEXT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppMessage {
    pub v: u8,
    /// Identifiant aléatoire (128 bits) — détection des doublons/rejeux.
    pub id: Uuid,
    /// Horloge de l'expéditeur (ms Unix), authentifiée par la signature MLS.
    pub sent_at_ms: i64,
    pub body: AppBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AppBody {
    /// Texte Markdown.
    Text { text: String },
}

impl AppMessage {
    pub fn text(text: String, sent_at_ms: i64) -> Result<Self> {
        if text.len() > MAX_TEXT_BYTES {
            return Err(CryptoError::Format("message trop long".into()));
        }
        Ok(Self { v: 1, id: Uuid::from_bytes(crate::random_bytes::<16>()?), sent_at_ms, body: AppBody::Text { text } })
    }

    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("sérialisation infaillible")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let m: Self = serde_json::from_slice(bytes).map_err(|e| CryptoError::Format(e.to_string()))?;
        if m.v != 1 {
            return Err(CryptoError::Format("version de message inconnue".into()));
        }
        let AppBody::Text { text } = &m.body;
        if text.len() > MAX_TEXT_BYTES {
            return Err(CryptoError::Format("message trop long".into()));
        }
        Ok(m)
    }
}
