//! Contenu applicatif transporté **à l'intérieur** des messages MLS chiffrés.
//! Tout ce qui figure ici (texte, nom de groupe, nom de fichier, miniature,
//! clé de pièce jointe, délai d'expiration) est donc invisible du serveur.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{CryptoError, Result};

/// Taille maximale du texte d'un message (octets UTF-8).
pub const MAX_TEXT_BYTES: usize = 64 * 1024;
/// Longueur maximale d'un nom de groupe ou de fichier.
pub const MAX_NAME_CHARS: usize = 255;
/// Taille maximale d'une miniature (octets, avant Base64).
pub const MAX_THUMBNAIL_BYTES: usize = 48 * 1024;
/// Durée de vie maximale d'un message éphémère (30 jours).
pub const MAX_TTL_SECS: u32 = 30 * 24 * 3600;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppMessage {
    pub v: u8,
    /// Identifiant aléatoire (128 bits) — détection des doublons/rejeux.
    pub id: Uuid,
    /// Horloge de l'expéditeur (ms Unix), authentifiée par la signature MLS.
    pub sent_at_ms: i64,
    /// Message éphémère : suppression `n` secondes après sa lecture... ou
    /// plus exactement après sa réception/émission (voir `msg-client-core`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_s: Option<u32>,
    pub body: AppBody,
}

/// Référence chiffrée vers une pièce jointe stockée (chiffrée) sur le serveur.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentRef {
    pub blob_id: Uuid,
    /// Nom de fichier d'origine (chiffré de bout en bout avec le message).
    pub name: String,
    pub mime: String,
    /// Taille du fichier en clair.
    pub size: u64,
    /// Clé XChaCha20-Poly1305 du fichier (hexadécimal).
    pub key_hex: String,
    /// SHA-256 du fichier chiffré (hexadécimal), vérifié au téléchargement.
    pub sha256_hex: String,
    /// Miniature JPEG (Base64), générée localement, sans métadonnées.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbnail_b64: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AppBody {
    /// Texte Markdown.
    Text { text: String },
    /// Informations du groupe (nom, administrateur), diffusées par l'administrateur.
    GroupInfo { name: String, admin: String },
    /// Pièce jointe (avec légende facultative).
    Attachment { attachment: AttachmentRef, caption: Option<String> },
}

impl AppMessage {
    fn new(body: AppBody, sent_at_ms: i64, expires_in_s: Option<u32>) -> Result<Self> {
        let m = Self { v: 1, id: Uuid::from_bytes(crate::random_bytes::<16>()?), sent_at_ms, expires_in_s, body };
        m.validate()?;
        Ok(m)
    }

    pub fn text(text: String, sent_at_ms: i64) -> Result<Self> {
        Self::new(AppBody::Text { text }, sent_at_ms, None)
    }

    pub fn with_body(body: AppBody, sent_at_ms: i64, expires_in_s: Option<u32>) -> Result<Self> {
        Self::new(body, sent_at_ms, expires_in_s)
    }

    fn validate(&self) -> Result<()> {
        let bad = |m: &str| Err(CryptoError::Format(m.into()));
        if self.v != 1 {
            return bad("version de message inconnue");
        }
        if self.expires_in_s.is_some_and(|t| t == 0 || t > MAX_TTL_SECS) {
            return bad("durée d'expiration invalide");
        }
        match &self.body {
            AppBody::Text { text } if text.len() > MAX_TEXT_BYTES => bad("message trop long"),
            AppBody::GroupInfo { name, admin } if name.chars().count() > MAX_NAME_CHARS || admin.is_empty() => {
                bad("informations de groupe invalides")
            }
            AppBody::Attachment { attachment: a, caption } => {
                if a.name.chars().count() > MAX_NAME_CHARS
                    || a.mime.len() > 100
                    || a.key_hex.len() != 64
                    || a.sha256_hex.len() != 64
                    || caption.as_ref().is_some_and(|c| c.len() > MAX_TEXT_BYTES)
                    || a.thumbnail_b64.as_ref().is_some_and(|t| t.len() > MAX_THUMBNAIL_BYTES * 4 / 3 + 4)
                {
                    bad("pièce jointe invalide")
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("sérialisation infaillible")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let m: Self = serde_json::from_slice(bytes).map_err(|e| CryptoError::Format(e.to_string()))?;
        m.validate()?;
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_validation() {
        let m = AppMessage::with_body(AppBody::Text { text: "x".into() }, 1, Some(60)).unwrap();
        assert_eq!(AppMessage::decode(&m.encode()).unwrap(), m);
        assert!(AppMessage::with_body(AppBody::Text { text: "x".into() }, 1, Some(0)).is_err());
        assert!(AppMessage::with_body(AppBody::Text { text: "x".into() }, 1, Some(MAX_TTL_SECS + 1)).is_err());
        assert!(AppMessage::text("a".repeat(MAX_TEXT_BYTES + 1), 1).is_err());
        let g = AppMessage::with_body(AppBody::GroupInfo { name: "Équipe".into(), admin: "alice".into() }, 1, None)
            .unwrap();
        assert_eq!(AppMessage::decode(&g.encode()).unwrap().body, g.body);
    }

    #[test]
    fn phase1_messages_still_decode() {
        let old =
            br#"{"v":1,"id":"00000000-0000-0000-0000-000000000000","sent_at_ms":1,"body":{"type":"text","text":"ok"}}"#;
        assert!(matches!(AppMessage::decode(old).unwrap().body, AppBody::Text { .. }));
    }
}
