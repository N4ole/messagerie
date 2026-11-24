//! Pièces jointes : nettoyage des images (EXIF/GPS supprimés), chiffrement
//! local, téléversement d'un blob opaque, référence chiffrée dans le message MLS.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use msg_crypto::app_message::{AppBody, AttachmentRef};
use msg_crypto::attachment;
use zeroize::Zeroizing;

use crate::client::Client;
use crate::conversations::MessageView;
use crate::error::{ClientError, Result};

/// Fichier déchiffré prêt à être affiché ou enregistré.
pub struct DownloadedFile {
    pub name: String,
    pub mime: String,
    pub data: Zeroizing<Vec<u8>>,
}

/// Nom de fichier sûr : sans chemin, sans caractères de contrôle ni
/// séparateurs, longueur bornée.
pub fn sanitize_file_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let cleaned: String = base
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
        .take(msg_crypto::app_message::MAX_NAME_CHARS)
        .collect();
    let cleaned = cleaned.trim().trim_matches('.').to_string();
    if cleaned.is_empty() {
        "fichier".into()
    } else {
        cleaned
    }
}

fn with_extension(name: &str, ext: &str) -> String {
    let stem = name.rsplit_once('.').map(|(s, _)| s).filter(|s| !s.is_empty()).unwrap_or(name);
    format!("{stem}.{ext}")
}

impl Client {
    /// Envoie un fichier. Les images sont ré-encodées (métadonnées supprimées)
    /// et accompagnées d'une miniature ; les autres fichiers sont envoyés tels
    /// quels (leurs métadonnées internes ne sont **pas** nettoyées).
    pub async fn send_file(
        &mut self,
        conversation_id: &str,
        file_name: &str,
        data: Vec<u8>,
        caption: Option<String>,
    ) -> Result<MessageView> {
        let c = self
            .store
            .conversation(&hex::decode(conversation_id).map_err(|_| ClientError::UnknownConversation)?)?
            .ok_or(ClientError::UnknownConversation)?;
        if c.status != crate::store::status::OK {
            return Err(ClientError::Invalid("conversation inactive".into()));
        }
        if data.is_empty() || data.len() > attachment::MAX_ATTACHMENT_BYTES {
            return Err(ClientError::Invalid("fichier vide ou trop volumineux (25 Mio max.)".into()));
        }
        let name = sanitize_file_name(file_name);
        let caption = caption.map(|c| c.trim().to_owned()).filter(|c| !c.is_empty());
        let (bytes, mime, name, thumbnail_b64) = if msg_media::detect(&data).is_some() {
            let clean = msg_media::sanitize_image(&data).map_err(|e| ClientError::Invalid(e.to_string()))?;
            let name = with_extension(&name, clean.extension);
            (Zeroizing::new(clean.bytes), clean.mime.to_owned(), name, Some(STANDARD.encode(&clean.thumbnail)))
        } else {
            let mime = msg_media::mime_from_name(&name).to_owned();
            (Zeroizing::new(data), mime, name, None)
        };
        let enc = attachment::encrypt(&bytes)?;
        let blob_id = self.api.upload_attachment(&enc.blob).await?;
        let aref = AttachmentRef {
            blob_id,
            name,
            mime,
            size: bytes.len() as u64,
            key_hex: hex::encode(*enc.key),
            sha256_hex: hex::encode(enc.sha256),
            thumbnail_b64,
        };
        let json = serde_json::to_string(&aref).map_err(|e| ClientError::Invalid(e.to_string()))?;
        let app = self
            .send_app(&c.group_id, AppBody::Attachment { attachment: aref, caption: caption.clone() }, c.ttl_s)
            .await?;
        self.store_outgoing(&c.group_id, &app, "attachment", caption.unwrap_or_default(), Some(json))
    }

    /// Télécharge, vérifie (SHA-256 + AEAD) et déchiffre la pièce jointe d'un message.
    pub async fn download_file(&self, message_id: &str) -> Result<DownloadedFile> {
        let m = self.store.message(message_id)?.ok_or_else(|| ClientError::Invalid("message inconnu".into()))?;
        let conv = self.store.conversation(&m.group_id)?.ok_or(ClientError::UnknownConversation)?;
        if conv.status == crate::store::status::IDENTITY_CHANGED {
            return Err(ClientError::IdentityChanged(conv.peer));
        }
        let aref: AttachmentRef = m
            .attachment
            .as_deref()
            .and_then(|j| serde_json::from_str(j).ok())
            .ok_or_else(|| ClientError::Invalid("ce message ne contient pas de pièce jointe".into()))?;
        let key: [u8; 32] = hex::decode(&aref.key_hex)
            .ok()
            .and_then(|k| k.try_into().ok())
            .ok_or_else(|| ClientError::Invalid("clé de pièce jointe invalide".into()))?;
        let key = Zeroizing::new(key);
        let sha: [u8; 32] = hex::decode(&aref.sha256_hex)
            .ok()
            .and_then(|k| k.try_into().ok())
            .ok_or_else(|| ClientError::Invalid("empreinte invalide".into()))?;
        let blob = self.api.download_attachment(aref.blob_id).await?;
        let data = attachment::decrypt(&blob, &key, &sha, aref.size)?;
        self.persist_tokens()?;
        Ok(DownloadedFile { name: sanitize_file_name(&aref.name), mime: aref.mime, data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names_are_sanitized() {
        assert_eq!(sanitize_file_name("C:\\Users\\a\\photo.jpg"), "photo.jpg");
        assert_eq!(sanitize_file_name("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_file_name("a<b>:c?.txt"), "abc.txt");
        assert_eq!(sanitize_file_name(".."), "fichier");
        assert_eq!(sanitize_file_name("\u{0}\u{7}"), "fichier");
        assert_eq!(with_extension("photo.HEIC", "jpg"), "photo.jpg");
        assert_eq!(with_extension("sans", "png"), "sans.png");
    }
}
