//! Types de l'API v1 de la messagerie.
//!
//! Toutes les données binaires (clés publiques, signatures, blobs chiffrés)
//! sont transportées en Base64 standard. Le serveur ne reçoit **jamais** de
//! clair : les champs `payload` sont des messages MLS opaques.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod b64;

/// Version du protocole applicatif (préfixe des routes).
pub const API_PREFIX: &str = "/v1";

/// En-têtes de signature des requêtes (voir `docs/conception/02-protocole-crypto.md` §5).
pub mod headers {
    pub const TIMESTAMP: &str = "x-msg-timestamp";
    pub const NONCE: &str = "x-msg-nonce";
    pub const SIGNATURE: &str = "x-msg-signature";
    pub const DEVICE: &str = "x-msg-device";
}

/// Fenêtre d'acceptation des horodatages de requête (secondes).
pub const REQUEST_MAX_SKEW_SECS: i64 = 60;

/// Taille maximale d'un blob (message MLS) accepté par le serveur.
pub const MAX_PAYLOAD_BYTES: usize = 256 * 1024;

/// Nombre maximal de KeyPackages par envoi.
pub const MAX_KEY_PACKAGES_PER_UPLOAD: usize = 100;

/// Règles de validation d'un identifiant utilisateur.
pub fn validate_username(username: &str) -> Result<(), &'static str> {
    let len = username.len();
    if !(3..=32).contains(&len) {
        return Err("l'identifiant doit faire entre 3 et 32 caractères");
    }
    if !username.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-' || b == b'_') {
        return Err("caractères autorisés : a-z, 0-9, '.', '-', '_'");
    }
    if !username.as_bytes()[0].is_ascii_alphanumeric() {
        return Err("l'identifiant doit commencer par une lettre ou un chiffre");
    }
    Ok(())
}

/// Politique minimale de mot de passe (longueur ; la robustesse réelle est
/// laissée à l'utilisateur, cf. NIST SP 800-63B).
pub fn validate_password(password: &str) -> Result<(), &'static str> {
    let n = password.chars().count();
    if n < 12 {
        return Err("le mot de passe doit contenir au moins 12 caractères");
    }
    if n > 256 {
        return Err("le mot de passe est trop long (256 caractères max.)");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Erreurs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    InvalidCredentials,
    TotpRequired,
    AccountLocked,
    AccountSuspended,
    AccountNotActive,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    IdentityMismatch,
    PayloadTooLarge,
    RateLimited,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
}

// ---------------------------------------------------------------------------
// Comptes et administration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    User,
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::User => "user",
            Role::Admin => "admin",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "user" => Some(Role::User),
            "admin" => Some(Role::Admin),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    /// Créé par un admin, en attente d'activation par l'utilisateur.
    PendingActivation,
    /// Mot de passe défini, TOTP pas encore confirmé.
    PendingTotp,
    Active,
    Suspended,
}

impl AccountStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            AccountStatus::PendingActivation => "pending_activation",
            AccountStatus::PendingTotp => "pending_totp",
            AccountStatus::Active => "active",
            AccountStatus::Suspended => "suspended",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending_activation" => Some(Self::PendingActivation),
            "pending_totp" => Some(Self::PendingTotp),
            "active" => Some(Self::Active),
            "suspended" => Some(Self::Suspended),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAccountRequest {
    pub username: String,
    pub role: Role,
}

/// Réponse contenant un code d'activation à usage unique, à transmettre
/// hors bande à l'utilisateur.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivationCodeResponse {
    pub username: String,
    pub activation_code: String,
    /// Expiration (secondes Unix).
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSummary {
    pub username: String,
    pub role: Role,
    pub status: AccountStatus,
    pub created_at: i64,
    pub device_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetStatusRequest {
    /// Seuls `active` et `suspended` sont acceptés.
    pub status: AccountStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetRoleRequest {
    pub role: Role,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSummary {
    pub device_id: Uuid,
    pub created_at: i64,
    pub last_seen_at: Option<i64>,
}

// ---------------------------------------------------------------------------
// Activation et authentification
// ---------------------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
pub struct ActivateRequest {
    pub username: String,
    pub activation_code: String,
    pub new_password: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ActivateResponse {
    /// Secret TOTP encodé en Base32 (à saisir dans l'application d'authentification).
    pub totp_secret_base32: String,
    /// URI `otpauth://` (à afficher en QR code côté client).
    pub otpauth_uri: String,
}

/// Enregistrement d'un appareil : clés publiques et certificat signé par la
/// clé d'identité de l'utilisateur.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRegistration {
    pub device_id: Uuid,
    /// Clé d'identité utilisateur (Ed25519, 32 octets).
    #[serde(with = "b64")]
    pub identity_key: Vec<u8>,
    /// Clé de signature des requêtes API (Ed25519, 32 octets).
    #[serde(with = "b64")]
    pub api_key: Vec<u8>,
    /// Clé de signature MLS de l'appareil (Ed25519).
    #[serde(with = "b64")]
    pub mls_signature_key: Vec<u8>,
    /// Date du certificat (secondes Unix).
    pub cert_created_at: i64,
    /// Signature Ed25519 par `identity_key` du certificat d'appareil.
    #[serde(with = "b64")]
    pub cert_signature: Vec<u8>,
}

/// Confirmation du TOTP : première connexion, enregistre l'appareil.
#[derive(Clone, Serialize, Deserialize)]
pub struct ConfirmTotpRequest {
    pub username: String,
    pub password: String,
    pub totp_code: String,
    pub device: DeviceRegistration,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub totp_code: String,
    pub device: DeviceRegistration,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SessionTokens {
    pub access_token: String,
    pub access_expires_at: i64,
    pub refresh_token: String,
    /// Durée de vie absolue de la session (pas de renouvellement au-delà).
    pub session_expires_at: i64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RefreshRequest {
    pub device_id: Uuid,
    pub refresh_token: String,
}

// ---------------------------------------------------------------------------
// Annuaire de clés
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadKeyPackagesRequest {
    #[serde(with = "b64::vec")]
    pub key_packages: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPackageCount {
    pub count: i64,
}

/// Appareil publié dans l'annuaire, avec son certificat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishedDevice {
    pub device_id: Uuid,
    #[serde(with = "b64")]
    pub api_key: Vec<u8>,
    #[serde(with = "b64")]
    pub mls_signature_key: Vec<u8>,
    pub cert_created_at: i64,
    #[serde(with = "b64")]
    pub cert_signature: Vec<u8>,
    /// KeyPackage réclamé (consommé) pour cet appareil, si demandé.
    #[serde(default, with = "b64::option")]
    pub key_package: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDirectoryEntry {
    pub username: String,
    #[serde(with = "b64")]
    pub identity_key: Vec<u8>,
    pub devices: Vec<PublishedDevice>,
}

// ---------------------------------------------------------------------------
// Distribution des messages (delivery service)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendRequest {
    /// Identifiant choisi par le client (idempotence).
    pub client_message_id: Uuid,
    /// Appareils destinataires.
    pub recipients: Vec<Uuid>,
    /// Message MLS sérialisé (opaque pour le serveur).
    #[serde(with = "b64")]
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendResponse {
    pub accepted: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedMessage {
    pub id: i64,
    pub received_at: i64,
    #[serde(with = "b64")]
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueResponse {
    pub messages: Vec<QueuedMessage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckRequest {
    pub ids: Vec<i64>,
}

/// Notification poussée par WebSocket : ne contient jamais de contenu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PushEvent {
    NewMessages,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames() {
        assert!(validate_username("alice").is_ok());
        assert!(validate_username("a.b-c_1").is_ok());
        assert!(validate_username("Al").is_err());
        assert!(validate_username("Alice").is_err());
        assert!(validate_username("_alice").is_err());
        assert!(validate_username("alice@x").is_err());
        assert!(validate_username(&"a".repeat(33)).is_err());
    }

    #[test]
    fn passwords() {
        assert!(validate_password("court").is_err());
        assert!(validate_password("une phrase de passe assez longue").is_ok());
    }

    #[test]
    fn binary_fields_roundtrip_as_base64() {
        let req =
            SendRequest { client_message_id: Uuid::nil(), recipients: vec![Uuid::nil()], payload: vec![0, 1, 2, 255] };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"payload\":\"AAEC/w==\""));
        let back: SendRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.payload, vec![0, 1, 2, 255]);
    }

    #[test]
    fn push_event_has_no_content() {
        let json = serde_json::to_string(&PushEvent::NewMessages).unwrap();
        assert_eq!(json, r#"{"type":"new_messages"}"#);
    }
}
