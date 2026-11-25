//! Configuration par variables d'environnement.

use anyhow::{bail, Context};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct Config {
    /// Nom du site (émetteur TOTP, futur identifiant de fédération).
    pub site_name: String,
    /// Secret maître du serveur (32 octets) : dérive le *pepper* Argon2 et la
    /// clé de chiffrement des secrets TOTP. Doit être stocké hors de la base.
    pub server_secret: Zeroizing<[u8; 32]>,
    pub access_ttl_secs: i64,
    pub session_ttl_secs: i64,
    pub activation_ttl_secs: i64,
    pub blob_retention_secs: i64,
    pub max_failed_logins: i32,
    pub lockout_secs: i64,
    /// Paramètres Argon2id du hachage serveur (m en Kio, t, p).
    pub argon2_m_kib: u32,
    pub argon2_t: u32,
    pub argon2_p: u32,
    /// Envois autorisés par appareil et par fenêtre de 10 s.
    pub send_rate_per_10s: u32,
    /// Conservation maximale d'une pièce jointe chiffrée.
    pub attachment_retention_secs: i64,
    /// Volume total de pièces jointes par appareil.
    pub attachment_quota_bytes: i64,
    /// WebAuthn : identifiant de la partie de confiance (domaine) et origine
    /// publique du serveur. Désactivé si absent.
    pub webauthn: Option<WebauthnConfig>,
    /// Client web : dossier des fichiers statiques (servis à la racine, même
    /// origine que l'API). Désactivé si absent.
    pub web_dir: Option<std::path::PathBuf>,
    /// Client web en mode Tor strict (refus hors adresse `.onion`).
    pub web_onion_only: bool,
}

#[derive(Clone, Debug)]
pub struct WebauthnConfig {
    pub rp_id: String,
    pub origin: String,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config").field("site_name", &self.site_name).finish_non_exhaustive()
    }
}

fn env_i64(name: &str, default: i64) -> anyhow::Result<i64> {
    match std::env::var(name) {
        Ok(v) => v.parse().with_context(|| format!("{name} invalide")),
        Err(_) => Ok(default),
    }
}

impl Config {
    /// Valeurs par défaut sûres (OWASP : Argon2id m=19 Mio, t=2, p=1 au minimum).
    pub fn with_secret(site_name: String, server_secret: [u8; 32]) -> Self {
        Self {
            site_name,
            server_secret: Zeroizing::new(server_secret),
            access_ttl_secs: 15 * 60,
            session_ttl_secs: 12 * 3600,
            activation_ttl_secs: 72 * 3600,
            blob_retention_secs: 30 * 24 * 3600,
            max_failed_logins: 5,
            lockout_secs: 15 * 60,
            argon2_m_kib: 64 * 1024,
            argon2_t: 3,
            argon2_p: 1,
            send_rate_per_10s: 50,
            attachment_retention_secs: 30 * 24 * 3600,
            attachment_quota_bytes: 1024 * 1024 * 1024,
            webauthn: None,
            web_dir: None,
            web_onion_only: false,
        }
    }

    pub fn from_env() -> anyhow::Result<Self> {
        let secret_hex = Zeroizing::new(
            std::env::var("MSG_SERVER_SECRET")
                .context("MSG_SERVER_SECRET manquant (64 caractères hexadécimaux, ex. `openssl rand -hex 32`)")?,
        );
        let bytes = Zeroizing::new(hex::decode(secret_hex.trim()).context("MSG_SERVER_SECRET : hexadécimal attendu")?);
        if bytes.len() != 32 {
            bail!("MSG_SERVER_SECRET doit faire 32 octets (64 caractères hexadécimaux)");
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&bytes);
        let mut c = Self::with_secret(std::env::var("MSG_SITE_NAME").unwrap_or_else(|_| "messagerie".into()), secret);
        secret.iter_mut().for_each(|b| *b = 0);
        c.access_ttl_secs = env_i64("MSG_ACCESS_TTL_SECS", c.access_ttl_secs)?;
        c.session_ttl_secs = env_i64("MSG_SESSION_TTL_SECS", c.session_ttl_secs)?;
        c.activation_ttl_secs = env_i64("MSG_ACTIVATION_TTL_SECS", c.activation_ttl_secs)?;
        c.blob_retention_secs = env_i64("MSG_BLOB_RETENTION_SECS", c.blob_retention_secs)?;
        c.max_failed_logins = env_i64("MSG_MAX_FAILED_LOGINS", c.max_failed_logins as i64)? as i32;
        c.lockout_secs = env_i64("MSG_LOCKOUT_SECS", c.lockout_secs)?;
        c.argon2_m_kib = env_i64("MSG_ARGON2_M_KIB", c.argon2_m_kib as i64)? as u32;
        c.argon2_t = env_i64("MSG_ARGON2_T", c.argon2_t as i64)? as u32;
        c.argon2_p = env_i64("MSG_ARGON2_P", c.argon2_p as i64)? as u32;
        c.send_rate_per_10s = env_i64("MSG_SEND_RATE_PER_10S", c.send_rate_per_10s as i64)? as u32;
        c.attachment_retention_secs = env_i64("MSG_ATTACHMENT_RETENTION_SECS", c.attachment_retention_secs)?;
        c.attachment_quota_bytes = env_i64("MSG_ATTACHMENT_QUOTA_BYTES", c.attachment_quota_bytes)?;
        c.webauthn = match (std::env::var("MSG_WEBAUTHN_RP_ID"), std::env::var("MSG_WEBAUTHN_ORIGIN")) {
            (Ok(rp_id), Ok(origin)) => Some(WebauthnConfig { rp_id, origin }),
            (Err(_), Err(_)) => None,
            _ => bail!("MSG_WEBAUTHN_RP_ID et MSG_WEBAUTHN_ORIGIN doivent être définis ensemble"),
        };
        c.web_dir = std::env::var_os("MSG_WEB_DIR").map(Into::into);
        c.web_onion_only = matches!(std::env::var("MSG_WEB_ONION_ONLY").as_deref(), Ok("1" | "true"));
        if c.access_ttl_secs <= 0 || c.session_ttl_secs < c.access_ttl_secs {
            bail!("durées de session incohérentes");
        }
        Ok(c)
    }
}
