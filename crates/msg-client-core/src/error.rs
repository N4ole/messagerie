use msg_proto::ErrorCode;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("{message}")]
    Api { status: u16, code: ErrorCode, message: String },
    #[error("serveur injoignable : {0}")]
    Network(String),
    #[error("adresse du serveur refusée : {0}")]
    InsecureUrl(String),
    #[error("mot de passe local incorrect")]
    WrongPassword,
    #[error("aucun compte local pour cet utilisateur sur cet appareil")]
    NoLocalAccount,
    #[error("un compte local existe déjà pour cet utilisateur sur cet appareil")]
    LocalAccountExists,
    #[error("code TOTP requis")]
    TotpRequired,
    #[error("ALERTE : la clé d'identité de « {0} » a changé ; conversation bloquée")]
    IdentityChanged(String),
    #[error("vérification de « {0} » échouée : {1}")]
    Verification(String, String),
    #[error("conversation inconnue")]
    UnknownConversation,
    #[error("non connecté")]
    NotLoggedIn,
    #[error("base locale : {0}")]
    Storage(String),
    #[error("cryptographie : {0}")]
    Crypto(#[from] msg_crypto::CryptoError),
    #[error("{0}")]
    Invalid(String),
}

impl From<rusqlite::Error> for ClientError {
    fn from(e: rusqlite::Error) -> Self {
        ClientError::Storage(e.to_string())
    }
}

impl From<reqwest::Error> for ClientError {
    fn from(e: reqwest::Error) -> Self {
        // Sans l'URL (peut contenir un identifiant).
        ClientError::Network(e.without_url().to_string())
    }
}

impl ClientError {
    pub fn api_code(&self) -> Option<ErrorCode> {
        match self {
            ClientError::Api { code, .. } => Some(*code),
            _ => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, ClientError>;
