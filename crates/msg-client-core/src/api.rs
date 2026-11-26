//! Client HTTP de l'API v1. Toute requête authentifiée est signée par la clé
//! API de l'appareil (horodatage + nonce) et porte le jeton d'accès.

use std::sync::Mutex;

use msg_crypto::identity::SigningKeyPair;
use msg_crypto::request::sign_request;
use msg_proto::*;
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use url::Url;
use uuid::Uuid;

use crate::error::{ClientError, Result};

/// Vérifie l'URL du serveur : HTTPS obligatoire, sauf boucle locale
/// (développement) et service onion (Tor chiffre et authentifie déjà la
/// connexion de bout en bout ; une adresse `.onion` n'est joignable que par
/// Tor).
pub fn validate_server_url(raw: &str, allow_insecure: bool) -> Result<Url> {
    let url = Url::parse(raw.trim()).map_err(|e| ClientError::InsecureUrl(e.to_string()))?;
    let loopback = matches!(url.host_str(), Some("localhost") | Some("127.0.0.1") | Some("[::1]") | Some("::1"));
    let onion = url.host_str().is_some_and(|h| h.ends_with(".onion"));
    match url.scheme() {
        "https" => {}
        "http" if loopback || onion || allow_insecure => {}
        _ => return Err(ClientError::InsecureUrl("HTTPS obligatoire (HTTP accepté uniquement en local)".into())),
    }
    if url.username() != "" || url.password().is_some() || url.query().is_some() {
        return Err(ClientError::InsecureUrl("l'URL ne doit contenir ni identifiants ni paramètres".into()));
    }
    Ok(url)
}

/// Message WebSocket (réexporté pour les applications).
#[cfg(not(target_arch = "wasm32"))]
pub use tokio_tungstenite::tungstenite::Message as WsMessage;

pub struct DeviceAuth {
    pub device_id: Uuid,
    pub api_key: SigningKeyPair,
}

pub struct ApiClient {
    http: reqwest::Client,
    base: Url,
    #[cfg(not(target_arch = "wasm32"))]
    network: crate::net::Network,
    #[cfg(not(target_arch = "wasm32"))]
    tls: Option<std::sync::Arc<rustls::ClientConfig>>,
    device: Option<DeviceAuth>,
    tokens: Mutex<Option<SessionTokens>>,
}

async fn decode<T: DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
    let status = resp.status();
    if status.is_success() {
        if status == StatusCode::NO_CONTENT {
            return serde_json::from_str("null").map_err(|e| ClientError::Invalid(e.to_string()));
        }
        return resp.json::<T>().await.map_err(ClientError::from);
    }
    let code = status.as_u16();
    match resp.json::<ApiError>().await {
        Ok(e) => Err(ClientError::Api { status: code, code: e.code, message: e.message }),
        Err(_) => {
            Err(ClientError::Api { status: code, code: ErrorCode::Internal, message: format!("erreur HTTP {code}") })
        }
    }
}

impl ApiClient {
    #[cfg(not(target_arch = "wasm32"))]
    pub fn new(base: Url) -> Result<Self> {
        Self::with_network(base, crate::net::Network::Direct, &[])
    }

    /// Client HTTP avec itinéraire réseau et épinglage TLS. En mode Tor, le
    /// proxy local d'arti est le **seul** itinéraire (proxys système
    /// ignorés, noms résolus par Tor) : aucune connexion directe possible.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_network(base: Url, network: crate::net::Network, pins: &[[u8; 32]]) -> Result<Self> {
        let mut b = reqwest::Client::builder()
            .user_agent("messagerie")
            .timeout(std::time::Duration::from_secs(120))
            .redirect(reqwest::redirect::Policy::none())
            .https_only(base.scheme() == "https")
            .no_proxy();
        if let crate::net::Network::TorStrict(p) = &network {
            // Identifiants SOCKS (RFC 1929) dans l'URL du proxy ; `socks5h` :
            // résolution des noms par Tor, aucune requête DNS locale.
            let mut url =
                Url::parse(&format!("socks5h://{}", p.addr)).map_err(|e| ClientError::Invalid(e.to_string()))?;
            url.set_username(&p.username).map_err(|_| ClientError::Invalid("proxy".into()))?;
            url.set_password(Some(&p.password)).map_err(|_| ClientError::Invalid("proxy".into()))?;
            let proxy = reqwest::Proxy::all(url.as_str()).map_err(|e| ClientError::Invalid(e.to_string()))?;
            b = b.proxy(proxy);
        }
        let tls = crate::net::pinned_tls(pins)?.map(std::sync::Arc::new);
        if let Some(cfg) = &tls {
            b = b.use_preconfigured_tls((**cfg).clone());
        }
        let http = b.build()?;
        Ok(Self { http, base, network, tls, device: None, tokens: Mutex::new(None) })
    }

    /// Navigateur : `fetch` (TLS, délais et politique de redirection sont
    /// ceux du navigateur ; la page est servie par le même site).
    #[cfg(target_arch = "wasm32")]
    pub fn new(base: Url) -> Result<Self> {
        let http = reqwest::Client::builder().build()?;
        Ok(Self { http, base, device: None, tokens: Mutex::new(None) })
    }

    pub fn base(&self) -> &Url {
        &self.base
    }

    pub fn set_device(&mut self, d: DeviceAuth) {
        self.device = Some(d);
    }

    pub fn device_id(&self) -> Option<Uuid> {
        self.device.as_ref().map(|d| d.device_id)
    }

    pub fn set_tokens(&self, t: Option<SessionTokens>) {
        *self.tokens.lock().unwrap_or_else(|e| e.into_inner()) = t;
    }

    pub fn tokens(&self) -> Option<SessionTokens> {
        self.tokens.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn url(&self, path_and_query: &str) -> Result<Url> {
        self.base.join(path_and_query).map_err(|e| ClientError::Invalid(e.to_string()))
    }

    async fn public<B: Serialize, T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<T> {
        let mut rb = self.http.request(method, self.url(path)?);
        if let Some(b) = body {
            rb = rb.json(b);
        }
        decode(rb.send().await?).await
    }

    fn signed_builder(&self, method: Method, path: &str, body: &[u8], bearer: bool) -> Result<reqwest::RequestBuilder> {
        self.signed_builder_ct(method, path, body, bearer, "application/json")
    }

    fn signed_builder_ct(
        &self,
        method: Method,
        path: &str,
        body: &[u8],
        bearer: bool,
        content_type: &str,
    ) -> Result<reqwest::RequestBuilder> {
        let dev = self.device.as_ref().ok_or(ClientError::NotLoggedIn)?;
        let url = self.url(path)?;
        let pq = match url.query() {
            Some(q) => format!("{}?{}", url.path(), q),
            None => url.path().to_owned(),
        };
        let h = sign_request(&dev.api_key, &dev.device_id, method.as_str(), &pq, body, crate::now_secs())?;
        let mut rb = self
            .http
            .request(method, url)
            .header(headers::DEVICE, h.device)
            .header(headers::TIMESTAMP, h.timestamp)
            .header(headers::NONCE, h.nonce)
            .header(headers::SIGNATURE, h.signature);
        if bearer {
            let t = self.tokens().ok_or(ClientError::NotLoggedIn)?;
            rb = rb.bearer_auth(t.access_token);
        }
        if !body.is_empty() {
            rb = rb.header(reqwest::header::CONTENT_TYPE, content_type).body(body.to_vec());
        }
        Ok(rb)
    }

    /// Requête authentifiée ; renouvelle la session une fois si le jeton
    /// d'accès a expiré.
    pub async fn call<B: Serialize, T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<T> {
        let bytes = match body {
            Some(b) => serde_json::to_vec(b).map_err(|e| ClientError::Invalid(e.to_string()))?,
            None => Vec::new(),
        };
        let needs_refresh = self.tokens().is_some_and(|t| t.access_expires_at <= crate::now_secs() + 5);
        if needs_refresh {
            self.refresh().await?;
        }
        let resp = self.signed_builder(method.clone(), path, &bytes, true)?.send().await?;
        if resp.status() == StatusCode::UNAUTHORIZED {
            self.refresh().await?;
            return decode(self.signed_builder(method, path, &bytes, true)?.send().await?).await;
        }
        decode(resp).await
    }

    /// Requête authentifiée à corps binaire ; renvoie la réponse brute.
    async fn call_raw(&self, method: Method, path: &str, body: &[u8], content_type: &str) -> Result<reqwest::Response> {
        if self.tokens().is_some_and(|t| t.access_expires_at <= crate::now_secs() + 5) {
            self.refresh().await?;
        }
        let resp = self.signed_builder_ct(method.clone(), path, body, true, content_type)?.send().await?;
        if resp.status() == StatusCode::UNAUTHORIZED {
            self.refresh().await?;
            return Ok(self.signed_builder_ct(method, path, body, true, content_type)?.send().await?);
        }
        Ok(resp)
    }

    /// Téléverse une pièce jointe **déjà chiffrée**.
    pub async fn upload_attachment(&self, blob: &[u8]) -> Result<Uuid> {
        let resp = self.call_raw(Method::POST, "/v1/attachments", blob, "application/octet-stream").await?;
        Ok(decode::<AttachmentUploadResponse>(resp).await?.blob_id)
    }

    /// Télécharge une pièce jointe chiffrée (hébergée par ce site, ou par le
    /// site de l'expéditeur : relayée par ce serveur).
    pub async fn download_attachment(&self, blob_id: Uuid, site: Option<&str>) -> Result<Vec<u8>> {
        let q = site.map(|s| format!("?site={s}")).unwrap_or_default();
        let resp = self
            .call_raw(Method::GET, &format!("/v1/attachments/{blob_id}{q}"), b"", "application/octet-stream")
            .await?;
        if !resp.status().is_success() {
            return decode::<()>(resp).await.map(|_| Vec::new());
        }
        let limit = msg_proto::MAX_ATTACHMENT_BLOB_BYTES;
        let bytes = resp.bytes().await?;
        if bytes.len() > limit {
            return Err(ClientError::Invalid("pièce jointe trop volumineuse".into()));
        }
        Ok(bytes.to_vec())
    }

    /// Renouvelle les jetons à l'aide du jeton de rafraîchissement (rotation).
    pub async fn refresh(&self) -> Result<SessionTokens> {
        let dev = self.device.as_ref().ok_or(ClientError::NotLoggedIn)?;
        let t = self.tokens().ok_or(ClientError::NotLoggedIn)?;
        let body = serde_json::to_vec(&RefreshRequest { device_id: dev.device_id, refresh_token: t.refresh_token })
            .map_err(|e| ClientError::Invalid(e.to_string()))?;
        let resp = self.signed_builder(Method::POST, "/v1/auth/refresh", &body, false)?.send().await?;
        match decode::<SessionTokens>(resp).await {
            Ok(n) => {
                self.set_tokens(Some(n.clone()));
                Ok(n)
            }
            Err(e) => {
                self.set_tokens(None);
                Err(e)
            }
        }
    }

    // --- Routes publiques -------------------------------------------------

    pub async fn health(&self) -> Result<HealthResponse> {
        self.public::<(), _>(Method::GET, "/v1/health", None).await
    }

    pub async fn activate(&self, req: &ActivateRequest) -> Result<ActivateResponse> {
        self.public(Method::POST, "/v1/auth/activate", Some(req)).await
    }

    pub async fn confirm_totp(&self, req: &ConfirmTotpRequest) -> Result<SessionTokens> {
        let t: SessionTokens = self.public(Method::POST, "/v1/auth/confirm-totp", Some(req)).await?;
        self.set_tokens(Some(t.clone()));
        Ok(t)
    }

    pub async fn login(&self, req: &LoginRequest) -> Result<SessionTokens> {
        let t: SessionTokens = self.public(Method::POST, "/v1/auth/login", Some(req)).await?;
        self.set_tokens(Some(t.clone()));
        Ok(t)
    }

    // --- Routes authentifiées ---------------------------------------------

    pub async fn logout(&self) -> Result<()> {
        let r = self.call::<(), ()>(Method::POST, "/v1/auth/logout", None).await;
        self.set_tokens(None);
        r
    }

    pub async fn upload_key_packages(&self, kps: Vec<Vec<u8>>) -> Result<()> {
        self.call(Method::POST, "/v1/keypackages", Some(&UploadKeyPackagesRequest { key_packages: kps })).await
    }

    pub async fn key_package_count(&self) -> Result<i64> {
        Ok(self.call::<(), KeyPackageCount>(Method::GET, "/v1/keypackages/count", None).await?.count)
    }

    /// Informations publiques du site (nom, clé de fédération).
    pub async fn site_info(&self) -> Result<SiteInfo> {
        self.public::<(), _>(Method::GET, "/v1/site", None).await
    }

    pub async fn directory(&self, username: &str) -> Result<UserDirectoryEntry> {
        parse_address(username).map_err(|e| ClientError::Invalid(e.into()))?;
        self.call::<(), _>(Method::GET, &format!("/v1/users/{username}"), None).await
    }

    pub async fn claim(&self, username: &str) -> Result<UserDirectoryEntry> {
        parse_address(username).map_err(|e| ClientError::Invalid(e.into()))?;
        self.call::<(), _>(Method::POST, &format!("/v1/users/{username}/claim"), None).await
    }

    /// Réclame des KeyPackages pour certains appareils seulement.
    pub async fn claim_devices(&self, username: &str, devices: &[Uuid]) -> Result<UserDirectoryEntry> {
        parse_address(username).map_err(|e| ClientError::Invalid(e.into()))?;
        let list = devices.iter().map(Uuid::to_string).collect::<Vec<_>>().join(",");
        self.call::<(), _>(Method::POST, &format!("/v1/users/{username}/claim?devices={list}"), None).await
    }

    // --- Key Transparency ---------------------------------------------------

    /// Tête du journal KT de ce site, ou d'un site fédéré (relayée).
    pub async fn kt_head(&self, site: Option<&str>) -> Result<KtHead> {
        let q = site.map(|s| format!("?site={s}")).unwrap_or_default();
        self.call::<(), _>(Method::GET, &format!("/v1/kt/head{q}"), None).await
    }

    pub async fn kt_audit(&self, site: Option<&str>, from: u64, to: u64) -> Result<KtAudit> {
        let q = site.map(|s| format!("&site={s}")).unwrap_or_default();
        self.call::<(), _>(Method::GET, &format!("/v1/kt/audit?from={from}&to={to}{q}"), None).await
    }

    // --- Appareils ------------------------------------------------------------

    pub async fn link_start(&self, req: &LinkStartRequest) -> Result<LinkStartResponse> {
        self.public(Method::POST, "/v1/auth/link/start", Some(req)).await
    }

    pub async fn link_poll(&self, req: &LinkPollRequest) -> Result<LinkPollResponse> {
        self.public(Method::POST, "/v1/auth/link/poll", Some(req)).await
    }

    /// Ticket d'ouverture du WebSocket (client web).
    pub async fn ws_ticket(&self) -> Result<WsTicket> {
        self.call::<(), _>(Method::POST, "/v1/ws/ticket", None).await
    }

    pub async fn devices(&self) -> Result<Vec<OwnDevice>> {
        self.call::<(), _>(Method::GET, "/v1/devices", None).await
    }

    pub async fn revoke_device(&self, device: Uuid) -> Result<()> {
        self.call::<(), ()>(Method::DELETE, &format!("/v1/devices/{device}"), None).await
    }

    pub async fn link_requests(&self) -> Result<Vec<LinkRequestView>> {
        self.call::<(), _>(Method::GET, "/v1/devices/links", None).await
    }

    pub async fn link_approve(&self, link_id: Uuid, req: &LinkApproveRequest) -> Result<()> {
        self.call(Method::POST, &format!("/v1/devices/links/{link_id}/approve"), Some(req)).await
    }

    pub async fn link_reject(&self, link_id: Uuid) -> Result<()> {
        self.call::<(), ()>(Method::DELETE, &format!("/v1/devices/links/{link_id}"), None).await
    }

    pub async fn send(&self, req: &SendRequest) -> Result<SendResponse> {
        self.call(Method::POST, "/v1/messages", Some(req)).await
    }

    pub async fn queue(&self, limit: u32) -> Result<QueueResponse> {
        self.call::<(), _>(Method::GET, &format!("/v1/queue?limit={limit}"), None).await
    }

    pub async fn ack(&self, ids: Vec<i64>) -> Result<()> {
        self.call(Method::POST, "/v1/queue/ack", Some(&AckRequest { ids })).await
    }

    // --- WebAuthn -----------------------------------------------------------

    pub async fn webauthn_login_challenge(&self, username: &str, password: &str) -> Result<WebauthnLoginChallenge> {
        self.public(
            Method::POST,
            "/v1/auth/webauthn/challenge",
            Some(&WebauthnChallengeRequest { username: username.into(), password: password.into() }),
        )
        .await
    }

    pub async fn webauthn_register_start(&self) -> Result<WebauthnRegisterChallenge> {
        self.call::<(), _>(Method::POST, "/v1/webauthn/register/start", None).await
    }

    pub async fn webauthn_register_finish(&self, req: &WebauthnRegisterFinish) -> Result<WebauthnCredentialSummary> {
        self.call(Method::POST, "/v1/webauthn/register/finish", Some(req)).await
    }

    pub async fn webauthn_list(&self) -> Result<Vec<WebauthnCredentialSummary>> {
        self.call::<(), _>(Method::GET, "/v1/webauthn/credentials", None).await
    }

    pub async fn webauthn_delete(&self, id: i64) -> Result<()> {
        self.call::<(), ()>(Method::DELETE, &format!("/v1/webauthn/credentials/{id}"), None).await
    }

    // --- Administration ---------------------------------------------------

    pub async fn admin_create(&self, username: &str, role: Role) -> Result<ActivationCodeResponse> {
        self.call(Method::POST, "/v1/admin/accounts", Some(&CreateAccountRequest { username: username.into(), role }))
            .await
    }

    pub async fn admin_list(&self) -> Result<Vec<AccountSummary>> {
        self.call::<(), _>(Method::GET, "/v1/admin/accounts", None).await
    }

    pub async fn admin_set_status(&self, username: &str, status: AccountStatus) -> Result<()> {
        self.call(Method::PUT, &format!("/v1/admin/accounts/{username}/status"), Some(&SetStatusRequest { status }))
            .await
    }

    pub async fn admin_set_role(&self, username: &str, role: Role) -> Result<()> {
        self.call(Method::PUT, &format!("/v1/admin/accounts/{username}/role"), Some(&SetRoleRequest { role })).await
    }

    pub async fn admin_reset(&self, username: &str) -> Result<ActivationCodeResponse> {
        self.call::<(), _>(Method::POST, &format!("/v1/admin/accounts/{username}/reset"), None).await
    }

    pub async fn admin_devices(&self, username: &str) -> Result<Vec<DeviceSummary>> {
        self.call::<(), _>(Method::GET, &format!("/v1/admin/accounts/{username}/devices"), None).await
    }

    pub async fn admin_revoke_device(&self, username: &str, device: Uuid) -> Result<()> {
        self.call::<(), ()>(Method::DELETE, &format!("/v1/admin/accounts/{username}/devices/{device}"), None).await
    }

    /// Ouvre le WebSocket de notification (requête d'ouverture signée).
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn connect_ws(
        &self,
    ) -> Result<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        if self.tokens().is_some_and(|t| t.access_expires_at <= crate::now_secs() + 5) {
            self.refresh().await?;
        }
        let dev = self.device.as_ref().ok_or(ClientError::NotLoggedIn)?;
        let t = self.tokens().ok_or(ClientError::NotLoggedIn)?;
        let mut url = self.url("/v1/ws")?;
        let scheme = if url.scheme() == "https" { "wss" } else { "ws" };
        url.set_scheme(scheme).map_err(|_| ClientError::Invalid("schéma".into()))?;
        let h = sign_request(&dev.api_key, &dev.device_id, "GET", "/v1/ws", b"", crate::now_secs())?;
        let mut req = url.as_str().into_client_request().map_err(|e| ClientError::Network(e.to_string()))?;
        let hm = req.headers_mut();
        let hv = |s: String| s.parse().map_err(|_| ClientError::Invalid("en-tête".into()));
        hm.insert(headers::DEVICE, hv(h.device)?);
        hm.insert(headers::TIMESTAMP, hv(h.timestamp)?);
        hm.insert(headers::NONCE, hv(h.nonce)?);
        hm.insert(headers::SIGNATURE, hv(h.signature)?);
        hm.insert("authorization", hv(format!("Bearer {}", t.access_token))?);
        let connector = self.tls.clone().map(tokio_tungstenite::Connector::Rustls);
        let (ws, _) = match &self.network {
            crate::net::Network::Direct => {
                tokio_tungstenite::connect_async_tls_with_config(req, None, false, connector).await
            }
            crate::net::Network::TorStrict(p) => {
                let host = url.host_str().ok_or_else(|| ClientError::Invalid("hôte".into()))?;
                let port = url.port_or_known_default().ok_or_else(|| ClientError::Invalid("port".into()))?;
                let stream = crate::net::socks_connect(p, host, port).await?;
                tokio_tungstenite::client_async_tls_with_config(req, stream, None, connector).await
            }
        }
        .map_err(|e| ClientError::Network(e.to_string()))?;
        Ok(ws)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_policy() {
        assert!(validate_server_url("https://msg.example.org", false).is_ok());
        assert!(validate_server_url("http://127.0.0.1:8080", false).is_ok());
        assert!(validate_server_url("http://localhost:8080", false).is_ok());
        assert!(validate_server_url("http://msg.example.org", false).is_err());
        let onion = "http://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvw.onion";
        assert!(validate_server_url(onion, false).is_ok(), "service onion sans TLS");
        assert!(validate_server_url("http://exemple.onion.example.org", false).is_err());
        assert!(validate_server_url("http://msg.example.org", true).is_ok());
        assert!(validate_server_url("https://user:pw@msg.example.org", false).is_err());
        assert!(validate_server_url("ftp://msg.example.org", false).is_err());
        assert!(validate_server_url("pas une url", false).is_err());
    }
}
