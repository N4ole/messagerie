//! Application de bureau.
//!
//! La WebView n'appelle que des commandes de haut niveau ; elle ne reçoit
//! jamais de clé. Toute la cryptographie s'exécute dans ce processus via
//! `msg-client-core`.
#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicIsize, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use futures_util::StreamExt;
use msg_client_core::api::WsMessage;
use msg_client_core::passkey::{
    GetAssertionRequest, GetAssertionResponse, MakeCredentialRequest, MakeCredentialResponse, RawAuthenticator,
};
use msg_client_core::{
    Client, ClientConfig, ClientError, ConversationView, LinkOutcome, LinkRequestInfo, MessageView, PendingLink,
    SafetyNumberView, SyncReport,
};
use msg_proto::{OwnDevice, WebauthnCredentialSummary};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_notification::NotificationExt;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

type Shared = Arc<Mutex<Client>>;

/// Verrouillage automatique par défaut (minutes d'inactivité).
const DEFAULT_AUTO_LOCK_MIN: u32 = 5;

struct AppState {
    client: Mutex<Option<(Shared, ClientConfig)>>,
    listener: std::sync::Mutex<Option<JoinHandle<()>>>,
    last_activity: std::sync::Mutex<Instant>,
    auto_lock_minutes: AtomicU32,
    /// Handle natif de la fenêtre principale (boîtes de dialogue WebAuthn).
    hwnd: AtomicIsize,
    capture_protection: std::sync::Mutex<String>,
    /// Liaison de cet appareil en attente d'approbation.
    pending_link: Mutex<Option<(Arc<PendingLink>, ClientConfig)>>,
    /// Itinéraire réseau choisi et empreintes TLS épinglées.
    network: Mutex<(msg_client_core::net::Network, Vec<[u8; 32]>)>,
    /// Tor embarqué (démarré à la demande, conservé ensuite).
    tor: Mutex<Option<msg_tor::TorRuntime>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            client: Mutex::new(None),
            listener: std::sync::Mutex::new(None),
            last_activity: std::sync::Mutex::new(Instant::now()),
            auto_lock_minutes: AtomicU32::new(DEFAULT_AUTO_LOCK_MIN),
            hwnd: AtomicIsize::new(0),
            capture_protection: std::sync::Mutex::new("indisponible".into()),
            pending_link: Mutex::new(None),
            network: Mutex::new((msg_client_core::net::Network::Direct, Vec::new())),
            tor: Mutex::new(None),
        }
    }
}

impl AppState {
    fn touch(&self) {
        *self.last_activity.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
    }
}

/// Erreur renvoyée à l'interface (aucune donnée sensible).
#[derive(Debug, Serialize)]
struct CmdError {
    kind: &'static str,
    message: String,
}

impl From<ClientError> for CmdError {
    fn from(e: ClientError) -> Self {
        if e.is_device_revoked() {
            return CmdError { kind: "device_revoked", message: e.to_string() };
        }
        let kind = match &e {
            ClientError::KeyTransparency(_) => "key_transparency",
            ClientError::NotPrimaryDevice => "not_primary_device",
            ClientError::TotpRequired => "totp_required",
            ClientError::WrongPassword => "wrong_password",
            ClientError::IdentityChanged(_) => "identity_changed",
            ClientError::Verification(..) => "verification_failed",
            ClientError::NoLocalAccount => "no_local_account",
            ClientError::LocalAccountExists => "local_account_exists",
            ClientError::Api { .. } => "api",
            ClientError::Network(_) => "network",
            ClientError::InsecureUrl(_) => "insecure_url",
            ClientError::NotLoggedIn => "not_logged_in",
            _ => "error",
        };
        CmdError { kind, message: e.to_string() }
    }
}

fn err(kind: &'static str, message: impl Into<String>) -> CmdError {
    CmdError { kind, message: message.into() }
}

type CmdResult<T> = Result<T, CmdError>;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionDto {
    username: String,
    device_id: String,
    fingerprint: String,
    vault_protection: String,
    capture_protection: String,
    primary: bool,
}

#[derive(Serialize)]
struct ActivationDto {
    totp_secret_base32: String,
    otpauth_uri: String,
    qr_data_uri: String,
}

#[derive(Serialize)]
struct SafetyDto {
    #[serde(flatten)]
    view: SafetyNumberView,
    qr_data_uri: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SecurityStatus {
    capture_protection: String,
    auto_lock_minutes: u32,
    passkeys_supported: bool,
}

fn config(app: &AppHandle, server: &str) -> CmdResult<ClientConfig> {
    let dir = app.path().app_data_dir().map_err(|e| err("error", format!("dossier de données : {e}")))?;
    let mut cfg = ClientConfig::new(server.trim().trim_end_matches('/'), dir);
    let state = app.state::<AppState>();
    let (network, pins) = state.network.try_lock().map(|g| g.clone()).map_err(|_| err("error", "réseau occupé"))?;
    cfg.network = network;
    cfg.tls_pins = pins;
    Ok(cfg)
}

/// Choisit l'itinéraire réseau avant toute connexion : `direct` ou `tor`
/// (mode strict : arti embarqué, aucune connexion directe). `pins` :
/// empreintes SHA-256 (hexadécimal) de la clé publique TLS du serveur.
#[tauri::command]
async fn configure_network(
    mode: String,
    pins: Vec<String>,
    app: AppHandle,
    state: State<'_, AppState>,
) -> CmdResult<String> {
    let pins = pins
        .iter()
        .map(|p| {
            let clean: String = p.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            hex::decode(&clean)
                .ok()
                .and_then(|v| <[u8; 32]>::try_from(v).ok())
                .ok_or_else(|| err("error", "empreinte TLS invalide (SHA-256 en hexadécimal, 64 caractères)"))
        })
        .collect::<CmdResult<Vec<_>>>()?;
    let (network, label) = match mode.as_str() {
        "direct" => (msg_client_core::net::Network::Direct, "connexion directe".to_string()),
        "tor" => {
            let mut tor = state.tor.lock().await;
            if tor.is_none() {
                let base = app.path().app_data_dir().map_err(|e| err("error", e.to_string()))?.join("tor");
                let rt = msg_tor::TorRuntime::start(&base.join("state"), &base.join("cache"))
                    .await
                    .map_err(|e| err("tor_unavailable", format!("{e}. Aucune connexion directe n'a été tentée.")))?;
                *tor = Some(rt);
            }
            let p = tor.as_ref().map(|t| t.proxy()).ok_or_else(|| err("tor_unavailable", "Tor indisponible"))?;
            let proxy = msg_client_core::net::TorProxy { addr: p.addr, username: p.username, password: p.password };
            (msg_client_core::net::Network::TorStrict(proxy), "Tor (mode strict)".to_string())
        }
        _ => return Err(err("error", "mode réseau inconnu")),
    };
    *state.network.lock().await = (network, pins);
    Ok(label)
}

async fn current(state: &State<'_, AppState>) -> CmdResult<Shared> {
    state.touch();
    state.client.lock().await.as_ref().map(|(c, _)| c.clone()).ok_or(CmdError::from(ClientError::NotLoggedIn))
}

/// QR code généré localement (aucun service externe).
fn qr_data_uri(payload: &str) -> CmdResult<String> {
    let code = qrcode::QrCode::new(payload.as_bytes()).map_err(|e| err("error", e.to_string()))?;
    let svg = code.render::<qrcode::render::svg::Color<'_>>().min_dimensions(200, 200).quiet_zone(true).build();
    Ok(format!("data:image/svg+xml;base64,{}", base64::engine::general_purpose::STANDARD.encode(svg)))
}

// --- Authentificateur natif ----------------------------------------------

/// Passerelle vers l'API WebAuthn de Windows (YubiKey, Windows Hello).
struct NativeAuthenticator {
    hwnd: isize,
}

fn platform_err(e: msg_platform_win::PlatformError) -> ClientError {
    match e {
        msg_platform_win::PlatformError::Unsupported => {
            ClientError::Invalid("clés de sécurité non prises en charge sur ce système".into())
        }
        e => ClientError::Invalid(e.to_string()),
    }
}

impl RawAuthenticator for NativeAuthenticator {
    fn make_credential(&self, r: &MakeCredentialRequest) -> msg_client_core::Result<MakeCredentialResponse> {
        let a = msg_platform_win::webauthn::make_credential(
            self.hwnd,
            &msg_platform_win::webauthn::MakeCredential {
                rp_id: &r.rp_id,
                rp_name: &r.rp_name,
                user_id: &r.user_id,
                user_name: &r.user_name,
                user_display_name: &r.user_display_name,
                client_data_json: &r.client_data_json,
                algorithms: &r.algorithms,
                exclude_credentials: &r.exclude_credentials,
                require_resident_key: r.require_resident_key,
                user_verification: &r.user_verification,
                timeout_ms: r.timeout_ms,
            },
        )
        .map_err(platform_err)?;
        Ok(MakeCredentialResponse { credential_id: a.credential_id, attestation_object: a.attestation_object })
    }

    fn get_assertion(&self, r: &GetAssertionRequest) -> msg_client_core::Result<GetAssertionResponse> {
        let a = msg_platform_win::webauthn::get_assertion(
            self.hwnd,
            &msg_platform_win::webauthn::GetAssertion {
                rp_id: &r.rp_id,
                client_data_json: &r.client_data_json,
                allow_credentials: &r.allow_credentials,
                user_verification: &r.user_verification,
                timeout_ms: r.timeout_ms,
            },
        )
        .map_err(platform_err)?;
        Ok(GetAssertionResponse {
            credential_id: a.credential_id,
            authenticator_data: a.authenticator_data,
            signature: a.signature,
            user_handle: a.user_handle,
        })
    }
}

fn authenticator(state: &State<'_, AppState>) -> Arc<dyn RawAuthenticator> {
    Arc::new(NativeAuthenticator { hwnd: state.hwnd.load(Ordering::Relaxed) })
}

// --- Session -------------------------------------------------------------

#[tauri::command]
async fn activate(
    server: String,
    username: String,
    code: String,
    password: String,
    app: AppHandle,
) -> CmdResult<ActivationDto> {
    let cfg = config(&app, &server)?;
    let r = Client::activate(&cfg, &username, &code, &password).await?;
    Ok(ActivationDto {
        qr_data_uri: qr_data_uri(&r.otpauth_uri)?,
        totp_secret_base32: r.totp_secret_base32,
        otpauth_uri: r.otpauth_uri,
    })
}

async fn start_session(app: AppHandle, state: &State<'_, AppState>, client: Client, cfg: ClientConfig) -> SessionDto {
    let dto = SessionDto {
        username: client.username().to_owned(),
        device_id: client.device_id().to_string(),
        fingerprint: client.identity_fingerprint(),
        vault_protection: client.vault_protection(&cfg),
        capture_protection: state.capture_protection.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        primary: client.is_primary(),
    };
    let shared: Shared = Arc::new(Mutex::new(client));
    stop_listener(state);
    *state.client.lock().await = Some((shared.clone(), cfg));
    state.touch();
    let handle = tokio::spawn(listen(app, shared));
    *state.listener.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);
    dto
}

fn stop_listener(state: &AppState) {
    if let Some(h) = state.listener.lock().unwrap_or_else(|e| e.into_inner()).take() {
        h.abort();
    }
}

#[tauri::command]
async fn enroll(
    server: String,
    username: String,
    password: String,
    totp: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> CmdResult<SessionDto> {
    let cfg = config(&app, &server)?;
    let client = Client::enroll(&cfg, &username, &password, &totp).await?;
    Ok(start_session(app, &state, client, cfg).await)
}

#[tauri::command]
async fn login(
    server: String,
    username: String,
    password: String,
    totp: Option<String>,
    app: AppHandle,
    state: State<'_, AppState>,
) -> CmdResult<SessionDto> {
    let cfg = config(&app, &server)?;
    let client = Client::login(&cfg, &username, &password, totp.as_deref()).await?;
    Ok(start_session(app, &state, client, cfg).await)
}

/// Connexion mot de passe + clé de sécurité / passkey (à la place du TOTP).
#[tauri::command]
async fn login_passkey(
    server: String,
    username: String,
    password: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> CmdResult<SessionDto> {
    let cfg = config(&app, &server)?;
    let client = Client::login_with_passkey(&cfg, &username, &password, authenticator(&state)).await?;
    Ok(start_session(app, &state, client, cfg).await)
}

/// Efface les clés de la mémoire (la base locale reste chiffrée sur disque).
async fn lock_now(state: &AppState) {
    stop_listener(state);
    // Le client (clés, état MLS) est libéré ; la session serveur reste valide
    // jusqu'à son expiration, pour un déverrouillage par mot de passe seul.
    state.client.lock().await.take();
}

#[tauri::command]
async fn lock(state: State<'_, AppState>) -> CmdResult<()> {
    lock_now(&state).await;
    Ok(())
}

/// Déconnexion complète : session serveur fermée, TOTP requis ensuite.
#[tauri::command]
async fn logout(state: State<'_, AppState>) -> CmdResult<()> {
    stop_listener(&state);
    let taken = state.client.lock().await.take();
    if let Some((shared, _)) = taken {
        if let Ok(m) = Arc::try_unwrap(shared) {
            let _ = m.into_inner().logout().await;
        }
    }
    Ok(())
}

#[tauri::command]
fn activity(state: State<'_, AppState>) {
    state.touch();
}

#[tauri::command]
fn set_auto_lock(minutes: u32, state: State<'_, AppState>) -> CmdResult<()> {
    if !(1..=240).contains(&minutes) {
        return Err(err("error", "délai de verrouillage invalide (1 à 240 minutes)"));
    }
    state.auto_lock_minutes.store(minutes, Ordering::Relaxed);
    Ok(())
}

#[tauri::command]
fn security_status(state: State<'_, AppState>) -> SecurityStatus {
    SecurityStatus {
        capture_protection: state.capture_protection.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        auto_lock_minutes: state.auto_lock_minutes.load(Ordering::Relaxed),
        passkeys_supported: msg_platform_win::webauthn::available(),
    }
}

// --- Conversations ---------------------------------------------------------

#[tauri::command]
async fn conversations(state: State<'_, AppState>) -> CmdResult<Vec<ConversationView>> {
    Ok(current(&state).await?.lock().await.conversations()?)
}

#[tauri::command]
async fn conversation(conversation_id: String, state: State<'_, AppState>) -> CmdResult<ConversationView> {
    Ok(current(&state).await?.lock().await.conversation(&conversation_id)?)
}

#[tauri::command]
async fn messages(conversation_id: String, state: State<'_, AppState>) -> CmdResult<Vec<MessageView>> {
    Ok(current(&state).await?.lock().await.messages(&conversation_id, 500)?)
}

#[tauri::command]
async fn start_conversation(peer: String, state: State<'_, AppState>) -> CmdResult<ConversationView> {
    Ok(current(&state).await?.lock().await.start_conversation(&peer).await?)
}

#[tauri::command]
async fn create_group(name: String, members: Vec<String>, state: State<'_, AppState>) -> CmdResult<ConversationView> {
    Ok(current(&state).await?.lock().await.create_group(&name, &members).await?)
}

#[tauri::command]
async fn add_member(
    conversation_id: String,
    username: String,
    state: State<'_, AppState>,
) -> CmdResult<ConversationView> {
    Ok(current(&state).await?.lock().await.add_member(&conversation_id, &username).await?)
}

#[tauri::command]
async fn remove_member(
    conversation_id: String,
    username: String,
    state: State<'_, AppState>,
) -> CmdResult<ConversationView> {
    Ok(current(&state).await?.lock().await.remove_member(&conversation_id, &username).await?)
}

#[tauri::command]
async fn leave_group(conversation_id: String, state: State<'_, AppState>) -> CmdResult<()> {
    Ok(current(&state).await?.lock().await.leave_group(&conversation_id).await?)
}

#[tauri::command]
async fn set_ephemeral(conversation_id: String, ttl_s: Option<u32>, state: State<'_, AppState>) -> CmdResult<()> {
    Ok(current(&state).await?.lock().await.set_ephemeral(&conversation_id, ttl_s)?)
}

#[tauri::command]
async fn send_message(conversation_id: String, text: String, state: State<'_, AppState>) -> CmdResult<MessageView> {
    Ok(current(&state).await?.lock().await.send_text(&conversation_id, &text).await?)
}

fn header(req: &tauri::ipc::Request<'_>, name: &str) -> CmdResult<String> {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .ok_or_else(|| err("error", format!("en-tête {name} manquant")))
}

/// Envoi de fichier : corps binaire brut, métadonnées en en-têtes
/// (nom et légende encodés en Base64URL UTF-8).
#[tauri::command]
async fn send_file(request: tauri::ipc::Request<'_>, state: State<'_, AppState>) -> CmdResult<MessageView> {
    let tauri::ipc::InvokeBody::Raw(data) = request.body() else {
        return Err(err("error", "corps binaire attendu"));
    };
    let decode = |s: String| -> CmdResult<String> {
        let b =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).map_err(|_| err("error", "en-tête invalide"))?;
        String::from_utf8(b).map_err(|_| err("error", "en-tête invalide"))
    };
    let conversation_id = header(&request, "x-conversation")?;
    let name = decode(header(&request, "x-file-name")?)?;
    let caption = header(&request, "x-caption").ok().map(decode).transpose()?;
    let client = current(&state).await?;
    let mut c = client.lock().await;
    Ok(c.send_file(&conversation_id, &name, data.clone(), caption).await?)
}

/// Aperçu d'une image reçue (octets bruts, affichés via une URL `blob:`).
#[tauri::command]
async fn image_bytes(message_id: String, state: State<'_, AppState>) -> CmdResult<tauri::ipc::Response> {
    let client = current(&state).await?;
    let f = client.lock().await.download_file(&message_id).await?;
    if !matches!(f.mime.as_str(), "image/jpeg" | "image/png") {
        return Err(err("error", "aperçu réservé aux images"));
    }
    Ok(tauri::ipc::Response::new(f.data.to_vec()))
}

/// Enregistre une pièce jointe à l'emplacement choisi par l'utilisateur.
#[tauri::command]
async fn save_attachment(message_id: String, app: AppHandle, state: State<'_, AppState>) -> CmdResult<bool> {
    let client = current(&state).await?;
    let f = client.lock().await.download_file(&message_id).await?;
    let name = f.name.clone();
    let dialog = app.clone();
    let target = tokio::task::spawn_blocking(move || dialog.dialog().file().set_file_name(&name).blocking_save_file())
        .await
        .map_err(|e| err("error", e.to_string()))?;
    let Some(target) = target else { return Ok(false) };
    let path = target.into_path().map_err(|e| err("error", e.to_string()))?;
    std::fs::write(&path, &f.data[..]).map_err(|e| err("error", format!("écriture impossible : {e}")))?;
    Ok(true)
}

#[tauri::command]
async fn mark_read(conversation_id: String, state: State<'_, AppState>) -> CmdResult<()> {
    Ok(current(&state).await?.lock().await.mark_read(&conversation_id)?)
}

#[tauri::command]
async fn sync(state: State<'_, AppState>) -> CmdResult<SyncReport> {
    Ok(current(&state).await?.lock().await.sync().await?)
}

// --- Vérification des correspondants ----------------------------------------

#[tauri::command]
async fn safety_number(username: String, state: State<'_, AppState>) -> CmdResult<SafetyDto> {
    let view = current(&state).await?.lock().await.safety_number(&username)?;
    Ok(SafetyDto { qr_data_uri: qr_data_uri(&view.qr_payload)?, view })
}

#[tauri::command]
async fn verify_safety_number(
    username: String,
    scanned: Option<String>,
    state: State<'_, AppState>,
) -> CmdResult<bool> {
    Ok(current(&state).await?.lock().await.verify_safety_number(&username, scanned.as_deref())?)
}

#[tauri::command]
async fn accept_identity_change(username: String, state: State<'_, AppState>) -> CmdResult<()> {
    Ok(current(&state).await?.lock().await.accept_identity_change(&username)?)
}

// --- Passkeys ----------------------------------------------------------------

// --- Appareils : liaison et révocation -----------------------------------

#[derive(Serialize)]
struct LinkStartDto {
    code: String,
    fingerprint: String,
    qr_data_uri: String,
    expires_at: i64,
}

#[derive(Serialize)]
struct LinkPollDto {
    status: &'static str,
    session: Option<SessionDto>,
}

/// Lie cet appareil à un compte existant : affiche un code à faire
/// approuver par l'appareil principal.
#[tauri::command]
async fn link_start(
    server: String,
    username: String,
    password: String,
    totp: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> CmdResult<LinkStartDto> {
    let cfg = config(&app, &server)?;
    let p = Client::link_start(&cfg, &username, &password, &totp).await?;
    let dto = LinkStartDto {
        qr_data_uri: qr_data_uri(&p.code())?,
        code: p.code(),
        fingerprint: p.fingerprint(),
        expires_at: p.expires_at,
    };
    *state.pending_link.lock().await = Some((Arc::new(p), cfg));
    Ok(dto)
}

#[tauri::command]
async fn link_poll(app: AppHandle, state: State<'_, AppState>) -> CmdResult<LinkPollDto> {
    let (p, cfg) = state.pending_link.lock().await.clone().ok_or_else(|| err("error", "aucune liaison en cours"))?;
    let outcome = p.poll().await?;
    let done = |status| LinkPollDto { status, session: None };
    Ok(match outcome {
        LinkOutcome::Pending => done("pending"),
        LinkOutcome::Rejected => {
            state.pending_link.lock().await.take();
            done("rejected")
        }
        LinkOutcome::Expired => {
            state.pending_link.lock().await.take();
            done("expired")
        }
        LinkOutcome::Linked(c) => {
            state.pending_link.lock().await.take();
            let s = start_session(app, &state, *c, cfg).await;
            LinkPollDto { status: "linked", session: Some(s) }
        }
    })
}

#[tauri::command]
async fn devices(state: State<'_, AppState>) -> CmdResult<Vec<OwnDevice>> {
    let client = current(&state).await?;
    let d = client.lock().await.devices().await?;
    Ok(d)
}

#[tauri::command]
async fn revoke_device(device_id: String, state: State<'_, AppState>) -> CmdResult<()> {
    let id = uuid::Uuid::parse_str(&device_id).map_err(|_| err("error", "identifiant invalide"))?;
    let client = current(&state).await?;
    client.lock().await.revoke_device(id).await?;
    Ok(())
}

#[tauri::command]
async fn link_requests(state: State<'_, AppState>) -> CmdResult<Vec<LinkRequestInfo>> {
    let client = current(&state).await?;
    let r = client.lock().await.link_requests().await?;
    Ok(r)
}

#[tauri::command]
async fn approve_link(code: String, state: State<'_, AppState>) -> CmdResult<()> {
    let client = current(&state).await?;
    client.lock().await.approve_link(&code).await?;
    Ok(())
}

#[tauri::command]
async fn reject_link(link_id: String, state: State<'_, AppState>) -> CmdResult<()> {
    let id = uuid::Uuid::parse_str(&link_id).map_err(|_| err("error", "identifiant invalide"))?;
    let client = current(&state).await?;
    client.lock().await.reject_link(id).await?;
    Ok(())
}

#[tauri::command]
async fn register_passkey(name: String, state: State<'_, AppState>) -> CmdResult<WebauthnCredentialSummary> {
    let auth = authenticator(&state);
    Ok(current(&state).await?.lock().await.register_passkey(&name, auth).await?)
}

#[tauri::command]
async fn list_passkeys(state: State<'_, AppState>) -> CmdResult<Vec<WebauthnCredentialSummary>> {
    Ok(current(&state).await?.lock().await.passkeys().await?)
}

#[tauri::command]
async fn delete_passkey(id: i64, state: State<'_, AppState>) -> CmdResult<()> {
    Ok(current(&state).await?.lock().await.delete_passkey(id).await?)
}

// --- Tâches de fond ----------------------------------------------------------

fn window_focused(app: &AppHandle) -> bool {
    app.get_webview_window("main").and_then(|w| w.is_focused().ok()).unwrap_or(false)
}

/// Synchronise et notifie l'interface ; renvoie `false` si l'appareil a été
/// révoqué (données locales effacées, écoute arrêtée).
async fn sync_and_emit(app: &AppHandle, client: &Shared) -> bool {
    let r = client.lock().await.sync().await;
    match r {
        Ok(report) => {
            if report.new_messages > 0 && !window_focused(app) {
                // Notification sans aperçu : ni expéditeur, ni contenu.
                let _ = app.notification().builder().title("Messagerie").body("Nouveau message").show();
            }
            if report.processed > 0 || report.expired > 0 || report.reconciled > 0 {
                let _ = app.emit("messages-updated", report);
            }
            true
        }
        Err(e) if e.is_device_revoked() => {
            handle_revoked(app).await;
            false
        }
        Err(e) => {
            tracing::warn!(error = %e, "synchronisation échouée");
            true
        }
    }
}

/// Appareil révoqué : clés libérées, compte local effacé, interface prévenue.
async fn handle_revoked(app: &AppHandle) {
    let state = app.state::<AppState>();
    let taken = state.client.lock().await.take();
    if let Some((shared, cfg)) = taken {
        let username = shared.lock().await.username().to_owned();
        drop(shared);
        if let Err(e) = Client::wipe_local(&cfg, &username) {
            tracing::error!(error = %e, "effacement du compte local");
        }
    }
    let _ = app.emit("revoked", ());
}

/// Écoute le WebSocket de notification (sans contenu) et synchronise à chaque
/// signal ; synchronisation de secours toutes les 30 s (expiration des
/// éphémères, rotation) ; reconnexion avec attente exponentielle.
async fn listen(app: AppHandle, client: Shared) {
    let mut backoff = 1u64;
    loop {
        let ws = { client.lock().await.api().connect_ws().await };
        match ws {
            Ok(mut ws) => {
                backoff = 1;
                if !sync_and_emit(&app, &client).await {
                    return;
                }
                loop {
                    let alive = tokio::select! {
                        msg = ws.next() => match msg {
                            Some(Ok(WsMessage::Text(_))) => sync_and_emit(&app, &client).await,
                            Some(Ok(WsMessage::Close(_))) | Some(Err(_)) | None => break,
                            Some(Ok(_)) => true,
                        },
                        _ = tokio::time::sleep(Duration::from_secs(30)) => sync_and_emit(&app, &client).await,
                    };
                    if !alive {
                        return;
                    }
                }
            }
            Err(e) if e.is_device_revoked() => {
                handle_revoked(&app).await;
                return;
            }
            Err(e) => tracing::warn!(error = %e, "WebSocket indisponible"),
        }
        tokio::time::sleep(Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(60);
    }
}

/// Verrouillage automatique après inactivité.
async fn auto_lock(app: AppHandle) {
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        let state = app.state::<AppState>();
        let idle = state.last_activity.lock().unwrap_or_else(|e| e.into_inner()).elapsed();
        let limit = Duration::from_secs(u64::from(state.auto_lock_minutes.load(Ordering::Relaxed)) * 60);
        if idle >= limit && state.client.lock().await.is_some() {
            lock_now(&state).await;
            let _ = app.emit("locked", ());
        }
    }
}

/// Anti-capture sur la fenêtre principale (Windows) ; renvoie l'état appliqué.
fn protect_main_window(app: &AppHandle) -> String {
    #[cfg(windows)]
    {
        if let Some(w) = app.get_webview_window("main") {
            if let Ok(h) = w.hwnd() {
                let hwnd = h.0 as isize;
                app.state::<AppState>().hwnd.store(hwnd, Ordering::Relaxed);
                return match msg_platform_win::capture::protect_window(hwnd, true) {
                    Ok(msg_platform_win::capture::CaptureProtection::Excluded) => "fenêtre exclue des captures".into(),
                    Ok(msg_platform_win::capture::CaptureProtection::Monitor) => {
                        "fenêtre noircie dans les captures".into()
                    }
                    Ok(_) => "protection désactivée".into(),
                    Err(e) => format!("échec ({e})"),
                };
            }
        }
        "échec (fenêtre introuvable)".into()
    }
    #[cfg(not(windows))]
    {
        let _ = app;
        "non disponible sur ce système".into()
    }
}

pub fn run() {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::new("warn")).init();
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .setup(|app| {
            let handle = app.handle().clone();
            let status = protect_main_window(&handle);
            *app.state::<AppState>().capture_protection.lock().unwrap_or_else(|e| e.into_inner()) = status;
            tauri::async_runtime::spawn(auto_lock(handle));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            activate,
            enroll,
            login,
            login_passkey,
            lock,
            logout,
            activity,
            set_auto_lock,
            security_status,
            conversations,
            conversation,
            messages,
            start_conversation,
            create_group,
            add_member,
            remove_member,
            leave_group,
            set_ephemeral,
            send_message,
            send_file,
            image_bytes,
            save_attachment,
            mark_read,
            sync,
            safety_number,
            verify_safety_number,
            accept_identity_change,
            configure_network,
            link_start,
            link_poll,
            devices,
            revoke_device,
            link_requests,
            approve_link,
            reject_link,
            register_passkey,
            list_passkeys,
            delete_passkey
        ])
        .run(tauri::generate_context!())
        .expect("erreur au démarrage de l'application");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_is_local_svg() {
        let uri = qr_data_uri("otpauth://totp/test:alice?secret=JBSWY3DPEHPK3PXP&issuer=test").unwrap();
        assert!(uri.starts_with("data:image/svg+xml;base64,"));
        let svg = base64::engine::general_purpose::STANDARD.decode(&uri[26..]).unwrap();
        let svg = String::from_utf8(svg).unwrap();
        assert!(svg.contains("<svg"));
        assert!(!svg.contains("http://") || svg.contains("http://www.w3.org"), "aucune ressource externe");
    }

    #[test]
    fn errors_are_classified() {
        assert_eq!(CmdError::from(ClientError::TotpRequired).kind, "totp_required");
        assert_eq!(CmdError::from(ClientError::IdentityChanged("bob".into())).kind, "identity_changed");
    }

    #[test]
    fn native_authenticator_reports_unsupported_off_windows() {
        if cfg!(windows) {
            return;
        }
        let a = NativeAuthenticator { hwnd: 0 };
        let r = GetAssertionRequest {
            rp_id: "x".into(),
            client_data_json: vec![],
            allow_credentials: vec![],
            user_verification: "required".into(),
            timeout_ms: 1000,
        };
        assert!(a.get_assertion(&r).is_err());
    }
}
