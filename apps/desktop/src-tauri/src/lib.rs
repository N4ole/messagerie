//! Application de bureau.
//!
//! La WebView n'appelle que des commandes de haut niveau ; elle ne reçoit
//! jamais de clé. Toute la cryptographie s'exécute dans ce processus via
//! `msg-client-core`.
#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use futures_util::StreamExt;
use msg_client_core::api::WsMessage;
use msg_client_core::{Client, ClientConfig, ClientError, ConversationView, MessageView, SyncReport};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

type Shared = Arc<Mutex<Client>>;

#[derive(Default)]
struct AppState {
    client: Mutex<Option<Shared>>,
    listener: std::sync::Mutex<Option<JoinHandle<()>>>,
}

/// Erreur renvoyée à l'interface (aucune donnée sensible).
#[derive(Debug, Serialize)]
struct CmdError {
    kind: &'static str,
    message: String,
}

impl From<ClientError> for CmdError {
    fn from(e: ClientError) -> Self {
        let kind = match &e {
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

type CmdResult<T> = Result<T, CmdError>;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionDto {
    username: String,
    device_id: String,
    fingerprint: String,
}

#[derive(Serialize)]
struct ActivationDto {
    totp_secret_base32: String,
    otpauth_uri: String,
    qr_data_uri: String,
}

fn config(app: &AppHandle, server: &str) -> CmdResult<ClientConfig> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| CmdError { kind: "error", message: format!("dossier de données : {e}") })?;
    Ok(ClientConfig::new(server.trim().trim_end_matches('/'), dir))
}

async fn current(state: &State<'_, AppState>) -> CmdResult<Shared> {
    state.client.lock().await.clone().ok_or(CmdError::from(ClientError::NotLoggedIn))
}

/// QR code du secret TOTP, généré localement (aucun service externe).
fn qr_data_uri(uri: &str) -> CmdResult<String> {
    let code = qrcode::QrCode::new(uri.as_bytes()).map_err(|e| CmdError { kind: "error", message: e.to_string() })?;
    let svg = code.render::<qrcode::render::svg::Color<'_>>().min_dimensions(200, 200).quiet_zone(true).build();
    Ok(format!("data:image/svg+xml;base64,{}", base64::engine::general_purpose::STANDARD.encode(svg)))
}

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

async fn start_session(app: AppHandle, state: &State<'_, AppState>, client: Client) -> SessionDto {
    let dto = SessionDto {
        username: client.username().to_owned(),
        device_id: client.device_id().to_string(),
        fingerprint: client.identity_fingerprint(),
    };
    let shared: Shared = Arc::new(Mutex::new(client));
    stop_listener(state);
    *state.client.lock().await = Some(shared.clone());
    let handle = tokio::spawn(listen(app, shared));
    *state.listener.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);
    dto
}

fn stop_listener(state: &State<'_, AppState>) {
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
    Ok(start_session(app, &state, client).await)
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
    Ok(start_session(app, &state, client).await)
}

/// Verrouillage : ferme la session serveur et efface les clés de la mémoire
/// (la base locale reste chiffrée sur disque).
#[tauri::command]
async fn logout(state: State<'_, AppState>) -> CmdResult<()> {
    stop_listener(&state);
    let taken = state.client.lock().await.take();
    if let Some(shared) = taken {
        if let Ok(m) = Arc::try_unwrap(shared) {
            let _ = m.into_inner().logout().await;
        }
    }
    Ok(())
}

#[tauri::command]
async fn conversations(state: State<'_, AppState>) -> CmdResult<Vec<ConversationView>> {
    Ok(current(&state).await?.lock().await.conversations()?)
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
async fn send_message(conversation_id: String, text: String, state: State<'_, AppState>) -> CmdResult<MessageView> {
    Ok(current(&state).await?.lock().await.send_text(&conversation_id, &text).await?)
}

#[tauri::command]
async fn mark_read(conversation_id: String, state: State<'_, AppState>) -> CmdResult<()> {
    Ok(current(&state).await?.lock().await.mark_read(&conversation_id)?)
}

#[tauri::command]
async fn sync(state: State<'_, AppState>) -> CmdResult<SyncReport> {
    Ok(current(&state).await?.lock().await.sync().await?)
}

async fn sync_and_emit(app: &AppHandle, client: &Shared) {
    let r = client.lock().await.sync().await;
    match r {
        Ok(report) if report.processed > 0 => {
            let _ = app.emit("messages-updated", report);
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "synchronisation échouée"),
    }
}

/// Écoute le WebSocket de notification (sans contenu) et synchronise à chaque
/// signal ; synchronisation de secours toutes les 60 s ; reconnexion avec
/// attente exponentielle.
async fn listen(app: AppHandle, client: Shared) {
    let mut backoff = 1u64;
    loop {
        let ws = { client.lock().await.api().connect_ws().await };
        match ws {
            Ok(mut ws) => {
                backoff = 1;
                sync_and_emit(&app, &client).await;
                loop {
                    tokio::select! {
                        msg = ws.next() => match msg {
                            Some(Ok(WsMessage::Text(_))) => sync_and_emit(&app, &client).await,
                            Some(Ok(WsMessage::Close(_))) | Some(Err(_)) | None => break,
                            Some(Ok(_)) => {}
                        },
                        _ = tokio::time::sleep(Duration::from_secs(60)) => sync_and_emit(&app, &client).await,
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "WebSocket indisponible"),
        }
        tokio::time::sleep(Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(60);
    }
}

pub fn run() {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::new("warn")).init();
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            activate,
            enroll,
            login,
            logout,
            conversations,
            messages,
            start_conversation,
            send_message,
            mark_read,
            sync
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
}
