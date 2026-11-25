//! Client web : le cœur client Rust (`msg-client-core`, identique à celui
//! du desktop) compilé en WebAssembly et exposé à l'interface React.
//!
//! - Chiffrement, déchiffrement, vérifications (certificats, Key
//!   Transparency, numéros de sécurité) : **dans le module WASM**.
//! - Stockage : coffre (Argon2id) et instantané chiffré de la base confiés à
//!   l'hôte via une interface clé-valeur (IndexedDB, côté TypeScript) ; l'hôte
//!   ne reçoit que des octets chiffrés.
//! - Réseau : `fetch` (même origine) ; le WebSocket de notification est
//!   ouvert par l'interface avec un ticket à usage unique.
#![cfg(target_arch = "wasm32")]
#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::rc::Rc;

use base64::Engine as _;
use futures_util::lock::Mutex;
use js_sys::{Function, Promise, Reflect, Uint8Array};
use msg_client_core::account::KvStore;
use msg_client_core::{Client, ClientConfig, ClientError, LinkOutcome, PendingLink};
use msg_crypto::keywrap::Argon2Params;
use serde::Serialize;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

/// Paramètres Argon2id du coffre web : plus légers que sur le desktop
/// (WebAssembly mono-fil), conformes aux recommandations OWASP (≥ 19 Mio).
const WEB_ARGON2: Argon2Params = Argon2Params { m_kib: 32 * 1024, t: 3, p: 1 };

#[derive(Serialize)]
struct JsError {
    kind: &'static str,
    message: String,
}

fn kind(e: &ClientError) -> &'static str {
    if e.is_device_revoked() {
        return "device_revoked";
    }
    match e {
        ClientError::TotpRequired => "totp_required",
        ClientError::WrongPassword => "wrong_password",
        ClientError::IdentityChanged(_) => "identity_changed",
        ClientError::Verification(..) => "verification_failed",
        ClientError::KeyTransparency(_) => "key_transparency",
        ClientError::NoLocalAccount => "no_local_account",
        ClientError::LocalAccountExists => "local_account_exists",
        ClientError::NotPrimaryDevice => "not_primary_device",
        ClientError::Api { .. } => "api",
        ClientError::Network(_) => "network",
        ClientError::InsecureUrl(_) => "insecure_url",
        ClientError::NotLoggedIn => "not_logged_in",
        _ => "error",
    }
}

fn to_js<T: Serialize>(v: &T) -> Result<JsValue, JsValue> {
    v.serialize(&serde_wasm_bindgen::Serializer::json_compatible()).map_err(|e| err("error", e.to_string()))
}

fn err(kind: &'static str, message: impl Into<String>) -> JsValue {
    to_js(&JsError { kind, message: message.into() }).unwrap_or_else(|_| JsValue::from_str("erreur"))
}

fn cerr(e: ClientError) -> JsValue {
    err(kind(&e), e.to_string())
}

fn qr_data_uri(payload: &str) -> Result<String, JsValue> {
    let code = qrcode::QrCode::new(payload.as_bytes()).map_err(|e| err("error", e.to_string()))?;
    let svg = code.render::<qrcode::render::svg::Color<'_>>().min_dimensions(200, 200).quiet_zone(true).build();
    Ok(format!("data:image/svg+xml;base64,{}", base64::engine::general_purpose::STANDARD.encode(svg)))
}

/// Stockage clé-valeur fourni par la page (`{ get, set, delete }`).
struct JsKv(JsValue);

impl JsKv {
    fn call(&self, name: &str, args: &[JsValue]) -> Option<JsValue> {
        let f: Function = Reflect::get(&self.0, &JsValue::from_str(name)).ok()?.dyn_into().ok()?;
        let arr = js_sys::Array::new();
        for a in args {
            arr.push(a);
        }
        f.apply(&self.0, &arr).ok()
    }
}

impl KvStore for JsKv {
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        let v = self.call("get", &[JsValue::from_str(key)])?;
        v.dyn_into::<Uint8Array>().ok().map(|a| a.to_vec())
    }
    fn set(&self, key: &str, value: &[u8]) {
        self.call("set", &[JsValue::from_str(key), Uint8Array::from(value).into()]);
    }
    fn delete(&self, key: &str) {
        self.call("delete", &[JsValue::from_str(key)]);
    }
}

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

fn session(c: &Client, cfg: &ClientConfig) -> SessionDto {
    SessionDto {
        username: c.username().to_owned(),
        device_id: c.device_id().to_string(),
        fingerprint: c.identity_fingerprint(),
        vault_protection: c.vault_protection(cfg),
        capture_protection: "indisponible dans un navigateur".into(),
        primary: c.is_primary(),
    }
}

struct Inner {
    cfg: ClientConfig,
    client: Mutex<Option<Client>>,
    pending: RefCell<Option<Rc<PendingLink>>>,
}

/// Application web : une instance par onglet.
#[wasm_bindgen]
pub struct WebApp {
    inner: Rc<Inner>,
}

macro_rules! with_client {
    ($self:ident, |$c:ident| $body:expr) => {{
        let inner = $self.inner.clone();
        future_to_promise(async move {
            let mut guard = inner.client.lock().await;
            let $c = guard.as_mut().ok_or_else(|| err("not_logged_in", "non connecté"))?;
            #[allow(clippy::redundant_closure_call)]
            let r = $body;
            r
        })
    }};
}

#[wasm_bindgen]
impl WebApp {
    /// `server` : origine de la page (le client web est servi par le serveur).
    /// `kv` : objet `{ get(key), set(key, bytes), delete(key) }` synchrone.
    #[wasm_bindgen(constructor)]
    pub fn new(server: String, kv: JsValue) -> Result<WebApp, JsValue> {
        let mut cfg = ClientConfig::new(server, "web");
        cfg.argon2 = WEB_ARGON2;
        cfg.kv = Some(Rc::new(JsKv(kv)));
        Ok(WebApp { inner: Rc::new(Inner { cfg, client: Mutex::new(None), pending: RefCell::new(None) }) })
    }

    // --- Compte -------------------------------------------------------------

    pub fn activate(&self, username: String, code: String, password: String) -> Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let r = Client::activate(&inner.cfg, &username, &code, &password).await.map_err(cerr)?;
            #[derive(Serialize)]
            struct Dto {
                totp_secret_base32: String,
                otpauth_uri: String,
                qr_data_uri: String,
            }
            to_js(&Dto {
                qr_data_uri: qr_data_uri(&r.otpauth_uri)?,
                totp_secret_base32: r.totp_secret_base32,
                otpauth_uri: r.otpauth_uri,
            })
        })
    }

    pub fn enroll(&self, username: String, password: String, totp: String) -> Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let c = Client::enroll(&inner.cfg, &username, &password, &totp).await.map_err(cerr)?;
            let dto = session(&c, &inner.cfg);
            *inner.client.lock().await = Some(c);
            to_js(&dto)
        })
    }

    pub fn login(&self, username: String, password: String, totp: Option<String>) -> Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let c = Client::login(&inner.cfg, &username, &password, totp.as_deref()).await.map_err(cerr)?;
            let dto = session(&c, &inner.cfg);
            *inner.client.lock().await = Some(c);
            to_js(&dto)
        })
    }

    /// Efface les clés de la mémoire (la base reste chiffrée dans le navigateur).
    pub fn lock(&self) -> Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            inner.client.lock().await.take();
            Ok(JsValue::UNDEFINED)
        })
    }

    pub fn logout(&self) -> Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            if let Some(c) = inner.client.lock().await.take() {
                let _ = c.logout().await;
            }
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Efface le compte local (appareil révoqué).
    pub fn wipe(&self, username: String) -> Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            inner.client.lock().await.take();
            Client::wipe_local(&inner.cfg, &username).map_err(cerr)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    // --- Liaison de ce navigateur à un compte existant ----------------------

    #[wasm_bindgen(js_name = linkStart)]
    pub fn link_start(&self, username: String, password: String, totp: String) -> Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let p = Client::link_start(&inner.cfg, &username, &password, &totp).await.map_err(cerr)?;
            #[derive(Serialize)]
            struct Dto {
                code: String,
                fingerprint: String,
                qr_data_uri: String,
                expires_at: i64,
            }
            let dto = Dto {
                qr_data_uri: qr_data_uri(&p.code())?,
                code: p.code(),
                fingerprint: p.fingerprint(),
                expires_at: p.expires_at,
            };
            *inner.pending.borrow_mut() = Some(Rc::new(p));
            to_js(&dto)
        })
    }

    #[wasm_bindgen(js_name = linkPoll)]
    pub fn link_poll(&self) -> Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let p = inner.pending.borrow().clone().ok_or_else(|| err("error", "aucune liaison en cours"))?;
            #[derive(Serialize)]
            struct Dto {
                status: &'static str,
                session: Option<SessionDto>,
            }
            let dto = match p.poll().await.map_err(cerr)? {
                LinkOutcome::Pending => Dto { status: "pending", session: None },
                LinkOutcome::Rejected => {
                    inner.pending.borrow_mut().take();
                    Dto { status: "rejected", session: None }
                }
                LinkOutcome::Expired => {
                    inner.pending.borrow_mut().take();
                    Dto { status: "expired", session: None }
                }
                LinkOutcome::Linked(c) => {
                    inner.pending.borrow_mut().take();
                    let s = session(&c, &inner.cfg);
                    *inner.client.lock().await = Some(*c);
                    Dto { status: "linked", session: Some(s) }
                }
            };
            to_js(&dto)
        })
    }

    // --- Conversations --------------------------------------------------------

    pub fn conversations(&self) -> Promise {
        with_client!(self, |c| to_js(&c.conversations().map_err(cerr)?))
    }

    pub fn conversation(&self, id: String) -> Promise {
        with_client!(self, |c| to_js(&c.conversation(&id).map_err(cerr)?))
    }

    pub fn messages(&self, id: String) -> Promise {
        with_client!(self, |c| to_js(&c.messages(&id, 500).map_err(cerr)?))
    }

    #[wasm_bindgen(js_name = startConversation)]
    pub fn start_conversation(&self, peer: String) -> Promise {
        with_client!(self, |c| to_js(&c.start_conversation(&peer).await.map_err(cerr)?))
    }

    #[wasm_bindgen(js_name = createGroup)]
    pub fn create_group(&self, name: String, members: Vec<String>) -> Promise {
        with_client!(self, |c| to_js(&c.create_group(&name, &members).await.map_err(cerr)?))
    }

    #[wasm_bindgen(js_name = addMember)]
    pub fn add_member(&self, id: String, username: String) -> Promise {
        with_client!(self, |c| to_js(&c.add_member(&id, &username).await.map_err(cerr)?))
    }

    #[wasm_bindgen(js_name = removeMember)]
    pub fn remove_member(&self, id: String, username: String) -> Promise {
        with_client!(self, |c| to_js(&c.remove_member(&id, &username).await.map_err(cerr)?))
    }

    #[wasm_bindgen(js_name = leaveGroup)]
    pub fn leave_group(&self, id: String) -> Promise {
        with_client!(self, |c| {
            c.leave_group(&id).await.map_err(cerr)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    #[wasm_bindgen(js_name = setEphemeral)]
    pub fn set_ephemeral(&self, id: String, ttl_s: Option<u32>) -> Promise {
        with_client!(self, |c| {
            c.set_ephemeral(&id, ttl_s).map_err(cerr)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    pub fn send(&self, id: String, text: String) -> Promise {
        with_client!(self, |c| to_js(&c.send_text(&id, &text).await.map_err(cerr)?))
    }

    #[wasm_bindgen(js_name = sendFile)]
    pub fn send_file(&self, id: String, name: String, data: Vec<u8>, caption: Option<String>) -> Promise {
        with_client!(self, |c| to_js(&c.send_file(&id, &name, data, caption).await.map_err(cerr)?))
    }

    /// Pièce jointe déchiffrée : `{ name, mime, data }`.
    #[wasm_bindgen(js_name = downloadFile)]
    pub fn download_file(&self, message_id: String) -> Promise {
        with_client!(self, |c| {
            let f = c.download_file(&message_id).await.map_err(cerr)?;
            let o = js_sys::Object::new();
            Reflect::set(&o, &"name".into(), &f.name.into())?;
            Reflect::set(&o, &"mime".into(), &f.mime.into())?;
            Reflect::set(&o, &"data".into(), &Uint8Array::from(&f.data[..]).into())?;
            Ok(o.into())
        })
    }

    #[wasm_bindgen(js_name = markRead)]
    pub fn mark_read(&self, id: String) -> Promise {
        with_client!(self, |c| {
            c.mark_read(&id).map_err(cerr)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    pub fn sync(&self) -> Promise {
        with_client!(self, |c| to_js(&c.sync().await.map_err(cerr)?))
    }

    /// URL du WebSocket de notification (ticket à usage unique inclus).
    #[wasm_bindgen(js_name = wsUrl)]
    pub fn ws_url(&self) -> Promise {
        let inner = self.inner.clone();
        with_client!(self, |c| {
            let t = c.api().ws_ticket().await.map_err(cerr)?;
            let mut url = msg_client_core::api::validate_server_url(&inner.cfg.server_url, false)
                .map_err(cerr)?
                .join("/v1/ws/connect")
                .map_err(|e| err("error", e.to_string()))?;
            let scheme = if url.scheme() == "https" { "wss" } else { "ws" };
            url.set_scheme(scheme).map_err(|_| err("error", "schéma"))?;
            url.query_pairs_mut().append_pair("ticket", &t.ticket);
            Ok(JsValue::from_str(url.as_str()))
        })
    }

    // --- Vérification ---------------------------------------------------------

    #[wasm_bindgen(js_name = safetyNumber)]
    pub fn safety_number(&self, username: String) -> Promise {
        with_client!(self, |c| {
            let view = c.safety_number(&username).map_err(cerr)?;
            #[derive(Serialize)]
            struct Dto {
                #[serde(flatten)]
                view: msg_client_core::SafetyNumberView,
                qr_data_uri: String,
            }
            to_js(&Dto { qr_data_uri: qr_data_uri(&view.qr_payload)?, view })
        })
    }

    #[wasm_bindgen(js_name = verifySafetyNumber)]
    pub fn verify_safety_number(&self, username: String, scanned: Option<String>) -> Promise {
        with_client!(self, |c| Ok(JsValue::from_bool(
            c.verify_safety_number(&username, scanned.as_deref()).map_err(cerr)?
        )))
    }

    #[wasm_bindgen(js_name = acceptIdentityChange)]
    pub fn accept_identity_change(&self, username: String) -> Promise {
        with_client!(self, |c| {
            c.accept_identity_change(&username).map_err(cerr)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    // --- Appareils --------------------------------------------------------------

    pub fn devices(&self) -> Promise {
        with_client!(self, |c| to_js(&c.devices().await.map_err(cerr)?))
    }

    #[wasm_bindgen(js_name = revokeDevice)]
    pub fn revoke_device(&self, device_id: String) -> Promise {
        with_client!(self, |c| {
            let id = uuid::Uuid::parse_str(&device_id).map_err(|_| err("error", "identifiant invalide"))?;
            c.revoke_device(id).await.map_err(cerr)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    #[wasm_bindgen(js_name = linkRequests)]
    pub fn link_requests(&self) -> Promise {
        with_client!(self, |c| to_js(&c.link_requests().await.map_err(cerr)?))
    }

    #[wasm_bindgen(js_name = approveLink)]
    pub fn approve_link(&self, code: String) -> Promise {
        with_client!(self, |c| {
            c.approve_link(&code).await.map_err(cerr)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    #[wasm_bindgen(js_name = rejectLink)]
    pub fn reject_link(&self, link_id: String) -> Promise {
        with_client!(self, |c| {
            let id = uuid::Uuid::parse_str(&link_id).map_err(|_| err("error", "identifiant invalide"))?;
            c.reject_link(id).await.map_err(cerr)?;
            Ok(JsValue::UNDEFINED)
        })
    }
}
