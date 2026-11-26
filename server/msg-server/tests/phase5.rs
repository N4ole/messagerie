//! Phase 5 — tests d'intrusion de base sur l'authentification et le
//! contrôle d'accès (complètent `e2e.rs` : rejeu, altération, verrouillage,
//! TOTP, codes d'activation).

mod common;

use common::{password, spawn, totp_code};
use msg_client_core::Client;
use msg_crypto::identity::{DeviceCertificate, SigningKeyPair};
use msg_crypto::request::{sign_request, SignedHeaders};
use msg_proto::{headers, ConfirmTotpRequest, DeviceRegistration, RefreshRequest, SessionTokens};
use uuid::Uuid;

/// Appareil construit à la main (clé API maîtrisée par le test).
struct RawDevice {
    id: Uuid,
    api_key: SigningKeyPair,
    tokens: SessionTokens,
}

async fn raw_device(url: &str, admin: &Client, username: &str) -> RawDevice {
    let r = admin.api().admin_create(username, msg_proto::Role::User).await.unwrap();
    let cfg = msg_client_core::ClientConfig::new(url, tempfile::tempdir().unwrap().keep());
    let act = Client::activate(&cfg, username, &r.activation_code, password()).await.unwrap();
    let identity = SigningKeyPair::generate().unwrap();
    let api_key = SigningKeyPair::generate().unwrap();
    let id = Uuid::new_v4();
    let mls_key = SigningKeyPair::generate().unwrap().public_bytes().to_vec();
    let cert = DeviceCertificate {
        username: username.into(),
        device_id: id,
        api_key: api_key.public_bytes().to_vec(),
        mls_signature_key: mls_key.clone(),
        created_at: 1,
    };
    let tokens = reqwest::Client::new()
        .post(format!("{url}/v1/auth/confirm-totp"))
        .json(&ConfirmTotpRequest {
            username: username.into(),
            password: password().into(),
            totp_code: totp_code(&act.totp_secret_base32, 0),
            device: DeviceRegistration {
                device_id: id,
                identity_key: identity.public_bytes().to_vec(),
                api_key: api_key.public_bytes().to_vec(),
                mls_signature_key: mls_key,
                cert_created_at: 1,
                cert_signature: cert.sign(&identity).to_vec(),
            },
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    RawDevice { id, api_key, tokens }
}

fn now() -> i64 {
    msg_server::now()
}

/// Requête signée (méthode, chemin, corps) avec un jeton et des en-têtes donnés.
async fn call(url: &str, method: &str, path: &str, body: &str, token: &str, h: SignedHeaders) -> reqwest::Response {
    let m = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
    let mut rb = reqwest::Client::new()
        .request(m, format!("{url}{path}"))
        .header(headers::DEVICE, h.device)
        .header(headers::TIMESTAMP, h.timestamp)
        .header(headers::NONCE, h.nonce)
        .header(headers::SIGNATURE, h.signature)
        .bearer_auth(token);
    if !body.is_empty() {
        rb = rb.header("content-type", "application/json").body(body.to_owned());
    }
    rb.send().await.unwrap()
}

fn sign(d: &RawDevice, method: &str, path: &str, body: &str) -> SignedHeaders {
    sign_request(&d.api_key, &d.id, method, path, body.as_bytes(), now()).unwrap()
}

/// Les réponses ne permettent pas de savoir si un compte existe.
#[tokio::test(flavor = "multi_thread")]
async fn no_account_enumeration() {
    let mut s = spawn().await;
    let admin = s.admin().await;
    let (_alice, _, _) = s.user(&admin, "alice").await;
    let http = reqwest::Client::new();
    let login = |user: &'static str| {
        let body = serde_json::json!({
            "username": user, "password": "mauvais-mot-de-passe-long", "totp_code": "000000",
            "device": { "device_id": Uuid::nil(), "identity_key": "", "api_key": "", "mls_signature_key": "",
                        "cert_created_at": 0, "cert_signature": "" }
        });
        http.post(format!("{}/v1/auth/login", s.url)).json(&body).send()
    };
    let known = login("alice").await.unwrap();
    let unknown = login("personne").await.unwrap();
    assert_eq!(known.status(), unknown.status());
    assert_eq!(known.text().await.unwrap(), unknown.text().await.unwrap(), "même message d'erreur");

    let activate = |user: &'static str| {
        let body = serde_json::json!({ "username": user, "activation_code": "AAAA-BBBB-CCCC", "new_password": "motdepasse-tres-long" });
        http.post(format!("{}/v1/auth/activate", s.url)).json(&body).send()
    };
    let known = activate("alice").await.unwrap();
    let unknown = activate("personne").await.unwrap();
    assert_eq!(known.status(), unknown.status());
    assert_eq!(known.text().await.unwrap(), unknown.text().await.unwrap());

    // Annuaire : un compte inexistant et un compte non activé sont indiscernables.
    let _ = admin.api().admin_create("enattente", msg_proto::Role::User).await.unwrap();
    let a = admin.api().directory("personne").await.err().map(|e| e.api_code());
    let b = admin.api().directory("enattente").await.err().map(|e| e.api_code());
    assert_eq!(a, b);
}

/// Jetons liés à l'appareil, signature liée à la requête, contrôle d'accès.
#[tokio::test(flavor = "multi_thread")]
async fn tokens_are_bound_to_devices_and_requests() {
    let mut s = spawn().await;
    let admin = s.admin().await;
    let mallory = raw_device(&s.url, &admin, "mallory").await;
    let victim = raw_device(&s.url, &admin, "victime").await;
    let url = s.url.clone();
    let ack = r#"{"ids":[]}"#;

    // Référence : requête légitime acceptée.
    let r = call(
        &url,
        "POST",
        "/v1/queue/ack",
        ack,
        &mallory.tokens.access_token,
        sign(&mallory, "POST", "/v1/queue/ack", ack),
    )
    .await;
    assert_eq!(r.status(), 204);

    // Jeton volé à la victime + signature de l'attaquant : refusé.
    let r = call(
        &url,
        "POST",
        "/v1/queue/ack",
        ack,
        &victim.tokens.access_token,
        sign(&mallory, "POST", "/v1/queue/ack", ack),
    )
    .await;
    assert_eq!(r.status(), 401, "jeton d'un autre appareil");

    // Signature valide pour une route, rejouée sur une autre : refusée.
    let h = sign(&mallory, "GET", "/v1/keypackages/count", "");
    let r = call(&url, "GET", "/v1/devices", "", &mallory.tokens.access_token, h).await;
    assert_eq!(r.status(), 401, "signature détournée vers une autre route");
    let h = sign(&mallory, "GET", "/v1/users/victime", "");
    let r = call(&url, "GET", "/v1/users/admin", "", &mallory.tokens.access_token, h).await;
    assert_eq!(r.status(), 401, "paramètre de chemin modifié");
    let h = sign(&mallory, "GET", "/v1/kt/audit?from=0&to=1", "");
    let r = call(&url, "GET", "/v1/kt/audit?from=0&to=2", "", &mallory.tokens.access_token, h).await;
    assert_eq!(r.status(), 401, "paramètre de requête modifié");
    let h = sign(&mallory, "GET", "/v1/devices", "");
    let r = call(&url, "DELETE", "/v1/devices", "", &mallory.tokens.access_token, h).await;
    assert!(r.status() == 401 || r.status() == 405, "méthode modifiée : {}", r.status());

    // Jeton seul (sans signature) ou signature seule (sans jeton) : refusés.
    let r = reqwest::Client::new()
        .get(format!("{url}/v1/devices"))
        .bearer_auth(&mallory.tokens.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    let r = call(&url, "GET", "/v1/devices", "", "jeton-invente", sign(&mallory, "GET", "/v1/devices", "")).await;
    assert_eq!(r.status(), 401);

    // Contrôle d'accès : routes d'administration interdites à un utilisateur.
    let r = call(
        &url,
        "GET",
        "/v1/admin/accounts",
        "",
        &mallory.tokens.access_token,
        sign(&mallory, "GET", "/v1/admin/accounts", ""),
    )
    .await;
    assert_eq!(r.status(), 403);
    let body = r#"{"status":"suspended"}"#;
    let path = "/v1/admin/accounts/victime/status";
    let r = call(&url, "PUT", path, body, &mallory.tokens.access_token, sign(&mallory, "PUT", path, body)).await;
    assert_eq!(r.status(), 403);
    // Révoquer l'appareil d'un autre compte : impossible (comme s'il n'existait pas).
    let path = format!("/v1/devices/{}", victim.id);
    let r = call(&url, "DELETE", &path, "", &mallory.tokens.access_token, sign(&mallory, "DELETE", &path, "")).await;
    assert_eq!(r.status(), 404);
    let r = call(&url, "GET", "/v1/devices", "", &victim.tokens.access_token, sign(&victim, "GET", "/v1/devices", ""))
        .await;
    assert_eq!(r.status(), 200, "l'appareil de la victime reste actif");

    // Renouvellement : jeton à usage unique, lié à l'appareil.
    let refresh = |d: &RawDevice, token: &str| {
        let body = serde_json::to_string(&RefreshRequest { device_id: d.id, refresh_token: token.into() }).unwrap();
        let h = sign(d, "POST", "/v1/auth/refresh", &body);
        let url = url.clone();
        async move {
            let r = reqwest::Client::new()
                .post(format!("{url}/v1/auth/refresh"))
                .header(headers::DEVICE, h.device)
                .header(headers::TIMESTAMP, h.timestamp)
                .header(headers::NONCE, h.nonce)
                .header(headers::SIGNATURE, h.signature)
                .header("content-type", "application/json")
                .body(body)
                .send()
                .await
                .unwrap();
            (r.status().as_u16(), r.json::<SessionTokens>().await.ok())
        }
    };
    let (st, _) = refresh(&mallory, &victim.tokens.refresh_token).await;
    assert_eq!(st, 401, "jeton de renouvellement d'un autre appareil");
    let (st, fresh) = refresh(&mallory, &mallory.tokens.refresh_token).await;
    assert_eq!(st, 200);
    let fresh = fresh.unwrap();
    let (st, _) = refresh(&mallory, &mallory.tokens.refresh_token).await;
    assert_eq!(st, 401, "jeton de renouvellement déjà utilisé");
    let r =
        call(&url, "GET", "/v1/devices", "", &mallory.tokens.access_token, sign(&mallory, "GET", "/v1/devices", ""))
            .await;
    assert_eq!(r.status(), 401, "ancien jeton d'accès invalidé par le renouvellement");

    // Déconnexion : jetons invalidés.
    let r =
        call(&url, "POST", "/v1/auth/logout", "", &fresh.access_token, sign(&mallory, "POST", "/v1/auth/logout", ""))
            .await;
    assert!(r.status().is_success());
    let r = call(&url, "GET", "/v1/devices", "", &fresh.access_token, sign(&mallory, "GET", "/v1/devices", "")).await;
    assert_eq!(r.status(), 401, "jeton après déconnexion");
    let (st, _) = refresh(&mallory, &fresh.refresh_token).await;
    assert_eq!(st, 401, "renouvellement après déconnexion");
}

/// En-têtes de sécurité, taille des requêtes, erreurs sans détail interne.
#[tokio::test(flavor = "multi_thread")]
async fn hardening_headers_and_limits() {
    let s = spawn().await;
    let http = reqwest::Client::new();
    let r = http.get(format!("{}/v1/health", s.url)).send().await.unwrap();
    let h = r.headers();
    assert!(h["content-security-policy"].to_str().unwrap().contains("default-src 'none'"));
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert_eq!(h["x-frame-options"], "DENY");
    assert_eq!(h["referrer-policy"], "no-referrer");
    assert_eq!(h["cache-control"], "no-store");
    assert!(h.get("server").is_none(), "pas d'en-tête Server");
    assert!(h.get("access-control-allow-origin").is_none(), "aucun CORS");

    // Corps de plus de 1 Mio refusé avant authentification.
    let big = "x".repeat(2 * 1024 * 1024);
    let r = http
        .post(format!("{}/v1/auth/login", s.url))
        .header("content-type", "application/json")
        .body(big)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 413);

    // JSON malformé : erreur générique, sans trace interne.
    let r = http
        .post(format!("{}/v1/auth/login", s.url))
        .header("content-type", "application/json")
        .body("{\"username\": [")
        .send()
        .await
        .unwrap();
    assert!(r.status().is_client_error());
    let text = r.text().await.unwrap();
    for leak in ["src/", ".rs", "panicked", "sqlx", "stack"] {
        assert!(!text.contains(leak), "détail interne dans l'erreur : {text}");
    }

    // Origine étrangère : aucune autorisation CORS accordée.
    let r = http
        .request(reqwest::Method::OPTIONS, format!("{}/v1/auth/login", s.url))
        .header("origin", "https://attaquant.example")
        .header("access-control-request-method", "POST")
        .send()
        .await
        .unwrap();
    assert!(r.headers().get("access-control-allow-origin").is_none());
}
