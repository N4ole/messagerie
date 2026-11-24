//! Passkeys / clés de sécurité FIDO2 (YubiKey) côté client.
//!
//! L'application de bureau parle directement à l'authentificateur (API
//! native Windows `webauthn.dll`, voir `msg-platform-win`) : c'est donc elle
//! qui construit le `clientDataJSON` que le navigateur construirait
//! d'ordinaire. Deux garde-fous remplacent ceux du navigateur :
//!
//! - l'**origine** est déduite de l'URL du serveur configuré (jamais fournie
//!   par le serveur) ;
//! - l'**identifiant de partie de confiance** (`rpId`) demandé par le serveur
//!   doit être le domaine du serveur ou un de ses suffixes : un serveur
//!   malveillant ne peut pas utiliser l'application pour obtenir une
//!   signature destinée à un autre site.

use std::sync::Arc;

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use msg_proto::{WebauthnAssertion, WebauthnCredentialSummary, WebauthnRegisterFinish};
use serde_json::{json, Value};
use url::Url;

use crate::client::{Client, ClientConfig};
use crate::error::{ClientError, Result};

pub struct MakeCredentialRequest {
    pub rp_id: String,
    pub rp_name: String,
    pub user_id: Vec<u8>,
    pub user_name: String,
    pub user_display_name: String,
    pub client_data_json: Vec<u8>,
    /// Algorithmes COSE acceptés par le serveur (ex. -7 = ES256).
    pub algorithms: Vec<i64>,
    pub exclude_credentials: Vec<Vec<u8>>,
    pub require_resident_key: bool,
    pub user_verification: String,
    pub timeout_ms: u32,
}

pub struct MakeCredentialResponse {
    pub credential_id: Vec<u8>,
    pub attestation_object: Vec<u8>,
}

pub struct GetAssertionRequest {
    pub rp_id: String,
    pub client_data_json: Vec<u8>,
    pub allow_credentials: Vec<Vec<u8>>,
    pub user_verification: String,
    pub timeout_ms: u32,
}

pub struct GetAssertionResponse {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Option<Vec<u8>>,
}

/// Authentificateur FIDO2 « brut » (appels bloquants, avec interface
/// système éventuelle : code PIN, contact sur la clé…).
pub trait RawAuthenticator: Send + Sync {
    fn make_credential(&self, req: &MakeCredentialRequest) -> Result<MakeCredentialResponse>;
    fn get_assertion(&self, req: &GetAssertionRequest) -> Result<GetAssertionResponse>;
}

fn b64url(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

/// Décode le Base64 (URL ou standard, avec ou sans remplissage).
fn b64_any(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| URL_SAFE.decode(s))
        .or_else(|_| STANDARD.decode(s))
        .or_else(|_| STANDARD_NO_PAD.decode(s))
        .map_err(|_| ClientError::Invalid("Base64 invalide dans le défi WebAuthn".into()))
}

fn field<'a>(v: &'a Value, path: &[&str]) -> Result<&'a Value> {
    let mut cur = v;
    for p in path {
        cur = cur.get(*p).ok_or_else(|| ClientError::Invalid(format!("défi WebAuthn incomplet ({p})")))?;
    }
    Ok(cur)
}

fn str_field(v: &Value, path: &[&str]) -> Result<String> {
    field(v, path)?.as_str().map(str::to_owned).ok_or_else(|| ClientError::Invalid("défi WebAuthn invalide".into()))
}

fn cred_ids(list: Option<&Value>) -> Result<Vec<Vec<u8>>> {
    match list.and_then(Value::as_array) {
        None => Ok(Vec::new()),
        Some(a) => a.iter().map(|c| b64_any(c.get("id").and_then(Value::as_str).unwrap_or_default())).collect(),
    }
}

/// Origine attendue et contrôle du `rpId` par rapport au serveur configuré.
pub fn check_rp(server: &Url, rp_id: &str) -> Result<String> {
    let host = server.host_str().ok_or_else(|| ClientError::Invalid("URL de serveur sans hôte".into()))?;
    let rp_id = rp_id.to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    if rp_id.is_empty() || !(host == rp_id || host.ends_with(&format!(".{rp_id}"))) {
        return Err(ClientError::Verification(
            rp_id,
            "identifiant de partie de confiance étranger au serveur configuré : refusé".into(),
        ));
    }
    Ok(server.origin().ascii_serialization())
}

fn client_data(kind: &str, challenge_b64: &str, origin: &str) -> Result<Vec<u8>> {
    // Le défi est réencodé en Base64URL sans remplissage, comme un navigateur.
    let challenge = b64url(&b64_any(challenge_b64)?);
    Ok(serde_json::to_vec(&json!({ "type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false }))
        .expect("JSON valide"))
}

/// Exécute une cérémonie d'enregistrement et produit le
/// `RegisterPublicKeyCredential` JSON attendu par le serveur.
pub fn create_credential(server: &Url, options: &Value, auth: &dyn RawAuthenticator) -> Result<Value> {
    let pk = field(options, &["publicKey"])?;
    let rp_id = str_field(pk, &["rp", "id"])?;
    let origin = check_rp(server, &rp_id)?;
    let cdj = client_data("webauthn.create", &str_field(pk, &["challenge"])?, &origin)?;
    let algorithms = pk
        .get("pubKeyCredParams")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|p| p.get("alg").and_then(Value::as_i64)).collect())
        .unwrap_or_else(|| vec![-7]);
    let sel = pk.get("authenticatorSelection");
    let req = MakeCredentialRequest {
        rp_name: pk.get("rp").and_then(|r| r.get("name")).and_then(Value::as_str).unwrap_or(&rp_id).to_owned(),
        rp_id,
        user_id: b64_any(&str_field(pk, &["user", "id"])?)?,
        user_name: str_field(pk, &["user", "name"])?,
        user_display_name: str_field(pk, &["user", "displayName"])?,
        client_data_json: cdj.clone(),
        algorithms,
        exclude_credentials: cred_ids(pk.get("excludeCredentials"))?,
        require_resident_key: sel.and_then(|s| s.get("requireResidentKey")).and_then(Value::as_bool).unwrap_or(false),
        user_verification: sel
            .and_then(|s| s.get("userVerification"))
            .and_then(Value::as_str)
            .unwrap_or("preferred")
            .to_owned(),
        timeout_ms: pk.get("timeout").and_then(Value::as_u64).unwrap_or(120_000).min(600_000) as u32,
    };
    let r = auth.make_credential(&req)?;
    Ok(json!({
        "id": b64url(&r.credential_id),
        "rawId": b64url(&r.credential_id),
        "type": "public-key",
        "response": {
            "attestationObject": b64url(&r.attestation_object),
            "clientDataJSON": b64url(&cdj),
        },
        "extensions": {},
    }))
}

/// Exécute une cérémonie d'authentification et produit le
/// `PublicKeyCredential` JSON attendu par le serveur.
pub fn get_assertion(server: &Url, options: &Value, auth: &dyn RawAuthenticator) -> Result<Value> {
    let pk = field(options, &["publicKey"])?;
    let rp_id = str_field(pk, &["rpId"])?;
    let origin = check_rp(server, &rp_id)?;
    let cdj = client_data("webauthn.get", &str_field(pk, &["challenge"])?, &origin)?;
    let req = GetAssertionRequest {
        rp_id,
        client_data_json: cdj.clone(),
        allow_credentials: cred_ids(pk.get("allowCredentials"))?,
        user_verification: pk.get("userVerification").and_then(Value::as_str).unwrap_or("preferred").to_owned(),
        timeout_ms: pk.get("timeout").and_then(Value::as_u64).unwrap_or(120_000).min(600_000) as u32,
    };
    let r = auth.get_assertion(&req)?;
    Ok(json!({
        "id": b64url(&r.credential_id),
        "rawId": b64url(&r.credential_id),
        "type": "public-key",
        "response": {
            "authenticatorData": b64url(&r.authenticator_data),
            "clientDataJSON": b64url(&cdj),
            "signature": b64url(&r.signature),
            "userHandle": r.user_handle.as_deref().map(b64url),
        },
        "extensions": {},
    }))
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f).await.map_err(|e| ClientError::Invalid(format!("authentificateur : {e}")))?
}

impl Client {
    /// Enregistre une nouvelle passkey / clé de sécurité pour ce compte.
    pub async fn register_passkey(
        &self,
        name: &str,
        auth: Arc<dyn RawAuthenticator>,
    ) -> Result<WebauthnCredentialSummary> {
        let challenge = self.api.webauthn_register_start().await?;
        let server = self.api.base().clone();
        let options = challenge.options.clone();
        let credential = blocking(move || create_credential(&server, &options, auth.as_ref())).await?;
        let r = self
            .api
            .webauthn_register_finish(&WebauthnRegisterFinish {
                challenge_id: challenge.challenge_id,
                name: name.into(),
                credential,
            })
            .await?;
        self.persist_tokens()?;
        Ok(r)
    }

    pub async fn passkeys(&self) -> Result<Vec<WebauthnCredentialSummary>> {
        self.api.webauthn_list().await
    }

    pub async fn delete_passkey(&self, id: i64) -> Result<()> {
        self.api.webauthn_delete(id).await
    }

    /// Connexion avec mot de passe + passkey / clé de sécurité (à la place du TOTP).
    pub async fn login_with_passkey(
        cfg: &ClientConfig,
        username: &str,
        password: &str,
        auth: Arc<dyn RawAuthenticator>,
    ) -> Result<Self> {
        let client = Self::open_local(cfg, username, password)?;
        let challenge = client.api.webauthn_login_challenge(username, password).await?;
        let server = client.api.base().clone();
        let options = challenge.options.clone();
        let credential = blocking(move || get_assertion(&server, &options, auth.as_ref())).await?;
        let tokens = client
            .api
            .login(&msg_proto::LoginRequest {
                username: username.into(),
                password: password.into(),
                totp_code: String::new(),
                webauthn: Some(WebauthnAssertion { challenge_id: challenge.challenge_id, credential }),
                device: client.registration()?,
            })
            .await?;
        client.save_session(&tokens)?;
        client.ensure_key_packages().await?;
        Ok(client)
    }
}

/// Authentificateur logiciel (ES256) **réservé aux tests** : il implémente
/// le format CTAP2/WebAuthn « none » pour éprouver la chaîne complète
/// (client ↔ serveur `webauthn-rs`) sans matériel.
#[cfg(any(test, feature = "soft-authenticator"))]
pub mod soft {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use ciborium::value::Value as Cbor;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{DerSignature, SigningKey};
    use sha2::{Digest, Sha256};

    use super::*;

    struct Cred {
        key: SigningKey,
        rp_id: String,
        user_handle: Vec<u8>,
        counter: u32,
    }

    #[derive(Default)]
    pub struct SoftAuthenticator {
        creds: Mutex<HashMap<Vec<u8>, Cred>>,
    }

    fn cbor(v: &Cbor) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(v, &mut out).expect("CBOR");
        out
    }

    impl RawAuthenticator for SoftAuthenticator {
        fn make_credential(&self, req: &MakeCredentialRequest) -> Result<MakeCredentialResponse> {
            if !req.algorithms.contains(&-7) {
                return Err(ClientError::Invalid("ES256 non proposé".into()));
            }
            let key = loop {
                if let Ok(k) = SigningKey::from_slice(&msg_crypto::random_bytes::<32>()?) {
                    break k;
                }
            };
            let cred_id = msg_crypto::random_bytes::<16>()?.to_vec();
            let point = key.verifying_key().to_encoded_point(false);
            let cose = Cbor::Map(vec![
                (Cbor::Integer(1.into()), Cbor::Integer(2.into())),
                (Cbor::Integer(3.into()), Cbor::Integer((-7).into())),
                (Cbor::Integer((-1).into()), Cbor::Integer(1.into())),
                (Cbor::Integer((-2).into()), Cbor::Bytes(point.x().expect("x").to_vec())),
                (Cbor::Integer((-3).into()), Cbor::Bytes(point.y().expect("y").to_vec())),
            ]);
            let mut auth_data = Sha256::digest(req.rp_id.as_bytes()).to_vec();
            auth_data.push(0x45); // UP | UV | AT
            auth_data.extend_from_slice(&0u32.to_be_bytes());
            auth_data.extend_from_slice(&[0u8; 16]); // AAGUID
            auth_data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
            auth_data.extend_from_slice(&cred_id);
            auth_data.extend_from_slice(&cbor(&cose));
            let att = Cbor::Map(vec![
                (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
                (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
                (Cbor::Text("authData".into()), Cbor::Bytes(auth_data)),
            ]);
            self.creds.lock().unwrap().insert(
                cred_id.clone(),
                Cred { key, rp_id: req.rp_id.clone(), user_handle: req.user_id.clone(), counter: 0 },
            );
            Ok(MakeCredentialResponse { credential_id: cred_id, attestation_object: cbor(&att) })
        }

        fn get_assertion(&self, req: &GetAssertionRequest) -> Result<GetAssertionResponse> {
            let mut creds = self.creds.lock().unwrap();
            let id = req
                .allow_credentials
                .iter()
                .find(|id| creds.get(*id).is_some_and(|c| c.rp_id == req.rp_id))
                .cloned()
                .ok_or_else(|| ClientError::Invalid("aucune clé correspondante".into()))?;
            let c = creds.get_mut(&id).expect("présente");
            c.counter += 1;
            let mut auth_data = Sha256::digest(req.rp_id.as_bytes()).to_vec();
            auth_data.push(0x05); // UP | UV
            auth_data.extend_from_slice(&c.counter.to_be_bytes());
            let mut signed = auth_data.clone();
            signed.extend_from_slice(&Sha256::digest(&req.client_data_json));
            let sig: DerSignature = c.key.sign(&signed);
            Ok(GetAssertionResponse {
                credential_id: id,
                authenticator_data: auth_data,
                signature: sig.as_bytes().to_vec(),
                user_handle: Some(c.user_handle.clone()),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rp_id_is_pinned_to_server() {
        let u = Url::parse("https://chat.exemple.org:8443").unwrap();
        assert_eq!(check_rp(&u, "chat.exemple.org").unwrap(), "https://chat.exemple.org:8443");
        assert!(check_rp(&u, "exemple.org").is_ok());
        assert!(check_rp(&u, "google.com").is_err());
        assert!(check_rp(&u, "evil-exemple.org").is_err());
        assert!(check_rp(&u, "").is_err());
    }

    #[test]
    fn foreign_rp_challenge_is_refused_before_touching_authenticator() {
        let auth = soft::SoftAuthenticator::default();
        let opts = json!({"publicKey": {"rpId": "banque.example", "challenge": "AAAA", "allowCredentials": []}});
        let u = Url::parse("https://chat.exemple.org").unwrap();
        assert!(matches!(get_assertion(&u, &opts, &auth), Err(ClientError::Verification(..))));
    }
}
