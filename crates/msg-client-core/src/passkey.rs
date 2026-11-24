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

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use msg_proto::webauthn::{
    AuthenticationExtensionsClientOutputs, AuthenticatorAssertionResponseRaw, AuthenticatorAttestationResponseRaw,
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential, RegistrationExtensionsClientOutputs,
    RequestChallengeResponse, UserVerificationPolicy,
};
use msg_proto::{WebauthnAssertion, WebauthnCredentialSummary, WebauthnRegisterFinish};
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

fn uv(p: &UserVerificationPolicy) -> String {
    match p {
        UserVerificationPolicy::Required => "required",
        UserVerificationPolicy::Preferred => "preferred",
        UserVerificationPolicy::Discouraged_DO_NOT_USE => "discouraged",
    }
    .into()
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

/// `clientDataJSON` tel qu'un navigateur le construirait (WebAuthn §5.8.1).
fn client_data(kind: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct ClientData<'a> {
        #[serde(rename = "type")]
        kind: &'a str,
        challenge: String,
        origin: &'a str,
        #[serde(rename = "crossOrigin")]
        cross_origin: bool,
    }
    serde_json::to_vec(&ClientData { kind, challenge: b64url(challenge), origin, cross_origin: false })
        .expect("sérialisation infaillible")
}

const DEFAULT_TIMEOUT_MS: u32 = 120_000;
const MAX_TIMEOUT_MS: u32 = 600_000;

/// Exécute une cérémonie d'enregistrement.
pub fn create_credential(
    server: &Url,
    options: &CreationChallengeResponse,
    auth: &dyn RawAuthenticator,
) -> Result<RegisterPublicKeyCredential> {
    let pk = &options.public_key;
    let origin = check_rp(server, &pk.rp.id)?;
    let cdj = client_data("webauthn.create", &pk.challenge, &origin);
    let sel = pk.authenticator_selection.as_ref();
    let req = MakeCredentialRequest {
        rp_id: pk.rp.id.clone(),
        rp_name: pk.rp.name.clone(),
        user_id: pk.user.id.clone(),
        user_name: pk.user.name.clone(),
        user_display_name: pk.user.display_name.clone(),
        client_data_json: cdj.clone(),
        algorithms: pk.pub_key_cred_params.iter().map(|p| p.alg).collect(),
        exclude_credentials: pk.exclude_credentials.iter().flatten().map(|c| c.id.clone()).collect(),
        require_resident_key: sel.is_some_and(|s| s.require_resident_key),
        user_verification: sel.map(|s| uv(&s.user_verification)).unwrap_or_else(|| "preferred".into()),
        timeout_ms: pk.timeout.unwrap_or(DEFAULT_TIMEOUT_MS).min(MAX_TIMEOUT_MS),
    };
    let r = auth.make_credential(&req)?;
    Ok(RegisterPublicKeyCredential {
        id: b64url(&r.credential_id),
        raw_id: r.credential_id,
        response: AuthenticatorAttestationResponseRaw {
            attestation_object: r.attestation_object,
            client_data_json: cdj,
            transports: None,
        },
        type_: "public-key".into(),
        extensions: RegistrationExtensionsClientOutputs::default(),
    })
}

/// Exécute une cérémonie d'authentification.
pub fn get_assertion(
    server: &Url,
    options: &RequestChallengeResponse,
    auth: &dyn RawAuthenticator,
) -> Result<PublicKeyCredential> {
    let pk = &options.public_key;
    let origin = check_rp(server, &pk.rp_id)?;
    let cdj = client_data("webauthn.get", &pk.challenge, &origin);
    let req = GetAssertionRequest {
        rp_id: pk.rp_id.clone(),
        client_data_json: cdj.clone(),
        allow_credentials: pk.allow_credentials.iter().map(|c| c.id.clone()).collect(),
        user_verification: uv(&pk.user_verification),
        timeout_ms: pk.timeout.unwrap_or(DEFAULT_TIMEOUT_MS).min(MAX_TIMEOUT_MS),
    };
    let r = auth.get_assertion(&req)?;
    Ok(PublicKeyCredential {
        id: b64url(&r.credential_id),
        raw_id: r.credential_id,
        response: AuthenticatorAssertionResponseRaw {
            authenticator_data: r.authenticator_data,
            client_data_json: cdj,
            signature: r.signature,
            user_handle: r.user_handle,
        },
        extensions: AuthenticationExtensionsClientOutputs::default(),
        type_: "public-key".into(),
    })
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
    use msg_proto::webauthn::{AllowCredentials, PublicKeyCredentialRequestOptions};

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
        let opts = RequestChallengeResponse {
            public_key: PublicKeyCredentialRequestOptions {
                challenge: vec![0; 32],
                timeout: None,
                rp_id: "banque.example".into(),
                allow_credentials: vec![AllowCredentials {
                    type_: "public-key".into(),
                    id: vec![1; 16],
                    transports: None,
                }],
                user_verification: UserVerificationPolicy::Required,
                hints: None,
                extensions: None,
            },
            mediation: None,
        };
        let u = Url::parse("https://chat.exemple.org").unwrap();
        assert!(matches!(get_assertion(&u, &opts, &auth), Err(ClientError::Verification(..))));
    }

    #[test]
    fn client_data_matches_webauthn_format() {
        let cdj = client_data("webauthn.get", &[0xfb, 0xff], "https://chat.exemple.org");
        assert_eq!(
            std::str::from_utf8(&cdj).unwrap(),
            r#"{"type":"webauthn.get","challenge":"-_8","origin":"https://chat.exemple.org","crossOrigin":false}"#
        );
    }
}
