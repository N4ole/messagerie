//! Réseau du client desktop : mode Tor (strict) et épinglage TLS.
//!
//! - **Tor** : toutes les connexions (HTTP et WebSocket) passent par le proxy
//!   SOCKS5 local d'arti (`msg-tor`), noms résolus par Tor. Le client HTTP
//!   n'a aucun autre itinéraire (proxys système ignorés) : si Tor est
//!   indisponible, la requête échoue, sans repli en clair.
//! - **Épinglage** : en plus de la validation habituelle (autorités de
//!   certification, nom), la clé publique (SPKI) du certificat du serveur doit
//!   avoir l'une des empreintes SHA-256 configurées. Pour une adresse
//!   `.onion` (déjà authentifiée par Tor), un certificat auto-signé est
//!   accepté **si et seulement si** sa clé est épinglée.

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use crate::error::{ClientError, Result};

/// Proxy SOCKS5 local de Tor (fourni par `msg-tor`).
#[derive(Clone)]
pub struct TorProxy {
    pub addr: SocketAddr,
    pub username: String,
    pub password: Zeroizing<String>,
}

/// Itinéraire réseau du client.
#[derive(Clone, Default)]
pub enum Network {
    /// Connexion directe (HTTPS).
    #[default]
    Direct,
    /// Tout passe par Tor ; aucune connexion directe possible.
    TorStrict(TorProxy),
}

/// Empreinte d'épinglage : SHA-256 de la clé publique (SPKI DER) du
/// certificat du serveur, en hexadécimal.
pub fn spki_sha256(cert_der: &[u8]) -> Result<[u8; 32]> {
    use x509_cert::der::{Decode, Encode};
    let cert = x509_cert::Certificate::from_der(cert_der).map_err(|e| ClientError::Invalid(e.to_string()))?;
    let spki =
        cert.tbs_certificate().subject_public_key_info().to_der().map_err(|e| ClientError::Invalid(e.to_string()))?;
    Ok(msg_crypto::sha256(&spki))
}

#[derive(Debug)]
struct PinningVerifier {
    webpki: Arc<rustls::client::WebPkiServerVerifier>,
    pins: Vec<[u8; 32]>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

fn is_onion(name: &ServerName<'_>) -> bool {
    matches!(name, ServerName::DnsName(d) if d.as_ref().ends_with(".onion"))
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let pin = spki_sha256(end_entity)
            .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
        if !self.pins.contains(&pin) {
            return Err(rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure));
        }
        if is_onion(server_name) {
            // Service onion : l'adresse authentifie le service ; la clé épinglée suffit.
            return Ok(ServerCertVerified::assertion());
        }
        self.webpki.verify_server_cert(end_entity, intermediates, server_name, ocsp, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

fn pinning_verifier(pins: &[[u8; 32]]) -> Result<Arc<PinningVerifier>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = Arc::new(rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() });
    let webpki = rustls::client::WebPkiServerVerifier::builder_with_provider(roots, provider.clone())
        .build()
        .map_err(|e| ClientError::Invalid(e.to_string()))?;
    Ok(Arc::new(PinningVerifier { webpki, pins: pins.to_vec(), provider }))
}

/// Configuration TLS épinglée (aucune si `pins` est vide : validation
/// standard du client HTTP).
pub(crate) fn pinned_tls(pins: &[[u8; 32]]) -> Result<Option<rustls::ClientConfig>> {
    if pins.is_empty() {
        return Ok(None);
    }
    let verifier = pinning_verifier(pins)?;
    let provider = verifier.provider.clone();
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| ClientError::Invalid(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(Some(cfg))
}

/// Ouvre un tunnel TCP vers `host:port` via le proxy SOCKS5 de Tor
/// (authentification RFC 1929, résolution du nom par Tor).
pub(crate) async fn socks_connect(p: &TorProxy, host: &str, port: u16) -> Result<TcpStream> {
    let net = |e: std::io::Error| ClientError::Network(format!("Tor : {e}"));
    let fail = |m: &str| ClientError::Network(format!("Tor : {m}"));
    if host.len() > 255 || p.username.len() > 255 || p.password.len() > 255 {
        return Err(fail("paramètres trop longs"));
    }
    let mut s = TcpStream::connect(p.addr).await.map_err(net)?;
    s.write_all(&[5, 1, 2]).await.map_err(net)?;
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.map_err(net)?;
    if m != [5, 2] {
        return Err(fail("proxy incompatible"));
    }
    let mut auth = Zeroizing::new(vec![1, p.username.len() as u8]);
    auth.extend_from_slice(p.username.as_bytes());
    auth.push(p.password.len() as u8);
    auth.extend_from_slice(p.password.as_bytes());
    s.write_all(&auth).await.map_err(net)?;
    let mut a = [0u8; 2];
    s.read_exact(&mut a).await.map_err(net)?;
    if a[1] != 0 {
        return Err(fail("authentification refusée"));
    }
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.map_err(net)?;
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.map_err(net)?;
    if rep[1] != 0 {
        return Err(fail("destination injoignable via Tor"));
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spki_pin_is_stable_and_key_specific() {
        // Certificats de test auto-signés (deux clés différentes).
        let a = include_bytes!("../tests/data/cert-a.der");
        let a2 = include_bytes!("../tests/data/cert-a-renewed.der");
        let b = include_bytes!("../tests/data/cert-b.der");
        let pa = spki_sha256(a).unwrap();
        // Renouvellement avec la même clé : même empreinte.
        assert_eq!(pa, spki_sha256(a2).unwrap());
        assert_ne!(pa, spki_sha256(b).unwrap());
        assert!(spki_sha256(b"pas un certificat").is_err());
    }

    fn verify(pins: &[[u8; 32]], host: &str, cert: &[u8]) -> bool {
        let v = pinning_verifier(pins).unwrap();
        let name = ServerName::try_from(host.to_owned()).unwrap();
        v.verify_server_cert(&CertificateDer::from(cert.to_vec()), &[], &name, &[], UnixTime::now()).is_ok()
    }

    #[test]
    fn pinning_rules() {
        let a = include_bytes!("../tests/data/cert-a.der");
        let b = include_bytes!("../tests/data/cert-b.der");
        let pin_a = spki_sha256(a).unwrap();
        assert!(pinned_tls(&[]).unwrap().is_none(), "sans épingle : validation standard");
        // Service onion : certificat auto-signé accepté seulement si sa clé est épinglée.
        assert!(verify(&[pin_a], "exemple.onion", a));
        assert!(!verify(&[pin_a], "exemple.onion", b));
        // Nom ordinaire : l'épingle ne dispense pas de la chaîne de certification.
        assert!(!verify(&[pin_a], "exemple.org", a));
    }
}
