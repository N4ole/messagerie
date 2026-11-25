//! Transport Tor embarqué pour le client desktop.
//!
//! - [`TorRuntime::start`] démarre **arti** (Tor en Rust) dans le processus,
//!   sans programme externe, et attend la fin de son amorçage.
//! - Un proxy SOCKS5 local ([`SocksProxy`]) relaie chaque connexion du client
//!   (HTTP et WebSocket) à travers Tor. Il n'écoute que sur `127.0.0.1` et
//!   exige un identifiant et un mot de passe aléatoires (RFC 1929), pour
//!   qu'aucun autre programme local ne puisse s'en servir.
//! - **Mode strict** : le client n'est configuré qu'avec ce proxy ; si Tor
//!   est indisponible, les connexions échouent. Aucun transport direct n'est
//!   jamais instancié, il n'existe donc pas de repli en clair.
//!
//! Les noms sont résolus par Tor (`socks5h`) : aucune requête DNS locale.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum TorError {
    #[error("Tor indisponible : {0}")]
    Bootstrap(String),
    #[error("délai d'amorçage de Tor dépassé")]
    Timeout,
    #[error("proxy local : {0}")]
    Io(#[from] std::io::Error),
}

/// Délai maximal d'amorçage de Tor.
pub const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(120);

/// Proxy SOCKS5 local : adresse et identifiants (aléatoires, propres au processus).
#[derive(Clone)]
pub struct SocksProxy {
    pub addr: SocketAddr,
    pub username: String,
    pub password: Zeroizing<String>,
}

impl std::fmt::Debug for SocksProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocksProxy").field("addr", &self.addr).finish_non_exhaustive()
    }
}

/// Flux bidirectionnel relayé par le proxy.
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// Établit une connexion sortante vers `host:port` (Tor en production ;
/// connexion directe dans les tests du protocole SOCKS).
#[async_trait::async_trait]
pub trait Dialer: Send + Sync + 'static {
    async fn dial(&self, host: &str, port: u16) -> std::io::Result<Box<dyn Stream>>;
}

/// Tor en fonctionnement et son proxy local.
pub struct TorRuntime {
    proxy: SocksProxy,
    task: JoinHandle<()>,
}

impl Drop for TorRuntime {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TorRuntime {
    /// Démarre arti (état et cache dans les dossiers indiqués) et le proxy.
    pub async fn start(state_dir: &Path, cache_dir: &Path) -> Result<Self, TorError> {
        // arti s'appuie sur rustls : fournisseur cryptographique du processus
        // fixé explicitement (ring, comme le reste du client). Sans effet s'il
        // est déjà installé.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cfg = arti_client::config::TorClientConfigBuilder::from_directories(state_dir, cache_dir)
            .build()
            .map_err(|e| TorError::Bootstrap(e.to_string()))?;
        let client = tokio::time::timeout(BOOTSTRAP_TIMEOUT, arti_client::TorClient::create_bootstrapped(cfg))
            .await
            .map_err(|_| TorError::Timeout)?
            .map_err(|e| TorError::Bootstrap(e.to_string()))?;
        tracing::info!("Tor amorcé");
        Self::with_dialer(ArtiDialer(client)).await
    }

    /// Proxy relayant vers un `Dialer` quelconque.
    pub async fn with_dialer(dialer: impl Dialer) -> Result<Self, TorError> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let proxy = SocksProxy {
            addr: listener.local_addr()?,
            username: hex::encode(msg_crypto::random_bytes::<16>().map_err(|e| TorError::Bootstrap(e.to_string()))?),
            password: Zeroizing::new(hex::encode(
                msg_crypto::random_bytes::<32>().map_err(|e| TorError::Bootstrap(e.to_string()))?,
            )),
        };
        let p = proxy.clone();
        let dialer: Arc<dyn Dialer> = Arc::new(dialer);
        let task = tokio::spawn(async move {
            loop {
                let Ok((conn, _)) = listener.accept().await else { continue };
                let (p, d) = (p.clone(), dialer.clone());
                tokio::spawn(async move {
                    if let Err(e) = serve(conn, &p, d.as_ref()).await {
                        tracing::debug!(error = %e, "connexion SOCKS refusée");
                    }
                });
            }
        });
        Ok(Self { proxy, task })
    }

    pub fn proxy(&self) -> SocksProxy {
        self.proxy.clone()
    }
}

/// Adaptateur arti → `Dialer`.
struct ArtiDialer(Arc<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>);

#[async_trait::async_trait]
impl Dialer for ArtiDialer {
    async fn dial(&self, host: &str, port: u16) -> std::io::Result<Box<dyn Stream>> {
        let s = self.0.connect((host.to_owned(), port)).await.map_err(std::io::Error::other)?;
        Ok(Box::new(s))
    }
}

/// Sert une connexion SOCKS5 (méthode « nom d'utilisateur / mot de passe »
/// obligatoire, commande CONNECT uniquement).
async fn serve(mut c: TcpStream, p: &SocksProxy, dialer: &dyn Dialer) -> std::io::Result<()> {
    let bad = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, m.to_owned());
    // Salutation : VER, NMETHODS, METHODS.
    let mut h = [0u8; 2];
    c.read_exact(&mut h).await?;
    if h[0] != 5 {
        return Err(bad("version SOCKS"));
    }
    let mut methods = vec![0u8; h[1] as usize];
    c.read_exact(&mut methods).await?;
    if !methods.contains(&2) {
        c.write_all(&[5, 0xff]).await?;
        return Err(bad("authentification requise"));
    }
    c.write_all(&[5, 2]).await?;
    // RFC 1929 : VER=1, ULEN, UNAME, PLEN, PASSWD.
    let mut v = [0u8; 2];
    c.read_exact(&mut v).await?;
    let mut user = vec![0u8; v[1] as usize];
    c.read_exact(&mut user).await?;
    let mut pl = [0u8; 1];
    c.read_exact(&mut pl).await?;
    let mut pass = Zeroizing::new(vec![0u8; pl[0] as usize]);
    c.read_exact(&mut pass).await?;
    let ok = v[0] == 1
        && bool::from(user.as_slice().ct_eq(p.username.as_bytes()))
        && bool::from(pass.as_slice().ct_eq(p.password.as_bytes()));
    c.write_all(&[1, if ok { 0 } else { 1 }]).await?;
    if !ok {
        return Err(bad("identifiants SOCKS invalides"));
    }
    // Requête : VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT.
    let mut r = [0u8; 4];
    c.read_exact(&mut r).await?;
    if r[0] != 5 || r[1] != 1 {
        c.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        return Err(bad("seule la commande CONNECT est prise en charge"));
    }
    let host = match r[3] {
        1 => {
            let mut a = [0u8; 4];
            c.read_exact(&mut a).await?;
            std::net::Ipv4Addr::from(a).to_string()
        }
        3 => {
            let mut l = [0u8; 1];
            c.read_exact(&mut l).await?;
            let mut d = vec![0u8; l[0] as usize];
            c.read_exact(&mut d).await?;
            String::from_utf8(d).map_err(|_| bad("nom d'hôte"))?
        }
        4 => {
            let mut a = [0u8; 16];
            c.read_exact(&mut a).await?;
            std::net::Ipv6Addr::from(a).to_string()
        }
        _ => return Err(bad("type d'adresse")),
    };
    let mut port = [0u8; 2];
    c.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);
    let mut upstream = match dialer.dial(&host, port).await {
        Ok(s) => s,
        Err(e) => {
            // 0x05 : connexion refusée (aucun détail transmis).
            c.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            return Err(e);
        }
    };
    c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    tokio::io::copy_bidirectional(&mut c, &mut upstream).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Connexion directe : sert uniquement à tester le protocole du proxy.
    struct Direct;

    #[async_trait::async_trait]
    impl Dialer for Direct {
        async fn dial(&self, host: &str, port: u16) -> std::io::Result<Box<dyn Stream>> {
            Ok(Box::new(TcpStream::connect((host, port)).await?))
        }
    }

    async fn echo_server() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        a
    }

    async fn handshake(p: &SocksProxy, user: &str, pass: &str, host: &str, port: u16) -> (TcpStream, u8, u8) {
        let mut c = TcpStream::connect(p.addr).await.unwrap();
        c.write_all(&[5, 1, 2]).await.unwrap();
        let mut m = [0u8; 2];
        c.read_exact(&mut m).await.unwrap();
        assert_eq!(m, [5, 2]);
        let mut auth = vec![1, user.len() as u8];
        auth.extend_from_slice(user.as_bytes());
        auth.push(pass.len() as u8);
        auth.extend_from_slice(pass.as_bytes());
        c.write_all(&auth).await.unwrap();
        let mut a = [0u8; 2];
        c.read_exact(&mut a).await.unwrap();
        if a[1] != 0 {
            return (c, a[1], 0xff);
        }
        let mut req = vec![5, 1, 0, 3, host.len() as u8];
        req.extend_from_slice(host.as_bytes());
        req.extend_from_slice(&port.to_be_bytes());
        c.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        c.read_exact(&mut rep).await.unwrap();
        (c, 0, rep[1])
    }

    #[tokio::test]
    async fn relays_only_with_the_right_credentials() {
        let echo = echo_server().await;
        let rt = TorRuntime::with_dialer(Direct).await.unwrap();
        let p = rt.proxy();
        assert!(p.addr.ip().is_loopback(), "écoute locale uniquement");

        // Bons identifiants : relais transparent (nom résolu par le dialer).
        let (mut c, auth, rep) = handshake(&p, &p.username, &p.password, "127.0.0.1", echo.port()).await;
        assert_eq!((auth, rep), (0, 0));
        c.write_all(b"ping").await.unwrap();
        let mut b = [0u8; 4];
        c.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"ping");

        // Mauvais mot de passe : refus avant toute connexion sortante.
        let (_, auth, _) = handshake(&p, &p.username, "faux", "127.0.0.1", echo.port()).await;
        assert_eq!(auth, 1);

        // Sans authentification proposée : refusé.
        let mut c = TcpStream::connect(p.addr).await.unwrap();
        c.write_all(&[5, 1, 0]).await.unwrap();
        let mut m = [0u8; 2];
        c.read_exact(&mut m).await.unwrap();
        assert_eq!(m, [5, 0xff]);

        // Destination injoignable : erreur SOCKS, rien d'autre.
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
        let (_, auth, rep) = handshake(&p, &p.username, &p.password, "127.0.0.1", closed).await;
        assert_eq!((auth, rep), (0, 5));
    }

    /// Amorçage réel sur le réseau Tor (manuel : `cargo test -p msg-tor -- --ignored`).
    #[tokio::test]
    #[ignore = "nécessite un accès au réseau Tor"]
    async fn bootstraps_real_tor() {
        let d = std::env::temp_dir().join(format!("msg-tor-test-{}", std::process::id()));
        let rt = TorRuntime::start(&d.join("state"), &d.join("cache")).await.unwrap();
        assert!(rt.proxy().addr.ip().is_loopback());
    }
}
