//! Outillage des tests d'intégration : un serveur réel sur une base
//! PostgreSQL éphémère (DATABASE_URL), des clients réels.
#![allow(dead_code)]

use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};

use msg_client_core::{Client, ClientConfig};
use msg_crypto::keywrap::Argon2Params;
use msg_proto::Role;
use msg_server::{config::Config, router, AppState};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use totp_rs::{Algorithm, Secret, TOTP};

/// Mot de passe des comptes de test, aléatoire à chaque exécution.
pub fn password() -> &'static str {
    static PW: OnceLock<String> = OnceLock::new();
    PW.get_or_init(|| hex::encode(msg_crypto::random_bytes::<16>().unwrap()))
}

/// Autre mot de passe aléatoire (forcément différent de [`password`]).
pub fn wrong_password() -> String {
    hex::encode(msg_crypto::random_bytes::<16>().unwrap())
}

/// Journaux du serveur capturés (tous niveaux) pour vérifier l'absence de clair.
pub fn logs() -> &'static Arc<Mutex<Vec<u8>>> {
    static LOGS: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    LOGS.get_or_init(|| {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let b2 = buf.clone();
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || LogWriter(b2.clone()))
            .try_init();
        buf
    })
}

struct LogWriter(Arc<Mutex<Vec<u8>>>);
impl Write for LogWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub struct TestServer {
    pub url: String,
    pub pool: PgPool,
    pub dirs: Vec<tempfile::TempDir>,
}

pub async fn spawn() -> TestServer {
    spawn_with(false).await
}

/// Serveur avec WebAuthn activé (origine `http://localhost:<port>`).
pub async fn spawn_webauthn() -> TestServer {
    spawn_with(true).await
}

async fn spawn_with(webauthn: bool) -> TestServer {
    logs();
    let base = std::env::var("DATABASE_URL").expect(
        "DATABASE_URL doit pointer vers un PostgreSQL de test (ex. postgres://postgres@127.0.0.1:5433/postgres)",
    );
    let admin = PgPoolOptions::new().max_connections(2).connect(&base).await.expect("connexion PostgreSQL");
    let name = format!("msgtest_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}"))).execute(&admin).await.unwrap();
    let mut url = url::Url::parse(&base).unwrap();
    url.set_path(&name);
    let pool = PgPoolOptions::new().max_connections(10).connect(url.as_str()).await.unwrap();
    msg_server::migrate(&pool).await.unwrap();
    let mut cfg = Config::with_secret("test".into(), msg_crypto::random_bytes::<32>().unwrap());
    cfg.argon2_m_kib = 64;
    cfg.argon2_t = 1;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = if webauthn { format!("http://localhost:{}", addr.port()) } else { format!("http://{addr}") };
    if webauthn {
        cfg.webauthn = Some(msg_server::config::WebauthnConfig { rp_id: "localhost".into(), origin: url.clone() });
    }
    let app = router(AppState::try_new(pool.clone(), cfg).expect("configuration"));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    TestServer { url, pool, dirs: Vec::new() }
}

pub fn totp_code(base32: &str, offset_steps: i64) -> String {
    let secret = Secret::Encoded(base32.into()).to_bytes().unwrap();
    let t = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret, None, "x".into()).unwrap();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    t.generate((now + offset_steps * 30) as u64)
}

impl TestServer {
    pub fn config(&mut self) -> ClientConfig {
        let d = tempfile::tempdir().unwrap();
        let mut c = ClientConfig::new(self.url.clone(), d.path());
        c.argon2 = Argon2Params::INSECURE_FOR_TESTS;
        self.dirs.push(d);
        c
    }

    /// Active un compte (code admin) et enrôle un appareil. Retourne le
    /// client, sa configuration et le secret TOTP (base32).
    pub async fn enroll(&mut self, username: &str, code: &str) -> (Client, ClientConfig, String) {
        let cfg = self.config();
        let act = Client::activate(&cfg, username, code, password()).await.unwrap();
        let c = Client::enroll(&cfg, username, password(), &totp_code(&act.totp_secret_base32, 0)).await.unwrap();
        (c, cfg, act.totp_secret_base32)
    }

    pub async fn admin(&mut self) -> Client {
        let r = msg_server::routes::admin::bootstrap_admin(&self.pool, "admin", 3600).await.unwrap();
        self.enroll("admin", &r.activation_code).await.0
    }

    pub async fn user(&mut self, admin: &Client, username: &str) -> (Client, ClientConfig, String) {
        let r = admin.api().admin_create(username, Role::User).await.unwrap();
        self.enroll(username, &r.activation_code).await
    }

    /// Contenu textuel intégral de toutes les tables (bytea en hexadécimal).
    pub async fn dump(&self) -> String {
        let tables: Vec<(String,)> =
            sqlx::query_as("SELECT table_name::text FROM information_schema.tables WHERE table_schema = 'public'")
                .fetch_all(&self.pool)
                .await
                .unwrap();
        let mut out = String::new();
        for (t,) in tables {
            let rows: Vec<(String,)> =
                sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT row_to_json(x)::text FROM \"{t}\" x")))
                    .fetch_all(&self.pool)
                    .await
                    .unwrap();
            for (r,) in rows {
                out.push_str(&r);
                out.push('\n');
            }
        }
        out
    }
}
