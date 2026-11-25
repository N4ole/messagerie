//! Client natif (même cœur que l'application de bureau) piloté par le test
//! d'interopérabilité desktop ↔ web (`tests/interop`). Il lit une commande
//! JSON par ligne sur l'entrée standard et répond une ligne JSON.
//!
//! Variables : `MSG_URL` (serveur), `DATABASE_URL` (amorçage de
//! l'administrateur et vérification de l'absence de clair en base).

use std::io::BufRead;
use std::time::{Duration, Instant};

use msg_client_core::{Client, ClientConfig};
use msg_crypto::keywrap::Argon2Params;
use msg_proto::Role;
use serde_json::{json, Value};
use totp_rs::{Algorithm, Builder, Secret};

struct Peer {
    url: String,
    pool: sqlx::PgPool,
    _dir: tempfile::TempDir,
    cfg: ClientConfig,
    alice: Option<Client>,
    alice_totp: String,
    password: String,
}

fn totp_now(base32: &str) -> String {
    totp_at(base32, 0)
}

fn totp_at(base32: &str, offset_steps: i64) -> String {
    let t = Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_step_duration(30)
        .with_secret(Secret::try_from_base32(base32).expect("base32"))
        .build()
        .expect("totp");
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    t.generate((now + offset_steps * 30) as u64).to_string()
}

impl Peer {
    fn alice(&mut self) -> anyhow::Result<&mut Client> {
        self.alice.as_mut().ok_or_else(|| anyhow::anyhow!("setup d'abord"))
    }

    async fn run(&mut self, cmd: &Value) -> anyhow::Result<Value> {
        let s = |k: &str| cmd[k].as_str().unwrap_or_default().to_owned();
        match cmd["cmd"].as_str().unwrap_or_default() {
            // Administrateur, comptes « alice » (ce client natif) et « bob »
            // (activé dans le navigateur avec le code renvoyé).
            "setup" => {
                let r = msg_server::routes::admin::bootstrap_admin(&self.pool, "admin", 3600).await?;
                let admin = self.enroll("admin", &r.activation_code).await?.0;
                let a = admin.api().admin_create("alice", Role::User).await?;
                let b = admin.api().admin_create("bob", Role::User).await?;
                let (alice, secret) = self.enroll("alice", &a.activation_code).await?;
                self.alice = Some(alice);
                self.alice_totp = secret;
                Ok(json!({ "bob_code": b.activation_code, "password": self.password }))
            }
            "send" => {
                let to = s("to");
                let text = s("text");
                let c = self.alice()?;
                let conv = c.start_conversation(&to).await?;
                c.send_text(&conv.id, &text).await?;
                Ok(json!({ "conversation": conv.id }))
            }
            // Attend un message entrant contenant `text` (30 s au plus).
            "wait" => {
                let text = s("text");
                let deadline = Instant::now() + Duration::from_secs(30);
                loop {
                    let c = self.alice()?;
                    c.sync().await?;
                    for conv in c.conversations()? {
                        if c.messages(&conv.id, 200)?.iter().any(|m| !m.outgoing && m.text.contains(&text)) {
                            return Ok(json!({ "found": true }));
                        }
                    }
                    if Instant::now() > deadline {
                        return Ok(json!({ "found": false }));
                    }
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
            }
            "totp" => Ok(json!({ "code": totp_at(&self.alice_totp, cmd["offset"].as_i64().unwrap_or(0)) })),
            "approve" => {
                let code = s("code");
                let c = self.alice()?;
                c.approve_link(&code).await?;
                Ok(json!({ "approved": true }))
            }
            "reconcile" => {
                let n = self.alice()?.reconcile_now().await?;
                Ok(json!({ "reconciled": n }))
            }
            // Recherche de textes en clair dans toutes les tables du serveur.
            "leaks" => {
                let needles: Vec<String> = cmd["needles"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                let tables: Vec<(String,)> = sqlx::query_as(
                    "SELECT table_name::text FROM information_schema.tables WHERE table_schema = 'public'",
                )
                .fetch_all(&self.pool)
                .await?;
                let mut dump = String::new();
                for (t,) in tables {
                    let rows: Vec<(String,)> =
                        sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT row_to_json(x)::text FROM \"{t}\" x")))
                            .fetch_all(&self.pool)
                            .await?;
                    rows.into_iter().for_each(|(r,)| dump.push_str(&r));
                }
                let leaked: Vec<&String> = needles.iter().filter(|n| dump.contains(n.as_str())).collect();
                Ok(json!({ "leaked": leaked }))
            }
            other => anyhow::bail!("commande inconnue : {other}"),
        }
    }

    async fn enroll(&self, username: &str, code: &str) -> anyhow::Result<(Client, String)> {
        let act = Client::activate(&self.cfg, username, code, &self.password).await?;
        let c = Client::enroll(&self.cfg, username, &self.password, &totp_now(&act.totp_secret_base32)).await?;
        Ok((c, act.totp_secret_base32))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = std::env::var("MSG_URL")?;
    let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
    let dir = tempfile::tempdir()?;
    let mut cfg = ClientConfig::new(url.clone(), dir.path());
    cfg.argon2 = Argon2Params::INSECURE_FOR_TESTS;
    let password = hex::encode(msg_crypto::random_bytes::<16>()?);
    let mut peer = Peer { url, pool, _dir: dir, cfg, alice: None, alice_totp: String::new(), password };
    let _ = &peer.url;
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let cmd: Value = serde_json::from_str(&line)?;
        let out = match peer.run(&cmd).await {
            Ok(v) => json!({ "ok": true, "result": v }),
            Err(e) => json!({ "ok": false, "error": e.to_string() }),
        };
        println!("{out}");
    }
    Ok(())
}
