//! Point d'entrée du serveur.

use clap::{Parser, Subcommand};
use msg_server::{config::Config, logging, migrate, router, tasks, AppState};
use sqlx::postgres::PgPoolOptions;

#[derive(Parser)]
#[command(name = "msg-server", version, about = "Serveur de messagerie chiffrée de bout en bout")]
struct Cli {
    /// URL PostgreSQL (ex. postgres://msg:***@localhost/messagerie).
    /// (ou fichier `DATABASE_URL_FILE`).
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Démarre l'API.
    Serve {
        #[arg(long, env = "MSG_BIND", default_value = "127.0.0.1:8080")]
        bind: String,
        /// Adresse des métriques Prometheus (désactivées si absente). À
        /// réserver au réseau d'administration.
        #[arg(long, env = "MSG_METRICS_BIND")]
        metrics_bind: Option<String>,
    },
    /// Applique les migrations puis quitte.
    Migrate,
    /// Crée le premier administrateur (impossible s'il en existe déjà un).
    BootstrapAdmin {
        #[arg(long)]
        username: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    logging::init();
    let cli = Cli::parse();
    let url = match cli.database_url {
        Some(u) => zeroize::Zeroizing::new(u),
        None => msg_server::config::secret_env("DATABASE_URL")?
            .ok_or_else(|| anyhow::anyhow!("DATABASE_URL (ou DATABASE_URL_FILE) manquant"))?,
    };
    let max = std::env::var("MSG_DB_MAX_CONNECTIONS").ok().and_then(|v| v.parse().ok()).unwrap_or(20);
    let pool = PgPoolOptions::new().max_connections(max).connect(&url).await?;
    migrate(&pool).await?;
    match cli.cmd {
        Cmd::Migrate => {
            tracing::info!("migrations appliquées");
        }
        Cmd::BootstrapAdmin { username } => {
            let cfg = Config::from_env()?;
            let r = msg_server::routes::admin::bootstrap_admin(&pool, &username, cfg.activation_ttl_secs).await?;
            // Affiché une seule fois sur la sortie standard, jamais journalisé.
            println!("Administrateur créé.");
            println!("Code d'activation (à usage unique, expire le {}): {}", r.expires_at, r.activation_code);
        }
        Cmd::Serve { bind, metrics_bind } => {
            let cfg = Config::from_env()?;
            let st = AppState::try_new(pool, cfg)?;
            tasks::spawn(st.clone());
            if let Some(addr) = metrics_bind {
                let l = tokio::net::TcpListener::bind(&addr).await?;
                tracing::info!(%addr, "métriques Prometheus exposées");
                let app = msg_server::metrics::router(st.clone());
                tokio::spawn(async move {
                    if let Err(e) = axum::serve(l, app).await {
                        tracing::error!(error = %e, "serveur de métriques arrêté");
                    }
                });
            }
            let listener = tokio::net::TcpListener::bind(&bind).await?;
            tracing::info!(%bind, "serveur démarré");
            axum::serve(listener, router(st)).with_graceful_shutdown(shutdown()).await?;
        }
    }
    Ok(())
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("arrêt demandé");
}
