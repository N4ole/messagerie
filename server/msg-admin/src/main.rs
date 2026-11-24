//! `msg-admin` : administration des comptes via l'API.
//!
//! L'administrateur dispose d'un appareil enregistré comme n'importe quel
//! utilisateur (clés signées, base locale SQLCipher). Le mot de passe et le
//! code TOTP sont saisis de façon interactive, jamais en argument.
#![forbid(unsafe_code)]

use std::path::PathBuf;

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use msg_client_core::{Client, ClientConfig, ClientError};
use msg_proto::{AccountStatus, Role};

#[derive(Parser)]
#[command(name = "msg-admin", version, about = "Administration de la messagerie")]
struct Cli {
    /// URL du serveur (HTTPS ; HTTP accepté uniquement en local).
    #[arg(long, env = "MSG_SERVER_URL")]
    server: String,
    /// Identifiant de l'administrateur.
    #[arg(long, env = "MSG_ADMIN_USER")]
    user: String,
    /// Dossier des données locales (défaut : dossier de configuration utilisateur).
    #[arg(long, env = "MSG_ADMIN_DATA_DIR")]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Active le compte administrateur sur ce poste (code d'activation requis).
    Enroll,
    /// Crée un compte et affiche son code d'activation (à transmettre hors bande).
    Create {
        username: String,
        #[arg(long, default_value = "user")]
        role: String,
    },
    /// Liste les comptes.
    List,
    /// Suspend un compte (révoque immédiatement ses sessions).
    Suspend { username: String },
    /// Réactive un compte suspendu.
    Unsuspend { username: String },
    /// Change le rôle d'un compte (user | admin).
    Role { username: String, role: String },
    /// Réinitialise un compte (nouvelle identité, nouveau code d'activation).
    Reset { username: String },
    /// Liste les appareils d'un compte.
    Devices { username: String },
    /// Révoque un appareil.
    Revoke { username: String, device_id: uuid::Uuid },
}

fn prompt(label: &str) -> anyhow::Result<String> {
    Ok(rpassword::prompt_password(label)?)
}

fn parse_role(s: &str) -> anyhow::Result<Role> {
    Role::parse(s).with_context(|| format!("rôle inconnu « {s} » (user | admin)"))
}

async fn session(cfg: &ClientConfig, user: &str) -> anyhow::Result<Client> {
    let pw = prompt("Mot de passe : ")?;
    match Client::login(cfg, user, &pw, None).await {
        Ok(c) => Ok(c),
        Err(ClientError::TotpRequired) => {
            let code = prompt("Code TOTP : ")?;
            Ok(Client::login(cfg, user, &pw, Some(&code)).await?)
        }
        Err(e) => Err(e.into()),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let data_dir = match cli.data_dir {
        Some(d) => d,
        None => dirs::config_dir().context("dossier de configuration introuvable")?.join("messagerie-admin"),
    };
    let cfg = ClientConfig::new(cli.server.clone(), data_dir);

    if let Cmd::Enroll = cli.cmd {
        let code = prompt("Code d'activation : ")?;
        let pw = prompt("Nouveau mot de passe (12 caractères min.) : ")?;
        if pw != prompt("Confirmation : ")? {
            bail!("les mots de passe ne correspondent pas");
        }
        let act = Client::activate(&cfg, &cli.user, &code, &pw).await?;
        println!("Ajoutez ce secret dans votre application d'authentification :");
        println!("  {}", act.totp_secret_base32);
        println!("  {}", act.otpauth_uri);
        let totp = prompt("Code TOTP affiché par l'application : ")?;
        let c = Client::enroll(&cfg, &cli.user, &pw, &totp).await?;
        println!("Appareil enregistré. Empreinte d'identité : {}", c.identity_fingerprint());
        return Ok(());
    }

    let client = session(&cfg, &cli.user).await?;
    let api = client.api();
    match cli.cmd {
        Cmd::Enroll => unreachable!(),
        Cmd::Create { username, role } => {
            let r = api.admin_create(&username, parse_role(&role)?).await?;
            println!("Compte « {} » créé.", r.username);
            println!("Code d'activation (usage unique, expire à {} UTC Unix) : {}", r.expires_at, r.activation_code);
        }
        Cmd::List => {
            println!("{:<32} {:<6} {:<20} {:>9}", "IDENTIFIANT", "RÔLE", "STATUT", "APPAREILS");
            for a in api.admin_list().await? {
                println!("{:<32} {:<6} {:<20} {:>9}", a.username, a.role.as_str(), a.status.as_str(), a.device_count);
            }
        }
        Cmd::Suspend { username } => {
            api.admin_set_status(&username, AccountStatus::Suspended).await?;
            println!("Compte « {username} » suspendu.");
        }
        Cmd::Unsuspend { username } => {
            api.admin_set_status(&username, AccountStatus::Active).await?;
            println!("Compte « {username} » réactivé.");
        }
        Cmd::Role { username, role } => {
            api.admin_set_role(&username, parse_role(&role)?).await?;
            println!("Rôle de « {username} » : {role}.");
        }
        Cmd::Reset { username } => {
            let r = api.admin_reset(&username).await?;
            println!("Compte « {} » réinitialisé. Ses contacts verront un changement d'identité.", r.username);
            println!("Nouveau code d'activation : {}", r.activation_code);
        }
        Cmd::Devices { username } => {
            for d in api.admin_devices(&username).await? {
                println!(
                    "{}  créé {}  vu {}",
                    d.device_id,
                    d.created_at,
                    d.last_seen_at.map(|t| t.to_string()).unwrap_or("-".into())
                );
            }
        }
        Cmd::Revoke { username, device_id } => {
            api.admin_revoke_device(&username, device_id).await?;
            println!("Appareil {device_id} révoqué.");
        }
    }
    Ok(())
}
