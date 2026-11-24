# Guide de développement

## Prérequis

| Outil | Version | Remarque |
|---|---|---|
| Rust | 1.97.0 (fixée par `rust-toolchain.toml`) | `rustup toolchain install` |
| Node.js / pnpm | 22 / 10.12 (`corepack enable`) | |
| PostgreSQL | 16 | Tests d'intégration et serveur |
| Windows | Visual Studio Build Tools (C++), Perl (Strawberry) | SQLCipher et OpenSSL sont compilés depuis les sources |
| Linux | `libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev` | Pour compiler l'application Tauri |

Le plus simple : **Codespaces / devcontainer** (`.devcontainer/`), qui installe tout et fournit PostgreSQL.

## Construire et tester

```bash
pnpm install --frozen-lockfile
pnpm build:ui
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres cargo test --workspace
pnpm typecheck && pnpm lint && pnpm test
```

Les tests de bout en bout (`server/msg-server/tests/e2e.rs`) créent une base
éphémère par test dans le PostgreSQL désigné par `DATABASE_URL`.

Vérification WASM des crates partagées :

```bash
RUSTFLAGS='--cfg getrandom_backend="wasm_js"' cargo build --target wasm32-unknown-unknown -p msg-proto -p msg-crypto -p msg-markdown
```

## Lancer un serveur local

```bash
export DATABASE_URL=postgres://postgres:postgres@localhost:5432/messagerie
export MSG_SERVER_SECRET=$(openssl rand -hex 32)   # à conserver : chiffre les secrets TOTP
cargo run -p msg-server -- bootstrap-admin --username admin
cargo run -p msg-server -- serve --bind 127.0.0.1:8080
```

Ou avec Docker :

```bash
MSG_SERVER_SECRET=$(openssl rand -hex 32) docker compose -f deploy/docker/compose.dev.yaml up --build
docker compose -f deploy/docker/compose.dev.yaml exec server msg-server bootstrap-admin --username admin
```

## Lancer l'application de bureau

```bash
pnpm tauri dev
```

Dans l'application, saisir `http://127.0.0.1:8080` comme serveur (HTTP n'est
accepté que sur la boucle locale ; HTTPS est obligatoire sinon).

## Construire le `.exe` Windows

```bash
pnpm tauri build
```

Produit `target/release/bundle/msi/*.msi`, `target/release/bundle/nsis/*-setup.exe`
et l'exécutable portable `target/release/messagerie.exe`.

## Variables du serveur

| Variable | Défaut | Rôle |
|---|---|---|
| `DATABASE_URL` | — | PostgreSQL |
| `MSG_SERVER_SECRET` | — (obligatoire) | 32 octets hex ; dérive le *pepper* Argon2 et la clé des secrets TOTP |
| `MSG_BIND` | `127.0.0.1:8080` | Adresse d'écoute |
| `MSG_SITE_NAME` | `messagerie` | Émetteur TOTP |
| `MSG_ACCESS_TTL_SECS` | `900` | Durée du jeton d'accès |
| `MSG_SESSION_TTL_SECS` | `43200` | Durée absolue d'une session |
| `MSG_ACTIVATION_TTL_SECS` | `259200` | Validité d'un code d'activation |
| `MSG_BLOB_RETENTION_SECS` | `2592000` | Rétention max. d'un message non retiré |
| `MSG_MAX_FAILED_LOGINS` / `MSG_LOCKOUT_SECS` | `5` / `900` | Verrouillage |
| `MSG_ARGON2_M_KIB` / `_T` / `_P` | `65536` / `3` / `1` | Coût Argon2id |
| `MSG_SEND_RATE_PER_10S` | `50` | Envois par appareil et par 10 s |
| `MSG_LOG` / `MSG_LOG_JSON` | `info` / `0` | Journalisation |

> Perdre `MSG_SERVER_SECRET` rend tous les mots de passe et secrets TOTP
> inutilisables (réinitialisation de tous les comptes nécessaire).
