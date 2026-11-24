# 05 — Arborescence cible du dépôt

Monodépôt : un *workspace* Cargo (Rust) + un *workspace* pnpm (TypeScript). La colonne « Phase » indique quand le dossier apparaît.

```
messagerie/
├── Cargo.toml                    # workspace Rust, profils release (lto, codegen-units=1, strip)   P1
├── Cargo.lock                                                                                       P1
├── rust-toolchain.toml           # version Rust épinglée (reproductibilité)                         P1
├── deny.toml                     # cargo-deny : licences autorisées, advisories, sources            P1
├── package.json / pnpm-workspace.yaml / pnpm-lock.yaml                                              P1
├── crates/
│   ├── msg-proto/                # types d'API protobuf (prost) + build.rs                         P1
│   │   └── proto/messagerie/v1/*.proto
│   ├── msg-crypto/               # façade OpenMLS, identités, certificats, safety numbers, AEAD    P1
│   ├── msg-client-core/          # logique client, traits Storage/Transport                        P1
│   ├── msg-storage-sqlcipher/    # Storage desktop                                                 P1
│   ├── msg-markdown/             # Markdown → AST sûr                                              P1
│   ├── msg-media/                # ré-encodage images, miniatures                                  P2
│   ├── msg-platform-win/         # TPM/CNG, DPAPI, anti-capture, WebAuthn natif, Authenticode      P1 (DPAPI) / P2 / P5
│   ├── msg-tor/                  # arti, mode strict                                               P3
│   ├── msg-kt/                   # vérification Key Transparency (akd)                             P3
│   └── msg-wasm/                 # liaisons wasm-bindgen + Storage IndexedDB + Transport fetch/WS  P3
├── server/
│   ├── msg-server/               # axum : auth, appareils, delivery service, fichiers, KT, fédé.   P1
│   │   ├── migrations/           # sqlx migrations PostgreSQL
│   │   └── tests/                # tests d'intégration (testcontainers PostgreSQL)
│   └── msg-admin/                # CLI d'administration                                            P1
├── ui/                           # frontend React/TS partagé (composants, i18n FR/EN, thèmes)      P1
│   ├── src/
│   │   ├── api/                  # interface abstraite : backend Tauri OU WASM
│   │   ├── components/ views/ theme/ a11y/
│   │   └── markdown/             # rendu de l'AST (aucun innerHTML)
│   └── tests/                    # Vitest + Testing Library
├── apps/
│   ├── desktop/                  # Tauri v2                                                        P1
│   │   ├── src-tauri/
│   │   │   ├── src/              # commandes IPC, verrouillage auto, intégrations Windows
│   │   │   ├── capabilities/     # permissions Tauri v2 minimales
│   │   │   ├── tauri.conf.json   # CSP stricte, bundles MSI + NSIS, pas d'updater réseau
│   │   │   └── wix/ nsis/        # personnalisation des installeurs
│   │   └── e2e/                  # tests de bout en bout (WebDriver Tauri)
│   └── web/                      # entrée Vite du client web (charge msg-wasm)                    P3
├── tests/
│   └── e2e-plaintext-leak/       # démonstration : aucun clair en BDD/logs/trafic                  P1 → P3
├── deploy/
│   ├── docker/                   # Dockerfiles (distroless), compose.yaml (dev + prod)             P1 (dev) / P4
│   ├── kubernetes/
│   │   ├── manifests/                                                                              P4
│   │   └── helm/messagerie/      # chart Helm                                                      P4
│   ├── vm/                       # script d'installation systemd + guide                           P4
│   ├── tor/                      # torrc service onion, Onionbalance                               P3/P4
│   └── monitoring/               # Prometheus, règles d'alerte, dashboards Grafana JSON            P4
├── docs/
│   ├── conception/               # Phase 0 (ce dossier)                                            P0
│   ├── adr/                      # décisions d'architecture                                        P0
│   ├── guides/                   # utilisateur, admin, exploitation, restauration après sinistre   P1→P5
│   └── site/                     # source GitHub Pages                                             P1
├── .github/
│   ├── workflows/                # ci.yml, release.yml, codeql.yml, pages.yml, docker.yml          P1→P5
│   ├── ISSUE_TEMPLATE/  PULL_REQUEST_TEMPLATE.md  CODEOWNERS  dependabot.yml                       P1
│   └── rulesets/                 # JSON des rulesets à importer (branch protection)               P1
├── .devcontainer/                # Codespaces : Rust, wasm-pack, Node, PostgreSQL                  P1
├── SECURITY.md  CONTRIBUTING.md  README.md  LICENSE                                                 P1
```

## Conventions

- `#![forbid(unsafe_code)]` dans toutes les crates **sauf** `msg-platform-win` (FFI Windows), où chaque bloc `unsafe` est commenté et isolé.
- Tout type contenant un secret implémente `Zeroize` + `ZeroizeOnDrop` et n'implémente **pas** `Debug`/`Clone` (ou un `Debug` masqué).
- Aucune dépendance réseau à l'exécution vers un tiers : polices et icônes embarquées, pas de CDN.
- Les crates partagées compilent pour `x86_64-pc-windows-msvc`, `x86_64-unknown-linux-gnu` et `wasm32-unknown-unknown` (vérifié en CI).
