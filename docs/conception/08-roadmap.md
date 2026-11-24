# 08 — Feuille de route et critères d'acceptation

Chaque phase se termine par : CI verte, tests passants, instructions de build/lancement exactes, section « Limites et risques connus », puis **attente de validation**.

## Phase 1 — MVP

**Contenu** : `msg-proto`, `msg-crypto` (MLS 2 membres), `msg-client-core`, `msg-storage-sqlcipher`, `msg-markdown`, `msg-server` (comptes admin, activation, login Argon2id + TOTP, appareils, KeyPackages, delivery service, WebSocket), `msg-admin`, UI React (connexion, liste des conversations, fil de messages, thème clair/sombre), app Tauri, CI + release `.exe` (non signé si pas de certificat), fichiers GitHub (§07), devcontainer, Docker Compose de dev.

**Critères d'acceptation**
- [ ] Deux comptes créés par `msg-admin` échangent des messages depuis deux instances desktop (test E2E automatisé sous Windows en CI, avec deux profils).
- [ ] Test « aucun clair » : marqueur aléatoire absent du dump PostgreSQL et des logs serveur.
- [ ] La BDD locale n'est pas lisible par `sqlite3` sans clé.
- [ ] `cargo test`, `pnpm test`, `clippy`, `cargo deny` verts sur Linux et Windows.
- [ ] Un tag `v0.1.0` produit une Release avec `.msi`, `-setup.exe` (NSIS), `.exe` portable, `SHA256SUMS`, attestation.

## Phase 2 — Sécurité avancée

Groupes MLS (ajout/retrait/rôles), pièces jointes (`msg-media`), QR / safety numbers, détection de changement de clé, éphémères, anti-capture, verrouillage auto, Passkeys/YubiKey (serveur `webauthn-rs` + desktop `webauthn.dll`), TPM/CNG + DPAPI, rotation automatique.

## Phase 3 — Réseau & web

`msg-tor` (arti, mode strict), service onion serveur, `msg-wasm` + client web, test d'interopérabilité desktop ↔ web en CI (Playwright + client Rust natif headless), Key Transparency (`akd`), révocation d'appareils, démo GitHub Pages.

## Phase 4 — Multi-site & infra

Fédération mTLS + liste blanche, file store-and-forward, réplication, HA (Patroni/CloudNativePG), load balancing, Compose prod, manifests K8s + Helm, script VM, sauvegardes `pgBackRest` + procédure DR testée, Prometheus/Grafana + test « métriques sans PII ».

## Phase 5 — Durcissement

Vérification d'intégrité au démarrage, signature Authenticode effective, builds reproductibles (serveur/WASM), revue de sécurité interne (checklist OWASP ASVS niveau 2 + revue des compositions crypto listées dans 02 §8), fuzzing (`cargo-fuzz` sur parseurs : protobuf, Markdown, images, messages MLS entrants), tests de pénétration de base (ZAP sur l'API, tests d'authentification), documentation finale.

## Décisions à valider avant la Phase 1

| # | Question | Recommandation |
|---|---|---|
| D1 | Protocole 1-à-1 | **MLS partout** (MIT, WASM, multi-appareils) plutôt que libsignal (AGPL, pas de WASM officiel) |
| D2 | Authentification par mot de passe | Argon2id serveur comme demandé en Phase 1 ; **migration OPAQUE** en Phase 5 si tu l'acceptes |
| D3 | Frontend | React + TypeScript |
| D4 | Suite MLS par défaut | Hybride PQ ML-KEM-768 + X25519 (révisé en Phase 1, ADR-0011) |
| D5 | Hébergement des services onion | C tor côté serveur, arti côté client |
| D6 | TOTP obligatoire ? | Obligatoire par défaut, désactivable par politique de site |
| D7 | Licence | Conserver MIT (compatible avec toutes les dépendances retenues : OpenMLS MIT, akd MIT/Apache, arti MIT/Apache, Tauri MIT/Apache ; `webauthn-rs` MPL-2.0, copyleft au niveau fichier, compatible ; seules d'éventuelles modifications de ses propres fichiers devraient être publiées sous MPL) |
| D8 | Signature de code | Choisir le fournisseur (Azure Artifact Signing, SignPath, autre) ; sans choix, releases non signées mais attestées |
| D9 | Visibilité du dépôt | Public recommandé (attestations, secret scanning et CodeQL gratuits) |
