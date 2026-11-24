# Phase 1 — MVP : rapport de livraison

> Statut : **livrée, en attente de validation.**

## 1. Périmètre

| Exigence Phase 1 | État | Où |
|---|---|---|
| Serveur (API, stockage de blobs chiffrés uniquement) | ✅ | `server/msg-server` |
| Comptes créés **uniquement** par un administrateur + gestion (création, suspension, réactivation, rôle, réinitialisation, révocation d'appareil) | ✅ | `server/msg-server/src/routes/admin.rs`, `server/msg-admin` |
| Connexion identifiant + mot de passe (Argon2id + *pepper*) | ✅ | `server/msg-server/src/passwords.rs` |
| TOTP obligatoire, anti-rejeu des codes, verrouillage après 5 échecs | ✅ | idem + `routes/account.rs` |
| Sessions à durée limitée (accès 15 min, absolue 12 h, rafraîchissement à rotation) | ✅ | `routes/account.rs` |
| Requêtes signées par l'appareil (horodatage + nonce, anti-rejeu) | ✅ | `crates/msg-crypto/src/request.rs`, `server/msg-server/src/auth.rs` |
| Messagerie 1-à-1 chiffrée de bout en bout (MLS, signature de chaque message) | ✅ | `crates/msg-crypto/src/mls.rs`, `crates/msg-client-core/src/client.rs` |
| Hybride post-quantique (ML-KEM-768 + X25519) | ✅ | ADR-0011 |
| Certificats d'appareil + confiance au premier usage (changement d'identité bloqué) | ✅ | `client.rs` (`check_identity`, `verify_members`) |
| Base locale chiffrée (SQLCipher), clé enveloppée Argon2id + DPAPI (Windows) | ✅ | `crates/msg-client-core/src/{vault,store}.rs`, `crates/msg-platform-win` |
| Markdown sûr (aucun HTML, aucune ressource distante) | ✅ | `crates/msg-markdown`, `ui/src/markdown` |
| Application de bureau Tauri, thème clair / sombre / système | ✅ | `apps/desktop`, `ui/` |
| Notification temps réel sans contenu (WebSocket) | ✅ | `routes/ws.rs`, `apps/desktop/src-tauri/src/lib.rs` |
| CI GitHub produisant le `.exe` (MSI + NSIS + portable) | ✅ | `.github/workflows/ci.yml`, `release.yml` |
| Fichiers GitHub (CodeQL, Dependabot, GHCR, Pages, templates, SECURITY, CODEOWNERS, rulesets, devcontainer) | ✅ | `.github/`, `.devcontainer/`, `scripts/github/` |

## 2. Arborescence créée

```
Cargo.toml  Cargo.lock  rust-toolchain.toml  rustfmt.toml  deny.toml
package.json  pnpm-workspace.yaml  pnpm-lock.yaml
crates/
  msg-proto/            types d'API JSON partagés (natif + WASM + serveur)
  msg-crypto/           identités, certificats, MLS, signature de requêtes, enveloppe de clés
  msg-markdown/         Markdown → AST sûr
  msg-client-core/      API signée, coffre + SQLCipher, logique de conversation
  msg-platform-win/     DPAPI (seul crate avec `unsafe`, FFI Win32)
server/
  msg-server/           axum + PostgreSQL ; migrations ; tests de bout en bout
  msg-admin/            CLI d'administration (passe par l'API)
apps/desktop/           Tauri v2 : commandes IPC, capabilities, icônes, installeurs
ui/                     React + TypeScript (Vite), tests Vitest
deploy/docker/          Dockerfile serveur (distroless, non-root), compose de dev
.github/                workflows CI/Release/CodeQL/Docker/Pages, Dependabot, templates, rulesets
.devcontainer/          Codespaces avec PostgreSQL
scripts/github/         application des rulesets, création du tableau Projects
docs/                   guides, ADR 0010-0011, ce rapport, mdBook
```

## 3. Tests

| Suite | Nombre | Contenu |
|---|---|---|
| `msg-crypto` | 18 | certificats (falsification), signature de requêtes, enveloppe de clé, **MLS : aller-retour, rejeu refusé, altération refusée, remplissage, export/restauration d'état, rotation d'époque, tiers incapable de déchiffrer** |
| `msg-markdown` | 7 | HTML brut → texte, images jamais chargées, schémas `javascript:`/`data:` bloqués, profondeur et nombre de nœuds bornés |
| `msg-proto` | 4 | validation, encodage Base64, notification sans contenu |
| `msg-client-core` | 7 | **fichier SQLCipher sans clair ni en-tête SQLite**, mauvaise clé refusée, coffre, politique d'URL (HTTPS obligatoire) |
| `msg-server` (unitaires) | 4 | Argon2id + pepper, TOTP (fenêtre, rejeu), codes d'activation, secrets TOTP liés au compte |
| `msg-server` (bout en bout) | 5 | voir ci-dessous |
| `msg-platform-win` | 1 | DPAPI réel sous Windows (CI) / « non pris en charge » ailleurs |
| `messagerie-desktop` | 2 | QR code TOTP local, classification des erreurs |
| UI (Vitest) | 13 | rendu Markdown sûr, thème, parcours de connexion/activation, envoi, alertes de rejet |

Tests de bout en bout (`server/msg-server/tests/e2e.rs`, serveur et clients réels, PostgreSQL) :

1. **`message_exchange_without_plaintext_leak`** — critère « aucune donnée en
   clair » : un marqueur aléatoire envoyé par Alice est recherché (texte et
   hexadécimal) dans **toutes les tables** du serveur avant et après
   distribution, dans **les journaux serveur au niveau TRACE** et dans **les
   fichiers locaux** ; il n'apparaît nulle part, alors que Bob le lit
   correctement. Les blobs sont supprimés après accusé de réception.
2. `restart_resumes_session_and_mls_state` — redémarrage, reprise sans TOTP,
   déconnexion puis TOTP redemandé.
3. `authentication_rules` — droits admin, code d'activation à usage unique,
   rejeu TOTP, suspension (sessions révoquées), verrouillage après 5 échecs.
4. `signed_requests_resist_replay_and_tampering` — rejeu de nonce, corps
   altéré, horodatage ancien, mauvaise clé, certificat invalide.
5. `identity_change_is_detected` — après réinitialisation d'un compte, ses
   contacts rejettent la nouvelle identité.

**Essai réel de l'application** (Linux, WebKitGTK, écran virtuel) : serveur
réel, Bob piloté par script, Alice dans l'application graphique. Connexion,
réception, rendu Markdown (pixel espion non chargé), réponse reçue par Bob,
message suivant poussé par WebSocket sans action, thème sombre :

![Connexion](img/connexion.png)
![Conversation](img/conversation-clair.png)
![Thème sombre](img/conversation-sombre.png)

Journal du serveur pendant cet essai : uniquement méthode, modèle de route,
statut et durée — aucun identifiant, aucune IP, aucun contenu.

## 4. Commandes

```bash
pnpm install --frozen-lockfile && pnpm build:ui
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres cargo test --workspace
pnpm typecheck && pnpm lint && pnpm test
cargo deny check advisories bans licenses sources
pnpm tauri build            # sous Windows : MSI + NSIS + exécutable portable
```

Voir [Guide de développement](../guides/developpement.md) et
[Guide d'administration](../guides/administration.md).

Publier une version : `git tag v0.1.0 && git push origin v0.1.0` → workflow
`release.yml` (installeurs, `SHA256SUMS`, attestation de provenance si dépôt public).

## 5. Écarts par rapport à la conception

| Écart | Raison | Trace |
|---|---|---|
| Fournisseur `openmls_rust_crypto` et suite `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519` au lieu de libcrux/X-Wing | 3 avis RUSTSEC dans libcrux (panique sur clé hybride courte → plantage du client à distance) ; correctifs seulement en *release candidate* | ADR-0011 |
| API JSON au lieu de Protobuf | Aucune dépendance à `protoc` ; natif dans le navigateur | ADR-0010 |
| `msg-platform-win` dès la Phase 1 | DPAPI nécessaire pour la clé de la base locale | ADR-0005 |

## 6. Limites et risques connus

**Sécurité**

1. **Aucun audit externe.** OpenMLS, la suite post-quantique (point de code
   provisoire 0x004F) et notre code n'ont pas été audités. Ne pas utiliser
   pour des usages à haut risque avant la Phase 5 et un audit indépendant.
2. **Deux avis de sécurité tolérés** (justifiés dans `deny.toml`) :
   RUSTSEC-2026-0387 (`crypto-bigint`, opérations P-256 non utilisées) et
   RUSTSEC-2026-0459 (SQLite, fichier WAL écrit par un tiers ; nous n'utilisons
   pas WAL). Levée prévue avec OpenMLS 0.10 stable.
3. **Confiance au premier usage seulement** : la première clé d'identité vue
   d'un contact est acceptée sans vérification hors bande. Le QR code /
   *safety numbers* arrivent en Phase 2, la Key Transparency en Phase 3.
4. **Le changement d'identité est bloqué mais pas encore expliqué dans l'UI** :
   l'utilisateur voit « N message(s) rejeté(s) » ; l'écran dédié (vérifier /
   accepter la nouvelle clé) arrive en Phase 2.
5. **Pas de rotation automatique des clés MLS** (`self_update` existe et est
   testé, mais n'est pas encore planifié) : Phase 2.
6. **Révocation d'appareil côté serveur uniquement** : l'appareil perd tout
   accès au serveur, mais il n'est pas encore retiré cryptographiquement des
   groupes MLS (Phase 3).
7. **Le mot de passe transite jusqu'au serveur** (sous TLS) pour la
   vérification Argon2id ; OPAQUE est proposé pour la Phase 5 (ADR-0007). Les
   clés E2EE n'en dérivent pas.
8. **Pas d'épinglage TLS** : le client vérifie le certificat via les
   autorités de confiance ; l'épinglage arrive avec Tor (Phase 3). HTTP
   n'est accepté que sur la boucle locale.
9. **État MLS en mémoire** : `openmls_memory_storage` conserve les secrets MLS
   dans une table de hachage non effacée (`zeroize`) à la libération ; ils sont
   persistés uniquement chiffrés (SQLCipher). Les messages affichés résident
   aussi dans la mémoire de la WebView (inévitable).
10. **TPM non utilisé** : la clé de la base est protégée par mot de passe
    (Argon2id) + DPAPI. Le scellement TPM arrive en Phase 2.
11. **Graphe social visible du serveur** : il sait quels appareils reçoivent
    quels blobs (documenté en Phase 0).
12. **Limitation de débit en mémoire** (par instance) et verrouillage par
    compte : un attaquant peut verrouiller un compte en échouant 5 fois
    (déni de service ciblé, compromis assumé).

**Fonctionnel**

13. Un seul appareil par utilisateur (liaison multi-appareils : Phase 3) ;
    un compte d'administration ne doit pas être utilisé en même temps dans
    l'application de bureau.
14. Interface en français uniquement ; pas encore de notifications système
    (Phase 2, sans aperçu).
15. Les liens Markdown ne sont pas cliquables (choix de sécurité : affichés
    avec leur adresse).

**Livraison**

16. **Binaires non signés (Authenticode)** : SmartScreen avertira. Signature
    en Phase 5, certificat à fournir (voir `docs/guides/github-setup.md`).
17. **Non testé sur un vrai Windows** depuis cet environnement (Linux) : la
    CI construit et teste sur `windows-2022` (y compris DPAPI), mais la
    [recette manuelle](../guides/recette-windows.md) reste à faire.
18. **Image Docker et site mdBook non construits localement** (pas de démon
    Docker ni d'exécution de binaire téléchargé ici) : vérifiés uniquement
    par les workflows `docker.yml` et `pages.yml`.
19. Les réglages GitHub (rulesets, secret scanning, environments, Pages,
    Projects) exigent tes droits d'administration :
    [procédure](../guides/github-setup.md).
