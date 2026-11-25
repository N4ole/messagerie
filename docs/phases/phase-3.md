# Phase 3 — Réseau et web : rapport de livraison

> Statut : **livrée, en attente de validation.**

## 1. Périmètre

| Exigence Phase 3 | État | Où |
|---|---|---|
| **Client web** interopérable avec le desktop (même cœur Rust compilé en WASM) | ✅ | `crates/msg-wasm`, `crates/msg-client-core` (cible `wasm32`), `ui/src/web/` |
| Stockage web chiffré (IndexedDB) | ✅ | `crates/msg-client-core/src/store_mem.rs`, `account.rs`, `ui/src/web/kv.ts` |
| Test d'interopérabilité desktop ↔ web **en CI** (client natif + Chromium) | ✅ | `tests/interop/`, `server/msg-server/examples/interop_peer.rs`, job `interop` |
| **Key Transparency** (akd) : journal serveur, preuves vérifiées par le client | ✅ | `crates/msg-kt`, `server/msg-server/src/kt.rs`, `crates/msg-client-core/src/kt.rs` |
| **Appareils multiples** : liaison par QR code sans transfert de clé | ✅ | `server/msg-server/src/routes/devices.rs`, `crates/msg-client-core/src/devices.rs` |
| **Révocation cryptographique** d'appareils (retrait MLS, effacement local) | ✅ | idem, ADR-0013 |
| **Tor embarqué** (arti), **mode strict** sans repli en clair | ✅ (desktop) | `crates/msg-tor`, `crates/msg-client-core/src/net.rs` |
| **Épinglage TLS** (clé publique du serveur) | ✅ (desktop) | `net.rs` |
| Service onion v3 côté serveur | ✅ (fichiers de déploiement) | `deploy/tor/`, `deploy/docker/compose.onion.yaml` |
| Web en mode Tor strict (refus hors `.onion`) | ✅ | `MSG_WEB_ONION_ONLY`, `ui/src/web/start.ts` |
| Démo GitHub Pages | ❌ (écart, §5) | — |

## 2. Fichiers créés ou modifiés

```
crates/msg-kt/                         nouveau : valeur canonique, vérification (natif + WASM), répertoire akd (serveur)
crates/msg-tor/                        nouveau : arti + proxy SOCKS5 local authentifié
crates/msg-wasm/                       nouveau : liaisons wasm-bindgen du cœur client
crates/msg-client-core/src/{account,devices,kt,net,store_mem}.rs   nouveaux
crates/msg-client-core/src/{api,client,conversations,store,vault,lib,error}.rs
crates/msg-proto/src/lib.rs            liaison, appareils, KT, ticket WebSocket, configuration web
server/msg-server/migrations/{0004_devices,0005_kt}.sql
server/msg-server/src/{kt.rs, routes/devices.rs, routes/web.rs}    nouveaux
server/msg-server/src/{auth,state,config,secrets,tasks}.rs, routes/{account,admin,keys,messages,ws,mod}.rs
server/msg-server/tests/phase3.rs, examples/interop_peer.rs
apps/desktop/src-tauri/                réseau (direct / Tor strict, épinglage), appareils, liaison, révocation
ui/src/web/{backend,kv,start}.ts, components/DevicesSection.tsx, views/Auth.tsx, App.tsx, main.tsx
ui/tests/Phase3.test.tsx, tests/interop/
deploy/docker/{Dockerfile.server, compose.onion.yaml}, deploy/tor/{Dockerfile, torrc}
.github/workflows/{ci.yml (jobs interop et tor-real), docker.yml}, dependabot.yml, deny.toml
docs/adr/{0013,0014}, ADR 0006 et 0008 complétés, guides, ce rapport
```

## 3. Tests

| Suite | Nombre | Nouveautés Phase 3 |
|---|---|---|
| `msg-kt` | 3 | valeur canonique (ordre, KeyPackages sans effet, toute modification détectée) ; **preuve refusée** pour une autre valeur, un autre utilisateur, une autre clé VRF, une racine altérée ; preuves d'ajout seul, point de départ incohérent ou racine intermédiaire falsifiée refusés ; **rejeu déterministe** |
| `msg-client-core` | 17 | base web : **instantané illisible** (aucun secret, contenu ou nom), mauvaise clé et altération refusées, transactions atomiques ; épinglage (clé épinglée, renouvellement à clé constante, chaîne exigée hors `.onion`) ; URL `.onion` |
| `msg-tor` | 1 (+1 manuel) | proxy : relais seulement avec les bons identifiants, refus sans authentification, erreur sans détail si la destination est injoignable ; amorçage Tor réel (`--ignored`, job CI informatif) |
| `msg-server` (bout en bout) | 9 + **3** | voir ci-dessous |
| UI (Vitest) | 35 (+11) | appareils (liste, révocation, approbation par code, appareil secondaire), liaison (code puis session), avis de révocation, backend web (WebSocket à ticket, persistance, révocation ⇒ effacement), réseau (Tor configuré **avant** toute connexion, aucune tentative si Tor échoue) |
| **Interopérabilité** (Chromium) | 2 | voir ci-dessous |

Scénarios de bout en bout (`tests/phase3.rs`, serveur réel et PostgreSQL) :

1. **`linked_device_joins_conversations_and_revocation_removes_it`** — code de liaison à
   l'empreinte falsifiée **refusé** ; liaison approuvée ; empreinte d'identité identique ;
   l'appareil secondaire ne peut pas approuver ; l'appareil lié est **ajouté** à la
   conversation existante (sans l'historique antérieur) ; messages reçus et envoyés sur les
   deux appareils ; une nouvelle conversation inclut d'emblée les deux appareils ;
   **révocation** : retrait MLS chez tous les membres, plus aucune distribution, l'appareil
   révoqué l'apprend et efface son compte local.
2. **`key_transparency_detects_unpublished_and_substituted_keys`** — journal **rejoué à
   l'identique** par une nouvelle instance, refusé avec une autre clé VRF ; clé d'identité
   remplacée en base sans publication ⇒ **refus KT** ; fausse clé publiée ⇒ **détectée par son
   titulaire** ; changement d'identité signalé aux correspondants ; preuves d'ajout seul
   vérifiées ; journal altéré ⇒ non servi.
3. **`tor_strict_mode_routes_everything_through_the_proxy`** — enrôlement, conversation, envoi
   et WebSocket **entièrement via le proxy SOCKS** (connexions comptées) ; proxy absent ⇒
   erreur réseau, **jamais de repli direct**.

Test d'interopérabilité (`pnpm test:interop`, job CI `interop`) : serveur réel servant le client
web, client natif (même cœur que le `.exe`), vrai Chromium :

1. Bob s'active **dans le navigateur** ; le client natif lui écrit, il lit ; il répond en
   Markdown, le client natif lit. **Aucun clair dans IndexedDB ni dans la base du serveur**,
   **aucune requête vers un tiers**, **aucune violation de CSP** ; après rechargement,
   déverrouillage par mot de passe et historique conservé.
2. Le navigateur est **lié comme appareil d'Alice** (code affiché, approuvé par le client
   natif), **ajouté à sa conversation** existante et reçoit les nouveaux messages.

![Client web : conversation avec le desktop](img/p3-web-conversation.png)
![Liaison d'un navigateur](img/p3-web-liaison.png)
![Appareils (navigateur lié)](img/p3-web-appareils.png)

## 4. Commandes

```bash
pnpm install --frozen-lockfile
```

```bash
DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres cargo test --workspace
```

```bash
pnpm test
```

```bash
cargo install wasm-bindgen-cli --version 0.2.130 --locked
```

```bash
pnpm build:web
```

```bash
cargo build -p msg-server --bin msg-server --example interop_peer
```

```bash
DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres pnpm test:interop
```

Serveur avec client web : `MSG_WEB_DIR=ui/dist-web` (voir le
[guide de développement](../guides/developpement.md#client-web-wasm)). Service onion : voir le
[guide d'administration](../guides/administration.md#service-onion-tor).

## 5. Écarts par rapport à la conception

| Écart | Raison | Trace |
|---|---|---|
| Tor par un **proxy SOCKS5 local** (dans le processus) plutôt qu'un transport branché directement sur arti | Le client HTTP (`reqwest`) n'accepte pas de flux arbitraires ; le proxy, limité à `127.0.0.1` et protégé par des identifiants aléatoires, est le seul itinéraire configuré | ADR-0006 |
| Base web : **instantané chiffré** unique plutôt qu'un chiffrement par enregistrement | Même interface que SQLCipher, atomicité simple ; coût proportionnel à la taille de l'historique (§6) | ADR-0014 |
| Journal KT : répertoire **en mémoire reconstruit au démarrage** (pas de stockage akd en base) | akd ne fournit pas de stockage PostgreSQL ; le rejeu est déterministe et vérifié racine par racine | ADR-0008 |
| Racines KT **non signées** et non échangées entre sites | Relève de la fédération (Phase 4) | ADR-0008, §6 |
| Liaison d'appareil : seul l'appareil principal approuve | Aucune clé d'identité transférée | ADR-0013 |
| **Démo GitHub Pages non livrée** | Une page statique sans serveur ne peut ni chiffrer ni échanger de messages ; une démo simulée serait trompeuse. Remplacée par le test d'interopérabilité en CI et les captures ci-dessus | — |

## 6. Limites et risques connus

**Sécurité**

1. **Aucun audit externe** (inchangé).
2. **Key Transparency sans auditeurs** : le client vérifie preuves et ajout seul, et son
   propre enregistrement à chaque connexion ; mais un serveur qui maintiendrait
   **durablement deux journaux** (vue divisée) n'est détectable que par comparaison des
   racines entre clients ou par un auditeur indépendant — non fourni en Phase 3 (racines
   signées et témoins croisés entre sites : Phase 4). La clé VRF est mémorisée au premier
   usage.
3. **Client web** : le code est servi par le serveur à chaque visite ; **un serveur compromis
   peut servir un client piégé** (limite fondamentale du chiffrement de bout en bout sur le
   web). Pas de passkeys ni d'anti-capture (flou dissuasif seulement) ; effacement de la
   mémoire non garanti dans un navigateur ; coffre Argon2id allégé (32 Mio) ; écritures
   IndexedDB différées. **Mode d'appoint** : le desktop reste recommandé.
4. **Tor** : l'**amorçage réel n'a pas pu être testé dans cet environnement** (réseau Tor
   bloqué) ; il est exercé par un job CI informatif et par la recette Windows (points 24 à 27).
   Ponts et transports enfichables non intégrés (Tor bloqué ⇒ pas de connexion en mode
   strict, par construction). Un logiciel malveillant dans la session de l'utilisateur
   pourrait lire les identifiants du proxy en mémoire (il pourrait de toute façon lire les
   messages déchiffrés).
5. **Service onion** : fichiers de déploiement fournis mais **non exécutés ici** (pas de
   Docker dans cet environnement) ; Onionbalance (haute disponibilité) en Phase 4.
6. **Épinglage TLS** : desktop uniquement ; une erreur d'empreinte bloque la connexion
   (volontairement).
7. **Appareils** : perdre l'appareil principal empêche de lier de nouveaux appareils et
   d'administrer ses groupes (réinitialisation par un administrateur). Un appareil révoqué
   **hors ligne** garde les messages déjà reçus ; il ne reçoit plus rien dès la révocation, et
   son retrait MLS de chaque groupe attend que l'appareil principal de l'administrateur du
   groupe se synchronise. Pas d'historique sur un appareil nouvellement lié.
8. **Changer `MSG_SERVER_SECRET`** rend le journal KT impossible à rejouer (le serveur refuse
   alors de servir KT) : rotation du secret = procédure à définir (Phase 4).
9. Licence `Unlicense` ajoutée à la liste autorisée (dépendance d'arti, domaine public).

**Fonctionnel et performances**

10. Journal KT : une époque par modification d'appareils ; rejeu au démarrage
    proportionnel au nombre d'époques ; répertoire en mémoire. Adapté à un site de taille
    modeste ; compaction et stockage persistant à évaluer en Phase 4.
11. Base web : instantané entier réécrit à chaque modification (historiques très longs plus
    lents dans le navigateur).
12. Tickets WebSocket et journal KT tenus par **une seule instance** du serveur (bus
    inter-instances : Phase 4).
13. Le `.exe` grossit avec arti (Tor complet embarqué).

**Livraison**

14. Binaires toujours **non signés** (Authenticode, Phase 5).
15. Recette manuelle Windows à faire : points 24 à 30 de la
    [recette](../guides/recette-windows.md#phase-3) (Tor réel, service onion, liaison
    navigateur ↔ desktop).
