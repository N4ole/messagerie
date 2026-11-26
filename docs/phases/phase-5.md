# Phase 5 — Durcissement : rapport de livraison

> Statut : **livrée, en attente de validation.**

Décisions prises au démarrage de la phase : **pas de signature Authenticode
pour l'instant** (workflow prêt, activable par secrets) ; **authentification
Argon2id conservée** (pas de migration OPAQUE).

## 1. Périmètre

| Exigence Phase 5 | État | Où |
|---|---|---|
| **Vérification d'intégrité au démarrage** | ✅ | desktop : `apps/desktop/src-tauri/src/integrity.rs`, `crates/msg-platform-win/src/integrity.rs` ; serveur : `server/msg-server/src/web_integrity.rs` |
| **Signature Authenticode effective** | ⚠️ prête, non activée (décision) | `.github/workflows/release.yml`, [guide](../guides/github-setup.md#signature-de-code-phase-5) |
| **Builds reproductibles** (serveur, WASM) | ✅ vérifiés en CI | `scripts/reproducible-build.sh`, `.github/workflows/reproducible.yml` |
| **Revue OWASP ASVS niveau 2** | ✅ (revue interne) | [docs/securite/asvs-l2.md](../securite/asvs-l2.md) |
| **Revue des compositions cryptographiques** | ✅ (revue interne, 1 correctif) | [docs/securite/revue-crypto.md](../securite/revue-crypto.md) |
| **Fuzzing** (Markdown, images, messages MLS entrants, JSON…) | ✅ | `fuzz/`, `.github/workflows/fuzz.yml` |
| **Tests de pénétration de base** (ZAP, authentification) | ✅ | job CI `zap`, `docs/api/openapi.yaml`, `server/msg-server/tests/phase5.rs` |
| **Documentation finale** | ✅ | README, guides, ADR, ce rapport |
| Migration OPAQUE (décision D2) | — non retenue (décision) | ASVS, écarts |

La conception mentionnait le fuzzing de « protobuf » : l'API est en JSON
(ADR-0010) ; ce sont donc les corps JSON (API et fédération) qui sont fuzzés.

## 2. Fichiers créés ou modifiés

```
fuzz/                                            nouveau : 7 cibles cargo-fuzz (crate hors workspace, nightly)
crates/msg-platform-win/src/integrity.rs         nouveau : WinVerifyTrust hors ligne
crates/msg-crypto/src/keywrap.rs                 correctif : bornes des paramètres Argon2 stockés
apps/desktop/src-tauri/src/{integrity.rs (nouveau), lib.rs}
server/msg-server/src/{web_integrity.rs (nouveau), main.rs, lib.rs}
server/msg-server/tests/phase5.rs                nouveau : tests d'intrusion (authentification, accès)
ui/src/{api/types.ts, components/SettingsDialog.tsx, web/backend.ts}, ui/tests/{Phase5.test.tsx, mockBackend.ts}
scripts/reproducible-build.sh                    nouveau
deploy/docker/Dockerfile.server                  manifeste d'intégrité du client web
docs/api/openapi.yaml                            nouveau : description de l'API (scan ZAP)
docs/securite/{asvs-l2.md, revue-crypto.md}      nouveaux
.github/workflows/{fuzz.yml, reproducible.yml (nouveaux), ci.yml (job zap), release.yml (signature)}
docs/conception/02-protocole-crypto.md, docs/adr/0015, guides, README, ce rapport
```

## 3. Tests

| Suite | Nombre | Nouveautés Phase 5 |
|---|---|---|
| `msg-crypto` | 30 (+1) | paramètres Argon2 hors bornes refusés à l'ouverture d'une enveloppe |
| `msg-platform-win` | 2 (+1, et +1 sous Windows) | fichier non signé reconnu ; sous Windows, binaire système signé jamais vu « altéré » |
| `messagerie-desktop` | 4 (+1) | empreinte SHA-256 ; blocage réservé aux signatures altérées |
| `msg-server` (unitaires) | 6 (+1) | manifeste du client web (fichier modifié, ajouté, supprimé détecté) |
| `msg-server` (bout en bout) | 9 + 3 + 4 + **3** | voir ci-dessous |
| UI (Vitest) | 37 (+1) | état de la signature et empreinte affichés dans « Sécurité » |
| **Fuzzing** | 7 cibles | voir ci-dessous |
| **ZAP** (CI) | scan actif | voir ci-dessous |
| **Reproductibilité** (CI) | 2 constructions | voir ci-dessous |

Tests d'intrusion (`tests/phase5.rs`, serveur réel et PostgreSQL) :

1. **`no_account_enumeration`** — connexion et activation : même statut et même message
   pour un compte existant et inexistant ; annuaire : compte inexistant et compte non activé
   indiscernables.
2. **`tokens_are_bound_to_devices_and_requests`** — jeton d'accès volé utilisé avec la
   signature d'un autre appareil ⇒ refus ; signature valide **rejouée sur une autre route**,
   avec un **paramètre de chemin** ou de **requête** modifié, ou une autre méthode ⇒ refus ;
   jeton sans signature, signature sans jeton ⇒ refus ; routes d'administration ⇒ 403 ;
   révocation de l'appareil d'un autre compte ⇒ 404 (et l'appareil reste actif) ; jeton de
   renouvellement d'un autre appareil, **déjà utilisé**, ou après déconnexion ⇒ refus ; ancien
   jeton d'accès invalidé par le renouvellement.
3. **`hardening_headers_and_limits`** — CSP, `nosniff`, `X-Frame-Options`, `Referrer-Policy`,
   `no-store` ; aucun en-tête `Server` ni CORS (y compris en pré-vol depuis une origine
   étrangère) ; corps de 2 Mio ⇒ 413 avant authentification ; JSON malformé ⇒ erreur sans
   détail interne.

Fuzzing (`fuzz/`, libFuzzer) — passe locale de 5 minutes par cible, **aucun plantage** :

| Cible | Données | Exécutions |
|---|---|---|
| `markdown` | Markdown reçu ; liens limités à `https`/`http`/`mailto`, arbre borné | 1,7 M |
| `media` | images reçues (détection, nettoyage, ré-encodage) | 44 k |
| `app_message` | messages applicatifs déchiffrés, identités MLS | 9,6 M |
| `mls_incoming` | messages MLS arbitraires traités par un client réel, KeyPackages | 5,2 M |
| `api_json` | corps JSON de l'API et de la fédération, validation des adresses | 6,3 M |
| `key_transparency` | preuves KT forgées (recherche, ajout seul) | 12,2 M |
| `signatures` | en-têtes de signature d'appareils et de sites | 8,1 M |

Le premier cas trouvé (`markdown`) était un faux positif de l'assertion (`javascript:` dans
du **texte**, affiché tel quel) : l'assertion porte désormais sur les URL des liens. En CI :
60 s par cible sur chaque PR touchant un parseur, 30 min par cible chaque semaine.

Scan ZAP actif (`zap-api-scan.py`, à partir de `docs/api/openapi.yaml`, serveur réel) :
**126 URL, 0 échec, 0 avertissement**, 114 règles passées ; **aucune réponse 5xx ni panique**
du serveur pendant l'attaque (entrées malformées : 400/422, non authentifié : 401, inconnu :
404). En CI, le job échoue au moindre avertissement.

Reproductibilité : deux constructions du même commit depuis deux copies (répertoires et
horodatages de fichiers différents) donnent un `msg-server` et un `msg_wasm.wasm`
**identiques octet pour octet** (vérifié localement, puis à chaque PR concernée en CI).

Intégrité au démarrage, vérifiée manuellement : un client web modifié après génération du
manifeste empêche le serveur de démarrer (« client web altéré (modifié : index.html) »).

## 4. Commandes

```bash
DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres cargo test --workspace
```

```bash
pnpm test
```

```bash
cd fuzz && cargo +nightly fuzz run mls_incoming -- -max_total_time=300
```

```bash
sh scripts/reproducible-build.sh check
```

Scan ZAP, manifeste du client web : [guide de développement](../guides/developpement.md#vérifications-de-sécurité-phase-5).
Signature : [configuration de GitHub](../guides/github-setup.md#signature-de-code-phase-5).

## 5. Écarts par rapport à la conception

| Écart | Raison | Trace |
|---|---|---|
| **Signature Authenticode non activée** | Décision de la phase (pas de certificat) ; workflow prêt : signature de chaque binaire et vérification dès l'ajout des secrets | `release.yml`, guide GitHub |
| **OPAQUE non retenu** | Décision de la phase (bibliothèque sans audit récent, migration de tous les comptes) | ASVS V2, écarts |
| Fuzzing du JSON au lieu de « protobuf » | L'API est en JSON (ADR-0010) | — |
| Reproductibilité **dans un environnement épinglé** (même chaîne Rust, même système hôte) | L'éditeur de liens du système entre dans le binaire du serveur : un autre système peut donner un autre binaire ; la comparaison se fait entre constructions du même environnement (CI) | §6 |
| ZAP sans authentification | Les requêtes signées par clé d'appareil ne sont pas reproductibles par ZAP ; l'authentification et le contrôle d'accès sont couverts par `tests/phase5.rs` | — |

## 6. Limites et risques connus

**Sécurité**

1. **Revue interne uniquement** : la grille ASVS et la revue des compositions ont été
   faites par le même auteur que le code. **Un audit externe** (code et cryptographie)
   reste indispensable avant un usage sensible.
2. **Binaires non signés** : SmartScreen avertit ; l'utilisateur doit vérifier
   `SHA256SUMS` et l'attestation. La vérification au démarrage ne protège pas un exécutable
   **non signé** modifié (elle ne peut que l'afficher comme non signé, avec son empreinte).
3. Une fois signé, la vérification Authenticode est faite **hors ligne** (zéro télémétrie) :
   un certificat révoqué n'est pas détecté si la révocation n'est pas déjà en cache.
4. **Manifeste du client web** : détecte une altération des fichiers déployés, pas un serveur
   entièrement compromis (qui peut réécrire le manifeste) — limite fondamentale du web.
5. Pas de vérification des mots de passe compromis (ASVS 2.1.7), pas de réauthentification
   pour la révocation d'appareil ou la suppression d'une passkey (ASVS 3.7.1).
6. Fuzzing : durées courtes (5 min locales, 30 min hebdomadaires) ; la cible `media` est
   lente (décodage d'images) et donc moins explorée. Pas de fuzzing des chemins réseau du
   serveur (couverts par ZAP et les tests).
7. Scan ZAP : couverture des routes publiques et du rejet des requêtes non authentifiées ;
   pas de scan **authentifié** (signatures d'appareil).

**Livraison et exploitation**

8. Reproductibilité vérifiée pour le serveur et le module WASM, **pas pour le `.exe`
   Windows** (outils de construction Windows non déterministes : ressources, horodatages
   des installeurs).
9. Le chart Helm n'a toujours pas été déployé sur un cluster réel (limite 10 de la
   Phase 4).
10. Recette manuelle Windows à faire : points 36 à 39 de la
    [recette](../guides/recette-windows.md#phase-5) (affichage de l'intégrité, exécutable
    signé puis altéré, absence de connexion de révocation).
