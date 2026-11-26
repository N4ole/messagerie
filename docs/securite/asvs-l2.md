# Revue OWASP ASVS 4.0.3 — niveau 2

> Revue **interne** (Phase 5), pas un audit indépendant. Chaque ligne cite la
> preuve (code ou test automatisé). Légende : ✅ conforme · ⚠️ partiel ou
> compensé · ❌ non conforme (écart assumé) · — non applicable.

Contexte : serveur « aveugle » (API JSON, aucun cookie, aucune page rendue
côté serveur), clients desktop (Tauri) et web (WASM) partageant le même cœur
Rust ; contenu chiffré de bout en bout (MLS).

## V1 — Architecture et modélisation des menaces

| # | Exigence (résumé) | État | Preuve |
|---|---|---|---|
| 1.1.2 | Modélisation des menaces à chaque évolution | ✅ | `docs/conception/03-modele-de-menace.md` (STRIDE), revu à chaque phase |
| 1.1.4 | Frontières de confiance documentées | ✅ | `01-architecture.md`, ADR-0004, ADR-0009 |
| 1.4.1 | Contrôle d'accès appliqué côté serveur de confiance | ✅ | `server/msg-server/src/auth.rs` (middleware), `tests/phase5.rs` |
| 1.6.1 | Politique de gestion des clés documentée | ✅ | `02-protocole-crypto.md`, ADR-0005, ADR-0016, [revue des compositions](revue-crypto.md) |
| 1.9.1 | Communications chiffrées entre composants | ✅ | TLS (HAProxy/Ingress), Tor ; réseaux internes Docker/NetworkPolicy |
| 1.14.6 | Pas de technologie côté client obsolète | ✅ | aucun plugin ; CSP stricte |

## V2 — Authentification

| # | Exigence | État | Preuve |
|---|---|---|---|
| 2.1.1 | Mot de passe ≥ 12 caractères | ✅ | `msg_proto::validate_password` (12 à 256) |
| 2.1.2–2.1.4 | Longueur ≥ 64 autorisée, tout Unicode, pas de troncature | ✅ | idem (256 caractères, Argon2id sur l'UTF-8 complet) |
| 2.1.7 | Vérification contre des mots de passe compromis | ❌ | non implémenté : un service en ligne (HIBP) violerait « zéro télémétrie » ; compensé par 12 caractères minimum, second facteur **obligatoire**, verrouillage et Argon2id |
| 2.1.9 | Pas de règles de composition | ✅ | longueur seule (NIST SP 800-63B) |
| 2.2.1 | Anti-automatisation (force brute) | ✅ | verrouillage après 5 échecs / 15 min (`e2e.rs::authentication_rules`), débit HAProxy, Argon2id |
| 2.2.3 | Notification des événements sensibles | ⚠️ | nouvel appareil : approbation sur l'appareil principal ; pas de notification hors bande (aucun e-mail par conception) |
| 2.4.1 | Stockage des mots de passe résistant au cassage | ✅ | Argon2id m = 64 Mio, t = 3 + poivre dérivé du secret serveur (`passwords.rs`) |
| 2.5.1–2.5.2 | Activation par secret à usage unique, sans secret par défaut | ✅ | codes d'activation aléatoires, usage unique, expiration 72 h (`e2e.rs`) |
| 2.5.4 | Pas de comptes partagés ou par défaut | ✅ | `bootstrap-admin` unique, refusé s'il existe un administrateur |
| 2.5.6 | Récupération sans révéler le mot de passe | ✅ | réinitialisation par l'administrateur uniquement (nouveau code d'activation) |
| 2.7.x / 2.8.x | Second facteur | ✅ | TOTP obligatoire (RFC 6238, rejeu du même pas refusé), WebAuthn/FIDO2 (`e2e.rs::passkey_second_factor`) |
| 2.8.4 | TOTP à usage unique dans sa fenêtre | ✅ | `totp_last_step` en base (`e2e.rs`) |
| 2.9.x | Authentification par clé d'appareil | ✅ | requêtes signées Ed25519 (`request.rs`), certificat d'appareil signé par la clé d'identité |
| — | Aucune énumération de comptes | ✅ | `tests/phase5.rs::no_account_enumeration`, hachage factice à temps constant |

## V3 — Gestion des sessions

| # | Exigence | État | Preuve |
|---|---|---|---|
| 3.1.1 | Jeton jamais dans l'URL | ⚠️ | jetons en en-tête ; seul le **ticket WebSocket** (usage unique, 30 s, haché en base) passe en paramètre, faute d'en-tête possible dans un WebSocket navigateur |
| 3.2.1–3.2.3 | Jetons aléatoires ≥ 128 bits, nouveaux à chaque connexion | ✅ | 256 bits (`passwords.rs`), stockés hachés |
| 3.3.1 | Déconnexion invalidant la session | ✅ | `tests/phase5.rs::tokens_are_bound_to_devices_and_requests` |
| 3.3.2 | Expiration (inactivité et absolue) | ✅ | accès 15 min, session 12 h absolue, verrouillage automatique du client |
| 3.3.4 | L'utilisateur peut fermer ses autres sessions | ✅ | liste et révocation des appareils |
| 3.4.x | Cookies | — | aucun cookie |
| 3.5.2 | Jetons liés à un secret de l'appareil | ✅ | chaque requête signée par la clé d'appareil ; jeton volé inutilisable seul (`phase5.rs`) |
| 3.5.3 | Jetons sans état signés et vérifiés | — | jetons opaques en base |
| 3.7.1 | Réauthentification avant opération sensible | ⚠️ | liaison d'appareil : mot de passe + second facteur + approbation ; révocation d'appareil et gestion des passkeys sans réauthentification (session déjà liée à l'appareil, verrouillage local) |

## V4 — Contrôle d'accès

| # | Exigence | État | Preuve |
|---|---|---|---|
| 4.1.1–4.1.3 | Contrôles côté serveur, moindre privilège, refus par défaut | ✅ | routeur : `public` / `signed` / `protected` / `federation` (`routes/mod.rs`) |
| 4.2.1 | Protection contre les IDOR | ✅ | appareils, file, liaisons filtrés par compte ; révocation d'un appareil tiers ⇒ 404 (`phase5.rs`) ; pièces jointes : identifiant aléatoire de 122 bits, contenu chiffré de bout en bout |
| 4.3.1 | Interfaces d'administration protégées | ✅ | rôle `admin` + 403 (`phase5.rs`) ; journal `admin_audit` |
| 4.3.2 | Pas de listage de répertoires | ✅ | `ServeDir` sans index de répertoire |

## V5 — Validation, assainissement, encodage

| # | Exigence | État | Preuve |
|---|---|---|---|
| 5.1.1–5.1.4 | Validation stricte des entrées | ✅ | types serde stricts, noms et sites validés, **fuzzing** (`fuzz/`) |
| 5.2.x | Assainissement du contenu riche | ✅ | Markdown → arbre restreint (aucun HTML, schémas `https`/`http`/`mailto` seulement, fuzzé), images ré-encodées (métadonnées supprimées) |
| 5.3.4 | Requêtes SQL paramétrées | ✅ | `sqlx` avec liaison de paramètres, aucune concaténation |
| 5.3.x | Encodage de sortie | ✅ | React (échappement), aucun `dangerouslySetInnerHTML` |
| 5.5.x | Désérialisation sûre | ✅ | JSON typé, MLS (OpenMLS, TLS-codec), fuzzé |

## V6 — Cryptographie stockée

| # | Exigence | État | Preuve |
|---|---|---|---|
| 6.2.1–6.2.3 | Bibliothèques reconnues, modes authentifiés | ✅ | OpenMLS, RustCrypto (XChaCha20-Poly1305, Ed25519, SHA-2, HKDF, Argon2), age ; aucune primitive maison |
| 6.2.5 | Pas d'algorithme faible | ⚠️ | TOTP HMAC-SHA-1 (exigé par la compatibilité RFC 6238 des applications d'authentification ; sûr dans ce mode) |
| 6.3.1 | Aléa cryptographique | ✅ | `getrandom` (OS) partout |
| 6.4.1–6.4.2 | Gestion des secrets, clés non exportées | ✅ | coffre local TPM/DPAPI/Argon2id, secrets serveur dérivés (HKDF, libellés distincts), fichiers secrets, zéroïsation |

## V7 — Erreurs et journalisation

| # | Exigence | État | Preuve |
|---|---|---|---|
| 7.1.1–7.1.2 | Pas de secrets ni de données personnelles dans les journaux | ✅ | journal d'accès : modèle de route, statut, durée — jamais d'IP, de chemin réel ni de corps (`logging.rs`) ; métriques testées sans données personnelles |
| 7.1.3 | Journalisation des événements de sécurité | ⚠️ | actions d'administration auditées (`admin_audit`), incohérences KT, échecs de fédération ; les échecs de connexion ne sont pas journalisés nominativement (choix de confidentialité) |
| 7.4.1 | Erreurs génériques | ✅ | codes d'erreur typés, aucun détail interne (`phase5.rs::hardening_headers_and_limits`) |

## V8 — Protection des données

| # | Exigence | État | Preuve |
|---|---|---|---|
| 8.1.1 | Pas de mise en cache des données sensibles | ✅ | `Cache-Control: no-store` partout |
| 8.2.x | Données côté client protégées | ✅ | SQLCipher (desktop), instantané chiffré IndexedDB (web), anti-capture, verrouillage automatique |
| 8.3.1 | Pas de données sensibles dans l'URL | ✅ | idem 3.1.1 |
| 8.3.4 | Minimisation | ✅ | serveur aveugle : ni contenu, ni noms de fichiers, ni groupes ; éphémères ; rétention bornée |

## V9 — Communications

| # | Exigence | État | Preuve |
|---|---|---|---|
| 9.1.1–9.1.3 | TLS partout, versions et suites robustes | ✅ | HAProxy TLS ≥ 1.2, suites AEAD, HSTS ; épinglage de clé côté desktop ; Tor (mode strict) |
| 9.2.1 | Connexions sortantes du serveur authentifiées | ✅ | fédération : liste blanche, réponses signées par la clé épinglée du pair (ADR-0009) |

## V10 — Code malveillant et chaîne d'approvisionnement

| # | Exigence | État | Preuve |
|---|---|---|---|
| 10.2.x | Pas de fonctionnalité cachée ni de télémétrie | ✅ | zéro appel tiers (tests d'interopérabilité : aucune requête vers un tiers) |
| 10.3.1 | Mises à jour signées ou vérifiées | ⚠️ | pas de mise à jour automatique ; releases attestées (Sigstore) + `SHA256SUMS` ; **non signées Authenticode** (décision Phase 5) |
| 10.3.2 | Intégrité de l'application | ✅ | vérification au démarrage (Authenticode hors ligne, empreinte) ; manifeste du client web ; **builds reproductibles** vérifiés en CI |
| 10.3.3 | Dépendances surveillées | ✅ | `cargo deny`, `pnpm audit`, Dependabot, actions épinglées par empreinte |

## V11 — Logique métier

| # | Exigence | État | Preuve |
|---|---|---|---|
| 11.1.4 | Limitation de débit | ✅ | envoi (50 / 10 s / appareil), connexion (verrouillage), HAProxy (300 / 10 s / IP, en mémoire), quotas de pièces jointes |
| 11.1.6 | Pas de condition de concurrence | ✅ | transactions PostgreSQL, verrous consultatifs (KT), `FOR UPDATE SKIP LOCKED` (fédération) |

## V12 — Fichiers

| # | Exigence | État | Preuve |
|---|---|---|---|
| 12.1.1 | Taille maximale | ✅ | 25 Mio par pièce jointe, 1 Mio par requête, quota par appareil |
| 12.3.x | Pas de chemin fourni par l'utilisateur | ✅ | identifiants aléatoires, aucun nom de fichier côté serveur |
| 12.5.1 | Fichiers servis non exécutables | ✅ | `application/octet-stream`, `nosniff`, contenu chiffré |

## V13 — API

| # | Exigence | État | Preuve |
|---|---|---|---|
| 13.1.x | Authentification et autorisation de chaque route | ✅ | `phase5.rs`, scan **ZAP actif** en CI (aucun avertissement, aucune 5xx) |
| 13.2.1 | Méthodes HTTP restreintes | ✅ | routeur axum (405) |
| 13.2.5 | Type de contenu vérifié | ✅ | extracteur JSON (415/422) |
| 13.2.6 | Pas de CORS ouvert | ✅ | aucun en-tête CORS (`phase5.rs`) |

## V14 — Configuration

| # | Exigence | État | Preuve |
|---|---|---|---|
| 14.1.x | Construction reproductible et automatisée | ✅ | `scripts/reproducible-build.sh`, workflow dédié |
| 14.2.x | Dépendances à jour, inventaire | ✅ | `Cargo.lock`, `pnpm-lock.yaml`, SBOM de l'image (BuildKit) |
| 14.3.2 | Pas de mode débogage en production | ✅ | profil release, `panic = abort`, erreurs génériques |
| 14.4.x | En-têtes de sécurité | ✅ | CSP stricte, `nosniff`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP (`routes/web.rs`, `phase5.rs`) |
| 14.5.x | Validation des en-têtes HTTP | ✅ | limites de taille, requêtes signées |

## Écarts assumés

1. **2.1.7** — pas de vérification de mots de passe compromis (exigerait un
   service en ligne ou une liste volumineuse embarquée) ; compensé par le
   second facteur obligatoire.
2. **3.7.1** — certaines opérations sensibles (révocation d'appareil,
   suppression d'une passkey) ne demandent pas de réauthentification.
3. **10.3.1** — binaires non signés Authenticode (décision de la Phase 5) ;
   workflow prêt (`docs/guides/github-setup.md`).
4. **7.1.3** — pas de journal nominatif des échecs de connexion (confidentialité).
5. Revue interne uniquement : **un audit externe reste nécessaire** avant un
   déploiement sensible.
