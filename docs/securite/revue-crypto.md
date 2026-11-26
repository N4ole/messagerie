# Revue des compositions cryptographiques (Phase 5)

> Revue **interne** des endroits où le projet assemble des primitives
> (liste du [protocole](../conception/02-protocole-crypto.md#8-compositions-à-faire-relire-phase-5),
> complétée des Phases 3 et 4). Aucune primitive n'est implémentée par le
> projet : toutes proviennent de bibliothèques reconnues (OpenMLS,
> RustCrypto, akd, age, webauthn-rs). Une relecture par un cryptographe
> indépendant reste recommandée.

Critères examinés pour chaque composition : séparation de domaine
(libellé), encodage non ambigu, liaison au contexte (qui, quoi, quand),
unicité des nonces, résistance au rejeu, comportement sur entrée hostile.

| # | Composition | Code | Verdict |
|---|---|---|---|
| 1 | Certificat d'appareil (Ed25519 par la clé d'identité) | `msg-crypto/src/identity.rs` | ✅ |
| 2 | Requêtes signées par l'appareil (type DPoP) | `msg-crypto/src/request.rs` | ✅ (remarque R1) |
| 3 | Enveloppe de la clé locale (Argon2id + XChaCha20-Poly1305, TPM/DPAPI) | `msg-crypto/src/keywrap.rs`, `msg-client-core/src/vault.rs` | ✅ **après correctif C1** |
| 4 | Pièces jointes (clé aléatoire, XChaCha20-Poly1305, empreinte) | `msg-crypto/src/attachment.rs` | ✅ |
| 5 | Numéros de sécurité | `msg-crypto/src/safety.rs` | ✅ (remarque R2) |
| 6 | Remplissage par paliers | `attachment.rs`, `app_message.rs` | ✅ (limite L1) |
| 7 | Valeur Key Transparency | `msg-kt/src/lib.rs::directory_value` | ✅ |
| 8 | Empreinte de liaison d'appareil (80 bits) | `msg-client-core/src/devices.rs` | ✅ (remarque R3) |
| 9 | Instantané chiffré de la base web | `msg-client-core/src/store_mem.rs`, `account.rs` | ✅ |
| 10 | Ticket WebSocket, épinglage TLS | `routes/ws.rs`, `msg-client-core/src/net.rs` | ✅ |
| 11 | Dérivation des secrets serveur (HKDF) | `server/msg-server/src/secrets.rs` | ✅ |
| 12 | Secret TOTP chiffré au repos | `secrets.rs::seal_totp` | ✅ |
| 13 | Requêtes et réponses de site (fédération) | `msg-crypto/src/request.rs` | ✅ (remarque R1) |
| 14 | Têtes KT signées par le site | `server/msg-server/src/federation/mod.rs` | ✅ |
| 15 | Sauvegardes (age vers clé publique) | `deploy/backup/` | ✅ |

## Détail

**1. Certificat d'appareil.** Encodage à longueurs préfixées précédé d'un
libellé (`to_be_signed`) : aucune ambiguïté entre champs ; lie nom (qualifié
`nom@site` depuis la Phase 4), identifiant d'appareil, clé API, clé de
signature MLS et date. La vérification est faite par le serveur
(enregistrement) **et** par chaque correspondant (annuaire, Key
Transparency).

**2 et 13. Requêtes signées.** Libellé distinct par usage
(`messagerie/request/v1`, `…/federation/request/v1`,
`…/federation/response/v1`) : une signature d'appareil ne peut pas servir
de signature de site, ni une requête de réponse. Lie méthode, chemin et
requête, horodatage (±60 s), nonce de 128 bits mémorisé (rejeu refusé),
identité de l'émetteur et SHA-256 du corps ; la réponse de site est liée au
nonce de la requête, à son statut et à son corps.
*R1* : les champs sont séparés par des sauts de ligne sans longueur
préfixée. C'est sans ambiguïté ici, car le seul champ libre (le chemin) ne
peut pas contenir de saut de ligne (refusé par le serveur HTTP) et les
autres ont un format fixe (entier, Base64, UUID, nom de site validé,
empreinte hexadécimale). À conserver en cas d'évolution (tout nouveau champ
libre devra être préfixé par sa longueur). Testé : `tests/phase5.rs`
(route, paramètres, méthode), `e2e.rs` (rejeu, corps, horodatage), fuzzing
`signatures`.

**3. Enveloppe de la clé locale.** KEK = Argon2id(mot de passe, sel de
128 bits) ; XChaCha20-Poly1305 avec nonce aléatoire de 192 bits ; AAD =
libellé ‖ paramètres Argon2 (une modification des paramètres rend
l'enveloppe invalide). Couche TPM/DPAPI facultative avec son propre libellé.
*C1 (corrigé)* : les paramètres lus depuis le fichier n'étaient pas bornés ;
un fichier modifié ne pouvait pas affaiblir le chiffrement (AAD), mais
pouvait imposer un coût mémoire démesuré à l'ouverture (déni de service
local). Bornes ajoutées (mémoire ≤ 1 Gio, passes ≤ 16, parallélisme ≤ 16),
test `stored_parameters_are_bounded`.

**4. Pièces jointes.** Clé aléatoire de 256 bits **par fichier** (donc
nonce aléatoire de 192 bits sans risque de collision utile), AEAD en un seul
bloc, empreinte SHA-256 et taille vérifiées au déchiffrement ; clé,
empreinte et nom de fichier transportés dans le message MLS (donc
authentifiés et chiffrés de bout en bout).

**5. Numéros de sécurité.** Construction publique du Signal Protocol
(5200 itérations de SHA-512). *R2* : clé et identifiant sont concaténés sans
longueur ; sans ambiguïté car la clé Ed25519 a une longueur fixe de
32 octets (vérifiée à la réception de l'annuaire). Entre sites, les adresses
qualifiées sont utilisées des deux côtés (numéros identiques, Phase 4).

**6. Remplissage.** Masque la taille exacte au serveur par paliers.
*L1* : les paliers laissent fuir un ordre de grandeur (voulu : compromis
bande passante / confidentialité) ; le nombre et la fréquence des messages
restent visibles.

**7. Valeur Key Transparency.** SHA-256 d'un encodage canonique à
longueurs préfixées, précédé d'un libellé de domaine, appareils triés par
identifiant ; marqueur explicite d'absence d'identité (compte réinitialisé).
Le nom d'utilisateur n'y figure pas : il est l'étiquette VRF d'akd.

**8. Empreinte de liaison.** 80 bits (SHA-256 tronqué) comparés
visuellement par l'utilisateur sur l'appareil principal. *R3* : 80 bits
suffisent contre une seconde préimage en ligne (l'attaquant doit fabriquer
des clés produisant l'empreinte affichée **pendant** la validité de la
demande) ; ce n'est pas une garantie contre une recherche hors ligne de
collisions, sans objet ici (l'empreinte est calculée sur les clés de la
demande en cours).

**9. Base web.** Même enveloppe que le coffre desktop (Argon2id allégé à
32 Mio dans le navigateur — limite documentée en Phase 3), instantané
XChaCha20-Poly1305 avec nonce aléatoire à chaque écriture.

**10. Ticket WebSocket / épinglage.** Ticket de 256 bits, usage unique,
30 s, stocké haché ; épinglage SHA-256 de la clé publique (SPKI), pas du
certificat (renouvellement à clé constante possible).

**11. Secrets serveur.** HKDF-SHA256 (sel de domaine fixe) depuis le
secret maître, un libellé par usage (`argon2-pepper`, `totp-at-rest`,
`kt-vrf`, `federation-signing`) : clés indépendantes.

**12. TOTP au repos.** XChaCha20-Poly1305, nonce aléatoire, AAD = nom du
compte (un secret ne peut pas être déplacé vers un autre compte).

**14. Têtes KT signées.** Libellé `messagerie/federation/kt-head/v1`,
lient site, époque et racine ; vérifiées avec la clé épinglée du pair ;
la cohérence entre époques est prouvée par akd (ajout seul).

**15. Sauvegardes.** age (X25519 + ChaCha20-Poly1305, spécification
publique) vers des clés publiques ; authentifie le contenu ; pas de clé
privée sur l'hôte.

## Points hors de la composition

- **MLS** (OpenMLS 0.9, suite `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519` (0x004F),
  hybride post-quantique) : utilisé tel quel ; seule la règle d'ordonnancement
  (un seul émetteur de commits, ADR-0012) est propre au projet.
- **Aléa** : `getrandom` partout (OS), aucun générateur applicatif.
- **Zéroïsation** : clés et secrets en `Zeroizing` ; non garantie dans le
  navigateur (limite Phase 3).
