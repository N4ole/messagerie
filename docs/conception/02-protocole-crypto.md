# 02 — Protocole cryptographique

> Règle : **aucune primitive ni construction maison.** Tout ce qui suit est soit une primitive fournie par une bibliothèque reconnue, soit un protocole standardisé (RFC 9420, RFC 6238, WebAuthn, HPKE RFC 9180), soit une *composition* simple et documentée (signature d'un certificat, hash d'empreinte). Chaque composition est listée en §8 pour revue.

## 1. Primitives et bibliothèques

| Usage | Primitive | Bibliothèque |
|---|---|---|
| Groupes et 1-à-1 | MLS RFC 9420 | `openmls` 0.9 |
| KEM (HPKE) | Hybride ML-KEM-768 + X25519, repli X25519 | `openmls_rust_crypto` (RustCrypto : `ml-kem`, `x25519-dalek`) |
| AEAD messages | ChaCha20-Poly1305 (suite MLS) | idem |
| Signatures | Ed25519 | idem / `ed25519-dalek` pour les certificats d'appareil |
| Pièces jointes | XChaCha20-Poly1305, clé aléatoire par fichier, découpage en blocs de 64 Kio avec construction STREAM | `chacha20poly1305` (RustCrypto) — STREAM via `aead::stream` |
| Hachage / empreintes | SHA-256, SHA-512 | `sha2` |
| Dérivation mot de passe | Argon2id (m=64 Mio, t=3, p=1 desktop ; ajusté web) | `argon2` |
| Dérivation de clés | HKDF-SHA256 | `hkdf` |
| BDD locale | SQLCipher 4 (AES-256-CBC + HMAC-SHA512 par page) | `rusqlite` |
| Effacement | `Zeroize`, `ZeroizeOnDrop`, `secrecy::SecretBox` | `zeroize`, `secrecy` |
| Key Transparency | Arbre de Merkle préfixe + VRF | `akd` |
| TOTP | RFC 6238, SHA-1/30 s/6 chiffres (compatibilité applis) | `totp-rs` |
| WebAuthn | FIDO2 / CTAP2 | `webauthn-rs` (serveur), `webauthn.dll` (desktop), API navigateur (web) |
| Aléa | OS CSPRNG | `getrandom` (feature `js` en WASM → `crypto.getRandomValues`) |

## 2. Suites MLS

- **Par défaut** : `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519` (0x004F, draft-ietf-mls-pq-ciphersuites). *(révisé en Phase 1, voir ADR-0011)*
- **Repli** (si une limite apparaît en WASM ou si le point de code provisoire change) : `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` (0x0003, suite obligatoire du RFC).
- Un groupe n'a qu'une suite ; un changement de suite = nouveau groupe (migration gérée par le client).

> Attention : 0x004F n'est pas un point de code IANA définitif. Si le brouillon IETF évolue, les clients de versions différentes ne seront pas compatibles sur cette suite ; la négociation se fait via les *capabilities* des KeyPackages.

## 3. Cycle de vie d'une conversation

1. Alice récupère sur le serveur un **KeyPackage** à usage unique pour chaque appareil de Bob (+ ses autres appareils à elle). Le serveur supprime chaque KeyPackage dès qu'il est distribué (anti-réutilisation) ; un KeyPackage « de dernier recours » est conservé par appareil.
2. Alice vérifie pour chaque KeyPackage :
   - la signature du certificat d'appareil par la **clé d'identité** de Bob ;
   - que cette clé d'identité correspond à celle **déjà connue** (sinon alerte, §6) ;
   - la **preuve KT** que (Bob → identité, appareils) est bien dans le journal publié.
3. Alice crée le groupe MLS, *commit* l'ajout des appareils, envoie le `Welcome` (chiffré HPKE vers chaque KeyPackage).
4. Les messages applicatifs sont des `PrivateMessage` MLS : chiffrés **et signés** (le contenu encadré est signé par la clé de feuille de l'expéditeur avant chiffrement — c'est la « signature cryptographique de chaque message » exigée).

## 4. Rotation automatique des clés

| Élément | Politique (configurable par l'admin du site) |
|---|---|
| Clé de chemin MLS (PCS) | Chaque appareil émet un *commit* `Update` vide au plus tard tous les **7 jours** ou tous les **100 messages envoyés**, au premier des deux |
| KeyPackages | Réapprovisionnement automatique (cible : 100 en stock) ; expiration 30 jours |
| Clé de signature d'appareil | Rotation 90 jours (nouveau certificat signé par l'identité, publié en KT) |
| Clé d'identité utilisateur | Pas de rotation automatique (casserait la vérification) ; rotation manuelle = alerte chez les contacts |
| Clé locale de BDD | Re-chiffrement (`PRAGMA rekey`) sur demande et lors d'un changement de mot de passe |
| Jetons de session serveur | Accès 15 min, rafraîchissement à rotation, durée absolue 12 h (configurables) |

## 5. Anti-rejeu et anti-MITM

- **MLS** : chaque message porte (`epoch`, `generation`) ; les clés de message sont effacées après usage → un rejeu ne déchiffre pas ; le client rejette tout `generation` déjà consommé et tout `epoch` trop ancien (fenêtre : 1 époque passée, 1000 générations hors-ordre max).
- **Horodatage signé** : le contenu applicatif chiffré contient `sent_at` (horloge expéditeur) et un identifiant de message aléatoire de 128 bits ; le client rejette les doublons et signale les écarts > 24 h.
- **API serveur** : requêtes liées à l'appareil — chaque requête sensible est signée par la clé d'appareil sur (`méthode`, `chemin`, `hash du corps`, `nonce`, `horodatage`) ; le serveur refuse nonce réutilisé ou horodatage hors ±60 s. (Composition de type DPoP, cf. RFC 9449, adaptée à Ed25519.)
- **Transport** : TLS 1.3 (rustls) avec **épinglage** de la clé publique serveur livrée dans la configuration du client ; au-dessus de Tor, l'adresse .onion authentifie déjà le service, TLS reste en défense en profondeur.
- **MITM sur les clés** : Key Transparency + vérification QR + alerte de changement (§6, §7).

## 6. Détection de changements suspects de clés

Le client conserve, par contact, `(empreinte identité, liste d'appareils, version KT vue)`.

| Événement | Réaction |
|---|---|
| Nouvel appareil certifié par la **même** identité | Notification discrète dans la conversation |
| **Changement de clé d'identité** | Bannière rouge ; si le contact était « vérifié », **envoi bloqué** jusqu'à nouvelle vérification ou acceptation explicite |
| Preuve KT invalide / journal non append-only (fork) | **Blocage** de la conversation + alerte « serveur potentiellement compromis » |
| Appareil retiré d'un groupe sans commit de l'utilisateur concerné ni révocation admin | Avertissement |
| Rafale de changements d'appareils (> 3 / 24 h) | Avertissement |

## 7. Vérification d'identité par QR code

- **Safety number** = pour chacun des deux utilisateurs : `SHA-512` itéré (5200 itérations, construction de l'empreinte Signal publiquement documentée) sur `version ‖ clé_identité ‖ identifiant`, tronqué à 30 chiffres ; concaténation triée des deux.
- Le **QR** encode `version ‖ empreinte_A ‖ empreinte_B` ; le scan compare localement. Vérification aussi possible à voix haute (60 chiffres).
- Le statut « vérifié » est stocké localement et synchronisé entre les appareils de l'utilisateur via un message MLS à soi-même.

## 8. Compositions à faire relire (Phase 5)

Liste exhaustive des endroits où nous assemblons des primitives :
1. Certificat d'appareil signé par la clé d'identité utilisateur.
2. Signature des requêtes API (type DPoP).
3. Enveloppe de la clé maîtresse locale (TPM/DPAPI/Argon2id).
4. Chiffrement des pièces jointes (clé aléatoire + STREAM) et transport de la clé dans le message MLS.
5. Calcul du safety number.
6. Remplissage (padding) des messages par paliers.

## 9. Messages éphémères et suppression programmée

- Le délai d'expiration est **dans le contenu chiffré** (le serveur ne le connaît pas) + un `delete_after` serveur grossier (arrondi à l'heure) pour purger les blobs non retirés.
- Le client supprime le message (et la pièce jointe locale) à expiration, puis exécute `VACUUM`/`secure_delete` SQLCipher.
- Le serveur supprime chaque blob dès que **tous** les appareils destinataires ont acquitté, et dans tous les cas après la rétention maximale (30 jours par défaut).
- **Limite** : impossible d'empêcher un destinataire de copier/photographier un message, ni un client modifié d'ignorer le délai.

## 10. Pièces jointes

1. Lecture du fichier → si image : **décodage + ré-encodage** par `msg-media` (supprime EXIF/GPS/XMP/IPTC/profils, corrige l'orientation) ; autres formats : envoyés tels quels, l'UI avertit que les métadonnées internes (PDF, DOCX…) ne sont pas nettoyées.
2. Génération de la miniature côté client.
3. Chiffrement fichier + miniature avec deux clés aléatoires distinctes.
4. Upload des blobs (nom aléatoire côté serveur, taille arrondie au palier supérieur).
5. Le message MLS contient : `{nom de fichier, MIME, taille réelle, clé, hash, id de blob, miniature chiffrée}` — donc **nom et miniature chiffrés**.
