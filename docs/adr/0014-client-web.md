# ADR-0014 — Client web : même cœur Rust en WASM, stockage chiffré dans IndexedDB

- **Statut** : Acceptée (Phase 3)
- **Date** : 2026-11-25

## Contexte

Le client web doit être interopérable avec le desktop (ADR-0001). SQLCipher
n'existe pas dans le navigateur ; un navigateur ne peut pas signer les
en-têtes de l'ouverture d'un WebSocket ; le code du client web est servi par
le serveur à chaque visite.

## Décision

- `msg-client-core` compile pour `wasm32-unknown-unknown` : **même code**
  (MLS, certificats, Key Transparency, numéros de sécurité) ; seules la
  base locale, l'horloge et le transport changent selon la cible.
- Base locale web (`store_mem`) : même interface que la base SQLCipher ;
  données en mémoire, persistées sous forme d'un **instantané chiffré**
  (XChaCha20-Poly1305) dont la clé est enveloppée par le mot de passe
  (Argon2id, 32 Mio, 3 passes). La page ne stocke dans IndexedDB que ces
  octets chiffrés.
- Transport : `fetch` (même origine) ; WebSocket de notification ouvert avec
  un **ticket** à usage unique (30 s) obtenu par une requête signée.
- Le serveur sert lui-même le client web (`MSG_WEB_DIR`) : aucune ressource
  tierce, CSP stricte (`script-src 'self' 'wasm-unsafe-eval'`,
  `connect-src 'self'`, `frame-ancestors 'none'`), pas de CORS.
- Mode Tor strict du web : `MSG_WEB_ONION_ONLY` — la page refuse de
  fonctionner hors d'une adresse `.onion` (Tor Browser).

## Conséquences

+ Interopérabilité par construction, vérifiée en CI dans Chromium.
− Limite fondamentale : un serveur compromis peut servir un client web
  piégé. Le client web est un mode d'appoint ; le desktop reste recommandé.
− Pas de passkeys ni d'anti-capture dans le navigateur (flou dissuasif
  seulement) ; écritures IndexedDB différées (une fermeture brutale de
  l'onglet peut perdre la dernière modification locale, jamais la cohérence
  cryptographique : le serveur conserve les messages non acquittés).
