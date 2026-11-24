# ADR-0007 — Authentification : Argon2id + TOTP + WebAuthn, OPAQUE en option

- **Statut** : Acceptée (validation de la Phase 0)
- **Date** : 2026-11-24

## Contexte

Comptes créés par admin ; exigence d'Argon2id côté serveur ; second facteur TOTP et passkeys.

## Décision

Phase 1 : mot de passe envoyé sur canal TLS (+ Tor), haché Argon2id côté serveur (paramètres OWASP, sel unique, *pepper* hors BDD) ; TOTP obligatoire par défaut. Phase 2 : WebAuthn (`webauthn-rs`) comme second facteur ou facteur principal. Jetons d'accès courts liés à la clé d'appareil (requêtes signées). Proposition Phase 5 : OPAQUE (`opaque-ke`) pour que le serveur ne reçoive jamais le mot de passe.

## Conséquences

+ Conforme à la consigne ; durcissement progressif.
− Tant qu'OPAQUE n'est pas en place, un serveur compromis *au moment de la connexion* voit le mot de passe (mais pas les clés E2EE, qui n'en dérivent pas).
