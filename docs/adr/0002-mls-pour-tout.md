# ADR-0002 — MLS (RFC 9420) pour le 1-à-1 et les groupes

- **Statut** : Proposée (Phase 0)
- **Date** : 2026-11-24

## Contexte

La consigne propose Signal pour le 1-à-1 et MLS pour les groupes. `libsignal` est AGPL-3.0 (le dépôt est MIT), n'est pas publié sur crates.io et ne cible pas officiellement WASM.

## Décision

Utiliser **OpenMLS** pour toutes les conversations ; une conversation 1-à-1 est un groupe MLS de deux utilisateurs (et de tous leurs appareils). Suite par défaut : `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` via `openmls_libcrux_crypto` ; repli `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`. Rotation forcée par commits `Update` périodiques pour la PCS.

## Conséquences

+ Licence MIT conservée ; WASM ; multi-appareils natif ; un seul protocole.
− PCS moins fine que le Double Ratchet (par commit et non par aller-retour).
− Point de code X-Wing provisoire ; signatures non post-quantiques.
− OpenMLS moins éprouvé en production que libsignal ; audit externe recommandé.
