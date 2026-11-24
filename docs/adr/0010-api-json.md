# ADR-0010 — API en JSON versionné plutôt qu'en Protobuf

- **Statut** : Acceptée (Phase 1)
- **Date** : 2026-11-24

## Contexte

La conception initiale prévoyait Protobuf (`prost`). `prost-build` exige le
compilateur `protoc` dans tous les environnements de build (Windows, WASM,
CI, devcontainer), et le client web (Phase 3) devra parler la même API depuis
le navigateur.

## Décision

API REST en **JSON** (`serde`), routes préfixées par `/v1`, types définis une
seule fois dans `crates/msg-proto` et partagés par le serveur, le client natif
et (Phase 3) le module WASM. Les octets (clés publiques, signatures, messages
MLS chiffrés) sont encodés en Base64. Les messages MLS eux-mêmes restent
sérialisés au format TLS du RFC 9420 : le JSON ne transporte que des blobs
opaques.

## Conséquences

+ Aucun outil externe au build ; débogage simple ; natif dans le navigateur.
+ Un seul crate de types, compilé et testé pour les trois cibles.
− Messages ~33 % plus volumineux (Base64) que du binaire.
− Pas de schéma indépendant du langage : si un client non-Rust apparaît, un
  schéma OpenAPI sera généré depuis `msg-proto`.
