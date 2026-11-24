# ADR-0011 — Fournisseur RustCrypto et suite ML-KEM-768 + X25519

- **Statut** : Acceptée (Phase 1) — remplace la suite proposée dans ADR-0002
- **Date** : 2026-11-24

## Contexte

La Phase 0 retenait `openmls_libcrux_crypto` 0.4 et la suite X-Wing (0x004D).
Pendant la Phase 1, `cargo deny` a signalé dans cette pile trois avis de
sécurité publiés (RUSTSEC-2026-0329, -0330, -0331) : `libcrux-kem` 0.0.9 peut
**paniquer** sur une clé hybride trop courte. Un KeyPackage malveillant
publié dans l'annuaire suffirait donc à faire planter le client (déni de
service). Les correctifs ne sont disponibles que dans des versions
*release candidate* d'OpenMLS 0.10 / `openmls_libcrux_crypto` 0.5.

## Décision

- Fournisseur **`openmls_rust_crypto` 0.6** (RustCrypto, pur Rust, compatible
  WASM), version stable sans avis de sécurité ouvert.
- Suite par défaut **`MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519`**
  (0x004F, draft-ietf-mls-pq-ciphersuites) : KEM hybride ML-KEM-768 + X25519,
  AES-128-GCM, SHA-256, Ed25519.
- Réévaluation à la sortie stable d'OpenMLS 0.10.

## Conséquences

+ Plus aucune dépendance vulnérable dans la pile MLS ; build WASM vérifié en CI.
+ Suite issue du groupe de travail MLS de l'IETF (et non d'un point de code privé).
− Point de code toujours **provisoire** : incompatibilité possible avec de
  futures versions si le brouillon change (négociation via les *capabilities*).
− RustCrypto `ml-kem` n'a pas, à notre connaissance, de vérification formelle
  comparable à libcrux ; audit externe recommandé (Phase 5).
− La sonde `spikes/mls-xwing-wasm` (Phase 0) reste en l'état, à titre historique.
