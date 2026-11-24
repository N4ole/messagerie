# Sonde : OpenMLS + X-Wing (post-quantique hybride) en natif et en WASM

Objectif : prouver, avant de valider l'ADR-0002, que la suite
`MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` d'OpenMLS 0.9 (fournisseur
`openmls_libcrux_crypto` 0.4) fonctionne **en natif et en `wasm32-unknown-unknown`**.

Scénario (`src/lib.rs`) : Alice crée un groupe, ajoute Bob via son KeyPackage,
le `Welcome` et le message sont sérialisés (comme via le serveur), Bob
rejoint et déchiffre. Le test vérifie aussi que le clair n'apparaît pas dans
les octets transmis.

## Natif

```bash
cargo test
```

## WASM (exécuté dans Node)

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.130 --locked
RUSTFLAGS='--cfg getrandom_backend="wasm_js"' cargo build --release --target wasm32-unknown-unknown
wasm-bindgen --target nodejs --out-dir pkg target/wasm32-unknown-unknown/release/spike_mls_xwing_wasm.wasm
node -e 'console.log(require("./pkg/spike_mls_xwing_wasm.js").probe("salut depuis WASM"))'
```

## Résultat obtenu (2026-11-24, rustc 1.97.0, Node 22)

- `cargo test` : 1 test passé.
- WASM : `Bob a déchiffré : salut depuis WASM (X-Wing)`.
- Taille du `.wasm` non optimisé : ~3,4 Mo (avant `wasm-opt`) — à surveiller pour le client web.

Ce code n'est **pas** du code de production : il sera remplacé par `crates/msg-crypto` en Phase 1.
