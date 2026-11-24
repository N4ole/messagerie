# ADR-0001 — Cœur client unique en Rust (natif + WASM)

- **Statut** : Acceptée (validation de la Phase 0)
- **Date** : 2026-11-24

## Contexte

Le desktop et le web doivent être interopérables et la crypto ne doit pas être réimplémentée deux fois. Les secrets doivent pouvoir être effacés de la mémoire.

## Décision

Toute la logique cryptographique et protocolaire client vit dans des crates Rust (`msg-crypto`, `msg-client-core`, …) compilées en natif pour Tauri et en `wasm32-unknown-unknown` pour le web. Les différences de plateforme passent par deux traits : `Storage` et `Transport`.

## Conséquences

+ Un seul code à auditer ; interopérabilité par construction ; `zeroize` disponible.
− Toutes les dépendances crypto doivent compiler en WASM (vérifié en CI dès la Phase 1).
− En WASM, la mémoire linéaire reste lisible par le JS de la même origine.
