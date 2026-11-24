# Contribuer

1. Ouvrez une issue (ou reprenez une issue existante) avant un changement important.
2. Environnement : Codespaces / devcontainer (`.devcontainer/`) ou voir `docs/guides/developpement.md`.
3. Avant la PR : `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`,
   `cargo test --workspace` (avec `DATABASE_URL`), `pnpm lint && pnpm test`.
4. Commits **signés** (exigés par le ruleset de `main`).

Règles non négociables : aucune cryptographie maison, aucun clair côté serveur
ni dans les journaux, aucune télémétrie, aucun appel à un service tiers.
