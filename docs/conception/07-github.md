# 07 — Exploitation de GitHub

| Fonctionnalité | Mise en œuvre | Fichier(s) | Phase | Action manuelle requise |
|---|---|---|---|---|
| CI (lint, tests, audit) | `ci.yml` : `cargo fmt --check`, `clippy -D warnings`, `cargo test` (Linux + Windows), build `wasm32`, `cargo deny`, `cargo audit`, `pnpm lint/test`, tests d'intégration PostgreSQL (service container) | `.github/workflows/ci.yml` | 1 | — |
| CD `.exe` | `release.yml` sur tag `v*` : build Tauri sur `windows-latest` → MSI + NSIS + portable `.exe`, signature, checksums, attestation, publication | `.github/workflows/release.yml` | 1 (non signé) / 5 (signé) | Certificat de signature |
| Releases | Notes générées (`generate_release_notes`), `SHA256SUMS`, `SHA256SUMS.sig` (cosign keyless) | idem + `.github/release.yml` (catégories) | 1 | — |
| Attestations SLSA | `actions/attest-build-provenance` sur binaires et images | idem | 1 | Dépôt public ou GHEC |
| GHCR | `docker.yml` : images `ghcr.io/n4ole/messagerie-server` multi-arch, signées et attestées | `.github/workflows/docker.yml` | 1 | — |
| CodeQL | Analyse Rust + JavaScript/TypeScript + Actions | `.github/workflows/codeql.yml` | 1 | — |
| Secret scanning + push protection | Paramètre du dépôt | `docs/guides/github-setup.md` | 1 | Activer dans *Settings → Code security* |
| Dependabot | Cargo, npm, GitHub Actions, Docker — hebdomadaire, groupé | `.github/dependabot.yml` | 1 | Activer les alertes |
| Rulesets | `main` : PR obligatoire, 1 revue, CI verte, commits signés, historique linéaire, pas de force-push ; tags `v*` protégés | `.github/rulesets/*.json` + script `gh api` | 1 | Import par un admin |
| Environments | `release-signing` (relecteur requis, branche `main`/tags uniquement) contenant les secrets de signature | doc | 1 | Création + secrets |
| Pages | Documentation (mdBook) + démo statique du client web (Phase 3) | `.github/workflows/pages.yml`, `docs/site/` | 1 / 3 | Activer Pages (source : Actions) |
| Templates | Bug, fonctionnalité, (vulnérabilité → renvoi vers *private vulnerability reporting*) | `.github/ISSUE_TEMPLATE/*`, `PULL_REQUEST_TEMPLATE.md` | 1 | — |
| SECURITY.md | Politique de divulgation, *private vulnerability reporting* | `SECURITY.md` | 1 | Activer le signalement privé |
| CODEOWNERS | Crates crypto et workflows : revue obligatoire du propriétaire | `.github/CODEOWNERS` | 1 | — |
| Projects | Tableau « Roadmap » (champs Phase, Priorité) | `scripts/github/create-project.sh` | 1 | Lancer le script |
| Codespaces | Rust stable + `wasm32`, `wasm-pack`, Node 22 + pnpm, PostgreSQL en service, extensions VS Code | `.devcontainer/` | 1 | — |

## Règles de durcissement des workflows

- Toutes les actions tierces **épinglées par SHA** de commit (Dependabot les met à jour).
- `permissions: {}` au niveau du workflow, élargies par job au strict nécessaire (`contents: read` par défaut ; `id-token: write` + `attestations: write` seulement pour la release).
- Aucun secret exposé aux workflows déclenchés par `pull_request` venant de forks ; pas de `pull_request_target`.
- La signature de code n'est possible que dans le job lié à l'*environment* `release-signing`.
