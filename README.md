# Messagerie sécurisée multi-site

Messagerie chiffrée de bout en bout, disponible en **application Windows (`.exe`)** et en **client web** interopérables, avec serveurs fédérés multi-sites.

> **État : Phase 3 — Réseau et web livrée** (client web WASM interopérable avec le desktop, Key Transparency, appareils multiples et révocation, Tor embarqué en mode strict, épinglage TLS, service onion). Voir les rapports de [Phase 1](docs/phases/phase-1.md), [Phase 2](docs/phases/phase-2.md) et [Phase 3](docs/phases/phase-3.md) et leurs **limites connues**. Aucun audit externe : ne pas utiliser pour des usages à haut risque.

## Démarrage rapide

```bash
pnpm install --frozen-lockfile && pnpm build:ui
DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres cargo test --workspace
pnpm test
pnpm build:web   # client web (nécessite wasm-bindgen-cli 0.2.130)
```

- [Guide de développement](docs/guides/developpement.md) — build, tests, serveur local, `.exe`
- [Guide d'administration](docs/guides/administration.md) — création des comptes
- [Configuration de GitHub](docs/guides/github-setup.md) — réglages à activer
- [Recette Windows](docs/guides/recette-windows.md) — vérifications manuelles

## Documents de conception

| # | Document | Contenu |
|---|---|---|
| 01 | [Architecture et choix techniques](docs/conception/01-architecture.md) | Vue d'ensemble, stack justifiée, écarts vs la stack suggérée, ce que voit le serveur |
| 02 | [Protocole cryptographique](docs/conception/02-protocole-crypto.md) | MLS + KEM hybride post-quantique, rotation, anti-rejeu, KT, QR, pièces jointes, éphémères |
| 03 | [Modèle de menace STRIDE](docs/conception/03-modele-de-menace.md) | Actifs, adversaires, frontières de confiance, menaces par composant |
| 04 | [Schémas de flux](docs/conception/04-flux.md) | Activation de compte, envoi, fédération, révocation, démarrage Tor strict |
| 05 | [Arborescence du dépôt](docs/conception/05-arborescence.md) | Structure cible et phase d'apparition |
| 06 | [Exigences, faisabilité et limites](docs/conception/06-exigences-et-limites.md) | **Ce qui est irréalisable ou partiel**, et pourquoi |
| 07 | [Exploitation de GitHub](docs/conception/07-github.md) | Actions, Releases, attestations, CodeQL, rulesets… |
| 08 | [Feuille de route et décisions à valider](docs/conception/08-roadmap.md) | Critères d'acceptation par phase, questions ouvertes |
| — | [ADR](docs/adr/) | Décisions d'architecture |
| — | [Sonde MLS/X-Wing/WASM](spikes/mls-xwing-wasm/) | Preuve exécutable (Phase 0, historique — voir ADR-0011) |

## Sécurité

Signalement des vulnérabilités : voir [SECURITY.md](SECURITY.md).

## Licence

[MIT](LICENSE).
