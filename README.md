# Messagerie sécurisée multi-site

Messagerie chiffrée de bout en bout, disponible en **application Windows (`.exe`)** et en **client web** interopérables, avec serveurs fédérés multi-sites.

> **État : Phase 0 — Conception.** Aucun code de production pour l'instant. Les documents ci-dessous attendent validation avant le début de la Phase 1.

## Documents de conception

| # | Document | Contenu |
|---|---|---|
| 01 | [Architecture et choix techniques](docs/conception/01-architecture.md) | Vue d'ensemble, stack justifiée, écarts vs la stack suggérée, ce que voit le serveur |
| 02 | [Protocole cryptographique](docs/conception/02-protocole-crypto.md) | MLS + X-Wing, rotation, anti-rejeu, KT, QR, pièces jointes, éphémères |
| 03 | [Modèle de menace STRIDE](docs/conception/03-modele-de-menace.md) | Actifs, adversaires, frontières de confiance, menaces par composant |
| 04 | [Schémas de flux](docs/conception/04-flux.md) | Activation de compte, envoi, fédération, révocation, démarrage Tor strict |
| 05 | [Arborescence du dépôt](docs/conception/05-arborescence.md) | Structure cible et phase d'apparition |
| 06 | [Exigences, faisabilité et limites](docs/conception/06-exigences-et-limites.md) | **Ce qui est irréalisable ou partiel**, et pourquoi |
| 07 | [Exploitation de GitHub](docs/conception/07-github.md) | Actions, Releases, attestations, CodeQL, rulesets… |
| 08 | [Feuille de route et décisions à valider](docs/conception/08-roadmap.md) | Critères d'acceptation par phase, questions ouvertes |
| — | [ADR](docs/adr/) | Décisions d'architecture |
| — | [Sonde MLS/X-Wing/WASM](spikes/mls-xwing-wasm/) | Preuve exécutable que le cœur crypto choisi fonctionne en natif et en WASM |

## Licence

[MIT](LICENSE).
