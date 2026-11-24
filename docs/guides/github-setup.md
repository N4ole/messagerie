# Configuration du dépôt GitHub

Les éléments suivants ne peuvent pas être activés par un fichier du dépôt :
ils demandent les droits d'administration.

| Réglage | Où | Action |
|---|---|---|
| Visibilité publique (recommandée) | *Settings → General* | Rend gratuits CodeQL, secret scanning et les attestations |
| Secret scanning + push protection | *Settings → Code security* | Activer les deux |
| Signalement privé de vulnérabilités | *Settings → Code security* | Activer |
| Dependabot alerts / security updates | *Settings → Code security* | Activer |
| Rulesets (`main`, tags `v*`) | — | `scripts/github/apply-rulesets.sh` (nécessite `gh`) |
| Environment `release-signing` | *Settings → Environments* | Créer ; limiter aux tags `v*` ; relecteur requis |
| GitHub Pages | *Settings → Pages* | Source : **GitHub Actions**, puis variable de dépôt `PAGES_ENABLED=true` |
| GitHub Projects | — | `scripts/github/create-project.sh` (après `gh auth refresh -s project`) |
| Paquets GHCR | *Packages* | Après la 1re publication : visibilité du paquet `messagerie-server` |

## Signature de code (Phase 5)

Depuis juin 2023, les clés de signature de code doivent être stockées dans un
HSM : aucun fichier `.pfx` ne doit être ajouté au dépôt. Options : Azure
Artifact Signing (ex-Trusted Signing), SignPath (offre open source), ou le HSM
cloud d'une autorité de certification. Les secrets correspondants seront
placés dans l'environment `release-signing`.

## Rulesets fournis

- **main** : PR obligatoire, 1 approbation (dont CODEOWNERS), commits signés,
  historique linéaire, checks CI requis, pas de force-push ni suppression.
- **tags `v*`** : ni suppression, ni modification.

> Avec un seul mainteneur, la revue obligatoire bloque toute fusion. Ajoutez
> un second relecteur ou retirez temporairement la règle `pull_request`.
