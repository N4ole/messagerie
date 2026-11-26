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

Décision de la Phase 5 : **releases non signées pour l'instant**, mais
attestées (provenance Sigstore) et accompagnées de `SHA256SUMS`.
L'application affiche l'état de sa signature et l'empreinte de son exécutable
(⚙ Sécurité) ; une signature présente mais altérée bloque l'application.

Le workflow `release.yml` signe automatiquement dès que des secrets sont
présents dans l'environment `release-signing` :

| Secret | Contenu |
|---|---|
| `WINDOWS_CERTIFICATE_PFX_BASE64` | certificat et clé au format PFX, encodés en Base64 |
| `WINDOWS_CERTIFICATE_PASSWORD` | mot de passe du PFX |

Tauri signe alors **chaque binaire** (y compris l'exécutable contenu dans les
installeurs) via `signtool`, horodatage RFC 3161 compris, puis le workflow
vérifie toutes les signatures (`signtool verify /pa`).

**Limite** : depuis juin 2023, la clé d'un certificat de signature de code
reconnu publiquement doit rester dans un HSM : elle n'est **pas exportable en
PFX**. Le chemin PFX convient donc à un certificat d'entreprise (AC interne,
déployée sur les postes par GPO). Pour une reconnaissance publique (sans
avertissement SmartScreen), utiliser un service à HSM — Azure Artifact Signing
(ex-Trusted Signing), SignPath (offre open source) ou le HSM cloud d'une
autorité de certification — en remplaçant la commande `signCommand` construite
à l'étape « Certificat de signature » par celle du fournisseur. Aucun fichier
`.pfx` ne doit être ajouté au dépôt.

## Rulesets fournis

- **main** : PR obligatoire, 1 approbation (dont CODEOWNERS), commits signés,
  historique linéaire, checks CI requis, pas de force-push ni suppression.
- **tags `v*`** : ni suppression, ni modification.

> Avec un seul mainteneur, la revue obligatoire bloque toute fusion. Ajoutez
> un second relecteur ou retirez temporairement la règle `pull_request`.
