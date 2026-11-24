#!/usr/bin/env bash
# Applique les rulesets du dépôt (droits d'administration requis).
# Usage : scripts/github/apply-rulesets.sh [owner/repo]
set -euo pipefail
REPO="${1:-N4ole/messagerie}"
DIR="$(cd "$(dirname "$0")/../../.github/rulesets" && pwd)"
for f in "$DIR"/*.json; do
  echo "→ $(basename "$f")"
  gh api -X POST "repos/$REPO/rulesets" --input "$f" >/dev/null
done
echo "Rulesets appliqués. Vérifiez : https://github.com/$REPO/settings/rules"
