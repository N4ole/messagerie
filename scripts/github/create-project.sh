#!/usr/bin/env bash
# Crée le tableau GitHub Projects « Roadmap » et une issue par phase.
# Prérequis : gh auth refresh -s project
# Usage : scripts/github/create-project.sh [owner] [owner/repo]
set -euo pipefail
OWNER="${1:-N4ole}"
REPO="${2:-N4ole/messagerie}"
NUM=$(gh project create --owner "$OWNER" --title "Messagerie — Roadmap" --format json --jq .number)
echo "Projet n°$NUM créé."
for p in \
  "Phase 2 — Sécurité avancée|Groupes MLS, pièces jointes (EXIF supprimé, noms chiffrés), QR code, alerte de changement de clé, éphémères, anti-capture, verrouillage auto, Passkeys/YubiKey, TPM, rotation." \
  "Phase 3 — Réseau & web|Tor (arti, mode strict), client web WASM interopérable, Key Transparency (akd), révocation cryptographique des appareils." \
  "Phase 4 — Multi-site & infra|Fédération sur liste blanche, réplication, HA, file store-and-forward, Docker/K8s/Helm/VM, sauvegardes, Prometheus/Grafana." \
  "Phase 5 — Durcissement|Signature Authenticode, intégrité au démarrage, builds reproductibles, revue de sécurité, fuzzing, tests de pénétration de base."; do
  title="${p%%|*}"; body="${p#*|}"
  url=$(gh issue create --repo "$REPO" --title "$title" --body "$body" --label roadmap 2>/dev/null || gh issue create --repo "$REPO" --title "$title" --body "$body")
  gh project item-add "$NUM" --owner "$OWNER" --url "$url"
done
