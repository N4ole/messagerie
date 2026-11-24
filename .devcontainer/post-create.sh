#!/usr/bin/env bash
# Installe les dépendances de développement (Linux) : WebKitGTK pour Tauri,
# cible WASM, pnpm et dépendances JavaScript.
set -euo pipefail
sudo apt-get update
sudo apt-get install -y --no-install-recommends libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev libayatana-appindicator3-dev postgresql-client
rustup toolchain install
corepack enable
pnpm install --frozen-lockfile
pnpm build:ui
echo "Prêt : cargo test --workspace && pnpm test"
