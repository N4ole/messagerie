#!/bin/sh
# Génère les secrets locaux du déploiement Compose (fichiers 0600, jamais
# commités). Ne remplace jamais un secret existant : MSG_SERVER_SECRET est
# la racine des jetons et de la clé de fédération du site.
set -eu
dir=$(cd "$(dirname "$0")" && pwd)/secrets
mkdir -p "$dir"; chmod 700 "$dir"; umask 077
gen() { [ -s "$dir/$1" ] || { eval "$2" > "$dir/$1"; echo "créé : secrets/$1"; }; }
gen db_password "openssl rand -hex 24"
gen server_secret "openssl rand -hex 32"
gen metrics_token "openssl rand -hex 32"
gen grafana_password "openssl rand -base64 24"
[ -s "$dir/database_url" ] || { printf 'postgres://messagerie:%s@db:5432/messagerie\n' "$(cat "$dir/db_password")" > "$dir/database_url"; echo "créé : secrets/database_url"; }
[ -s "$dir/backup-recipients.txt" ] || echo "À FAIRE : placer la clé publique age (age1…) dans secrets/backup-recipients.txt (clé privée conservée HORS de cet hôte)"
[ -s "$dir/tls.pem" ] || echo "À FAIRE : placer certificat + clé privée TLS (PEM concaténés) dans secrets/tls.pem"
