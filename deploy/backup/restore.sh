#!/bin/sh
# Restauration d'une sauvegarde chiffrée dans une base VIDE.
#   restore.sh <fichier.dump.age> <fichier d'identité age (clé privée)>
# La clé privée n'est utilisée que le temps de la restauration (poste
# d'administration ou coffre hors ligne) ; elle ne doit pas rester sur l'hôte.
set -eu
[ $# -eq 2 ] || { echo "usage : $0 <sauvegarde.dump.age> <identité age>" >&2; exit 2; }
file=$1; identity=$2
if [ -z "${PGPASSWORD:-}" ] && [ -n "${PGPASSWORD_FILE:-}" ]; then
  PGPASSWORD=$(cat "$PGPASSWORD_FILE"); export PGPASSWORD
fi
if [ -f "$file.sha256" ]; then
  (cd "$(dirname "$file")" && sha256sum -c "$(basename "$file").sha256") >/dev/null || { echo "empreinte invalide" >&2; exit 1; }
fi
tables=$(psql -tAc "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public'")
if [ "$tables" != "0" ]; then
  echo "la base cible n'est pas vide ($tables tables) : restauration refusée" >&2
  exit 1
fi
# age authentifie le contenu : une sauvegarde altérée échoue au déchiffrement.
age --decrypt --identity "$identity" "$file" | pg_restore --no-owner --no-privileges --exit-on-error --dbname "${PGDATABASE:?PGDATABASE requis}"
echo "restauration terminée"
