#!/bin/sh
# Exercice de reprise après sinistre (exécuté en CI) :
#   1. base peuplée par le serveur (migrations + administrateur) ;
#   2. sauvegarde chiffrée ; vérification qu'aucun nom n'apparaît en clair ;
#   3. restauration dans une base neuve ; comparaison table par table ;
#   4. sauvegarde altérée et mauvaise clé : restauration refusée.
# Prérequis : PostgreSQL joignable (PGHOST/PGPORT/PGUSER, droits CREATE
# DATABASE), binaires age, pg_dump, pg_restore, psql et msg-server.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
: "${MSG_SERVER_BIN:=msg-server}"
src=msg_dr_source; dst=msg_dr_restore
for db in $src $dst; do psql -q -d postgres -c "DROP DATABASE IF EXISTS $db" -c "CREATE DATABASE $db"; done
base="postgres://${PGUSER:-postgres}${PGPASSWORD:+:$PGPASSWORD}@${PGHOST:-127.0.0.1}:${PGPORT:-5432}"
MSG_SERVER_SECRET=$(openssl rand -hex 32) "$MSG_SERVER_BIN" --database-url "$base/$src" bootstrap-admin --username adminreprise > /dev/null
age-keygen -o "$work/identite.txt" 2> /dev/null
age-keygen -y "$work/identite.txt" > "$work/destinataires.txt"
PGDATABASE=$src BACKUP_DIR="$work/sauvegardes" BACKUP_RECIPIENTS="$work/destinataires.txt" sh "$here/backup.sh"
dump=$(ls "$work"/sauvegardes/*.dump.age)
if grep -q adminreprise "$dump"; then echo "ÉCHEC : nom d'utilisateur en clair dans la sauvegarde" >&2; exit 1; fi
PGDATABASE=$dst sh "$here/restore.sh" "$dump" "$work/identite.txt"
for t in $(psql -tA -d $src -c "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY 1"); do
  a=$(psql -tA -d $src -c "SELECT md5(COALESCE(string_agg(x::text, ',' ORDER BY x::text), '')) FROM \"$t\" x")
  b=$(psql -tA -d $dst -c "SELECT md5(COALESCE(string_agg(x::text, ',' ORDER BY x::text), '')) FROM \"$t\" x")
  [ "$a" = "$b" ] || { echo "ÉCHEC : table $t différente après restauration" >&2; exit 1; }
done
psql -tA -d $dst -c "SELECT username FROM accounts" | grep -qx adminreprise
# Restauration refusée : base non vide, sauvegarde altérée, mauvaise clé.
if PGDATABASE=$dst sh "$here/restore.sh" "$dump" "$work/identite.txt" 2>/dev/null; then echo "ÉCHEC : base non vide acceptée" >&2; exit 1; fi
psql -q -d postgres -c "DROP DATABASE $dst" -c "CREATE DATABASE $dst"
cp "$dump" "$work/altere.dump.age"
printf '\001' | dd of="$work/altere.dump.age" bs=1 seek=200 conv=notrunc 2>/dev/null
if PGDATABASE=$dst sh "$here/restore.sh" "$work/altere.dump.age" "$work/identite.txt" 2>/dev/null; then echo "ÉCHEC : sauvegarde altérée acceptée" >&2; exit 1; fi
age-keygen -o "$work/autre.txt" 2> /dev/null
if PGDATABASE=$dst sh "$here/restore.sh" "$dump" "$work/autre.txt" 2>/dev/null; then echo "ÉCHEC : mauvaise clé acceptée" >&2; exit 1; fi
for db in $src $dst; do psql -q -d postgres -c "DROP DATABASE $db"; done
echo "exercice de reprise réussi"
