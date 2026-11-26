#!/bin/sh
# Sauvegarde chiffrée de la base : pg_dump (format personnalisé) chiffré avec
# age (X25519 + ChaCha20-Poly1305, https://age-encryption.org) vers une ou
# plusieurs clés PUBLIQUES. L'hôte de sauvegarde ne détient jamais la clé
# privée : une sauvegarde volée est inexploitable.
#
# Variables :
#   PGHOST, PGPORT, PGUSER, PGDATABASE, PGPASSWORD(_FILE)  connexion PostgreSQL
#   BACKUP_DIR           répertoire de destination (défaut /backups)
#   BACKUP_RECIPIENTS    fichier de destinataires age (une clé « age1… » par ligne)
#   BACKUP_KEEP          nombre de sauvegardes conservées (défaut 14)
set -eu
umask 077
: "${BACKUP_DIR:=/backups}"
: "${BACKUP_KEEP:=14}"
: "${BACKUP_RECIPIENTS:?fichier de destinataires age requis}"
if [ -z "${PGPASSWORD:-}" ] && [ -n "${PGPASSWORD_FILE:-}" ]; then
  PGPASSWORD=$(cat "$PGPASSWORD_FILE"); export PGPASSWORD
fi
grep -q '^age1' "$BACKUP_RECIPIENTS" || { echo "aucune clé publique age dans $BACKUP_RECIPIENTS" >&2; exit 1; }
mkdir -p "$BACKUP_DIR"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
out="$BACKUP_DIR/messagerie-$stamp.dump.age"
tmp="$out.partiel"
# Pas de fichier en clair sur disque : le flux est chiffré à la volée.
pg_dump --format=custom --no-owner --no-privileges | age --encrypt --recipients-file "$BACKUP_RECIPIENTS" > "$tmp"
mv "$tmp" "$out"
sha256sum "$out" > "$out.sha256"
echo "sauvegarde écrite : $out ($(wc -c < "$out") octets)"
# Rotation : conserver les BACKUP_KEEP plus récentes.
ls -1t "$BACKUP_DIR"/messagerie-*.dump.age | tail -n +"$((BACKUP_KEEP + 1))" | while read -r old; do
  rm -f "$old" "$old.sha256"
done
