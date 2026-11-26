#!/bin/sh
# Installation sur une VM Debian/Ubuntu (systemd ≥ 250) : binaire, unités
# durcies, secrets, PostgreSQL local, deux instances et sauvegardes.
#   sudo sh deploy/vm/install.sh <binaire msg-server> [nombre d'instances]
# Idempotent : ne régénère jamais un secret existant.
set -eu
[ "$(id -u)" = 0 ] || { echo "à exécuter en root" >&2; exit 1; }
bin=${1:?chemin du binaire msg-server}; n=${2:-2}
here=$(cd "$(dirname "$0")" && pwd)
command -v age > /dev/null || apt-get install -y age
command -v psql > /dev/null || apt-get install -y postgresql
install -m 0755 "$bin" /usr/local/bin/msg-server
install -d -m 0755 /etc/messagerie /usr/local/lib/messagerie
install -d -m 0700 /etc/messagerie/credentials
install -d -m 0700 -o postgres -g postgres /var/backups/messagerie
install -m 0755 "$here/../backup/backup.sh" "$here/../backup/restore.sh" /usr/local/lib/messagerie/
[ -f /etc/messagerie/msg-server.env ] || install -m 0644 "$here/msg-server.env.example" /etc/messagerie/msg-server.env
umask 077
c=/etc/messagerie/credentials
[ -s $c/server_secret ] || openssl rand -hex 32 > $c/server_secret
[ -s $c/metrics_token ] || openssl rand -hex 32 > $c/metrics_token
if [ ! -s $c/database_url ]; then
  pw=$(openssl rand -hex 24)
  su postgres -c "psql -q -c \"CREATE ROLE messagerie LOGIN PASSWORD '$pw'\"" 2> /dev/null || true
  su postgres -c "createdb -O messagerie messagerie" 2> /dev/null || true
  printf 'postgres://messagerie:%s@127.0.0.1:5432/messagerie\n' "$pw" > $c/database_url
fi
for i in $(seq 1 "$n"); do
  f=/etc/messagerie/instance-$i.env
  [ -f "$f" ] || printf 'MSG_BIND=127.0.0.1:%s\nMSG_METRICS_BIND=127.0.0.1:%s\n' $((8080 + i)) $((9100 + i)) > "$f"
done
install -m 0644 "$here/msg-server@.service" "$here/msg-server-backup.service" "$here/msg-server-backup.timer" /etc/systemd/system/
systemctl daemon-reload
for i in $(seq 1 "$n"); do systemctl enable --now "msg-server@$i"; done
if [ -s /etc/messagerie/backup-recipients.txt ]; then
  systemctl enable --now msg-server-backup.timer
else
  echo "À FAIRE : clé publique age dans /etc/messagerie/backup-recipients.txt puis : systemctl enable --now msg-server-backup.timer"
fi
echo "Instances : $(seq -s ' ' 1 "$n" | sed 's/[0-9]*/127.0.0.1:808&/g') — à placer derrière HAProxy/nginx (TLS)."
echo "Premier administrateur (root) : env DATABASE_URL_FILE=$c/database_url MSG_SERVER_SECRET_FILE=$c/server_secret msg-server bootstrap-admin --username admin"
echo "Sauvegardez $c/server_secret HORS LIGNE."
