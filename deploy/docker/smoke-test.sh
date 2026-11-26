#!/bin/sh
# Test de fumée du déploiement Compose de production (exécuté en CI) :
# démarrage complet, TLS via HAProxy, métriques inaccessibles publiquement
# mais collectées par Prometheus, perte d'une instance sans interruption,
# sauvegarde chiffrée produite. Les secrets sont générés dans un répertoire
# jetable (jamais ceux d'un vrai déploiement).
#   MSG_IMAGE=ghcr.io/…/messagerie-server:tag sh deploy/docker/smoke-test.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
export MSG_SITE_NAME=smoke.example MSG_DOMAIN=localhost MSG_HTTPS_PORT=${MSG_HTTPS_PORT:-18443} MSG_HTTP_PORT=${MSG_HTTP_PORT:-18080}
compose() { docker compose -p messagerie-smoke -f "$here/compose.prod.yaml" --profile monitoring "$@"; }
cleanup() {
  status=$?
  [ $status -eq 0 ] || compose logs --tail 50 >&2 || true
  compose down -v --remove-orphans > /dev/null 2>&1 || true
  [ -n "${SMOKE_KEEP_SECRETS:-}" ] || rm -rf "$here/secrets/db_password" "$here/secrets/database_url" "$here/secrets/server_secret" \
    "$here/secrets/metrics_token" "$here/secrets/grafana_password" "$here/secrets/backup-recipients.txt" "$here/secrets/tls.pem"
  exit $status
}
trap cleanup EXIT
sh "$here/init-secrets.sh" > /dev/null
umask 077
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=localhost \
  -keyout "$here/secrets/tls.key" -out "$here/secrets/tls.crt" 2> /dev/null
cat "$here/secrets/tls.crt" "$here/secrets/tls.key" > "$here/secrets/tls.pem"; rm -f "$here/secrets/tls.key" "$here/secrets/tls.crt"
age-keygen 2> /dev/null | age-keygen -y > "$here/secrets/backup-recipients.txt"
chmod 644 "$here"/secrets/*
build=--build; [ -z "${SMOKE_NO_BUILD:-}" ] || build=--no-build
compose up -d $build --wait --wait-timeout 180 db server-1 server-2 haproxy backup prometheus grafana
base="https://localhost:$MSG_HTTPS_PORT"
for i in $(seq 1 30); do curl -fsk "$base/v1/health" > /dev/null && break; sleep 2; done
curl -fsk "$base/v1/health" | grep -q '"ok"'
echo "✓ API joignable en TLS via HAProxy"
code=$(curl -sk -o /dev/null -w '%{http_code}' "http://localhost:$MSG_HTTP_PORT/v1/health")
[ "$code" = "301" ]; echo "✓ HTTP redirigé vers HTTPS"
code=$(curl -sk -o /dev/null -w '%{http_code}' "$base/metrics")
[ "$code" = "404" ]; echo "✓ /metrics non exposé publiquement"
for i in $(seq 1 30); do
  up=$(curl -fs "http://127.0.0.1:9090/api/v1/query?query=sum(up%7Bjob%3D%22messagerie%22%7D)" | sed -n 's/.*"value":\[[^,]*,"\([0-9]*\)"\].*/\1/p' || true)
  [ "$up" = "2" ] && break; sleep 3
done
[ "$up" = "2" ]; echo "✓ Prometheus collecte les deux instances (jeton porteur)"
for i in $(seq 1 30); do
  curl -fs -u "admin:$(cat "$here/secrets/grafana_password")" "http://127.0.0.1:3000/api/search?query=Messagerie" 2> /dev/null | grep -q '"uid":"messagerie"' && break; sleep 2
done
curl -fs -u "admin:$(cat "$here/secrets/grafana_password")" "http://127.0.0.1:3000/api/search?query=Messagerie" | grep -q '"uid":"messagerie"'
echo "✓ tableau de bord Grafana chargé"
compose stop server-1 > /dev/null
for i in $(seq 1 10); do curl -fsk "$base/v1/health" > /dev/null || { echo "requête échouée après arrêt d'une instance" >&2; exit 1; }; done
echo "✓ service maintenu après l'arrêt d'une instance"
compose exec -T backup /usr/local/bin/backup.sh > /dev/null
compose exec -T backup sh -c 'ls /backups/*.dump.age' > /dev/null
echo "✓ sauvegarde chiffrée produite"
echo "test de fumée réussi"
