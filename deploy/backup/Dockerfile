# Conteneur de sauvegarde : client PostgreSQL + age, sans clé privée.
FROM postgres:16-alpine
RUN apk add --no-cache age
COPY backup.sh restore.sh /usr/local/bin/
# Volume de sauvegarde initialisé avec ce propriétaire.
RUN mkdir -p /backups && chown postgres:postgres /backups && chmod 700 /backups
USER postgres
ENTRYPOINT ["/bin/sh", "-c"]
# Sauvegarde toutes les BACKUP_INTERVAL secondes (défaut 6 h).
CMD ["while true; do /usr/local/bin/backup.sh || echo 'sauvegarde échouée' >&2; sleep \"${BACKUP_INTERVAL:-21600}\"; done"]
