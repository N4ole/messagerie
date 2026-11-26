# Secrets du déploiement Compose

Ce répertoire ne contient que ce fichier dans le dépôt : tout le reste est
ignoré par Git (`.gitignore`). `../init-secrets.sh` génère les fichiers
manquants (droits 0600) :

| Fichier | Contenu |
|---|---|
| `db_password` | mot de passe PostgreSQL |
| `database_url` | URL de connexion (contient le mot de passe) |
| `server_secret` | secret racine du site (32 octets hex) — **à sauvegarder hors ligne** : sans lui, sessions et clé de fédération sont perdues |
| `metrics_token` | jeton porteur de `/metrics` |
| `grafana_password` | mot de passe administrateur Grafana |
| `backup-recipients.txt` | clé(s) publique(s) age des sauvegardes |
| `tls.pem` | certificat TLS + clé privée (PEM concaténés) |
