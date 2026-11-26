# Déploiement en production (Phase 4)

Trois modes de déploiement, tous avec des **instances sans état** du serveur
(ADR-0015) : le secret `MSG_SERVER_SECRET` doit être **identique** sur toutes
les instances d'un site et **sauvegardé hors ligne** (sessions, jetons et clé de
fédération en dérivent).

| Mode | Fichiers | Haute disponibilité |
|---|---|---|
| Docker Compose | `deploy/docker/compose.prod.yaml` | Perte d'une instance tolérée ; **PostgreSQL unique** (pas de bascule) |
| Kubernetes + Helm | `deploy/helm/messagerie` | Instances réparties, PostgreSQL répliqué (CloudNativePG, bascule automatique) |
| VM (systemd) | `deploy/vm/` | Plusieurs instances locales ; PostgreSQL HA via Patroni (non fourni) |

Tous les secrets sont lus depuis des **fichiers** : `MSG_SERVER_SECRET_FILE`,
`DATABASE_URL_FILE`, `MSG_METRICS_TOKEN_FILE` (Docker secrets, Kubernetes,
systemd `LoadCredential`). Jamais en argument de ligne de commande.

## Docker Compose

```bash
sh deploy/docker/init-secrets.sh
```

Puis placer dans `deploy/docker/secrets/` le certificat TLS (`tls.pem` :
certificat complet puis clé privée) et la **clé publique** age des sauvegardes
(`backup-recipients.txt`). La clé privée age se génère sur un poste
d'administration et n'est jamais copiée sur le serveur :

```bash
age-keygen -o messagerie-sauvegardes.key
```

```bash
MSG_SITE_NAME=paris.example.org MSG_DOMAIN=paris.example.org docker compose -f deploy/docker/compose.prod.yaml up -d
```

```bash
MSG_SITE_NAME=paris.example.org MSG_DOMAIN=paris.example.org docker compose -f deploy/docker/compose.prod.yaml run --rm server-1 bootstrap-admin --username admin
```

Supervision (Prometheus `127.0.0.1:9090`, Grafana `127.0.0.1:3000`, accès par
tunnel SSH) :

```bash
MSG_SITE_NAME=paris.example.org MSG_DOMAIN=paris.example.org docker compose -f deploy/docker/compose.prod.yaml --profile monitoring up -d
```

- HAProxy termine TLS (1.2 minimum, suites AEAD), redirige HTTP vers HTTPS,
  ajoute HSTS, ne journalise rien (aucune IP conservée) et refuse `/metrics`.
  Limitation de débit par IP **en mémoire** uniquement (300 requêtes / 10 s).
- Réseaux : `backend` et `monitoring` internes (sans accès extérieur), `egress`
  pour la fédération uniquement.
- Conteneurs en lecture seule, sans capacités, `no-new-privileges`.
- `maxconn 8000` (≈ 2 descripteurs par connexion) : pour davantage, relever
  `ulimits.nofile` du service `haproxy` puis `maxconn`.
- Test complet du déploiement (utilisé en CI) :

```bash
MSG_IMAGE=ghcr.io/n4ole/messagerie-server:main sh deploy/docker/smoke-test.sh
```

## Kubernetes (Helm)

Prérequis : opérateur [CloudNativePG](https://cloudnative-pg.io) ≥ 1.25, un
contrôleur d'Ingress, cert-manager (ou un secret TLS).

```bash
kubectl create secret generic messagerie-secrets --from-literal=server-secret="$(openssl rand -hex 32)" --from-literal=metrics-token="$(openssl rand -hex 32)"
```

```bash
helm install messagerie deploy/helm/messagerie --set site.name=paris.example.org --set site.domain=paris.example.org
```

```bash
kubectl exec deploy/messagerie -- msg-server bootstrap-admin --username admin
```

- **PostgreSQL** : 3 instances, anti-affinité par nœud, réplication synchrone
  (`database.cloudnativepg.synchronous`), sommes de contrôle ; bascule
  automatique par l'opérateur. Archivage continu vers S3 (PITR) avec
  `database.cloudnativepg.backup.enabled=true`.
- **Instances** : 3 réplicas répartis par nœud et par zone, PDB (`minAvailable: 2`),
  mises à jour progressives sans interruption, migrations par un Job (hook Helm).
- **Sécurité des pods** : non-root, système de fichiers en lecture seule, seccomp,
  aucune capacité, pas de jeton de compte de service ; NetworkPolicy (entrées :
  Ingress et supervision ; sorties : DNS, PostgreSQL et CIDR des pairs).
- **Métriques** : service `messagerie-metrics` séparé (jamais via l'Ingress),
  `ServiceMonitor` facultatif avec le jeton.
- Sauvegarde logique age en complément : `logicalBackup.enabled=true`,
  `logicalBackup.image` (image construite depuis `deploy/backup/Dockerfile`),
  `logicalBackup.recipients`.

## VM (systemd)

```bash
sudo sh deploy/vm/install.sh ./msg-server 2
```

Installe deux instances `msg-server@1` et `msg-server@2` (`127.0.0.1:8081`,
`127.0.0.1:8082`) à placer derrière HAProxy (reprendre
`deploy/docker/haproxy.cfg` en remplaçant `server-1:8080` par
`127.0.0.1:8081`, etc.). L'unité est durcie : utilisateur dynamique,
`ProtectSystem=strict`, filtre d'appels système, secrets via `LoadCredential`.
Sauvegardes : `msg-server-backup.timer` (toutes les 6 h) une fois la clé
publique age placée dans `/etc/messagerie/backup-recipients.txt`.

Haute disponibilité de PostgreSQL sur VM : [Patroni](https://patroni.readthedocs.io)
(3 nœuds + etcd) ; non fourni par ce dépôt.

## Fédération entre sites

1. Chaque site publie sa clé : `curl https://paris.example.org/v1/site`
   (`{"name": "...", "federation_key": "…64 hex…"}`).
2. Les administrateurs **échangent ces clés par un canal authentifié** (en
   personne, signature) : c'est l'épinglage qui protège la fédération.
3. Chaque site liste ses pairs dans un fichier JSON (`MSG_FEDERATION_PEERS`) :

```json
[{ "name": "lyon.example.org", "url": "https://lyon.example.org", "public_key": "…64 hex…" }]
```

4. Pairs `.onion` : URL `http://xxxx.onion` et `MSG_FEDERATION_PROXY=socks5h://tor:9050`.
5. Les utilisateurs écrivent à `bob@lyon.example.org` ; les messages vers un site
   indisponible sont conservés 7 jours et ré-émis automatiquement.

**Rotation du secret serveur** : elle change la clé de fédération du site ;
publier la nouvelle clé aux pairs avant la bascule. Elle invalide aussi les
sessions et le journal KT (le serveur refuse de servir un journal qu'il ne peut
pas rejouer) : réservée à une compromission avérée, suivie d'une
réinitialisation des comptes.

## Supervision

Métriques Prometheus **sans donnée personnelle** (test automatisé
`metrics_contain_no_personal_data`) sur `MSG_METRICS_BIND` (port séparé), jeton
porteur `MSG_METRICS_TOKEN`. Routes étiquetées par **modèle**
(`/v1/users/{username}`), jamais par chemin réel ; seules des valeurs agrégées.

| Métrique | Sens |
|---|---|
| `msg_http_requests_total`, `msg_http_request_duration_seconds` | trafic, erreurs, latence par modèle de route |
| `msg_websocket_connections` | connexions ouvertes par instance |
| `msg_accounts{status}`, `msg_devices`, `msg_pending_deliveries`, `msg_stored_blobs`, `msg_attachments_bytes` | volumes agrégés |
| `msg_kt_epoch`, `msg_kt_pending_updates` | journal Key Transparency |
| `msg_federation_outbox{site}`, `msg_federation_outbox_oldest_seconds`, `msg_federation_*_total` | fédération |
| `msg_kt_witness_epoch{site}`, `msg_kt_witness_age_seconds{site}`, `msg_kt_witness_inconsistent_total` | témoin KT des pairs |

Alertes fournies (`deploy/monitoring/alerts.yml`) : instance injoignable,
taux de 5xx, file de fédération bloquée, **incohérence KT chez un pair**,
témoin obsolète, publication KT en retard. Tableau de bord :
`deploy/monitoring/grafana/messagerie.json` (Grafana configuré sans
télémétrie).

## Sauvegardes et reprise après sinistre

- `deploy/backup/backup.sh` : `pg_dump` chiffré à la volée avec age vers des
  clés publiques ; empreinte SHA-256 ; rotation (`BACKUP_KEEP`).
- `deploy/backup/restore.sh` : vérifie l'empreinte, refuse une base non vide,
  déchiffre (age authentifie le contenu) et restaure.
- **Exercice de reprise exécuté à chaque CI** (`deploy/backup/test-restore.sh`) :
  sauvegarde, restauration dans une base neuve, comparaison table par table,
  refus d'une sauvegarde altérée, d'une mauvaise clé et d'une base non vide.

Procédure de reprise (perte de la base) :

1. Arrêter les instances (`docker compose stop server-1 server-2`).
2. Créer une base vide (nouveau volume, ou `DROP DATABASE` / `CREATE DATABASE`).
3. Sur le poste qui détient la clé privée :

```bash
PGHOST=… PGUSER=messagerie PGDATABASE=messagerie sh deploy/backup/restore.sh messagerie-AAAAMMJJTHHMMSSZ.dump.age messagerie-sauvegardes.key
```

4. Redémarrer les instances **avec le même `MSG_SERVER_SECRET`** (sinon le
   journal KT ne peut pas être rejoué et les sessions sont invalides).
5. Les messages distribués depuis la sauvegarde sont perdus côté serveur (les
   expéditeurs les ont toujours) ; les clients se resynchronisent seuls.

Objectifs indicatifs : RPO = intervalle des sauvegardes (6 h) en Compose/VM,
quelques secondes avec l'archivage continu CloudNativePG ; RTO = durée de la
restauration (minutes pour une base de quelques Go).

## Service onion à haute disponibilité (Onionbalance)

Un service onion est servi par **un** démon Tor ; pour le répartir :

1. Créer N services onion « dorsaux », un par instance (ou par hôte), chacun avec
   `deploy/tor/torrc` pointant sur son instance.
2. Installer [Onionbalance](https://onionbalance.readthedocs.io) (v3) sur un hôte
   distinct : il publie le descripteur de l'adresse **principale** en agrégeant
   les points d'introduction des services dorsaux.
3. Les clients utilisent l'adresse principale ; la perte d'un dorsal est
   transparente.

Non automatisé ni testé dans ce dépôt (dépend du réseau Tor public) ; la clé de
l'adresse principale doit être sauvegardée chiffrée.
