# Phase 4 — Multi-site et infrastructure : rapport de livraison

> Statut : **livrée, en attente de validation.**

## 1. Périmètre

| Exigence Phase 4 | État | Où |
|---|---|---|
| **Serveur multi-instance** sans état (repris de la limite 12 de la Phase 3) | ✅ | `server/msg-server/src/notify.rs`, `kt.rs`, `routes/ws.rs`, ADR-0015 |
| **Fédération** entre sites, liste blanche à clés épinglées | ✅ (requêtes signées au lieu de mTLS, §5) | `server/msg-server/src/federation/`, ADR-0009 révisé |
| File **store-and-forward** (coupure d'un site) | ✅ | `federation/outbox.rs`, migration `0007_federation.sql` |
| Adresses `utilisateur@site`, client relayé par son serveur | ✅ | `crates/msg-client-core`, `crates/msg-crypto/src/mls.rs` |
| **Témoin Key Transparency** entre sites (têtes signées, ajout seul) | ✅ (repris de la limite 2 de la Phase 3) | `federation/witness.rs` |
| **Transfert d'administration** des groupes (repris de la Phase 2) | ✅ | `conversations.rs::transfer_admin`, ADR-0012 complété |
| **Prometheus sans donnée personnelle** + test automatisé | ✅ | `server/msg-server/src/metrics.rs`, test `metrics_contain_no_personal_data` |
| Tableau de bord **Grafana**, règles d'alerte | ✅ | `deploy/monitoring/` |
| **Docker Compose de production** (2 instances, HAProxy, TLS) | ✅ (testé de bout en bout) | `deploy/docker/compose.prod.yaml`, `haproxy.cfg`, `smoke-test.sh` |
| **Kubernetes + Helm**, PostgreSQL HA (CloudNativePG) | ✅ (validé par schémas, pas sur un cluster réel, §6) | `deploy/helm/messagerie` |
| **Script VM** (systemd durci) | ✅ (vérifié statiquement, §6) | `deploy/vm/` |
| **Sauvegardes chiffrées** + **reprise testée en CI** | ✅ | `deploy/backup/`, ADR-0016 |
| Répartition de charge | ✅ | HAProxy (Compose/VM), Ingress + Service (Kubernetes) |
| Service onion à haute disponibilité (Onionbalance) | 📄 documenté, non automatisé | [guide de production](../guides/production.md#service-onion-à-haute-disponibilité-onionbalance) |

## 2. Fichiers créés ou modifiés

```
server/msg-server/migrations/{0006_multi_instance,0007_federation}.sql
server/msg-server/src/notify.rs                     nouveau : bus LISTEN/NOTIFY entre instances
server/msg-server/src/metrics.rs                    nouveau : métriques Prometheus sans donnée personnelle
server/msg-server/src/federation/{mod,client,routes,outbox,witness}.rs   nouveaux
server/msg-server/src/{kt,state,config,secrets,tasks,auth,main,lib}.rs
server/msg-server/src/routes/{mod,ws,keys,messages,attachments,account,devices}.rs
server/msg-server/tests/{phase4.rs (nouveau), common/mod.rs, e2e.rs, phase3.rs}
crates/msg-proto/src/lib.rs                         adresses, fédération, têtes KT signées
crates/msg-crypto/src/{request,mls,app_message}.rs  signatures de site, noms qualifiés
crates/msg-client-core/src/{client,api,kt,conversations,devices,attachments,store,store_mem}.rs
crates/msg-wasm/src/lib.rs, apps/desktop/src-tauri/src/lib.rs     transfert d'administration
ui/src/{views/Chat.tsx, api/*.ts, web/*.ts}, ui/tests/{Phase2.test.tsx, mockBackend.ts}
deploy/docker/{compose.prod.yaml, haproxy.cfg, init-secrets.sh, smoke-test.sh, secrets/}
deploy/backup/{backup.sh, restore.sh, test-restore.sh, Dockerfile}
deploy/helm/messagerie/                             nouveau chart
deploy/vm/{install.sh, msg-server@.service, msg-server-backup.{service,timer}, msg-server.env.example}
deploy/monitoring/{prometheus.yml, alerts.yml, grafana/}
.github/workflows/{ci.yml (job deploy), docker.yml (test de fumée)}
docs/adr/{0009 révisé, 0012 complété, 0015, 0016}, docs/guides/production.md, ce rapport
```

## 3. Tests

| Suite | Nombre | Nouveautés Phase 4 |
|---|---|---|
| `msg-crypto` | 29 | requêtes et réponses de site signées (autre site, autre clé, nonce différent, statut ou corps modifié ⇒ refus) ; noms MLS qualifiés ramenés au nom local pour son propre site |
| `msg-server` (unitaires) | 5 | secrets lus depuis un fichier (`*_FILE`) |
| `msg-server` (bout en bout) | 9 + 3 + **4** | voir ci-dessous ; `group_lifecycle` étendu au transfert d'administration |
| `msg-client-core` | 17 | inchangé (stockage web : réinitialisation à la ré-invitation) |
| UI (Vitest) | **36** (+1) | transfert d'administration avec confirmation (annulation ⇒ aucun appel) |
| **Exercice de reprise** (CI) | 1 script | sauvegarde chiffrée sans nom en clair, restauration identique table par table, refus d'une base non vide, d'une sauvegarde altérée et d'une mauvaise clé |
| **Test de fumée Compose** (CI) | 1 script | voir ci-dessous |
| Chart Helm (CI) | lint + 15 manifestes | `kubeconform -strict`, ressources CloudNativePG et ServiceMonitor comprises |
| Règles Prometheus, unités systemd (CI) | — | `promtool check rules` (6 règles), `systemd-analyze verify` |

Scénarios de bout en bout (`tests/phase4.rs`, serveurs réels et PostgreSQL) :

1. **`two_instances_share_notifications_and_key_transparency`** — deux instances sur la même
   base : Bob s'enrôle et ouvre son WebSocket (ticket stocké en base) sur l'instance B ;
   un message envoyé par Alice via l'instance A lui est **notifié en direct** sur B
   (LISTEN/NOTIFY) ; les époques KT publiées par A sont rejouées par B (conversation avec
   un compte créé via A, auto-vérification KT de Bob) ; **même tête de journal** sur les
   deux instances.
2. **`federated_sites_exchange_messages_with_store_and_forward`** — deux sites (`site-a`,
   `site-b`) : conversation `alice@site-a` ↔ `bob@site-b` **dans les deux sens**, correspondant
   affiché avec son site, **numéros de sécurité identiques** ; pièce jointe hébergée par
   site-a récupérée par Bob via son serveur ; **coupure de site-b** : message conservé en file
   (tentative comptée), **ré-émis au retour** et reçu ; ré-émission idempotente ; **témoin KT** :
   journal du pair vérifié, nouvelle époque prouvée, racine mémorisée falsifiée ⇒
   **incohérence détectée** ; site hors liste blanche refusé ; **aucun clair** dans les deux bases.
3. **`federation_requests_are_authenticated`** — requête signée par une clé non épinglée ⇒ 401 ;
   site inconnu ⇒ 401 ; requête valide ⇒ 200 avec **réponse signée** vérifiable ; **rejeu** du
   même nonce ⇒ 401 ; utilisateur d'un troisième site demandé à un pair ⇒ 400 ; `/v1/site`.
4. **`metrics_contain_no_personal_data`** — après une conversation inter-sites : aucun nom
   d'utilisateur, identifiant d'appareil, de conversation ou de message, ni adresse dans les
   métriques des deux sites ; **chaque étiquette vérifiée contre un ensemble borné**
   (méthode, statut, modèle de route, site de la liste blanche) ; nombre de séries borné ;
   jeton exigé (absent ou faux ⇒ 401) ; `/metrics` absent de l'API publique.

Test de fumée du déploiement de production (`deploy/docker/smoke-test.sh`, exécuté avec
l'image réelle dans le workflow `docker.yml`, et localement pendant le développement) :
API joignable en TLS via HAProxy ; HTTP redirigé ; `/metrics` refusé publiquement ;
Prometheus collecte **les deux instances** avec le jeton ; tableau de bord Grafana chargé ;
**arrêt d'une instance sans échec de requête** ; sauvegarde chiffrée produite.

## 4. Commandes

```bash
DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres cargo test --workspace
```

```bash
pnpm test
```

```bash
PGHOST=localhost PGUSER=postgres PGPASSWORD=postgres MSG_SERVER_BIN=target/debug/msg-server sh deploy/backup/test-restore.sh
```

```bash
MSG_IMAGE=ghcr.io/n4ole/messagerie-server:main sh deploy/docker/smoke-test.sh
```

```bash
helm lint deploy/helm/messagerie
```

```bash
helm template t deploy/helm/messagerie -f deploy/helm/messagerie/ci-values.yaml | kubeconform -strict -summary -schema-location default -schema-location 'https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'
```

Mise en production, fédération, supervision, sauvegardes : [guide de production](../guides/production.md).

## 5. Écarts par rapport à la conception

| Écart | Raison | Trace |
|---|---|---|
| Fédération authentifiée par **requêtes et réponses signées** (clé de site épinglée, nonce à usage unique) au lieu de **mTLS** | Les sites sont derrière un répartiteur qui termine TLS (le certificat client n'atteindrait pas le serveur) ou derrière Tor ; la signature applicative fonctionne partout, protège aussi les réponses et ne dépend d'aucune PKI. TLS (ou Tor) reste le transport | ADR-0009 révisé |
| **Aucun bus de messages dédié** (Redis, NATS) | PostgreSQL `LISTEN/NOTIFY` et verrous consultatifs suffisent ; un service de moins à sécuriser | ADR-0015 |
| Sauvegardes **`pg_dump` + age** plutôt que pgBackRest | Chiffrement côté client vers une clé publique (l'hôte ne peut pas relire) avec un outil unique en Compose, VM et Kubernetes ; l'archivage continu (PITR) est assuré par CloudNativePG sur Kubernetes | ADR-0016 |
| « Réplication » entre sites non retenue | Chaque site reste maître de ses comptes et de leurs données ; seuls les messages destinés à un site lui sont transmis (minimisation). La redondance est assurée **dans** un site (PostgreSQL répliqué) | ADR-0009 |
| Patroni : documenté, **non fourni** | CloudNativePG couvre la HA sur Kubernetes ; sur VM, Patroni (+ etcd) relève de l'exploitation locale | guide de production |
| Onionbalance : documenté, **non automatisé** | Dépend du réseau Tor public, non testable en CI | guide de production |

## 6. Limites et risques connus

**Sécurité**

1. **Aucun audit externe** (inchangé).
2. **Métadonnées entre sites** : un site pair voit qui, chez lui, reçoit des messages de quel
   site, quand et de quelle taille ; il connaît les identifiants d'appareils de ses
   correspondants distants. Le contenu, les noms de fichiers et les groupes restent chiffrés.
3. **Confiance dans la liste blanche** : un site pair compromis peut refuser de délivrer, ou
   mentir sur ses propres utilisateurs. Les clés qu'il publie sont soumises à **sa** Key
   Transparency, surveillée par le témoin ; les numéros de sécurité restent le contrôle
   final. L'échange initial des clés de site doit se faire par un canal authentifié.
4. **Témoin KT** : il détecte un pair qui réécrit son journal ou montre des racines
   différentes au fil du temps ; une **vue divisée** (racines différentes pour des clients
   différents) n'est détectée que si un client compare sa racine avec celle vue par le
   témoin — comparaison client ↔ témoin non implémentée.
5. **Rotation du secret serveur** : change la clé de fédération et invalide le journal KT
   (refus de servir) ; réservée à une compromission, suivie d'une réinitialisation.
6. **Transfert d'administration** : un administrateur disparu sans transfert bloque toujours
   le groupe. Pas d'ordonnancement des commits côté serveur (ADR-0012).
7. **Comptes antérieurs** : les appareils créés avant la Phase 4 ont des credentials MLS au nom
   seul ; ils restent valides localement mais ne sont pas utilisables entre sites
   (re-création ou réinitialisation pour fédérer).
8. GitHub signale une alerte Dependabot de sécurité (n° 1) sur le dépôt ; `cargo deny check
   advisories` et `pnpm audit` ne trouvent aucune vulnérabilité dans la version actuelle.
   À consulter dans l'onglet *Security* (elle concerne probablement une version antérieure
   déjà mise à jour).

**Infrastructure**

9. **Compose** : PostgreSQL unique ⇒ pas de bascule automatique ; la perte de l'hôte implique
   une restauration (RPO = intervalle des sauvegardes, 6 h par défaut).
10. **Helm** : chart validé par schémas (`kubeconform`, CRD comprises) mais **pas déployé sur
    un cluster réel** ici (kind ne démarre pas dans cet environnement) ; à valider en
    pré-production (installation, bascule CloudNativePG, restauration PITR).
11. **VM** : unités systemd vérifiées (`systemd-analyze verify`), script d'installation non
    exécuté en CI (nécessite une VM complète).
12. `LISTEN/NOTIFY` exige une connexion directe à PostgreSQL (pas via PgBouncer en mode
    transaction). Sur bascule de base, les clients sont resynchronisés (notification
    générale à la reconnexion).
13. Liste blanche de fédération statique : la modifier exige un redémarrage des instances.
14. La file de fédération conserve 7 jours ; au-delà, l'expéditeur n'est **pas** informé de
    l'échec (journalisé côté serveur, alerte `FileFederationBloquee`).
15. HAProxy : `maxconn 8000` par défaut (limite de descripteurs) ; à relever avec
    `ulimits.nofile` pour une forte charge.

**Fonctionnel et performances**

16. Journal KT toujours rejoué en mémoire au démarrage de chaque instance (proportionnel au
    nombre d'époques) ; compaction non implémentée.
17. Interface : les adresses distantes s'affichent `nom@site` ; pas d'annuaire inter-sites
    (il faut connaître l'adresse exacte).

**Livraison**

18. Binaires toujours **non signés** (Authenticode, Phase 5).
19. Recette manuelle Windows à faire : points 31 à 35 de la
    [recette](../guides/recette-windows.md#phase-4).
