# ADR-0015 — Serveur multi-instance : PostgreSQL comme bus et comme verrou

- **Statut** : Acceptée (Phase 4)
- **Date** : 2026-11-26

## Contexte

La haute disponibilité exige plusieurs instances du serveur derrière un répartiteur.
Jusqu'en Phase 3, trois états vivaient en mémoire : les notifications WebSocket, les
tickets WebSocket et le répertoire Key Transparency (écrivain unique).

## Décision

Aucun composant supplémentaire (pas de Redis ni de file de messages) : PostgreSQL, déjà
nécessaire et répliqué, sert de bus et de verrou.

- **Notifications** : `pg_notify('msg_deliveries', …)` après chaque distribution ; chaque
  instance écoute (`LISTEN`) et réveille ses WebSockets locaux. À la (re)connexion de
  l'écoute, une notification générale force les clients à se resynchroniser (aucune
  notification perdue silencieusement). La notification ne contient que des identifiants
  d'appareils, jamais de contenu.
- **Tickets WebSocket** en base (haché, usage unique, 30 s) : le ticket peut être émis par
  une instance et consommé par une autre.
- **Key Transparency** : publication sous verrou consultatif transactionnel
  (`pg_advisory_xact_lock`) ; avant toute lecture ou publication, chaque instance rejoue les
  époques du journal qu'elle n'a pas encore vues et vérifie chaque racine.
- **File de fédération** : bail par `UPDATE … FOR UPDATE SKIP LOCKED`.

## Conséquences

+ Instances interchangeables et sans état ; mise à l'échelle horizontale, mises à jour
  sans interruption.
+ Pas de nouveau service à sécuriser ni à sauvegarder.
− PostgreSQL reste le point critique : sa disponibilité est assurée par réplication
  (CloudNativePG ou Patroni), pas par ce choix.
− `LISTEN/NOTIFY` ne traverse pas un pooler en mode transaction (PgBouncer) : connexion
  directe requise pour l'écoute.
