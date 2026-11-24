# ADR-0009 — Fédération mTLS sur liste blanche, store-and-forward

- **Statut** : Acceptée (validation de la Phase 0)
- **Date** : 2026-11-24

## Contexte

Plusieurs sites, seuls des serveurs approuvés communiquent ; tolérance aux coupures.

## Décision

Identifiants `utilisateur@site`. Chaque site a une paire de clés de fédération ; la liste blanche contient `{nom de site, URL ou .onion, empreinte de clé publique}`. Échanges en mTLS avec épinglage. Les messages vers un site distant passent par une file persistante PostgreSQL (backoff exponentiel, rétention configurable, accusés signés, idempotence par identifiant). Un site ne peut annoncer que les utilisateurs de son domaine.

## Conséquences

+ Cloisonnement par site ; administration indépendante possible.
− Un site fédéré compromis voit les métadonnées de routage concernant ses utilisateurs.
