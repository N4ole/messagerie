# ADR-0012 — Un seul membre émet les commits MLS d'un groupe

- **Statut** : Acceptée (Phase 2)
- **Date** : 2026-11-24

## Contexte

MLS exige que tous les membres appliquent les commits **dans le même ordre**.
Le *delivery service* doit donc soit ordonner les commits (en refusant ceux
qui visent une époque dépassée), soit s'assurer qu'un seul membre en émet.
Notre serveur relaie des blobs opaques sans connaître les groupes : deux
commits simultanés (ajout d'un membre par l'un, rotation par l'autre)
produiraient une **fourche** irrécupérable.

## Décision

- Chaque groupe a un **administrateur** (son créateur ; pour une conversation
  directe, celui qui l'a ouverte ; pour les conversations de la Phase 1, le
  plus petit identifiant parmi les membres — règle déterministe).
- **Seul l'administrateur émet des commits** (ajout, retrait, rotation,
  validation des propositions).
- Les autres membres envoient des **propositions** MLS (mise à jour de leur
  feuille, départ) ; l'administrateur les valide automatiquement.
- Tout commit reçu d'un autre membre est **rejeté avant application**
  (`MlsClient::process_with`), l'état du groupe restant inchangé.
- L'identité de l'administrateur est annoncée dans un message chiffré
  `GroupInfo`, accepté seulement s'il est émis par l'administrateur annoncé.

## Conséquences

+ Aucune fourche possible sans coopération du serveur ; aucune métadonnée de
  groupe supplémentaire côté serveur.
− L'administrateur est un point de passage : s'il est hors ligne, les
  propositions attendent ; s'il disparaît, le groupe ne peut plus évoluer.
− Transfert d'administration et ordonnancement côté serveur (époque attendue
  par groupe, sans révéler la composition) : Phase 4.
