# ADR-0016 — Sauvegardes chiffrées côté client avec age

- **Statut** : Acceptée (Phase 4)
- **Date** : 2026-11-26

## Contexte

Le contenu des messages est déjà chiffré de bout en bout, mais la base contient des
métadonnées sensibles (comptes, appareils, file de distribution, journal KT, hachés de
mots de passe). Une sauvegarde volée ne doit rien révéler, et l'hôte qui produit les
sauvegardes ne doit pas pouvoir les relire. Règle du projet : aucune cryptographie maison.

## Décision

- Sauvegarde logique `pg_dump` **chiffrée à la volée** avec [age](https://age-encryption.org)
  (X25519 + ChaCha20-Poly1305, spécification publique, implémentation de référence) vers
  une ou plusieurs **clés publiques**. Aucun fichier en clair n'est écrit. La clé privée
  est conservée hors ligne (coffre, poste d'administration) et n'est utilisée qu'à la
  restauration.
- Empreinte SHA-256 à côté de chaque fichier ; age authentifie le contenu (une sauvegarde
  altérée échoue au déchiffrement).
- Restauration **uniquement dans une base vide**.
- Sur Kubernetes, l'archivage continu CloudNativePG (WAL + sauvegardes de base, PITR) est
  proposé **en plus** ; il repose sur le chiffrement côté stockage objet (SSE), d'où la
  sauvegarde logique age conservée comme copie indépendante.
- L'exercice de reprise (`deploy/backup/test-restore.sh`) est exécuté **à chaque CI**.

## Conséquences

+ Une sauvegarde volée, ou l'hôte de sauvegarde compromis, ne révèle rien.
+ Outil unique et simple, identique en Compose, VM et Kubernetes.
− Perdre la clé privée age rend les sauvegardes irrécupérables : la conserver en
  plusieurs exemplaires hors ligne.
− Sauvegarde logique : la perte maximale de données (RPO) est l'intervalle entre deux
  sauvegardes (6 h par défaut) ; pour un RPO proche de zéro, utiliser l'archivage
  continu CloudNativePG ou pgBackRest.
