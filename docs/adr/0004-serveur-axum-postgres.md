# ADR-0004 — Serveur axum + PostgreSQL, serveur aveugle

- **Statut** : Acceptée (validation de la Phase 0)
- **Date** : 2026-11-24

## Contexte

Le serveur ne doit jamais voir de clair et doit partager les types d'API avec le client.

## Décision

Serveur Rust (axum 0.8, tokio, sqlx, rustls). PostgreSQL ne stocke que : comptes (hash Argon2id, secret TOTP chiffré par une clé hors BDD), appareils et clés publiques, files de blobs chiffrés, journal KT, journal d'audit admin. Les pièces jointes chiffrées sont sur disque ou stockage S3 auto-hébergé. Aucun log d'IP ni de contenu ; logs structurés avec liste blanche de champs.

## Conséquences

+ Requêtes SQL vérifiées à la compilation ; types partagés.
− Le graphe de routage (quels appareils reçoivent quels blobs) reste visible du serveur.
