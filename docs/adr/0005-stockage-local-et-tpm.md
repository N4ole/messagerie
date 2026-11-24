# ADR-0005 — Stockage local chiffré et protection de clé TPM/DPAPI

- **Statut** : Acceptée (validation de la Phase 0)
- **Date** : 2026-11-24

## Contexte

La BDD locale contient toutes les clés et l'historique. Le TPM Windows (Platform Crypto Provider) ne supporte ni Ed25519 ni X25519.

## Décision

Desktop : SQLCipher avec une clé maîtresse aléatoire de 256 bits. Cette clé est enveloppée (a) par une clé RSA-2048 ou ECDH P-256 non exportable créée dans le TPM via CNG (`NCryptCreatePersistedKey` sur `MS_PLATFORM_CRYPTO_PROVIDER`), sinon (b) par DPAPI (`CryptProtectData`, portée utilisateur), et (c) optionnellement en plus par une clé Argon2id dérivée d'un mot de passe local. Web : enregistrements IndexedDB chiffrés AES-256-GCM sous une clé dérivée du mot de passe ; `CryptoKey` WebCrypto non extractible pour l'enveloppe de session.

## Conséquences

+ Disque volé inexploitable sans le TPM/la session Windows.
− Un maliciel s'exécutant dans la session de l'utilisateur peut demander le descellement : ajouter le mot de passe local pour les profils à risque.
− Pas de TPM sur le web.
