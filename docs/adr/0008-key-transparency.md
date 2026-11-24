# ADR-0008 — Key Transparency avec `akd`

- **Statut** : Acceptée (validation de la Phase 0)
- **Date** : 2026-11-24

## Contexte

Détecter qu'un serveur distribue de fausses clés publiques.

## Décision

Chaque site maintient un répertoire `akd` (arbre de Merkle préfixe + VRF) : `utilisateur → {empreinte identité, appareils}`. Les clients vérifient les preuves d'appartenance à chaque récupération de clés et surveillent l'historique de leur propre entrée. Les racines publiées sont signées et échangées entre sites fédérés (auditeurs croisés).

## Conséquences

+ Bibliothèque utilisée en production (WhatsApp) ; pas d'arbre maison.
− Sans auditeur indépendant de l'opérateur, une vue divisée reste théoriquement possible.
