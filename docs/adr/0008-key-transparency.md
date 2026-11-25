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

## Mise en œuvre (Phase 3)

- Crate `msg-kt` : configuration akd « expérimentale » (BLAKE3) avec
  séparation de domaine `messagerie-kt-v1` ; VRF dérivée du secret serveur
  (HKDF, libellé `kt-vrf`).
- Valeur publiée par utilisateur : SHA-256 d'un encodage canonique de sa clé
  d'identité et de ses certificats d'appareils (KeyPackages exclus).
- Le répertoire est tenu en mémoire et reconstruit au démarrage en rejouant
  le journal des lots (`kt_log`) ; chaque racine recalculée doit égaler la
  racine journalisée, sinon le serveur ne sert pas KT.
- Client : clé VRF mémorisée au premier usage ; chaque réponse d'annuaire est
  vérifiée ; toute nouvelle époque exige une preuve d'ajout seul depuis la
  dernière racine vérifiée ; retour en arrière refusé ; à chaque connexion,
  le client vérifie que le journal publie **sa** clé d'identité.
- Écart : pas encore de racines **signées** ni d'échange entre sites
  (fédération, Phase 4) : sans auditeur externe, une vue divisée cohérente
  dans le temps reste possible (voir le rapport de Phase 3).
