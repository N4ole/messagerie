# Politique de sécurité

## Signaler une vulnérabilité

**N'ouvrez pas d'issue publique.** Utilisez le signalement privé de GitHub :
<https://github.com/N4ole/messagerie/security/advisories/new>.

Merci d'indiquer : version, composant (application Windows, client web,
serveur), étapes de reproduction et impact estimé. N'incluez aucune donnée
personnelle réelle.

Nous accusons réception sous 7 jours et visons un correctif sous 90 jours,
avec publication coordonnée d'un avis (GHSA) et crédit si vous le souhaitez.

## Versions prises en charge

Le projet est en développement (phases 1 à 5). Seule la dernière version
publiée reçoit des correctifs de sécurité. **Aucun audit externe n'a encore
été réalisé** : ne pas utiliser pour des usages à haut risque avant la
Phase 5 et un audit indépendant.

## Périmètre

Inclus : cryptographie et protocole (`crates/msg-crypto`), authentification
et autorisation serveur, stockage local, application de bureau, CI/CD.

Hors périmètre : postes compromis (maliciel actif), attaques par coercition,
adversaire global passif sur Tor — voir `docs/conception/03-modele-de-menace.md`.
