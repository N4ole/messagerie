# ADR-0013 — Appareils multiples : liaison sans transfert de clé, révocation, réconciliation

- **Statut** : Acceptée (Phase 3)
- **Date** : 2026-11-25

## Contexte

Le client web doit pouvoir être un appareil de plus d'un compte existant
(par exemple le desktop). Dans MLS, les membres d'un groupe sont des
**appareils** : chaque nouvel appareil doit être ajouté à chaque groupe,
chaque appareil révoqué doit en être retiré. Le serveur ne connaît pas les
groupes (ADR-0004) et un seul membre émet les commits (ADR-0012).

## Décision

1. **Liaison sans transfert de clé privée.** Seul l'appareil qui a créé
   l'identité (« appareil principal ») détient la clé d'identité. Un nouvel
   appareil s'authentifie (mot de passe + second facteur), publie ses clés
   **publiques** et affiche un code (QR) contenant l'identifiant de la
   demande et une empreinte de 80 bits de ses clés. L'appareil principal
   recalcule l'empreinte à partir des clés reçues du serveur : si elle
   diffère, il refuse ; sinon il signe le certificat d'appareil. Le serveur
   ne fait confiance qu'à cette signature. Le résultat n'est délivré qu'une
   fois, au porteur d'un secret de consultation de 256 bits.
2. **Révocation.** L'appareil est supprimé de l'annuaire et du journal KT
   (sa clé API est conservée pour lui répondre « appareil révoqué », et à
   lui seul, s'il se reconnecte ; il efface alors ses données locales).
3. **Réconciliation.** L'appareil principal de l'administrateur de chaque
   groupe compare les appareils membres à l'annuaire vérifié par KT : il
   ajoute les appareils liés (Welcome + `GroupInfo`) et retire les appareils
   révoqués (commit). Seuls les appareils **principaux** émettent des
   commits automatiques (rotation, validation des propositions) : deux
   appareils d'un même administrateur ne peuvent pas créer de fourche.
4. Une nouvelle conversation inclut d'emblée tous mes appareils ; un message
   envoyé par un autre de mes appareils s'affiche comme envoyé.

## Conséquences

+ Aucune clé privée ne transite, même chiffrée.
+ Le serveur ne peut pas ajouter un appareil à un compte (signature exigée).
− Perdre l'appareil principal empêche de lier de nouveaux appareils et
  d'administrer ses groupes : réinitialisation par un administrateur.
− Pas d'historique antérieur à la liaison sur le nouvel appareil.
− La révocation dans un groupe attend que l'appareil principal de son
  administrateur soit en ligne (le serveur cesse toutefois immédiatement de
  distribuer quoi que ce soit à l'appareil révoqué).
