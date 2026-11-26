# ADR-0009 — Fédération sur liste blanche, requêtes signées, store-and-forward

- **Statut** : Acceptée (Phase 0), **révisée en Phase 4** (authentification par signatures de site au lieu de mTLS)
- **Date** : 2026-11-24, révision 2026-11-26

## Contexte

Plusieurs sites, seuls des serveurs approuvés communiquent ; tolérance aux coupures.
La conception initiale prévoyait du mTLS avec épinglage. En pratique, les sites sont
déployés derrière un répartiteur qui termine TLS (HAProxy, Ingress) ou joints par un
service onion (où TLS est superflu) : un certificat client n'arriverait pas jusqu'au
serveur, et l'épinglage TLS dépendrait de chaque déploiement.

## Décision

1. **Adresses** `utilisateur@site` ; les credentials MLS et certificats d'appareils des
   nouveaux comptes portent l'adresse qualifiée (non ambiguë entre sites). Un site ne sert
   que ses propres utilisateurs.
2. **Clé de site** Ed25519 dérivée du secret serveur (HKDF, étiquette `federation-signing`),
   publiée par `GET /v1/site`. La **liste blanche** (`MSG_FEDERATION_PEERS`) contient
   `{nom, URL https ou .onion, clé publique}` : la clé est **épinglée**.
3. **Authentification mutuelle au niveau applicatif**, indépendante de TLS :
   - chaque requête est signée (`messagerie/federation/request/v1` : site, méthode, chemin,
     empreinte du corps, horodatage ±60 s, nonce à usage unique mémorisé en base) ;
   - chaque réponse est signée (`messagerie/federation/response/v1`) et **liée au nonce** de
     la requête (statut et corps compris) : une réponse ne peut être ni forgée ni rejouée.
   TLS (ou Tor) reste utilisé pour la confidentialité du transport.
4. **Relais par le site d'origine** : un client ne contacte jamais un site distant ;
   annuaire, KeyPackages, journal KT et pièces jointes passent par son propre serveur
   (`?site=` ou adresse qualifiée). Les sites `.onion` sont joints via
   `MSG_FEDERATION_PROXY` (SOCKS).
5. **File persistante** (`federation_outbox`) : remise immédiate puis ré-émission avec
   attente exponentielle (≤ 1 h), bail multi-instance (`FOR UPDATE SKIP LOCKED`), accusé
   signé, idempotence par (site d'origine, identifiant du message), rétention 7 jours.
6. **Témoin KT** : chaque site suit le journal de ses pairs (têtes signées par la clé du
   pair, preuves d'ajout seul) et signale toute incohérence.

## Conséquences

+ Cloisonnement par site ; administration indépendante.
+ Fonctionne derrière n'importe quel répartiteur et via Tor, sans PKI.
+ Une réponse altérée par un intermédiaire (ou par la terminaison TLS) est détectée.
− Un site fédéré compromis voit les métadonnées de routage concernant ses utilisateurs
  (qui écrit à qui, quand, tailles).
− Changer le secret serveur change la clé de site : les pairs doivent mettre à jour leur
  liste blanche (procédure documentée dans le guide d'administration).
− Le contenu de la liste blanche est de la configuration statique (redémarrage requis).
