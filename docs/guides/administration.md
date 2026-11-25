# Guide d'administration

Il n'existe **aucune inscription libre** : chaque compte est créé par un
administrateur, qui transmet hors bande un code d'activation à usage unique.
L'administrateur ne connaît jamais le mot de passe ni les clés de
l'utilisateur, et **ne peut pas lire les messages**.

## Premier administrateur

Sur le serveur (accès direct à la base, une seule fois) :

```bash
msg-server bootstrap-admin --username admin
```

Puis sur le poste d'administration :

```bash
msg-admin --server https://messagerie.exemple.org --user admin enroll
```

La commande demande le code d'activation, définit le mot de passe, affiche le
secret TOTP **sous forme de QR code uniquement** (jamais en texte, pour qu'il ne
reste pas dans l'historique du terminal), à scanner avec une application
d'authentification, et enregistre
un appareil d'administration (clés dans une base locale chiffrée).

> Utilisez un compte dédié à l'administration : le même identifiant ne peut
> pas être utilisé en parallèle dans l'application de bureau en Phase 1
> (multi-appareils en Phase 3).

## Commandes

```bash
msg-admin --server URL --user admin create alice            # code d'activation
msg-admin --server URL --user admin create bob --role admin
msg-admin --server URL --user admin list
msg-admin --server URL --user admin suspend alice            # révoque les sessions
msg-admin --server URL --user admin unsuspend alice
msg-admin --server URL --user admin role alice admin
msg-admin --server URL --user admin reset alice              # nouvelle identité
msg-admin --server URL --user admin devices alice
msg-admin --server URL --user admin revoke alice <device-id>
```

`MSG_SERVER_URL` et `MSG_ADMIN_USER` peuvent remplacer les options.

Toutes les actions sont tracées dans la table `admin_audit` (append-only).

## Passkeys et clés de sécurité (YubiKey)

Activation côté serveur :

```bash
export MSG_WEBAUTHN_RP_ID=messagerie.exemple.org
export MSG_WEBAUTHN_ORIGIN=https://messagerie.exemple.org
```

Le domaine doit être celui de l'URL que les utilisateurs saisissent dans
l'application (le client refuse tout autre domaine). Chaque utilisateur
ajoute ensuite ses clés depuis *⚙ Sécurité* ; elles remplacent le code TOTP à
la connexion (le mot de passe reste exigé). Une réinitialisation de compte
supprime ses clés.

## Groupes

Le créateur d'un groupe en est l'administrateur : lui seul ajoute ou retire
des membres (ADR-0012). Le serveur ne connaît ni les groupes, ni leurs noms,
ni leurs membres : il relaie des messages vers des appareils.

## Réinitialisation d'un compte

`reset` efface mot de passe, TOTP, clé d'identité et appareils, puis émet un
nouveau code d'activation. Les correspondants de l'utilisateur **rejetteront**
sa nouvelle identité : leurs conversations sont suspendues (contenu masqué,
envoi bloqué) jusqu'à vérification du numéro de sécurité (QR code ou
chiffres) ou acceptation explicite.

## Appareils (Phase 3)

- Un utilisateur lie un nouvel appareil (navigateur, second poste) depuis
  l'écran de connexion (« Lier cet appareil ») ; il l'approuve depuis son
  **appareil principal** (⚙ Sécurité → Appareils), en scannant le QR code ou
  en saisissant le code affiché.
- Révocation par l'utilisateur (⚙ Sécurité → Appareils → Révoquer) ou par
  un administrateur :

```bash
msg-admin --server https://messagerie.exemple.org --user admin devices alice
msg-admin --server https://messagerie.exemple.org --user admin revoke alice <device_id>
```

  L'appareil disparaît aussitôt de l'annuaire et du journal Key
  Transparency ; il est retiré de chaque groupe par l'appareil principal de
  l'administrateur du groupe à sa prochaine synchronisation, et efface ses
  données locales s'il se reconnecte.
- Appareil principal perdu : réinitialiser le compte (section suivante).

## Service onion (Tor)

Déploiement « Tor uniquement » (aucun port publié sur l'hôte, client web
refusant toute adresse autre que `.onion`) :

```bash
MSG_SERVER_SECRET=$(openssl rand -hex 32) POSTGRES_PASSWORD=$(openssl rand -hex 16) docker compose -f deploy/docker/compose.onion.yaml up -d --build
```

```bash
docker compose -f deploy/docker/compose.onion.yaml exec tor cat /var/lib/tor/messagerie/hostname
```

- Les clés du service (donc son adresse) sont dans le volume `onion` :
  sauvegardez-le chiffré.
- Clients desktop : URL `http://<adresse>.onion`, réseau « Tor, mode
  strict ». Navigateur : Tor Browser sur la même adresse.
- TLS au-dessus de Tor (facultatif, défense en profondeur) : certificat
  auto-signé accepté par le desktop uniquement si l'empreinte SHA-256 de sa
  clé publique est épinglée :

```bash
openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum
```
