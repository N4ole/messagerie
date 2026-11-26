# 04 — Schémas de flux

## 1. Création de compte par un administrateur et première connexion

```mermaid
sequenceDiagram
  autonumber
  actor Admin
  participant CLI as msg-admin
  participant S as msg-server
  actor U as Utilisateur
  participant C as Client (desktop/web)

  Admin->>CLI: account create alice --role user
  CLI->>S: POST /admin/accounts (jeton admin + TOTP)
  S-->>CLI: code d'activation à usage unique (expire 72 h)
  Admin-->>U: remet le code hors bande
  U->>C: identifiant + code d'activation + nouveau mot de passe
  C->>S: POST /auth/activate
  S->>S: Argon2id(mot de passe) ; code invalidé
  S-->>C: secret TOTP (URI otpauth://)
  U->>C: saisit le code TOTP
  C->>S: POST /auth/totp/confirm
  C->>C: génère clé d'identité + appareil + KeyPackages (local)
  C->>S: POST /devices (certificat d'appareil, KeyPackages publics)
  S->>S: publie (alice → identité, appareils) dans le journal KT
  S-->>C: jetons de session (accès 15 min / refresh)
```

L'administrateur ne connaît jamais le mot de passe final ni aucune clé privée.

## 2. Envoi d'un message 1-à-1 (nouvelle conversation)

```mermaid
sequenceDiagram
  autonumber
  participant A as Client Alice
  participant S as Serveur
  participant B as Client(s) Bob

  A->>S: GET /keys/bob (KeyPackages + certificats)
  S-->>A: KeyPackages (consommés) + preuve KT
  A->>A: vérifie certificats, identité connue ?, preuve KT
  A->>A: crée groupe MLS, Commit(Add), Welcome
  A->>S: POST /groups/{id}/commit + Welcome (blobs)
  A->>A: chiffre + signe le message (PrivateMessage)
  A->>S: POST /messages (blob, liste d'appareils destinataires)
  S->>B: WebSocket : notification « nouveau blob » (sans contenu)
  B->>S: GET /queue
  S-->>B: Welcome + blob
  B->>B: vérifie, rejoint le groupe, déchiffre, vérifie signature
  B->>S: ACK → le serveur supprime le blob
```

## 3. Fédération inter-sites avec perte de liaison

```mermaid
sequenceDiagram
  autonumber
  participant A as Client alice@site-a
  participant SA as Serveur site A
  participant Q as File persistante (site A)
  participant SB as Serveur site B
  participant B as Client bob@site-b

  A->>SA: POST /messages (destinataires @site-b)
  SA->>Q: mise en file (blob chiffré)
  SA-xSB: POST /v1/federation/deliver (signée) — échec liaison
  loop backoff exponentiel (max 1 h), rétention 7 j
    Q->>SB: ré-émission
  end
  SB-->>Q: 200 + accusé signé
  Q->>Q: suppression
  SB->>B: notification
```

## 4. Révocation d'un appareil compromis

```mermaid
sequenceDiagram
  autonumber
  actor U as Utilisateur (autre appareil) ou Admin
  participant S as Serveur
  participant KT as Journal KT
  participant G as Membres des groupes

  U->>S: DELETE /devices/{id}
  S->>S: invalide jetons + KeyPackages de l'appareil
  S->>KT: nouvelle version (appareil retiré)
  S->>G: événement « appareil révoqué »
  G->>G: chaque groupe : Commit(Remove appareil) par un membre légitime
  Note over G: nouvelle époque → l'appareil révoqué ne déchiffre plus rien (PCS)
```

## 5. Démarrage du client desktop (mode Tor strict)

```mermaid
flowchart TD
  A[Démarrage] --> B{Signature Authenticode<br/>et hash OK ?}
  B -- non --> X[Refus + alerte]
  B -- oui --> C[Déverrouillage BDD :<br/>clé descellée TPM/DPAPI<br/>+ mot de passe local si activé]
  C --> D{Mode Tor strict ?}
  D -- oui --> E[Bootstrap arti]
  E -- échec --> F[Erreur « Tor indisponible »<br/>AUCUNE connexion en clair]
  E -- ok --> G[Connexion .onion + TLS épinglé]
  D -- non --> H[Tor préféré ; si échec,<br/>demande explicite avant connexion directe]
  G --> I[Session]
  H --> I
```

## 6. Pièce jointe

```mermaid
flowchart LR
  F[Fichier] --> M{Image ?}
  M -- oui --> R["Décodage + ré-encodage<br/>(supprime EXIF/GPS)"] --> T[Miniature]
  M -- non --> D{PDF, Office,<br/>OpenDocument ?}
  D -- oui --> C["Suppression des métadonnées<br/>(auteur, dates, logiciel, miniature)"] --> E1
  D -- "non, ou échec" --> W[Avertissement : métadonnées<br/>internes non nettoyées]
  R --> E1[Chiffrement XChaCha20-Poly1305<br/>clé aléatoire K1]
  T --> E2[Chiffrement clé K2]
  W --> E1
  E1 --> U[Upload blob opaque<br/>taille arrondie]
  E2 --> MSG
  U --> MSG[Message MLS : nom, MIME,<br/>K1, hash, id blob, miniature chiffrée]
```
