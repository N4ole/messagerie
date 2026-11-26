# Recette manuelle sous Windows 10/11

La CI construit et teste le `.exe` sur `windows-2022`, mais une validation
manuelle sur de vrais postes reste nécessaire (environnement de développement
sous Linux, sans poste Windows physique).

Prérequis : un serveur accessible en HTTPS (ou `http://127.0.0.1:8080` sur le
même poste) et deux comptes créés par `msg-admin`.

| # | Vérification | Windows 10 | Windows 11 |
|---|---|---|---|
| 1 | L'installeur NSIS (`*-setup.exe`) s'installe **sans droits administrateur** | ☐ | ☐ |
| 2 | L'installeur MSI s'installe et se désinstalle proprement | ☐ | ☐ |
| 3 | L'exécutable portable se lance sans installation (WebView2 présent) | ☐ | ☐ |
| 4 | Activation d'un compte : QR code affiché, code TOTP accepté | ☐ | ☐ |
| 5 | Envoi/réception d'un message entre deux postes | ☐ | ☐ |
| 6 | Fermeture puis réouverture : reconnexion sans TOTP tant que la session est valide | ☐ | ☐ |
| 7 | Bouton « Verrouiller » puis reconnexion : TOTP redemandé | ☐ | ☐ |
| 8 | `%APPDATA%\org.messagerie.desktop\accounts\*\local.db` illisible avec DB Browser for SQLite | ☐ | ☐ |
| 9 | `vault.json` indique `"protection": "dpapi"` ; copié sur un autre compte Windows, il est inutilisable | ☐ | ☐ |
| 10 | Thème clair / sombre / système | ☐ | ☐ |
| 11 | Navigation complète au clavier, lecteur d'écran (Narrateur) | ☐ | ☐ |
| 12 | Aucune connexion réseau autre que le serveur configuré (Moniteur de ressources ou Wireshark) | ☐ | ☐ |

## Phase 2

| # | Vérification | Windows 10 | Windows 11 |
|---|---|---|---|
| 13 | ⚙ Sécurité affiche « fenêtre exclue des captures » ; une capture (Win+Maj+S, OBS, Teams) montre une fenêtre vide | ☐ | ☐ |
| 14 | Poste avec TPM 2.0 : ⚙ Sécurité affiche « TPM + DPAPI » ; `vault.json` contient `"protection": "tpm+dpapi"` | ☐ | ☐ |
| 15 | Base de Phase 1 existante : après connexion, le coffre passe en `tpm+dpapi` et l'historique est conservé | ☐ | ☐ |
| 16 | YubiKey : ajout d'une clé (PIN + contact), connexion « avec une clé de sécurité » sans TOTP | ☐ | ☐ |
| 17 | Windows Hello comme passkey (si disponible) | ☐ | ☐ |
| 18 | Verrouillage automatique au bout du délai choisi ; déverrouillage par mot de passe seul | ☐ | ☐ |
| 19 | Notification « Nouveau message » sans nom ni contenu quand la fenêtre est en arrière-plan | ☐ | ☐ |
| 20 | Photo d'un smartphone avec position GPS : après envoi, le fichier enregistré par le destinataire n'a plus d'EXIF (Propriétés → Détails) | ☐ | ☐ |
| 21 | Groupe à 3 : ajout, retrait (le membre retiré ne reçoit plus rien), départ | ☐ | ☐ |
| 22 | Vérification par QR code entre deux postes équipés de webcam | ☐ | ☐ |
| 23 | Message éphémère de 30 s : disparaît chez les deux correspondants | ☐ | ☐ |

## Phase 3

| # | Vérification | Résultat | Remarques |
|---|---|---|---|
| 24 | Réseau « Tor, mode strict » : connexion réussie (premier amorçage < 2 min) ; ⚙ indique Tor | ☐ | ☐ |
| 25 | Tor bloqué (pare-feu sortant) en mode strict : erreur « Aucune connexion directe n'a été tentée » ; aucune connexion vers le serveur dans le moniteur de ressources | ☐ | ☐ |
| 26 | Serveur en service onion (`compose.onion.yaml`) : connexion du desktop en `http://….onion` | ☐ | ☐ |
| 27 | Empreinte TLS épinglée erronée : connexion refusée ; correcte : connexion acceptée | ☐ | ☐ |
| 28 | Liaison d'un navigateur (client web) : code/QR, empreinte identique sur les deux appareils, approbation, conversations existantes visibles | ☐ | ☐ |
| 29 | Révocation du navigateur depuis le desktop : le navigateur est déconnecté et ses données effacées | ☐ | ☐ |
| 30 | Desktop lié comme second appareil d'un compte créé sur un autre poste | ☐ | ☐ |

## Phase 4

| # | Vérification | Résultat | Remarques |
|---|---|---|---|
| 31 | Desktop connecté à un site fédéré : conversation avec `utilisateur@autre-site`, correspondant affiché avec son site, numéro de sécurité identique des deux côtés | ☐ | ☐ |
| 32 | Pièce jointe envoyée à un utilisateur d'un autre site, téléchargée et ouverte | ☐ | ☐ |
| 33 | Site distant arrêté : message envoyé, puis reçu après redémarrage du site | ☐ | ☐ |
| 34 | Transfert d'administration d'un groupe (★) : le nouvel administrateur ajoute un membre ; l'ancien quitte le groupe | ☐ | ☐ |
| 35 | Desktop derrière le déploiement Compose de production (2 instances) : arrêt d'une instance pendant une conversation sans perte de messages | ☐ | ☐ |
