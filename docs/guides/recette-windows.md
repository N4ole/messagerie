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
