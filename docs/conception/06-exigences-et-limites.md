# 06 — Matrice des exigences, faisabilité et limites

Légende : ✅ réalisable intégralement · ⚠️ partiellement / avec conditions · ❌ irréalisable tel quel (alternative proposée)

## 1. Comptes & authentification

| Exigence | Statut | Remarque |
|---|---|---|
| Identifiant + mot de passe, Argon2id serveur | ✅ | Option plus forte proposée : **OPAQUE** (`opaque-ke`) — le serveur ne voit jamais le mot de passe. À valider. |
| Dérivation de clé locale séparée | ✅ | Clé locale aléatoire, enveloppée par TPM/DPAPI et (option) Argon2id avec sel local jamais envoyé |
| Comptes créés uniquement par admin, gestion complète | ✅ | Code d'activation à usage unique ; l'admin ne fixe jamais le mot de passe final |
| TOTP | ✅ | |
| Passkeys / FIDO2 / YubiKey | ⚠️ | Web : ✅. Desktop : via l'API native `webauthn.dll` (WebView2 ne garantit pas WebAuthn dans tous les contextes). **Point à confirmer en Phase 2** : le comportement exact du RP ID pour une application native. Une passkey authentifie auprès du serveur ; elle ne protège pas les clés E2EE (sauf extension PRF, optionnelle, si l'authentificateur la supporte). |
| Sessions à durée limitée | ✅ | |
| Verrouillage auto après inactivité | ✅ | Desktop : efface la clé BDD de la mémoire. Web : idem côté WASM. |
| Révocation à distance des appareils | ✅ | Effective cryptographiquement **dès que** un membre légitime de chaque groupe émet le commit de retrait (automatique à la prochaine connexion d'un membre). |

## 2. Messagerie

| Exigence | Statut | Remarque |
|---|---|---|
| 1-à-1 et groupes | ✅ | MLS pour les deux (voir ADR-0002) |
| Photos et pièces jointes | ✅ | |
| Suppression EXIF | ⚠️ | ✅ pour les images (ré-encodage). Pour PDF/Office/vidéo : **non nettoyé**, avertissement affiché. Le ré-encodage peut dégrader légèrement la qualité. |
| Noms de fichiers et miniatures chiffrés | ✅ | |
| Markdown sécurisé | ✅ | |
| Blocage contenus distants / pixels | ✅ | Les liens sont affichés, jamais pré-chargés ; pas d'aperçu de lien |
| Éphémères / suppression programmée | ⚠️ | Impossible d'empêcher copie, photo, client modifié |
| Notifications sans aperçu | ✅ | |
| Signature de chaque message | ✅ | Signature MLS ; vérifiable par les membres du groupe uniquement (déniabilité vis-à-vis des tiers non garantie : MLS signe avec des clés liées à l'identité) |

## 3. Cryptographie & clés

| Exigence | Statut | Remarque |
|---|---|---|
| E2EE avancé, hybride post-quantique | ⚠️ | Confidentialité hybride X-Wing ✅ ; **authentification (Ed25519) non post-quantique** ; suite au point de code provisoire |
| Rotation automatique | ✅ | |
| Vérification QR | ✅ | |
| Détection de changements de clés | ✅ | |
| Key Transparency | ⚠️ | `akd` fournit le journal et les preuves. Une KT complète exige **des auditeurs/témoins indépendants** qui vérifient la cohérence du journal ; nous fournissons un mode « auditeur » (les autres sites fédérés et chaque client) mais si tous les auditeurs sont contrôlés par l'opérateur, une vue divisée (*split view*) reste possible. |
| Anti-MITM / anti-rejeu | ✅ | |
| BDD locale chiffrée | ✅ | Desktop SQLCipher ; web : chiffrement par enregistrement |
| Clés dans le TPM | ⚠️ | Le Platform Crypto Provider de Windows ne gère que RSA et ECC NIST (P-256/P-384), **pas Ed25519/X25519**. Le TPM **scelle la clé maîtresse locale** (qui chiffre tout le reste) au lieu de contenir les clés MLS. Repli DPAPI si pas de TPM 2.0. **Côté web : ❌**, aucune API navigateur pour le TPM ; meilleure alternative : clé WebCrypto non extractible + mot de passe. |
| Effacement mémoire (`zeroize`) | ⚠️ | Efficace dans notre code ; ne couvre pas les copies faites par l'OS (swap, hibernation), par la WebView (le texte affiché est dans le DOM) ni toutes les copies internes des bibliothèques. Mitigations : `VirtualLock` sur les pages de secrets (desktop), recommandation BitLocker. |

## 4. Réseau

| Exigence | Statut | Remarque |
|---|---|---|
| Masquage IP | ⚠️ | ✅ desktop (Tor). Web : seulement via Tor Browser, ou proxy du site (masque l'IP aux autres utilisateurs/sites mais **pas** au site lui-même). |
| Tor autant que possible | ⚠️ | Desktop : arti. Web : **impossible d'embarquer Tor dans une page** (pas de sockets TCP en WASM). |
| Mode Tor strict sans basculement | ✅ | Desktop : garanti par le code (aucun transport direct instancié). Web : la page refuse de fonctionner si elle n'est pas servie depuis une adresse `.onion`. |

## 5. Interface

| Exigence | Statut | Remarque |
|---|---|---|
| UI moderne, accessible, clair/sombre | ✅ | Cible WCAG 2.2 AA, navigation clavier, lecteurs d'écran |
| Anti-capture desktop | ⚠️ | `WDA_EXCLUDEFROMCAPTURE` (Windows 10 2004+) : la fenêtre apparaît noire dans les captures logicielles standard. **N'empêche pas** : appareil photo, cartes d'acquisition, maliciel noyau, bureau à distance selon configuration. Sur versions antérieures : `WDA_MONITOR`. |
| Anti-capture web | ❌ | **Techniquement impossible** dans un navigateur. Mesures dissuasives seulement : filigrane avec identifiant de l'utilisateur, flou à la perte de focus / `visibilitychange`, désactivation de la sélection (contournable). |

## 6. Intégrité du logiciel

| Exigence | Statut | Remarque |
|---|---|---|
| Binaires signés Authenticode | ⚠️ | Nécessite un **certificat de signature de code que tu dois acquérir** (clés obligatoirement en HSM depuis 2023 : Azure Artifact Signing, SignPath — gratuit pour projets open source sous conditions —, ou HSM cloud d'une AC). Sans secret configuré, la CI produit des binaires **non signés, clairement marqués**. SmartScreen affichera un avertissement tant que la réputation n'est pas établie. |
| Vérification d'intégrité au démarrage | ⚠️ | `WinVerifyTrust` sur soi-même + hash des ressources. **Limite** : un attaquant capable de modifier le binaire peut supprimer la vérification ; la vraie garantie est la signature vérifiée par Windows et la provenance SLSA vérifiable par l'utilisateur. |
| Builds reproductibles | ⚠️ | Rust est reproductible sous conditions (`--remap-path-prefix`, toolchain épinglée, `SOURCE_DATE_EPOCH`) ; MSVC/WiX/NSIS ajoutent des horodatages. Objectif réaliste : **serveur et WASM reproductibles** (vérifiés en CI par double build), `.exe` « au mieux » avant signature. |

## 7. Multi-site & infrastructure

| Exigence | Statut | Remarque |
|---|---|---|
| Fédération sur liste blanche | ✅ | |
| Admin centralisée ou par site | ✅ | Mode « indépendant » (chaque site gère ses comptes) ou « central » (un site maître pousse les politiques signées) |
| HA + basculement auto | ⚠️ | ✅ dans un site (instances sans état + PostgreSQL HA via Patroni/CloudNativePG). Entre sites : un utilisateur appartient à un site ; si ce site tombe entièrement, ses comptes sont indisponibles jusqu'au basculement vers le site de secours (procédure semi-automatique, car un basculement automatique inter-sites risque le *split-brain*). |
| Équilibrage de charge | ✅ | HAProxy/Ingress ; WebSocket avec routage par appareil via PostgreSQL `LISTEN/NOTIFY` ou bus interne |
| Réplication des données chiffrées | ✅ | Intra-site : réplication PostgreSQL. Inter-sites : réplication asynchrone des sauvegardes chiffrées et des files. |
| File store-and-forward | ✅ | |
| Sauvegardes chiffrées + restauration | ✅ | `pgBackRest` (chiffrement AES-256) ou `pg_dump` + `age` ; procédure testée en CI (restauration dans un conteneur) |
| Docker Compose / Kubernetes + Helm / VM | ✅ | |
| Prometheus + Grafana sans donnée personnelle | ✅ | Test automatisé qui échoue si une métrique contient un label à forte cardinalité ou un identifiant |
| **Tor + HA** | ⚠️ | Onionbalance répartit un service .onion sur plusieurs backends ; fonctionnel mais ajoute de la complexité opérationnelle. |

## 8. GitHub

| Exigence | Statut | Remarque |
|---|---|---|
| Actions CI/CD, Releases, GHCR, CodeQL, Dependabot, Pages, templates, CODEOWNERS, devcontainer | ✅ | Fournis sous forme de fichiers dans le dépôt |
| Attestations SLSA / Sigstore | ✅ | `actions/attest-build-provenance` — **dépôt public** ou plan GitHub Enterprise Cloud requis pour un dépôt privé |
| Secret scanning + push protection | ⚠️ | Activation **dans les paramètres du dépôt** (gratuit sur dépôt public ; GitHub Secret Protection payant en privé). Je ne peux que documenter la procédure. |
| Branch protection / rulesets, commits signés, revue | ⚠️ | Je fournis les rulesets en JSON + commande d'import ; **l'application nécessite tes droits d'admin**. Avec un seul mainteneur, « revue requise » bloque toute fusion : prévoir un second relecteur ou une exception. |
| Environments avec secrets protégés | ⚠️ | Création manuelle (ou via API) par toi ; je fournis la procédure. |
| GitHub Projects | ⚠️ | Les Projects ne se configurent pas par fichier ; je fournis la liste des issues/jalons et un script `gh` à lancer. |

## 9. Critères de réussite globaux

| Critère | Statut | Remarque |
|---|---|---|
| `.exe` sur Windows 10/11 sans dépendance manuelle | ✅ | WebView2 : présent sur Windows 11 et Windows 10 à jour ; l'installeur embarque le *bootstrapper* WebView2 pour les autres cas (nécessite alors Internet à l'installation ; option « installeur hors-ligne » plus lourd). |
| Desktop ↔ web interopérables | ✅ | Même cœur Rust (Phase 3) |
| Aucun clair en BDD / logs / trafic, démontré par test | ✅ | Test d'intégration qui envoie un marqueur aléatoire et le recherche dans le dump PostgreSQL, les logs et une capture réseau (côté serveur, après TLS) |
| CI verte publiant une release signée | ⚠️ | « Signée » dépend du certificat (voir §6). Les checksums et attestations Sigstore sont, eux, toujours produits. |

## 10. Ce que je ne pourrai pas faire depuis cet environnement

- **Exécuter le `.exe` sous Windows** : mon environnement est Linux. Le build Windows sera fait et testé (tests unitaires) par la CI GitHub sur `windows-latest`. Les tests manuels d'installation sur Windows 10/11 réels restent à ta charge (checklist fournie en Phase 1).
- **Tester le TPM, WebAuthn natif, `SetWindowDisplayAffinity`** autrement qu'en CI Windows (sans TPM physique ni clé YubiKey) : ces chemins auront des tests unitaires et un mode de repli testé, mais leur validation finale est manuelle.
- **Réaliser un audit de sécurité indépendant** : la Phase 5 fournit une revue interne et des tests de pénétration de base, **pas** un audit externe, qui reste indispensable avant un usage à risque élevé.
