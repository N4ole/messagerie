## Résumé

<!-- Quoi et pourquoi. -->

## Phase / exigences concernées

## Sécurité

- [ ] Aucune nouvelle primitive ou construction cryptographique maison
- [ ] Aucun clair (contenu, nom de fichier, identifiant) ajouté aux journaux, métriques ou à la base serveur
- [ ] Aucun appel réseau vers un tiers
- [ ] Les secrets ajoutés sont effacés de la mémoire (`zeroize`)

## Tests

- [ ] `cargo test --workspace` (avec `DATABASE_URL`)
- [ ] `pnpm test`
- [ ] Testé manuellement sous Windows (si l'application de bureau est concernée)

## Limites connues
