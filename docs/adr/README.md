# Décisions d'architecture (ADR)

Format : contexte → décision → conséquences. Statut « Proposée » jusqu'à validation de la Phase 0.

| N° | Titre | Statut |
|---|---|---|
| [0001](0001-rust-coeur-partage.md) | Cœur client unique en Rust (natif + WASM) | Proposée |
| [0002](0002-mls-pour-tout.md) | MLS (RFC 9420) pour le 1-à-1 et les groupes | Proposée |
| [0003](0003-tauri-react.md) | Tauri v2 + React/TypeScript | Proposée |
| [0004](0004-serveur-axum-postgres.md) | Serveur axum + PostgreSQL, serveur aveugle | Proposée |
| [0005](0005-stockage-local-et-tpm.md) | Stockage local chiffré et protection de clé TPM/DPAPI | Proposée |
| [0006](0006-tor.md) | Tor : arti côté client, C tor côté serveur | Proposée |
| [0007](0007-authentification.md) | Authentification : Argon2id + TOTP + WebAuthn, OPAQUE en option | Proposée |
| [0008](0008-key-transparency.md) | Key Transparency avec `akd` | Proposée |
| [0009](0009-federation.md) | Fédération mTLS sur liste blanche, store-and-forward | Proposée |
