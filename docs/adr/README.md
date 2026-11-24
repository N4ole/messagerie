# Décisions d'architecture (ADR)

Format : contexte → décision → conséquences. Les ADR 0001-0009 ont été acceptés avec la validation de la Phase 0.

| N° | Titre | Statut |
|---|---|---|
| [0001](0001-rust-coeur-partage.md) | Cœur client unique en Rust (natif + WASM) | Acceptée |
| [0002](0002-mls-pour-tout.md) | MLS (RFC 9420) pour le 1-à-1 et les groupes | Acceptée |
| [0003](0003-tauri-react.md) | Tauri v2 + React/TypeScript | Acceptée |
| [0004](0004-serveur-axum-postgres.md) | Serveur axum + PostgreSQL, serveur aveugle | Acceptée |
| [0005](0005-stockage-local-et-tpm.md) | Stockage local chiffré et protection de clé TPM/DPAPI | Acceptée |
| [0006](0006-tor.md) | Tor : arti côté client, C tor côté serveur | Acceptée |
| [0007](0007-authentification.md) | Authentification : Argon2id + TOTP + WebAuthn, OPAQUE en option | Acceptée |
| [0008](0008-key-transparency.md) | Key Transparency avec `akd` | Acceptée |
| [0009](0009-federation.md) | Fédération mTLS sur liste blanche, store-and-forward | Acceptée |
| [0010](0010-api-json.md) | API en JSON versionné plutôt qu'en Protobuf | Acceptée (Phase 1) |
| [0011](0011-fournisseur-crypto-rustcrypto.md) | Fournisseur RustCrypto et suite ML-KEM-768 + X25519 | Acceptée (Phase 1) |
| [0012](0012-committer-unique.md) | Un seul membre émet les commits MLS d'un groupe | Acceptée (Phase 2) |
