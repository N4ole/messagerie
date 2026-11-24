-- Schéma initial. Le serveur ne stocke AUCUN contenu en clair :
-- `blobs.payload` contient uniquement des messages MLS chiffrés.
-- Tous les horodatages sont en secondes Unix (BIGINT).

CREATE TABLE accounts (
    id                     BIGSERIAL PRIMARY KEY,
    username               TEXT    NOT NULL UNIQUE,
    role                   TEXT    NOT NULL CHECK (role IN ('user', 'admin')),
    status                 TEXT    NOT NULL CHECK (status IN ('pending_activation', 'pending_totp', 'active', 'suspended')),
    password_hash          TEXT,
    -- Secret TOTP chiffré (XChaCha20-Poly1305, clé serveur hors base).
    totp_secret_enc        BYTEA,
    -- Dernier pas TOTP accepté (anti-rejeu des codes).
    totp_last_step         BIGINT,
    -- Clé d'identité publique de l'utilisateur (fixée au premier appareil).
    identity_key           BYTEA,
    activation_code_hash   BYTEA,
    activation_expires_at  BIGINT,
    failed_logins          INTEGER NOT NULL DEFAULT 0,
    locked_until           BIGINT,
    created_at             BIGINT  NOT NULL
);

CREATE TABLE devices (
    id                 UUID    PRIMARY KEY,
    account_id         BIGINT  NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    api_key            BYTEA   NOT NULL,
    mls_signature_key  BYTEA   NOT NULL,
    cert_created_at    BIGINT  NOT NULL,
    cert_signature     BYTEA   NOT NULL,
    created_at         BIGINT  NOT NULL,
    last_seen_at       BIGINT
);
CREATE INDEX devices_account_idx ON devices (account_id);

-- Jetons stockés uniquement sous forme de hachés SHA-256.
CREATE TABLE sessions (
    id                  BIGSERIAL PRIMARY KEY,
    device_id           UUID   NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    access_hash         BYTEA  NOT NULL UNIQUE,
    access_expires_at   BIGINT NOT NULL,
    refresh_hash        BYTEA  NOT NULL UNIQUE,
    session_expires_at  BIGINT NOT NULL,
    created_at          BIGINT NOT NULL
);
CREATE INDEX sessions_device_idx ON sessions (device_id);

-- Nonces de requêtes signées déjà vus (anti-rejeu), purgés régulièrement.
CREATE TABLE request_nonces (
    device_id  UUID   NOT NULL,
    nonce      TEXT   NOT NULL,
    seen_at    BIGINT NOT NULL,
    PRIMARY KEY (device_id, nonce)
);
CREATE INDEX request_nonces_seen_idx ON request_nonces (seen_at);

CREATE TABLE key_packages (
    id          BIGSERIAL PRIMARY KEY,
    device_id   UUID   NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    data        BYTEA  NOT NULL,
    created_at  BIGINT NOT NULL
);
CREATE INDEX key_packages_device_idx ON key_packages (device_id, id);

CREATE TABLE blobs (
    id                 BIGSERIAL PRIMARY KEY,
    sender_device      UUID   REFERENCES devices (id) ON DELETE SET NULL,
    client_message_id  UUID   NOT NULL,
    payload            BYTEA  NOT NULL,
    created_at         BIGINT NOT NULL,
    expires_at         BIGINT NOT NULL,
    UNIQUE (sender_device, client_message_id)
);
CREATE INDEX blobs_expires_idx ON blobs (expires_at);

CREATE TABLE deliveries (
    id          BIGSERIAL PRIMARY KEY,
    blob_id     BIGINT NOT NULL REFERENCES blobs (id) ON DELETE CASCADE,
    device_id   UUID   NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    created_at  BIGINT NOT NULL
);
CREATE INDEX deliveries_device_idx ON deliveries (device_id, id);
CREATE INDEX deliveries_blob_idx ON deliveries (blob_id);

-- Journal des actions d'administration (append-only : pas de route de modification).
CREATE TABLE admin_audit (
    id      BIGSERIAL PRIMARY KEY,
    at      BIGINT NOT NULL,
    actor   TEXT   NOT NULL,
    action  TEXT   NOT NULL,
    target  TEXT   NOT NULL
);
