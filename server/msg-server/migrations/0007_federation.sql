-- Phase 4 : fédération entre sites (liste blanche, store-and-forward).

-- Nonces des requêtes de sites pairs déjà vus (anti-rejeu).
CREATE TABLE federation_nonces (
    site     TEXT    NOT NULL,
    nonce    TEXT    NOT NULL,
    seen_at  BIGINT  NOT NULL,
    PRIMARY KEY (site, nonce)
);
CREATE INDEX federation_nonces_seen_idx ON federation_nonces (seen_at);

-- File persistante des messages à remettre à d'autres sites : blobs
-- chiffrés de bout en bout uniquement, ré-émis avec attente exponentielle,
-- supprimés à l'accusé de réception signé ou après la rétention maximale.
CREATE TABLE federation_outbox (
    id               BIGSERIAL PRIMARY KEY,
    site             TEXT     NOT NULL,
    message_id       UUID     NOT NULL,
    devices          UUID[]   NOT NULL,
    payload          BYTEA    NOT NULL,
    attempts         INTEGER  NOT NULL DEFAULT 0,
    next_attempt_at  BIGINT   NOT NULL,
    created_at       BIGINT   NOT NULL,
    expires_at       BIGINT   NOT NULL,
    UNIQUE (site, message_id)
);
CREATE INDEX federation_outbox_due_idx ON federation_outbox (next_attempt_at);

-- Messages reçus d'autres sites : site d'origine (idempotence des
-- ré-émissions par (site, identifiant de message)).
ALTER TABLE blobs ADD COLUMN origin_site TEXT;
CREATE UNIQUE INDEX blobs_origin_idx ON blobs (origin_site, client_message_id) WHERE origin_site IS NOT NULL;

-- Témoin Key Transparency des sites pairs : dernières racines vérifiées
-- (preuves d'ajout seul), pour détecter un journal non append-only.
CREATE TABLE kt_witness (
    site       TEXT    PRIMARY KEY,
    epoch      BIGINT  NOT NULL,
    root_hash  BYTEA   NOT NULL,
    checked_at BIGINT  NOT NULL
);
