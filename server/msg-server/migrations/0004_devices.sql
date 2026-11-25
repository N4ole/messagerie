-- Phase 3 : liaison d'appareils et révocation.

-- Demandes de liaison d'un nouvel appareil. Le secret de consultation n'est
-- stocké que haché. Une demande n'ouvre aucun accès tant qu'un appareil
-- détenteur de la clé d'identité n'a pas signé le certificat.
CREATE TABLE link_requests (
    id                 UUID    PRIMARY KEY,
    account_id         BIGINT  NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    device_id          UUID    NOT NULL UNIQUE,
    api_key            BYTEA   NOT NULL,
    mls_signature_key  BYTEA   NOT NULL,
    poll_hash          BYTEA   NOT NULL,
    status             TEXT    NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
    created_at         BIGINT  NOT NULL,
    expires_at         BIGINT  NOT NULL
);
CREATE INDEX link_requests_account_idx ON link_requests (account_id);
CREATE INDEX link_requests_expires_idx ON link_requests (expires_at);

-- Appareils révoqués : la clé API est conservée pour authentifier l'appareil
-- révoqué (et lui seul) lorsqu'il se reconnecte, afin qu'il efface ses
-- données locales.
CREATE TABLE revoked_devices (
    device_id   UUID    PRIMARY KEY,
    account_id  BIGINT  REFERENCES accounts (id) ON DELETE CASCADE,
    api_key     BYTEA   NOT NULL,
    revoked_at  BIGINT  NOT NULL
);
