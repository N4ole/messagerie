-- Phase 2 : passkeys / clés de sécurité FIDO2 (YubiKey) comme second facteur.
ALTER TABLE accounts ADD COLUMN webauthn_user_id UUID;

CREATE TABLE webauthn_credentials (
    id             BIGSERIAL PRIMARY KEY,
    account_id     BIGINT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    credential_id  BYTEA  NOT NULL UNIQUE,
    name           TEXT   NOT NULL,
    -- État public de la clé (clé publique COSE, compteur), sérialisé par webauthn-rs.
    passkey        TEXT   NOT NULL,
    created_at     BIGINT NOT NULL,
    last_used_at   BIGINT
);
CREATE INDEX webauthn_credentials_account_idx ON webauthn_credentials (account_id);

-- Défis en cours (usage unique, courte durée).
CREATE TABLE webauthn_challenges (
    id          UUID   PRIMARY KEY,
    account_id  BIGINT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    kind        TEXT   NOT NULL CHECK (kind IN ('register', 'authenticate')),
    state       TEXT   NOT NULL,
    expires_at  BIGINT NOT NULL
);
CREATE INDEX webauthn_challenges_expires_idx ON webauthn_challenges (expires_at);
