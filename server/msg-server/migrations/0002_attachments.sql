-- Phase 2 : pièces jointes CHIFFRÉES (le serveur ne voit ni le nom, ni le
-- type, ni la taille exacte — remplissage par paliers côté client).
CREATE TABLE attachments (
    id            UUID   PRIMARY KEY,
    owner_device  UUID   NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    data          BYTEA  NOT NULL,
    size          BIGINT NOT NULL,
    created_at    BIGINT NOT NULL,
    expires_at    BIGINT NOT NULL
);
CREATE INDEX attachments_owner_idx ON attachments (owner_device);
CREATE INDEX attachments_expires_idx ON attachments (expires_at);
