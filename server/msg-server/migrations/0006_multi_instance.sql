-- Phase 4 : plusieurs instances du serveur sur la même base.

-- Tickets d'ouverture du WebSocket (client web) : partagés entre instances,
-- stockés uniquement hachés, à usage unique, 30 secondes.
CREATE TABLE ws_tickets (
    ticket_hash  BYTEA   PRIMARY KEY,
    device_id    UUID    NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    expires_at   BIGINT  NOT NULL
);
CREATE INDEX ws_tickets_expires_idx ON ws_tickets (expires_at);
