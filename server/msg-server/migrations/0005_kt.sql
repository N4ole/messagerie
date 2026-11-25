-- Phase 3 : Key Transparency (akd).

-- Lots publiés, dans l'ordre. Le répertoire akd est reconstruit en mémoire
-- au démarrage en rejouant ces lots ; chaque racine recalculée doit être
-- identique à la racine journalisée (sinon le serveur refuse de servir KT).
-- Les valeurs publiées sont des hachés : ni clé ni appareil en clair ici.
CREATE TABLE kt_log (
    epoch       BIGINT  PRIMARY KEY,
    entries     TEXT    NOT NULL,
    root_hash   BYTEA   NOT NULL,
    created_at  BIGINT  NOT NULL
);

-- Utilisateurs dont l'entrée d'annuaire a changé et doit être publiée.
CREATE TABLE kt_dirty (
    username  TEXT  PRIMARY KEY
);
