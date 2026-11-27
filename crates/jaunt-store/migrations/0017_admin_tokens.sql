CREATE TABLE admin_tokens (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    creator_user_id TEXT NOT NULL,
    secret_hash TEXT NOT NULL UNIQUE,
    scope TEXT NOT NULL,
    cidrs TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    revoked_at BIGINT,
    last_used_at BIGINT,
    CHECK (id <> ''),
    CHECK (name <> ''),
    CHECK (creator_user_id <> ''),
    CHECK (secret_hash <> ''),
    CHECK (expires_at > created_at)
);

CREATE INDEX admin_tokens_creator_user_id_name_idx ON admin_tokens (creator_user_id, name);

CREATE INDEX admin_tokens_expires_at_idx ON admin_tokens (expires_at);
