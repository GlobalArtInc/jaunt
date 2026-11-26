CREATE TABLE join_tokens (
    id TEXT PRIMARY KEY NOT NULL,
    hash TEXT NOT NULL UNIQUE,
    name TEXT,
    name_prefix TEXT,
    labels TEXT NOT NULL,
    max_uses BIGINT NOT NULL,
    uses_left BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    allow_replace INTEGER NOT NULL,
    created_by TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    revoked_at BIGINT,
    CHECK ((name IS NULL AND name_prefix IS NOT NULL) OR (name IS NOT NULL AND name_prefix IS NULL)),
    CHECK (name IS NULL OR name <> ''),
    CHECK (name_prefix IS NULL OR name_prefix <> ''),
    CHECK (max_uses > 0 AND uses_left >= 0 AND uses_left <= max_uses),
    CHECK (allow_replace IN (0, 1))
);

CREATE INDEX join_tokens_expires_at_idx ON join_tokens (expires_at);
