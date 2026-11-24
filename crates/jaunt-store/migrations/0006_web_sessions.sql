CREATE TABLE web_sessions (
    id_hash TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id),
    csrf_token_hash TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    last_seen_at BIGINT NOT NULL,
    source_ip TEXT,
    user_agent TEXT
);

CREATE INDEX web_sessions_user_id_created_at_idx ON web_sessions (user_id, created_at);

CREATE INDEX web_sessions_expires_at_idx ON web_sessions (expires_at);
