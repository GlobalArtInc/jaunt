CREATE TABLE api_tokens (
    token_hash TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id),
    cert_serial BIGINT NOT NULL REFERENCES certificates(serial),
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);

CREATE INDEX api_tokens_user_id_idx ON api_tokens (user_id);

ALTER TABLE login_requests ADD COLUMN completion_hash TEXT;
