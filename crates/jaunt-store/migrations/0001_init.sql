CREATE TABLE users (
    id TEXT PRIMARY KEY NOT NULL,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    email TEXT NOT NULL,
    display_name TEXT,
    groups TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE (issuer, subject)
);

CREATE TABLE login_requests (
    id TEXT PRIMARY KEY NOT NULL,
    kind TEXT NOT NULL,
    state TEXT NOT NULL,
    pkce_challenge TEXT NOT NULL,
    user_id TEXT REFERENCES users(id),
    client_label TEXT,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    redeemed_at BIGINT
);

CREATE INDEX login_requests_expires_at_idx ON login_requests (expires_at);

CREATE TABLE serial_counter (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    next_serial BIGINT NOT NULL
);

INSERT INTO serial_counter (id, next_serial) VALUES (1, 1);

CREATE TABLE certificates (
    serial BIGINT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id),
    kind TEXT NOT NULL,
    key_id TEXT NOT NULL,
    valid_after BIGINT NOT NULL,
    valid_before BIGINT NOT NULL,
    issued_at BIGINT NOT NULL
);

CREATE INDEX certificates_user_id_idx ON certificates (user_id);
