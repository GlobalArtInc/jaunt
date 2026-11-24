CREATE TABLE sessions (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id),
    serial BIGINT NOT NULL REFERENCES certificates(serial),
    node_id TEXT NOT NULL REFERENCES nodes(id),
    state TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    authorized_at BIGINT,
    ended_at BIGINT,
    login TEXT,
    exit_status INTEGER,
    bytes_in BIGINT,
    bytes_out BIGINT,
    recording_incomplete INTEGER
);

CREATE INDEX sessions_state_expires_at_idx ON sessions (state, expires_at);

CREATE INDEX sessions_node_id_idx ON sessions (node_id);
