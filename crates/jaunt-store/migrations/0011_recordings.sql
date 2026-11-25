ALTER TABLE sessions ADD COLUMN pty INTEGER;

ALTER TABLE sessions ADD COLUMN record_input INTEGER;

CREATE TABLE recordings (
    session_id TEXT PRIMARY KEY NOT NULL REFERENCES sessions(id),
    node_id TEXT NOT NULL REFERENCES nodes(id),
    state TEXT NOT NULL,
    chunks BIGINT NOT NULL,
    raw_bytes BIGINT NOT NULL,
    progress_sha256 TEXT,
    digest TEXT,
    input_recorded INTEGER NOT NULL,
    incomplete INTEGER NOT NULL,
    session_incomplete INTEGER,
    salvaged INTEGER NOT NULL,
    dropped_chunks BIGINT NOT NULL,
    location TEXT,
    cast_sha256 TEXT,
    manifest_sha256 TEXT,
    created_at BIGINT NOT NULL,
    completed_at BIGINT
);

CREATE INDEX recordings_node_id_created_at_idx ON recordings (node_id, created_at, session_id);

CREATE INDEX recordings_state_idx ON recordings (state);
