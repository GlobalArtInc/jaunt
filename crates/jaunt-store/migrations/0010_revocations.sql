CREATE TABLE revocations (
    id TEXT PRIMARY KEY NOT NULL,
    kind TEXT NOT NULL,
    subject TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    created_by TEXT NOT NULL,
    UNIQUE (kind, subject)
);

CREATE INDEX revocations_created_at_id_idx ON revocations (created_at, id);

ALTER TABLE sessions ADD COLUMN end_reason TEXT;

ALTER TABLE sessions ADD COLUMN max_duration_secs BIGINT;

CREATE INDEX sessions_user_id_idx ON sessions (user_id);

CREATE INDEX sessions_serial_idx ON sessions (serial);
