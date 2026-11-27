CREATE TABLE user_pins (
    user_id TEXT NOT NULL REFERENCES users(id),
    node_id TEXT NOT NULL REFERENCES nodes(id),
    created_at BIGINT NOT NULL,
    PRIMARY KEY (user_id, node_id)
);

ALTER TABLE sessions ADD COLUMN origin TEXT NOT NULL DEFAULT 'ssh' CHECK (origin IN ('web', 'ssh'));

UPDATE sessions SET origin = 'web' WHERE id IN
    (SELECT session_id FROM audit_events WHERE event_type = 'terminal.opened' AND session_id IS NOT NULL);

CREATE INDEX sessions_user_id_origin_created_at_idx ON sessions (user_id, origin, created_at);

ALTER TABLE audit_events ADD COLUMN reference TEXT;

CREATE INDEX audit_events_reference_time_ms_idx ON audit_events (reference, time_ms) WHERE reference IS NOT NULL;
