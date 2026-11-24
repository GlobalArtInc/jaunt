CREATE TABLE audit_events (
    id TEXT PRIMARY KEY NOT NULL,
    time_ms BIGINT NOT NULL,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    node TEXT,
    session_id TEXT,
    policy_hash TEXT,
    payload TEXT NOT NULL,
    v INTEGER NOT NULL
);

CREATE INDEX audit_events_time_ms_id_idx ON audit_events (time_ms, id);

CREATE INDEX audit_events_actor_time_ms_idx ON audit_events (actor, time_ms);

CREATE INDEX audit_events_node_time_ms_idx ON audit_events (node, time_ms);

CREATE INDEX audit_events_session_id_time_ms_idx ON audit_events (session_id, time_ms);
