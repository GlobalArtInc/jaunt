ALTER TABLE sessions ADD COLUMN parent_session_id TEXT REFERENCES sessions(id);

ALTER TABLE sessions ADD COLUMN record INTEGER CHECK (record IS NULL OR record IN (0, 1));

CREATE INDEX sessions_parent_session_id_idx ON sessions (parent_session_id, state);

CREATE INDEX sessions_node_id_children_idx ON sessions (node_id, state) WHERE parent_session_id IS NOT NULL;
