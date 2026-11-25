ALTER TABLE nodes ADD COLUMN agent_version TEXT;

CREATE INDEX sessions_created_at_id_idx ON sessions (created_at, id);
