ALTER TABLE sessions ADD COLUMN kind TEXT NOT NULL DEFAULT 'ssh' CHECK (kind IN ('ssh', 'kube', 'db', 'tcp'));

ALTER TABLE sessions ADD COLUMN service_id TEXT;

ALTER TABLE sessions ADD COLUMN service_name TEXT CHECK (service_name IS NULL OR length(service_name) <= 63);

ALTER TABLE sessions ADD COLUMN target TEXT CHECK (target IS NULL OR length(target) <= 320);

ALTER TABLE sessions ADD COLUMN roles TEXT NOT NULL DEFAULT '[]' CHECK (length(roles) <= 4096);

ALTER TABLE sessions ADD COLUMN grant_ids TEXT NOT NULL DEFAULT '[]' CHECK (length(grant_ids) <= 4096);

ALTER TABLE sessions ADD COLUMN db_client_serial BIGINT;

ALTER TABLE sessions ADD COLUMN outcome TEXT CHECK (outcome IS NULL OR length(outcome) <= 32);

ALTER TABLE sessions ADD COLUMN decision_hash TEXT CHECK (decision_hash IS NULL OR length(decision_hash) = 64);

CREATE INDEX sessions_kind_state_idx ON sessions (kind, state);

CREATE INDEX sessions_service_id_idx ON sessions (service_id);

CREATE INDEX sessions_service_name_idx ON sessions (service_name, kind, state);
