ALTER TABLE nodes ADD COLUMN ssh_enabled INTEGER NOT NULL DEFAULT 1 CHECK (ssh_enabled IN (0, 1));

CREATE TABLE services (
    id TEXT PRIMARY KEY NOT NULL,
    node_id TEXT NOT NULL REFERENCES nodes(id),
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    labels TEXT NOT NULL,
    announced_labels TEXT NOT NULL,
    settings TEXT NOT NULL,
    address_hint TEXT,
    state TEXT NOT NULL,
    revision BIGINT NOT NULL,
    announced INTEGER NOT NULL,
    approved_by TEXT,
    approved_at BIGINT,
    created_at BIGINT NOT NULL,
    last_seen_at BIGINT NOT NULL,
    CHECK (kind IN ('kubernetes', 'postgres', 'tcp')),
    CHECK (state IN ('pending', 'approved', 'removed')),
    CHECK (announced IN (0, 1)),
    CHECK (revision > 0),
    CHECK (state <> 'approved' OR (approved_by IS NOT NULL AND approved_at IS NOT NULL))
);

CREATE UNIQUE INDEX services_revision_idx ON services (node_id, kind, name, revision);

CREATE UNIQUE INDEX services_approved_idx ON services (node_id, kind, name) WHERE state = 'approved';

CREATE UNIQUE INDEX services_pending_idx ON services (node_id, kind, name) WHERE state = 'pending';

CREATE INDEX services_kind_name_idx ON services (kind, name);

CREATE INDEX services_created_at_id_idx ON services (created_at, id);
