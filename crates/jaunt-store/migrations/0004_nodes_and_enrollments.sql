CREATE TABLE nodes (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    labels TEXT NOT NULL,
    hostname TEXT NOT NULL,
    tls_public_key TEXT NOT NULL,
    ssh_host_public_key TEXT NOT NULL,
    tls_spki_sha256 TEXT NOT NULL,
    ssh_host_key_fingerprint TEXT NOT NULL,
    state TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    removed_at BIGINT
);

CREATE UNIQUE INDEX nodes_active_name_idx ON nodes (name) WHERE state = 'active';

CREATE TABLE enrollments (
    id TEXT PRIMARY KEY NOT NULL,
    handle_hash TEXT NOT NULL UNIQUE,
    code_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    labels TEXT NOT NULL,
    hostname TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    peer_addr TEXT NOT NULL,
    tls_public_key TEXT NOT NULL,
    ssh_host_public_key TEXT NOT NULL,
    replace_existing INTEGER NOT NULL,
    agent_version TEXT NOT NULL,
    state TEXT NOT NULL,
    node_id TEXT,
    approved_by TEXT,
    delivering_at BIGINT,
    expired_reported_at BIGINT,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);

CREATE INDEX enrollments_code_hash_idx ON enrollments (code_hash);

CREATE INDEX enrollments_expires_at_idx ON enrollments (expires_at);

CREATE TABLE node_certificates (
    id TEXT PRIMARY KEY NOT NULL,
    node_id TEXT NOT NULL REFERENCES nodes(id),
    kind TEXT NOT NULL,
    serial TEXT NOT NULL,
    not_before BIGINT NOT NULL,
    not_after BIGINT NOT NULL,
    issued_at BIGINT NOT NULL
);

CREATE INDEX node_certificates_node_id_idx ON node_certificates (node_id);
