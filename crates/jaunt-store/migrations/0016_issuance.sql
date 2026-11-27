ALTER TABLE certificates ADD COLUMN parent_serial BIGINT REFERENCES certificates(serial);

CREATE INDEX certificates_parent_serial_idx ON certificates (parent_serial);

CREATE TABLE service_certificates (
    serial BIGINT PRIMARY KEY NOT NULL,
    node_id TEXT NOT NULL REFERENCES nodes(id),
    service_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    dns_name TEXT NOT NULL,
    valid_after BIGINT NOT NULL,
    valid_before BIGINT NOT NULL,
    issued_at BIGINT NOT NULL,
    root_sha256 TEXT NOT NULL,
    subject_fingerprint TEXT NOT NULL,
    CHECK (kind IN ('kubernetes', 'postgres', 'tcp')),
    CHECK (valid_before > valid_after)
);

CREATE INDEX service_certificates_node_id_idx ON service_certificates (node_id);

CREATE INDEX service_certificates_valid_before_idx ON service_certificates (valid_before);
