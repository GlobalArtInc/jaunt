ALTER TABLE certificates ADD COLUMN ca_fingerprint TEXT;

ALTER TABLE certificates ADD COLUMN host_trust_id TEXT;

ALTER TABLE node_certificates ADD COLUMN ca_fingerprint TEXT;

ALTER TABLE nodes ADD COLUMN trust_served_id TEXT;

ALTER TABLE nodes ADD COLUMN trust_served_at BIGINT;

CREATE INDEX certificates_valid_before_idx ON certificates (valid_before);
