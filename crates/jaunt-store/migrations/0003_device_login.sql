ALTER TABLE login_requests ADD COLUMN user_code_hash TEXT;

ALTER TABLE login_requests ADD COLUMN requester_ip TEXT;

CREATE INDEX login_requests_user_code_hash_idx ON login_requests (user_code_hash);
