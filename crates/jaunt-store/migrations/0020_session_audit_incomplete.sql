ALTER TABLE sessions ADD COLUMN audit_incomplete INTEGER NOT NULL DEFAULT 0 CHECK (audit_incomplete IN (0, 1));
