-- Associate completed proxy audits with NewAPI's system log by the opaque
-- request id returned in X-Oneapi-Request-Id. Retry state lives in SQLite so
-- the single background worker can resume after a process restart.
ALTER TABLE audit_records
ADD COLUMN newapi_request_id TEXT;

ALTER TABLE audit_records
ADD COLUMN caller_status TEXT NOT NULL DEFAULT 'none'
    CHECK (caller_status IN ('none', 'pending', 'resolved', 'unresolved'));

ALTER TABLE audit_records
ADD COLUMN caller_attempts INTEGER NOT NULL DEFAULT 0
    CHECK (caller_attempts >= 0);

ALTER TABLE audit_records
ADD COLUMN caller_next_at_ns INTEGER;

ALTER TABLE audit_records
ADD COLUMN caller_updated_at_ns INTEGER;

CREATE INDEX audit_records_caller_due_idx
    ON audit_records(caller_status, caller_next_at_ns, started_at_ns, audit_id);

CREATE INDEX audit_records_newapi_request_idx
    ON audit_records(newapi_request_id);

-- Keep masked_key only for backward compatibility with version-3 databases.
-- New request-id based links never populate or expose it.
ALTER TABLE token_links
ADD COLUMN newapi_user_id INTEGER NOT NULL DEFAULT 0;

ALTER TABLE token_links
ADD COLUMN username TEXT NOT NULL DEFAULT '';
