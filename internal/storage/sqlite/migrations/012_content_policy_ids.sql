-- Preserve current identities and retain the allocation high-water mark across deletes/restarts.
CREATE TABLE content_policy_rules_monotonic (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    action TEXT NOT NULL CHECK (action IN ('block', 'dry_run')),
    model_pattern TEXT NOT NULL CHECK (length(model_pattern) <= 2048),
    scan_scopes TEXT NOT NULL CHECK (length(scan_scopes) BETWEEN 2 AND 512),
    keywords TEXT NOT NULL CHECK (length(keywords) BETWEEN 2 AND 65536),
    created_at_ns INTEGER NOT NULL CHECK (created_at_ns > 0),
    updated_at_ns INTEGER NOT NULL CHECK (updated_at_ns >= created_at_ns)
);

INSERT INTO content_policy_rules_monotonic SELECT * FROM content_policy_rules;
DROP TABLE content_policy_rules;
ALTER TABLE content_policy_rules_monotonic RENAME TO content_policy_rules;
