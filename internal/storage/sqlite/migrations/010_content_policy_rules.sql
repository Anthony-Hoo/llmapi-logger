-- Dynamically configured keyword rules (doc/features/22-content-policy.md).
-- Rules are local administrator configuration, not audit evidence, so they do
-- not participate in the integrity event chain. The table starts empty on
-- purpose: no rule means no interception. scan_scopes and keywords store JSON
-- arrays; the service layer serializes and validates them before persisting.
CREATE TABLE content_policy_rules (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    action TEXT NOT NULL CHECK (action IN ('block', 'dry_run')),
    model_pattern TEXT NOT NULL CHECK (length(model_pattern) <= 2048),
    scan_scopes TEXT NOT NULL CHECK (length(scan_scopes) BETWEEN 2 AND 512),
    keywords TEXT NOT NULL CHECK (length(keywords) BETWEEN 2 AND 65536),
    created_at_ns INTEGER NOT NULL CHECK (created_at_ns > 0),
    updated_at_ns INTEGER NOT NULL CHECK (updated_at_ns >= created_at_ns)
);
