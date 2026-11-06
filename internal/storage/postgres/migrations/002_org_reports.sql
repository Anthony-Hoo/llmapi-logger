-- Organisation project reports (doc/features/23-org-project-reports.md).
-- Every table here is derived or management data: none is part of the
-- integrity event chain and none is copied by the SQLite offline importer.
-- Raw repository paths, remote URLs and working directories never appear in
-- plaintext; identity_enc holds them encrypted and the *_fpr columns are
-- keyed HMAC tags.
CREATE TABLE audit_project_identity (
    audit_id TEXT COLLATE "C" PRIMARY KEY REFERENCES audit_records(audit_id) ON DELETE CASCADE,
    identity_version BIGINT NOT NULL CHECK (identity_version > 0),
    extracted_at_ns BIGINT NOT NULL CHECK (extracted_at_ns > 0),
    source TEXT COLLATE "C" NOT NULL CHECK (source IN
        ('declared', 'codex_turn_metadata', 'agent_header', 'root', 'cwd', 'none')),
    body_scanned BIGINT NOT NULL CHECK (body_scanned IN (0, 1)),
    identity_fpr BYTEA CHECK (identity_fpr IS NULL OR length(identity_fpr) = 32),
    remote_fpr BYTEA CHECK (remote_fpr IS NULL OR length(remote_fpr) = 32),
    repo_root_fpr BYTEA CHECK (repo_root_fpr IS NULL OR length(repo_root_fpr) = 32),
    cwd_fpr BYTEA CHECK (cwd_fpr IS NULL OR length(cwd_fpr) = 32),
    identity_enc BYTEA CHECK (identity_enc IS NULL OR length(identity_enc) > 0),
    CHECK (
        (source = 'none' AND identity_fpr IS NULL AND identity_enc IS NULL
            AND remote_fpr IS NULL AND repo_root_fpr IS NULL AND cwd_fpr IS NULL)
        OR
        (source <> 'none' AND identity_fpr IS NOT NULL AND identity_enc IS NOT NULL)
    )
);

CREATE INDEX audit_project_identity_fpr_idx ON audit_project_identity (identity_fpr)
    WHERE identity_fpr IS NOT NULL;

CREATE INDEX audit_project_identity_version_idx ON audit_project_identity (identity_version);
