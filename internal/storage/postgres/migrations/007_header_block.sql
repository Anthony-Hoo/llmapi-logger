-- Capture version 2 (doc/design/issue-59-stage3-write-path.md, C and E.1).
-- A version 2 audit stores its Headers as one sealed block per audit in
-- http_header_blocks, its inbound User-Agent in audit_records.user_agent_enc
-- and the content headers the parser uses in two http_stages columns. Version 1
-- audits keep their http_headers rows.
--
-- Nothing is backfilled and no existing row is rewritten. ADD COLUMN with a
-- constant default or none only changes the catalog. A CHECK added with a new
-- column would scan the whole table to validate it, so every CHECK on an
-- existing table is added NOT VALID: it holds for every row written or updated
-- from now on, and the existing rows are version 1 with the new columns NULL.
ALTER TABLE audit_records
    ADD COLUMN capture_version BIGINT NOT NULL DEFAULT 1,
    ADD COLUMN user_agent_enc BYTEA;
ALTER TABLE audit_records
    ADD CONSTRAINT audit_records_capture_version_check
    CHECK (capture_version IN (1, 2)) NOT VALID;

ALTER TABLE http_stages
    ADD COLUMN content_type TEXT COLLATE "C",
    ADD COLUMN content_encoding TEXT COLLATE "C";
ALTER TABLE http_stages
    ADD CONSTRAINT http_stages_content_type_check
    CHECK (content_type <> '') NOT VALID,
    ADD CONSTRAINT http_stages_content_encoding_check
    CHECK (content_encoding <> '') NOT VALID;

CREATE TABLE http_header_blocks (
    audit_id TEXT COLLATE "C" PRIMARY KEY
        REFERENCES audit_records(audit_id) ON DELETE CASCADE,
    compression TEXT COLLATE "C" NOT NULL CHECK (compression IN ('none', 'gzip')),
    plaintext_length BIGINT NOT NULL CHECK (plaintext_length >= 0),
    block_enc BYTEA NOT NULL
);

-- The audit_capture section of runtime_settings holds the CommitAudit retry
-- count (H.3). runtime_settings_section_check is the name PostgreSQL gave the
-- inline CHECK of 003_session_analysis.sql. The table has a few rows at most,
-- so validating the new constraint costs nothing.
ALTER TABLE runtime_settings DROP CONSTRAINT runtime_settings_section_check;
ALTER TABLE runtime_settings ADD CONSTRAINT runtime_settings_section_check
    CHECK (section IN ('session_analysis', 'org_reports', 'audit_capture'));
