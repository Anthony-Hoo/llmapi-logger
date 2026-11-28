-- Cold archive catalog (doc/design/issue-59-stage4-cold-archive.md, I).
-- Management data only: no table here is part of the integrity event chain,
-- none references audit_records (an archived audit is later removed), and the
-- SQLite offline importer never sees them.
CREATE TABLE archive_runs (
    run_id TEXT COLLATE "C" PRIMARY KEY CHECK (length(run_id) = 32),
    mode TEXT COLLATE "C" NOT NULL CHECK (mode IN ('export_only', 'archive_then_delete')),
    cutoff_ns BIGINT NOT NULL CHECK (cutoff_ns > 0),
    started_at_ns BIGINT NOT NULL CHECK (started_at_ns > 0),
    finished_at_ns BIGINT,
    status TEXT COLLATE "C" NOT NULL CHECK (status IN ('running', 'completed', 'archive_failed', 'interrupted')),
    exported_audits BIGINT NOT NULL DEFAULT 0 CHECK (exported_audits >= 0),
    integrity_failed_audits BIGINT NOT NULL DEFAULT 0 CHECK (integrity_failed_audits >= 0),
    stale_audits BIGINT NOT NULL DEFAULT 0 CHECK (stale_audits >= 0),
    removed_audits BIGINT NOT NULL DEFAULT 0 CHECK (removed_audits >= 0),
    removed_gaps BIGINT NOT NULL DEFAULT 0 CHECK (removed_gaps >= 0),
    deferred_audits BIGINT NOT NULL DEFAULT 0 CHECK (deferred_audits >= 0),
    segments BIGINT NOT NULL DEFAULT 0 CHECK (segments >= 0),
    disk_bytes BIGINT NOT NULL DEFAULT 0 CHECK (disk_bytes >= 0),
    -- Selection watermark (B.1) after the last completed pass, for this format.
    format_version BIGINT NOT NULL CHECK (format_version >= 0),
    watermark_started_at_ns BIGINT,
    watermark_audit_id TEXT COLLATE "C",
    CHECK ((watermark_started_at_ns IS NULL) = (watermark_audit_id IS NULL))
);

-- Audits a pass looked at behind the watermark but did not export, which the
-- next passes check again (B.1).
CREATE TABLE archive_deferred (
    audit_id TEXT COLLATE "C" PRIMARY KEY,
    reason TEXT COLLATE "C" NOT NULL CHECK (reason IN ('open', 'parse_pending', 'caller_pending', 'integrity_failed')),
    first_seen_at_ns BIGINT NOT NULL CHECK (first_seen_at_ns > 0),
    last_checked_at_ns BIGINT NOT NULL CHECK (last_checked_at_ns >= first_seen_at_ns)
);

CREATE TABLE archive_segments (
    segment_id TEXT COLLATE "C" PRIMARY KEY CHECK (length(segment_id) = 32),
    run_id TEXT COLLATE "C" NOT NULL REFERENCES archive_runs(run_id) ON DELETE RESTRICT,
    bundle_kind TEXT COLLATE "C" NOT NULL CHECK (bundle_kind IN ('conversation', 'bucket', 'gaps')),
    format_version BIGINT NOT NULL CHECK (format_version >= 0),
    -- Relative to archive.dir, forward slashes; never an absolute path.
    manifest_name TEXT COLLATE "C" NOT NULL UNIQUE
        CHECK (length(manifest_name) BETWEEN 1 AND 1024 AND left(manifest_name, 1) <> '/'),
    manifest_sha256 BYTEA CHECK (manifest_sha256 IS NULL OR length(manifest_sha256) = 32),
    key_fingerprint BYTEA NOT NULL CHECK (length(key_fingerprint) = 32),
    encrypted BIGINT NOT NULL CHECK (encrypted IN (0, 1)),
    member_count BIGINT NOT NULL CHECK (member_count >= 0),
    disk_bytes BIGINT NOT NULL CHECK (disk_bytes >= 0),
    first_started_at_ns BIGINT,
    last_ended_at_ns BIGINT,
    state TEXT COLLATE "C" NOT NULL CHECK (state IN ('publishing', 'sealed', 'hot_removed')),
    created_at_ns BIGINT NOT NULL CHECK (created_at_ns > 0),
    sealed_at_ns BIGINT,
    removed_at_ns BIGINT,
    CHECK (state = 'publishing' OR (manifest_sha256 IS NOT NULL AND sealed_at_ns IS NOT NULL))
);

CREATE TABLE archive_members (
    audit_id TEXT COLLATE "C" NOT NULL,
    revision BIGINT NOT NULL CHECK (revision >= 1),
    segment_id TEXT COLLATE "C" NOT NULL REFERENCES archive_segments(segment_id) ON DELETE CASCADE,
    record_digest BYTEA NOT NULL CHECK (length(record_digest) = 32),
    -- NULL only for members registered from an unrecorded bundle (stale).
    change_stamp BYTEA CHECK (change_stamp IS NULL OR length(change_stamp) = 32),
    state TEXT COLLATE "C" NOT NULL CHECK (state IN ('sealed', 'hot_removed', 'stale')),
    started_at_ns BIGINT NOT NULL,
    -- turns.created_at_ns at export; NULL for an audit without a turn. Removal
    -- deletes in descending order of it (M.2).
    turn_created_at_ns BIGINT,
    state_changed_at_ns BIGINT NOT NULL CHECK (state_changed_at_ns > 0),
    PRIMARY KEY (audit_id, revision),
    CHECK (state = 'stale' OR change_stamp IS NOT NULL)
);

-- At most one current (not stale) member per audit.
CREATE UNIQUE INDEX archive_members_current_idx
    ON archive_members (audit_id) WHERE state <> 'stale';
CREATE INDEX archive_members_segment_idx ON archive_members (segment_id);
CREATE INDEX archive_members_removal_idx
    ON archive_members (segment_id, turn_created_at_ns DESC, audit_id) WHERE state = 'sealed';

CREATE TABLE archive_gap_members (
    gap_id BIGINT PRIMARY KEY,
    segment_id TEXT COLLATE "C" NOT NULL REFERENCES archive_segments(segment_id) ON DELETE CASCADE,
    state TEXT COLLATE "C" NOT NULL CHECK (state IN ('sealed', 'hot_removed'))
);
CREATE INDEX archive_gap_members_segment_idx ON archive_gap_members (segment_id);
