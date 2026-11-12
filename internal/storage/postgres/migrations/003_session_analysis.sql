-- Session analysis (doc/features/24-session-analysis.md). Every table here is
-- derived data: recomputable, outside the integrity event chain, and never
-- part of the offline SQLite import. Plaintext columns hold only counts, enums,
-- model names and keyed fingerprints; anything else is AES-GCM ciphertext.

-- One analysis session is the part of one agent-tree root sent with one API
-- key: session_key is a keyed fingerprint of (agent_root_fpr, api_key_fpr), so
-- two keys reusing a client session id never share derived rows.
CREATE TABLE session_signals (
    session_key BYTEA PRIMARY KEY CHECK (length(session_key) = 32),
    agent_root_fpr BYTEA NOT NULL CHECK (length(agent_root_fpr) = 32),
    kind TEXT COLLATE "C" NOT NULL CHECK (kind IN ('agent', 'chat')),
    api_key_fpr BYTEA,
    newapi_user_id BIGINT,
    newapi_token_id BIGINT,
    client TEXT COLLATE "C",
    main_session_id TEXT COLLATE "C",
    main_model TEXT COLLATE "C",
    first_ns BIGINT NOT NULL,
    last_ns BIGINT NOT NULL CHECK (last_ns >= first_ns),
    last_audit_id TEXT COLLATE "C" NOT NULL,
    requests BIGINT NOT NULL DEFAULT 0,
    main_requests BIGINT NOT NULL DEFAULT 0,
    sub_requests BIGINT NOT NULL DEFAULT 0,
    aux_requests BIGINT NOT NULL DEFAULT 0,
    subagents BIGINT NOT NULL DEFAULT 0,
    max_depth BIGINT NOT NULL DEFAULT 0,
    user_turns BIGINT NOT NULL DEFAULT 0,
    active_ns BIGINT NOT NULL DEFAULT 0,
    input_tokens BIGINT NOT NULL DEFAULT 0,
    output_tokens BIGINT NOT NULL DEFAULT 0,
    cache_read_tokens BIGINT NOT NULL DEFAULT 0,
    cost_usd DOUBLE PRECISION,
    compactions BIGINT NOT NULL DEFAULT 0,
    model_switches BIGINT NOT NULL DEFAULT 0,
    length_stops BIGINT NOT NULL DEFAULT 0,
    upstream_errors BIGINT NOT NULL DEFAULT 0,
    tool_calls BIGINT NOT NULL DEFAULT 0,
    tool_failures BIGINT NOT NULL DEFAULT 0,
    tool_unknown BIGINT NOT NULL DEFAULT 0,
    max_failure_streak BIGINT NOT NULL DEFAULT 0,
    loops BIGINT NOT NULL DEFAULT 0,
    max_loop_length BIGINT NOT NULL DEFAULT 0,
    thrash_files BIGINT NOT NULL DEFAULT 0,
    max_file_writes BIGINT NOT NULL DEFAULT 0,
    verified TEXT COLLATE "C" NOT NULL DEFAULT 'no_writes' CHECK (verified IN ('yes', 'no', 'no_writes')),
    error_pastes BIGINT NOT NULL DEFAULT 0,
    interrupts BIGINT NOT NULL DEFAULT 0,
    corrections BIGINT NOT NULL DEFAULT 0,
    heavy_model BOOLEAN NOT NULL DEFAULT FALSE,
    danger_counts TEXT COLLATE "C" NOT NULL DEFAULT '{}',
    secret_counts TEXT COLLATE "C" NOT NULL DEFAULT '{}',
    eligible BOOLEAN NOT NULL DEFAULT FALSE,
    skip_reason TEXT COLLATE "C",
    signal_version BIGINT NOT NULL CHECK (signal_version > 0),
    computed_at_ns BIGINT NOT NULL,
    -- Single-turn chats only: the keyed fingerprint of their digest bucket
    -- (key, client, local day), and whether that bucket's digest packs still
    -- have to be rebuilt to include them. Cleared by the bucket's rebuild.
    digest_bucket BYTEA CHECK (digest_bucket IS NULL OR length(digest_bucket) = 32),
    digest_pending BOOLEAN NOT NULL DEFAULT FALSE,
    -- Organisation reports only (doc 23): the project the session is booked
    -- to and its bucket. Both NULL when org reports are off or the project
    -- identity of its requests has not been extracted yet.
    project_id BIGINT,
    bucket TEXT COLLATE "C" CHECK (bucket IS NULL OR bucket IN ('attributed', 'unattributed', 'no_context', 'service'))
);
CREATE INDEX session_signals_last_idx ON session_signals(last_ns);
CREATE INDEX session_signals_digest_pending_idx ON session_signals(last_ns) WHERE digest_pending;
CREATE INDEX session_signals_root_idx ON session_signals(agent_root_fpr);
CREATE INDEX session_signals_key_idx ON session_signals(api_key_fpr, last_ns);
CREATE INDEX session_signals_token_idx ON session_signals(newapi_token_id, last_ns);
CREATE INDEX session_signals_project_idx ON session_signals(project_id, last_ns) WHERE project_id IS NOT NULL;
CREATE INDEX session_signals_user_idx ON session_signals(newapi_user_id, last_ns) WHERE newapi_user_id IS NOT NULL;

-- Keyed fingerprints of normalized sentences, kept beyond audit retention for
-- cross-session repeat detection. No text is stored.
CREATE TABLE session_text_fprs (
    session_key BYTEA NOT NULL CHECK (length(session_key) = 32),
    source TEXT COLLATE "C" NOT NULL CHECK (source IN ('user_text', 'injected_rules', 'facet_instruction', 'facet_skill')),
    fpr BYTEA NOT NULL CHECK (length(fpr) = 32),
    api_key_fpr BYTEA,
    seen_at_ns BIGINT NOT NULL,
    -- The session's project when it was last booked; kept here because these
    -- rows outlive session_signals.
    project_id BIGINT,
    PRIMARY KEY (session_key, source, fpr)
);
CREATE INDEX session_text_fprs_fpr_idx ON session_text_fprs(fpr, source);
CREATE INDEX session_text_fprs_seen_idx ON session_text_fprs(seen_at_ns);
CREATE INDEX session_text_fprs_project_idx ON session_text_fprs(project_id, seen_at_ns) WHERE project_id IS NOT NULL;

-- Input packs (doc 24 section 6): one per eligible session, or one chat
-- digest per key, client and local day (members list its sessions). The text
-- is AES-GCM ciphertext; ref_map maps line labels to audit ids.
CREATE TABLE session_packs (
    session_key BYTEA PRIMARY KEY CHECK (length(session_key) = 32),
    kind TEXT COLLATE "C" NOT NULL CHECK (kind IN ('session', 'chat_digest')),
    api_key_fpr BYTEA,
    newapi_token_id BIGINT,
    client TEXT COLLATE "C",
    pack_hash TEXT COLLATE "C" NOT NULL CHECK (length(pack_hash) = 64),
    pack_enc BYTEA NOT NULL,
    ref_map TEXT COLLATE "C" NOT NULL DEFAULT '{}',
    token_estimate BIGINT NOT NULL CHECK (token_estimate >= 0),
    truncated BOOLEAN NOT NULL DEFAULT FALSE,
    members BIGINT NOT NULL DEFAULT 1,
    first_ns BIGINT NOT NULL,
    last_ns BIGINT NOT NULL,
    last_audit_id TEXT COLLATE "C" NOT NULL,
    built_at_ns BIGINT NOT NULL
);
CREATE INDEX session_packs_last_idx ON session_packs(last_ns);

CREATE TABLE session_pack_members (
    pack_key BYTEA NOT NULL REFERENCES session_packs(session_key) ON DELETE CASCADE,
    session_key BYTEA NOT NULL CHECK (length(session_key) = 32),
    PRIMARY KEY (pack_key, session_key)
);
CREATE INDEX session_pack_members_session_idx ON session_pack_members(session_key);

-- Append-only record of who opened which session's pack or facet (doc 24
-- section 9). Kept beyond retention.
CREATE TABLE analysis_view_log (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    at_ns BIGINT NOT NULL,
    viewer_role TEXT COLLATE "C" NOT NULL CHECK (viewer_role IN ('admin', 'developer')),
    viewer_user_id BIGINT,
    viewer_token_id BIGINT,
    resource TEXT COLLATE "C" NOT NULL CHECK (resource IN ('pack', 'facet')),
    session_key BYTEA NOT NULL CHECK (length(session_key) = 32)
);
CREATE INDEX analysis_view_log_at_idx ON analysis_view_log(at_ns);

CREATE TABLE session_analysis_runs (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    started_at_ns BIGINT NOT NULL,
    finished_at_ns BIGINT NOT NULL,
    trigger TEXT COLLATE "C" NOT NULL CHECK (trigger IN ('schedule', 'manual')),
    candidates BIGINT NOT NULL DEFAULT 0,
    analyzed BIGINT NOT NULL DEFAULT 0,
    skipped BIGINT NOT NULL DEFAULT 0,
    skip_reasons TEXT COLLATE "C" NOT NULL DEFAULT '{}',
    pruned BIGINT NOT NULL DEFAULT 0,
    l1_candidates BIGINT NOT NULL DEFAULT 0,
    l1_ok BIGINT NOT NULL DEFAULT 0,
    l1_invalid BIGINT NOT NULL DEFAULT 0,
    l1_failed BIGINT NOT NULL DEFAULT 0,
    l1_input_tokens BIGINT NOT NULL DEFAULT 0,
    l1_output_tokens BIGINT NOT NULL DEFAULT 0,
    error_category TEXT COLLATE "C"
);

-- L1 facets (doc 24 section 7): one per pack, cached by
-- (pack_hash, prompt_version, model). Enums are plaintext; goal, instructions,
-- skill candidate and evidence are AES-GCM ciphertext in text_enc.
CREATE TABLE session_facets (
    session_key BYTEA PRIMARY KEY REFERENCES session_packs(session_key) ON DELETE CASCADE,
    kind TEXT COLLATE "C" NOT NULL CHECK (kind IN ('session', 'chat_digest')),
    api_key_fpr BYTEA,
    newapi_token_id BIGINT,
    last_ns BIGINT NOT NULL,
    pack_hash TEXT COLLATE "C" NOT NULL,
    prompt_version TEXT COLLATE "C" NOT NULL,
    model TEXT COLLATE "C" NOT NULL,
    facet_status TEXT COLLATE "C" NOT NULL CHECK (facet_status IN ('ok', 'invalid', 'failed')),
    task_type TEXT COLLATE "C",
    outcome TEXT COLLATE "C",
    collaboration TEXT COLLATE "C",
    work_relevance TEXT COLLATE "C",
    friction TEXT COLLATE "C" NOT NULL DEFAULT '[]',
    items TEXT COLLATE "C" NOT NULL DEFAULT '[]',
    invalid_fields TEXT COLLATE "C" NOT NULL DEFAULT '[]',
    text_enc BYTEA,
    input_tokens BIGINT NOT NULL DEFAULT 0,
    output_tokens BIGINT NOT NULL DEFAULT 0,
    latency_ms BIGINT NOT NULL DEFAULT 0,
    attempts BIGINT NOT NULL DEFAULT 1,
    created_at_ns BIGINT NOT NULL
);
CREATE INDEX session_facets_last_idx ON session_facets(last_ns);

-- Calibration runs (doc 24 section 7.3): per-field agreement between human
-- labels and stored facets of one prompt version and model.
CREATE TABLE facet_calibrations (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    created_at_ns BIGINT NOT NULL,
    prompt_version TEXT COLLATE "C" NOT NULL,
    model TEXT COLLATE "C" NOT NULL,
    samples BIGINT NOT NULL,
    agreement TEXT COLLATE "C" NOT NULL
);

-- L2 (doc 24 section 8): suggestions and weekly statistics outlive audit
-- retention. scope 'person' is keyed by the API key fingerprint, 'all' by 32
-- zero bytes, 'project' and 'group' (organisation reports only) by the id as
-- 8 big-endian bytes after 24 zero bytes. Suggestion text and narratives are
-- AES-GCM ciphertext.
CREATE TABLE analysis_suggestions (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    scope TEXT COLLATE "C" NOT NULL CHECK (scope IN ('person', 'all', 'project', 'user')),
    scope_key BYTEA NOT NULL CHECK (length(scope_key) = 32),
    newapi_token_id BIGINT,
    kind TEXT COLLATE "C" NOT NULL CHECK (kind IN ('instruction', 'skill')),
    fpr BYTEA NOT NULL CHECK (length(fpr) = 32),
    support_sessions BIGINT NOT NULL,
    first_seen_ns BIGINT NOT NULL,
    last_seen_ns BIGINT NOT NULL,
    status TEXT COLLATE "C" NOT NULL CHECK (status IN ('open', 'adopted_detected', 'dismissed')),
    text_enc BYTEA NOT NULL,
    evidence TEXT COLLATE "C" NOT NULL DEFAULT '[]',
    updated_at_ns BIGINT NOT NULL,
    UNIQUE (scope, scope_key, kind, fpr)
);

CREATE TABLE analysis_period_stats (
    week_start_ns BIGINT NOT NULL,
    scope TEXT COLLATE "C" NOT NULL CHECK (scope IN ('person', 'all', 'project', 'group', 'user')),
    scope_key BYTEA NOT NULL CHECK (length(scope_key) = 32),
    newapi_token_id BIGINT,
    stats TEXT COLLATE "C" NOT NULL,
    narrative_enc BYTEA,
    narrative_source TEXT COLLATE "C" CHECK (narrative_source IN ('model', 'template')),
    input_hash TEXT COLLATE "C" NOT NULL DEFAULT '',
    computed_at_ns BIGINT NOT NULL,
    PRIMARY KEY (week_start_ns, scope, scope_key)
);

-- Settings saved from the management UI (doc 10 section 11). One row per
-- section holds the fields the page edits and overrides the configuration
-- file for them; deleting the row returns to the file. secret_enc is the
-- section's secret (the model API key) as AES-GCM ciphertext; it never appears
-- in settings.
CREATE TABLE runtime_settings (
    section TEXT COLLATE "C" PRIMARY KEY CHECK (section IN ('session_analysis', 'org_reports')),
    settings TEXT COLLATE "C" NOT NULL,
    secret_enc BYTEA,
    updated_at_ns BIGINT NOT NULL
);