-- Derived context analysis (doc/features/20-context-insights.md). Every row is
-- recomputable from captured evidence, versioned by analysis_version, and stays
-- out of the integrity event chain: capturePayloadDigest and
-- appendParsedResultDigest must never select these tables. Adding them there
-- would change the recomputed digest of every historical audit.
--
-- Plaintext columns hold only numbers, enums, JSON objects of counts and keyed
-- HMAC fingerprints. Message text, tool names, file paths and raw agent IDs
-- live only in detail_enc (AES-256-GCM, AAD label "analysis_detail").
CREATE TABLE audit_analysis (
    audit_id TEXT PRIMARY KEY REFERENCES audit_records(audit_id) ON DELETE CASCADE,
    analysis_version INTEGER NOT NULL CHECK (analysis_version > 0),
    analyzed_at_ns INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    model TEXT,
    started_at_ns INTEGER NOT NULL,

    -- Normalized usage buckets; prompt total = uncached + cache_read + cache_write.
    u_uncached_input INTEGER CHECK (u_uncached_input IS NULL OR u_uncached_input >= 0),
    u_cache_read INTEGER CHECK (u_cache_read IS NULL OR u_cache_read >= 0),
    u_cache_write INTEGER CHECK (u_cache_write IS NULL OR u_cache_write >= 0),
    u_output INTEGER CHECK (u_output IS NULL OR u_output >= 0),
    u_reasoning INTEGER CHECK (u_reasoning IS NULL OR u_reasoning >= 0),
    max_output_tokens INTEGER,

    -- Composition estimates in estimated tokens.
    est_system INTEGER NOT NULL DEFAULT 0,
    est_tools INTEGER NOT NULL DEFAULT 0,
    est_user INTEGER NOT NULL DEFAULT 0,
    est_injected INTEGER NOT NULL DEFAULT 0,
    est_assistant INTEGER NOT NULL DEFAULT 0,
    est_reasoning INTEGER NOT NULL DEFAULT 0,
    est_tool_result INTEGER NOT NULL DEFAULT 0,
    est_media INTEGER NOT NULL DEFAULT 0,
    n_items INTEGER NOT NULL DEFAULT 0,
    n_tool_defs INTEGER NOT NULL DEFAULT 0,
    n_tool_results INTEGER NOT NULL DEFAULT 0,
    n_media INTEGER NOT NULL DEFAULT 0,

    -- This response only.
    stop_reason TEXT CHECK (stop_reason IS NULL OR stop_reason IN
        ('end_turn', 'tool_use', 'length', 'content_filter', 'other')),
    resp_kinds INTEGER NOT NULL DEFAULT 0,
    resp_tool_calls INTEGER NOT NULL DEFAULT 0,
    tool_kind_counts TEXT NOT NULL DEFAULT '{}',

    -- Session, previous step and events.
    analysis_session_id TEXT,
    session_link TEXT CHECK (session_link IS NULL OR session_link IN
        ('agent', 'conversation', 'explicit', 'inferred', 'root')),
    prev_audit_id TEXT,
    turn_start INTEGER NOT NULL DEFAULT 0 CHECK (turn_start IN (0, 1)),
    appended_items INTEGER,
    removed_items INTEGER,
    event_flags INTEGER NOT NULL DEFAULT 0,
    system_fpr BLOB CHECK (system_fpr IS NULL OR length(system_fpr) = 32),
    tools_fpr BLOB CHECK (tools_fpr IS NULL OR length(tools_fpr) = 32),

    -- Timing relative to the audit start.
    first_event_ns INTEGER,
    generation_ns INTEGER,

    -- Agent tree.
    agent_client TEXT,
    agent_role TEXT CHECK (agent_role IS NULL OR agent_role IN
        ('main', 'subagent', 'compaction', 'title', 'review', 'auxiliary')),
    agent_node_fpr BLOB CHECK (agent_node_fpr IS NULL OR length(agent_node_fpr) = 32),
    agent_parent_fpr BLOB CHECK (agent_parent_fpr IS NULL OR length(agent_parent_fpr) = 32),
    agent_root_fpr BLOB CHECK (agent_root_fpr IS NULL OR length(agent_root_fpr) = 32),
    agent_link_source TEXT CHECK (agent_link_source IS NULL OR agent_link_source IN
        ('header', 'body', 'content')),
    agent_link_confidence INTEGER CHECK (agent_link_confidence IS NULL OR
        (agent_link_confidence >= 0 AND agent_link_confidence <= 100)),

    detail_enc BLOB
);

CREATE INDEX audit_analysis_time_idx ON audit_analysis (started_at_ns, audit_id);
CREATE INDEX audit_analysis_session_idx ON audit_analysis (analysis_session_id, started_at_ns)
    WHERE analysis_session_id IS NOT NULL;
CREATE INDEX audit_analysis_model_idx ON audit_analysis (model, started_at_ns);
CREATE INDEX audit_analysis_node_idx ON audit_analysis (agent_node_fpr, started_at_ns)
    WHERE agent_node_fpr IS NOT NULL;
CREATE INDEX audit_analysis_parent_idx ON audit_analysis (agent_parent_fpr)
    WHERE agent_parent_fpr IS NOT NULL;
CREATE INDEX audit_analysis_root_idx ON audit_analysis (agent_root_fpr, started_at_ns)
    WHERE agent_root_fpr IS NOT NULL;
CREATE INDEX audit_analysis_version_idx ON audit_analysis (analysis_version);

-- Keyed fingerprints of sub-agent spawn prompts seen in a response, used by the
-- content-matching fallback that links a child agent to its parent when no
-- client header or body back-link identifies the parent.
CREATE TABLE agent_spawn_hints (
    audit_id TEXT NOT NULL REFERENCES audit_records(audit_id) ON DELETE CASCADE,
    hint_fpr BLOB NOT NULL CHECK (length(hint_fpr) = 32),
    created_at_ns INTEGER NOT NULL,
    PRIMARY KEY (audit_id, hint_fpr)
);
CREATE INDEX agent_spawn_hints_fpr_idx ON agent_spawn_hints (hint_fpr, created_at_ns);
