-- PostgreSQL schema. Nanosecond timestamps and counters remain signed 64-bit integers.
-- Evidence booleans retain 0/1 encoding to preserve historical integrity digests.
-- C collation preserves bytewise ordering used in evidence hashes and keyset cursors.
CREATE TABLE user_agent_rules (
    id BIGINT PRIMARY KEY,
    name TEXT COLLATE "C" NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    enabled BIGINT NOT NULL CHECK (enabled IN (0, 1)),
    model_pattern TEXT COLLATE "C" NOT NULL CHECK (length(model_pattern) BETWEEN 1 AND 2048),
    user_agent_pattern TEXT COLLATE "C" NOT NULL CHECK (length(user_agent_pattern) BETWEEN 1 AND 2048),
    created_at_ns BIGINT NOT NULL CHECK (created_at_ns > 0),
    updated_at_ns BIGINT NOT NULL CHECK (updated_at_ns >= created_at_ns)
);

CREATE TABLE audit_records (
    audit_id TEXT COLLATE "C" PRIMARY KEY,
    schema_generation BIGINT NOT NULL DEFAULT 2 CHECK (schema_generation = 2),
    started_at_ns BIGINT NOT NULL,
    ended_at_ns BIGINT,
    route_id TEXT COLLATE "C" NOT NULL,
    protocol TEXT COLLATE "C" NOT NULL,
    parser_name TEXT COLLATE "C" NOT NULL,
    method TEXT COLLATE "C" NOT NULL,
    path TEXT COLLATE "C" NOT NULL,
    request_uri_enc BYTEA NOT NULL,
    mode TEXT COLLATE "C" NOT NULL CHECK (mode IN ('available', 'strict')),
    status_code BIGINT CHECK (status_code IS NULL OR status_code BETWEEN 100 AND 599),
    ttft_ns BIGINT CHECK (ttft_ns IS NULL OR ttft_ns >= 0),
    forward_status TEXT COLLATE "C" NOT NULL CHECK (forward_status IN (
        'in_progress', 'completed', 'rejected', 'client_cancelled',
        'newapi_error', 'proxy_error', 'interrupted'
    )),
    capture_status TEXT COLLATE "C" NOT NULL CHECK (capture_status IN ('pending', 'complete', 'partial', 'failed')),
    parse_status TEXT COLLATE "C" NOT NULL CHECK (parse_status IN ('pending', 'processing', 'ok', 'partial', 'error', 'skipped')),
    blocked_by TEXT COLLATE "C",
    block_code TEXT COLLATE "C",
    error_code TEXT COLLATE "C",
    newapi_request_id TEXT COLLATE "C" CHECK (
        newapi_request_id IS NULL OR (
            length(newapi_request_id) BETWEEN 1 AND 128
            AND trim(newapi_request_id) = newapi_request_id

            AND position(chr(10) in newapi_request_id) = 0
            AND position(chr(13) in newapi_request_id) = 0
        )
    ),
    caller_status TEXT COLLATE "C" NOT NULL DEFAULT 'none'
        CHECK (caller_status IN ('none', 'pending', 'resolved', 'unresolved')),
    caller_attempts BIGINT NOT NULL DEFAULT 0 CHECK (caller_attempts >= 0),
    caller_next_at_ns BIGINT,
    caller_updated_at_ns BIGINT, api_key_fpr BYTEA
    CHECK (api_key_fpr IS NULL OR length(api_key_fpr) = 32), parse_save_failures BIGINT NOT NULL DEFAULT 0
    CHECK (parse_save_failures >= 0), parse_next_at_ns BIGINT,
    CHECK (
        (
            forward_status = 'rejected'
            AND blocked_by IS NOT NULL AND length(trim(blocked_by)) > 0
            AND block_code IS NOT NULL AND length(trim(block_code)) > 0
            AND parse_status = 'skipped'
            AND (status_code BETWEEN 400 AND 499 OR status_code = 503)
        )
        OR
        (
            forward_status <> 'rejected'
            AND blocked_by IS NULL
            AND block_code IS NULL
        )
    ),
    CHECK (
        (
            caller_status = 'none'
            AND newapi_request_id IS NULL
            AND caller_attempts = 0
            AND caller_next_at_ns IS NULL
            AND caller_updated_at_ns IS NULL
        )
        OR
        (
            caller_status = 'pending'
            AND newapi_request_id IS NOT NULL
            AND caller_next_at_ns IS NOT NULL
            AND caller_updated_at_ns IS NOT NULL
        )
        OR
        (
            caller_status IN ('resolved', 'unresolved')
            AND newapi_request_id IS NOT NULL
            AND caller_attempts > 0
            AND caller_next_at_ns IS NULL
            AND caller_updated_at_ns IS NOT NULL
        )
    )
);

CREATE INDEX audit_records_started_idx
    ON audit_records(started_at_ns, audit_id);

CREATE INDEX audit_records_route_started_idx
    ON audit_records(route_id, started_at_ns, audit_id);

CREATE INDEX audit_records_capture_started_idx
    ON audit_records(capture_status, started_at_ns, audit_id);

CREATE INDEX audit_records_parse_started_idx
    ON audit_records(parse_status, started_at_ns, audit_id);

CREATE INDEX audit_records_caller_due_idx
    ON audit_records(caller_status, caller_next_at_ns, started_at_ns, audit_id);

CREATE INDEX audit_records_newapi_request_idx
    ON audit_records(newapi_request_id);

CREATE TABLE http_stages (
    audit_id TEXT COLLATE "C" NOT NULL,
    stage TEXT COLLATE "C" NOT NULL CHECK (stage IN (
        'request_for_newapi_received_from_nginx',
        'request_sent_to_newapi',
        'response_received_from_newapi',
        'response_from_newapi_sent_to_nginx'
    )),
    state TEXT COLLATE "C" NOT NULL CHECK (state IN ('not_started', 'streaming', 'complete', 'partial')),
    proto TEXT COLLATE "C" NOT NULL,
    method TEXT COLLATE "C" NOT NULL,
    host TEXT COLLATE "C" NOT NULL,
    status_code BIGINT CHECK (status_code IS NULL OR status_code BETWEEN 100 AND 599),
    content_length BIGINT CHECK (content_length IS NULL OR content_length >= -1),
    started_at_ns BIGINT NOT NULL,
    ended_at_ns BIGINT,
    error_code TEXT COLLATE "C",
    PRIMARY KEY (audit_id, stage),
    FOREIGN KEY (audit_id) REFERENCES audit_records(audit_id) ON DELETE CASCADE
);

CREATE TABLE http_headers (
    audit_id TEXT COLLATE "C" NOT NULL,
    stage TEXT COLLATE "C" NOT NULL,
    kind TEXT COLLATE "C" NOT NULL CHECK (kind IN ('header', 'trailer')),
    name TEXT COLLATE "C" NOT NULL,
    value_index BIGINT NOT NULL CHECK (value_index >= 0),
    value_length BIGINT NOT NULL CHECK (value_length >= 0),
    value_enc BYTEA NOT NULL,
    PRIMARY KEY (audit_id, stage, kind, name, value_index),
    FOREIGN KEY (audit_id, stage) REFERENCES http_stages(audit_id, stage) ON DELETE CASCADE
);

CREATE TABLE body_streams (
    audit_id TEXT COLLATE "C" NOT NULL,
    stage TEXT COLLATE "C" NOT NULL,
    source_stage TEXT COLLATE "C" NOT NULL,
    observed_length BIGINT NOT NULL CHECK (observed_length >= 0),
    stored_length BIGINT NOT NULL CHECK (stored_length >= 0 AND stored_length <= observed_length),
    sha256 BYTEA CHECK (sha256 IS NULL OR length(sha256) = 32),
    hash_complete BIGINT NOT NULL CHECK (hash_complete IN (0, 1)),
    eof_seen BIGINT NOT NULL CHECK (eof_seen IN (0, 1)),
    state TEXT COLLATE "C" NOT NULL CHECK (state IN ('not_started', 'streaming', 'complete', 'partial')),
    retention_state TEXT COLLATE "C" NOT NULL CHECK (retention_state IN ('pending', 'metadata', 'full')),
    first_observed_at_ns BIGINT,
    last_observed_at_ns BIGINT,
    chunk_count BIGINT NOT NULL DEFAULT 0 CHECK (chunk_count >= 0),
    stream_event_count BIGINT NOT NULL DEFAULT 0 CHECK (stream_event_count >= 0),
    stream_timeline_complete BIGINT NOT NULL DEFAULT 1 CHECK (stream_timeline_complete IN (0, 1)),
    error_code TEXT COLLATE "C",
    CHECK (hash_complete = 0 OR eof_seen = 1),
    CHECK ((first_observed_at_ns IS NULL AND last_observed_at_ns IS NULL) OR
           (first_observed_at_ns IS NOT NULL AND last_observed_at_ns >= first_observed_at_ns)),
    PRIMARY KEY (audit_id, stage),
    FOREIGN KEY (audit_id, stage) REFERENCES http_stages(audit_id, stage) ON DELETE CASCADE,
    FOREIGN KEY (audit_id, source_stage) REFERENCES http_stages(audit_id, stage) ON DELETE CASCADE
);

CREATE TABLE body_chunks (
    audit_id TEXT COLLATE "C" NOT NULL,
    stage TEXT COLLATE "C" NOT NULL,
    seq BIGINT NOT NULL CHECK (seq >= 0),
    "offset" BIGINT NOT NULL CHECK ("offset" >= 0),
    plaintext_length BIGINT NOT NULL CHECK (plaintext_length >= 0),
    encoded_length BIGINT NOT NULL CHECK (encoded_length >= 0),
    observed_at_ns BIGINT NOT NULL,
    compression TEXT COLLATE "C" NOT NULL CHECK (compression IN ('none', 'gzip')),
    data_enc BYTEA NOT NULL,
    PRIMARY KEY (audit_id, stage, seq),
    FOREIGN KEY (audit_id, stage) REFERENCES body_streams(audit_id, stage) ON DELETE CASCADE
);

CREATE TABLE parsed_results (
    audit_id TEXT COLLATE "C" PRIMARY KEY,
    parser_name TEXT COLLATE "C" NOT NULL,
    parser_version TEXT COLLATE "C" NOT NULL,
    status TEXT COLLATE "C" NOT NULL CHECK (status IN ('ok', 'partial', 'error', 'skipped')),
    request_model TEXT COLLATE "C",
    response_model TEXT COLLATE "C",
    requested_stream BIGINT CHECK (requested_stream IS NULL OR requested_stream IN (0, 1)),
    observed_stream BIGINT CHECK (observed_stream IS NULL OR observed_stream IN (0, 1)),
    response_id TEXT COLLATE "C",
    usage_input BIGINT CHECK (usage_input IS NULL OR usage_input >= 0),
    usage_output BIGINT CHECK (usage_output IS NULL OR usage_output >= 0),
    usage_total BIGINT CHECK (usage_total IS NULL OR usage_total >= 0),
    error_type TEXT COLLATE "C",
    error_code TEXT COLLATE "C",
    message_count BIGINT CHECK (message_count IS NULL OR message_count >= 0),
    tool_call_count BIGINT CHECK (tool_call_count IS NULL OR tool_call_count >= 0),
    has_tool_call BIGINT CHECK (has_tool_call IS NULL OR has_tool_call IN (0, 1)),
    parsed_json_enc BYTEA,
    parsed_at_ns BIGINT NOT NULL, upstream_error_class TEXT COLLATE "C",
    FOREIGN KEY (audit_id) REFERENCES audit_records(audit_id) ON DELETE CASCADE
);

CREATE TABLE content_objects (
    object_hash BYTEA PRIMARY KEY CHECK (length(object_hash) = 32),
    semantic_hash BYTEA NOT NULL CHECK (length(semantic_hash) = 32),
    kind TEXT COLLATE "C" NOT NULL CHECK (length(kind) BETWEEN 1 AND 128),
    compression TEXT COLLATE "C" NOT NULL CHECK (compression IN ('none', 'gzip')),
    plaintext_length BIGINT NOT NULL CHECK (plaintext_length >= 0),
    encoded_length BIGINT NOT NULL CHECK (encoded_length >= 0),
    data_enc BYTEA NOT NULL,
    created_at_ns BIGINT NOT NULL CHECK (created_at_ns > 0)
);

CREATE INDEX content_objects_semantic_idx
    ON content_objects(semantic_hash, kind);

CREATE TABLE binary_objects (
    binary_hash BYTEA PRIMARY KEY CHECK (length(binary_hash) = 32),
    media_type TEXT COLLATE "C" NOT NULL CHECK (length(media_type) BETWEEN 1 AND 255),
    compression TEXT COLLATE "C" NOT NULL CHECK (compression IN ('none', 'gzip')),
    plaintext_length BIGINT NOT NULL CHECK (plaintext_length >= 0),
    encoded_length BIGINT NOT NULL CHECK (encoded_length >= 0),
    data_enc BYTEA NOT NULL,
    created_at_ns BIGINT NOT NULL CHECK (created_at_ns > 0)
);

CREATE TABLE content_binary_refs (
    object_hash BYTEA NOT NULL,
    json_pointer TEXT COLLATE "C" NOT NULL,
    binary_hash BYTEA NOT NULL,
    media_type TEXT COLLATE "C" NOT NULL,
    encoding TEXT COLLATE "C" NOT NULL CHECK (encoding IN ('data_url', 'base64')),
    PRIMARY KEY (object_hash, json_pointer, binary_hash),
    FOREIGN KEY (object_hash) REFERENCES content_objects(object_hash) ON DELETE CASCADE,
    FOREIGN KEY (binary_hash) REFERENCES binary_objects(binary_hash) ON DELETE RESTRICT
);

CREATE TABLE content_external_refs (
    object_hash BYTEA NOT NULL,
    json_pointer TEXT COLLATE "C" NOT NULL,
    ref_kind TEXT COLLATE "C" NOT NULL,
    value_hash BYTEA NOT NULL CHECK (length(value_hash) = 32),
    value_enc BYTEA NOT NULL,
    PRIMARY KEY (object_hash, json_pointer, ref_kind),
    FOREIGN KEY (object_hash) REFERENCES content_objects(object_hash) ON DELETE CASCADE
);

CREATE INDEX content_external_refs_hash_idx
    ON content_external_refs(ref_kind, value_hash);

CREATE TABLE conversations (
    conversation_id TEXT COLLATE "C" PRIMARY KEY,
    protocol TEXT COLLATE "C" NOT NULL,
    key_hash BYTEA CHECK (key_hash IS NULL OR length(key_hash) = 32),
    created_at_ns BIGINT NOT NULL,
    updated_at_ns BIGINT NOT NULL CHECK (updated_at_ns >= created_at_ns)
);

CREATE UNIQUE INDEX conversations_key_idx
    ON conversations(protocol, key_hash)
    WHERE key_hash IS NOT NULL;

CREATE TABLE turns (
    turn_id TEXT COLLATE "C" PRIMARY KEY,
    audit_id TEXT COLLATE "C" NOT NULL UNIQUE,
    conversation_id TEXT COLLATE "C" NOT NULL,
    parent_turn_id TEXT COLLATE "C",
    parent_base TEXT COLLATE "C" NOT NULL CHECK (parent_base IN ('root', 'request', 'post_turn')),
    link_reason TEXT COLLATE "C" NOT NULL CHECK (link_reason IN (
        'root', 'previous_response_id', 'conversation_key', 'retry',
        'continuation', 'context_edit', 'branch', 'retention_checkpoint'
    )),
    link_confidence BIGINT NOT NULL CHECK (link_confidence BETWEEN 0 AND 100),
    request_layout TEXT COLLATE "C" NOT NULL,
    response_layout TEXT COLLATE "C" NOT NULL,
    request_envelope_hash BYTEA NOT NULL CHECK (length(request_envelope_hash) = 32),
    response_envelope_hash BYTEA NOT NULL CHECK (length(response_envelope_hash) = 32),
    request_item_count BIGINT NOT NULL CHECK (request_item_count >= 0),
    response_item_count BIGINT NOT NULL CHECK (response_item_count >= 0),
    request_sequence_hash BYTEA NOT NULL CHECK (length(request_sequence_hash) = 32),
    response_sequence_hash BYTEA NOT NULL CHECK (length(response_sequence_hash) = 32),
    request_reconstruction_hash BYTEA NOT NULL CHECK (length(request_reconstruction_hash) = 32),
    response_reconstruction_hash BYTEA NOT NULL CHECK (length(response_reconstruction_hash) = 32),
    reconstruction_status TEXT COLLATE "C" NOT NULL CHECK (reconstruction_status IN ('verified', 'failed')),
    previous_response_id TEXT COLLATE "C",
    response_id TEXT COLLATE "C",
    created_at_ns BIGINT NOT NULL,
    FOREIGN KEY (audit_id) REFERENCES audit_records(audit_id) ON DELETE CASCADE,
    FOREIGN KEY (conversation_id) REFERENCES conversations(conversation_id) ON DELETE RESTRICT,
    FOREIGN KEY (parent_turn_id) REFERENCES turns(turn_id) ON DELETE RESTRICT,
    FOREIGN KEY (request_envelope_hash) REFERENCES content_objects(object_hash) ON DELETE RESTRICT,
    FOREIGN KEY (response_envelope_hash) REFERENCES content_objects(object_hash) ON DELETE RESTRICT
);

CREATE INDEX turns_conversation_created_idx
    ON turns(conversation_id, created_at_ns, turn_id);

CREATE INDEX turns_parent_idx
    ON turns(parent_turn_id, created_at_ns, turn_id);

CREATE INDEX turns_response_id_idx
    ON turns(response_id);

CREATE INDEX turns_request_envelope_idx
    ON turns(request_envelope_hash);

CREATE INDEX turns_response_envelope_idx
    ON turns(response_envelope_hash);

CREATE TABLE turn_context_ops (
    turn_id TEXT COLLATE "C" NOT NULL,
    op_index BIGINT NOT NULL CHECK (op_index >= 0),
    operation TEXT COLLATE "C" NOT NULL CHECK (operation IN ('retain', 'delete', 'insert')),
    item_count BIGINT NOT NULL CHECK (item_count > 0),
    slot TEXT COLLATE "C",
    object_hash BYTEA,
    semantic_hash BYTEA,
    CHECK (
        (operation = 'insert' AND item_count = 1 AND slot IS NOT NULL
            AND object_hash IS NOT NULL AND length(object_hash) = 32
            AND semantic_hash IS NOT NULL AND length(semantic_hash) = 32)
        OR
        (operation IN ('retain', 'delete') AND slot IS NULL
            AND object_hash IS NULL AND semantic_hash IS NULL)
    ),
    PRIMARY KEY (turn_id, op_index),
    FOREIGN KEY (turn_id) REFERENCES turns(turn_id) ON DELETE CASCADE,
    FOREIGN KEY (object_hash) REFERENCES content_objects(object_hash) ON DELETE RESTRICT
);

CREATE TABLE turn_response_items (
    turn_id TEXT COLLATE "C" NOT NULL,
    ordinal BIGINT NOT NULL CHECK (ordinal >= 0),
    slot TEXT COLLATE "C" NOT NULL,
    object_hash BYTEA NOT NULL CHECK (length(object_hash) = 32),
    semantic_hash BYTEA NOT NULL CHECK (length(semantic_hash) = 32),
    PRIMARY KEY (turn_id, ordinal),
    FOREIGN KEY (turn_id) REFERENCES turns(turn_id) ON DELETE CASCADE,
    FOREIGN KEY (object_hash) REFERENCES content_objects(object_hash) ON DELETE RESTRICT
);

CREATE INDEX turn_context_ops_object_idx
    ON turn_context_ops(object_hash)
    WHERE object_hash IS NOT NULL;

CREATE INDEX turn_response_items_object_idx
    ON turn_response_items(object_hash);

CREATE INDEX content_binary_refs_binary_idx
    ON content_binary_refs(binary_hash);

CREATE TABLE stream_timelines (
    audit_id TEXT COLLATE "C" NOT NULL,
    stage TEXT COLLATE "C" NOT NULL,
    event_count BIGINT NOT NULL CHECK (event_count >= 0),
    first_event_at_ns BIGINT,
    last_event_at_ns BIGINT,
    timeline_complete BIGINT NOT NULL CHECK (timeline_complete IN (0, 1)),
    compression TEXT COLLATE "C" NOT NULL CHECK (compression IN ('none', 'gzip')),
    plaintext_length BIGINT NOT NULL CHECK (plaintext_length >= 0),
    timeline_enc BYTEA,
    PRIMARY KEY (audit_id, stage),
    FOREIGN KEY (audit_id, stage) REFERENCES http_stages(audit_id, stage) ON DELETE CASCADE
);

CREATE TABLE integrity_events (
    sequence BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    audit_id TEXT COLLATE "C" NOT NULL,
    event_type TEXT COLLATE "C" NOT NULL CHECK (event_type IN (
        'capture_finalized', 'semantic_compacted', 'reconstruction_failed'
    )),
    previous_mac BYTEA CHECK (previous_mac IS NULL OR length(previous_mac) = 32),
    payload_digest BYTEA NOT NULL CHECK (length(payload_digest) = 32),
    event_mac BYTEA NOT NULL CHECK (length(event_mac) = 32),
    created_at_ns BIGINT NOT NULL,
    UNIQUE (audit_id, event_type)
);

CREATE TABLE audit_gaps (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    started_at_ns BIGINT NOT NULL,
    ended_at_ns BIGINT NOT NULL,
    reason TEXT COLLATE "C" NOT NULL CHECK (reason IN (
        'db_unavailable', 'queue_full', 'encryption_error',
        'write_error', 'process_exit'
    )),
    request_count BIGINT NOT NULL CHECK (request_count > 0),
    detail TEXT COLLATE "C" NOT NULL,
    created_at_ns BIGINT NOT NULL
);

CREATE INDEX audit_records_api_key_fpr_idx
    ON audit_records (api_key_fpr, started_at_ns, audit_id)
    WHERE api_key_fpr IS NOT NULL;

CREATE TABLE audit_analysis (
    audit_id TEXT COLLATE "C" PRIMARY KEY REFERENCES audit_records(audit_id) ON DELETE CASCADE,
    analysis_version BIGINT NOT NULL CHECK (analysis_version > 0),
    analyzed_at_ns BIGINT NOT NULL,
    protocol TEXT COLLATE "C" NOT NULL,
    model TEXT COLLATE "C",
    started_at_ns BIGINT NOT NULL,

    -- Normalized usage buckets; prompt total = uncached + cache_read + cache_write.
    u_uncached_input BIGINT CHECK (u_uncached_input IS NULL OR u_uncached_input >= 0),
    u_cache_read BIGINT CHECK (u_cache_read IS NULL OR u_cache_read >= 0),
    u_cache_write BIGINT CHECK (u_cache_write IS NULL OR u_cache_write >= 0),
    u_output BIGINT CHECK (u_output IS NULL OR u_output >= 0),
    u_reasoning BIGINT CHECK (u_reasoning IS NULL OR u_reasoning >= 0),
    max_output_tokens BIGINT,

    -- Composition estimates in estimated tokens.
    est_system BIGINT NOT NULL DEFAULT 0,
    est_tools BIGINT NOT NULL DEFAULT 0,
    est_user BIGINT NOT NULL DEFAULT 0,
    est_injected BIGINT NOT NULL DEFAULT 0,
    est_assistant BIGINT NOT NULL DEFAULT 0,
    est_reasoning BIGINT NOT NULL DEFAULT 0,
    est_tool_result BIGINT NOT NULL DEFAULT 0,
    est_media BIGINT NOT NULL DEFAULT 0,
    n_items BIGINT NOT NULL DEFAULT 0,
    n_tool_defs BIGINT NOT NULL DEFAULT 0,
    n_tool_results BIGINT NOT NULL DEFAULT 0,
    n_media BIGINT NOT NULL DEFAULT 0,

    -- This response only.
    stop_reason TEXT COLLATE "C" CHECK (stop_reason IS NULL OR stop_reason IN
        ('end_turn', 'tool_use', 'length', 'content_filter', 'other')),
    resp_kinds BIGINT NOT NULL DEFAULT 0,
    resp_tool_calls BIGINT NOT NULL DEFAULT 0,
    tool_kind_counts TEXT COLLATE "C" NOT NULL DEFAULT '{}',

    -- Session, previous step and events.
    analysis_session_id TEXT COLLATE "C",
    session_link TEXT COLLATE "C" CHECK (session_link IS NULL OR session_link IN
        ('agent', 'conversation', 'explicit', 'inferred', 'root')),
    prev_audit_id TEXT COLLATE "C",
    turn_start BIGINT NOT NULL DEFAULT 0 CHECK (turn_start IN (0, 1)),
    appended_items BIGINT,
    removed_items BIGINT,
    event_flags BIGINT NOT NULL DEFAULT 0,
    system_fpr BYTEA CHECK (system_fpr IS NULL OR length(system_fpr) = 32),
    tools_fpr BYTEA CHECK (tools_fpr IS NULL OR length(tools_fpr) = 32),

    -- Timing relative to the audit start.
    first_event_ns BIGINT,
    generation_ns BIGINT,

    -- Agent tree.
    agent_client TEXT COLLATE "C",
    agent_role TEXT COLLATE "C" CHECK (agent_role IS NULL OR agent_role IN
        ('main', 'subagent', 'compaction', 'title', 'review', 'auxiliary')),
    agent_node_fpr BYTEA CHECK (agent_node_fpr IS NULL OR length(agent_node_fpr) = 32),
    agent_parent_fpr BYTEA CHECK (agent_parent_fpr IS NULL OR length(agent_parent_fpr) = 32),
    agent_root_fpr BYTEA CHECK (agent_root_fpr IS NULL OR length(agent_root_fpr) = 32),
    agent_link_source TEXT COLLATE "C" CHECK (agent_link_source IS NULL OR agent_link_source IN
        ('header', 'body', 'content')),
    agent_link_confidence BIGINT CHECK (agent_link_confidence IS NULL OR
        (agent_link_confidence >= 0 AND agent_link_confidence <= 100)),

    detail_enc BYTEA
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

CREATE TABLE agent_spawn_hints (
    audit_id TEXT COLLATE "C" NOT NULL REFERENCES audit_records(audit_id) ON DELETE CASCADE,
    hint_fpr BYTEA NOT NULL CHECK (length(hint_fpr) = 32),
    created_at_ns BIGINT NOT NULL,
    PRIMARY KEY (audit_id, hint_fpr)
);

CREATE INDEX agent_spawn_hints_fpr_idx ON agent_spawn_hints (hint_fpr, created_at_ns);

CREATE TABLE "token_links" (
    audit_id TEXT COLLATE "C" PRIMARY KEY,
    newapi_user_id BIGINT NOT NULL CHECK (newapi_user_id > 0),
    username TEXT COLLATE "C" NOT NULL,
    newapi_token_id BIGINT NOT NULL CHECK (newapi_token_id >= 0),
    token_name TEXT COLLATE "C" NOT NULL,
    linked_at_ns BIGINT NOT NULL CHECK (linked_at_ns > 0),
    billing_state TEXT COLLATE "C" NOT NULL DEFAULT 'unchecked'
        CHECK (billing_state IN ('unchecked', 'billed', 'unbilled')),
    quota BIGINT CHECK (quota IS NULL OR quota >= 0),
    quota_per_unit DOUBLE PRECISION CHECK (quota_per_unit IS NULL OR quota_per_unit > 0),
    billed_prompt_tokens BIGINT CHECK (billed_prompt_tokens IS NULL OR billed_prompt_tokens >= 0),
    billed_completion_tokens BIGINT CHECK (billed_completion_tokens IS NULL OR billed_completion_tokens >= 0),
    billing_attempts BIGINT NOT NULL DEFAULT 0 CHECK (billing_attempts >= 0),
    CHECK (
        (
            billing_state = 'billed'
            AND quota IS NOT NULL
            AND quota_per_unit IS NOT NULL
            AND billed_prompt_tokens IS NOT NULL
            AND billed_completion_tokens IS NOT NULL
        )
        OR
        (
            billing_state <> 'billed'
            AND quota IS NULL
            AND quota_per_unit IS NULL
            AND billed_prompt_tokens IS NULL
            AND billed_completion_tokens IS NULL
        )
    ),
    FOREIGN KEY (audit_id) REFERENCES audit_records(audit_id) ON DELETE CASCADE
);

CREATE INDEX token_links_unchecked_idx
    ON token_links (linked_at_ns DESC, audit_id)
    WHERE billing_state = 'unchecked';

CREATE TABLE "content_policy_rules" (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    name TEXT COLLATE "C" NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    enabled BIGINT NOT NULL CHECK (enabled IN (0, 1)),
    action TEXT COLLATE "C" NOT NULL CHECK (action IN ('block', 'dry_run')),
    model_pattern TEXT COLLATE "C" NOT NULL CHECK (length(model_pattern) <= 2048),
    scan_scopes TEXT COLLATE "C" NOT NULL CHECK (length(scan_scopes) BETWEEN 2 AND 512),
    keywords TEXT COLLATE "C" NOT NULL CHECK (length(keywords) BETWEEN 2 AND 65536),
    created_at_ns BIGINT NOT NULL CHECK (created_at_ns > 0),
    updated_at_ns BIGINT NOT NULL CHECK (updated_at_ns >= created_at_ns)
);

-- Derived encrypted prefix nodes are deliberately outside the evidence chain.
CREATE TABLE analysis_detail_objects (
    hash BYTEA PRIMARY KEY CHECK (length(hash) = 32),
    parent_hash BYTEA CHECK (parent_hash IS NULL OR length(parent_hash) = 32),
    payload_enc BYTEA NOT NULL CHECK (length(payload_enc) > 0),
    FOREIGN KEY (parent_hash) REFERENCES analysis_detail_objects(hash)
);
CREATE INDEX analysis_detail_parent_idx ON analysis_detail_objects(parent_hash);
ALTER TABLE audit_analysis ADD COLUMN detail_root BYTEA
    REFERENCES analysis_detail_objects(hash)
    CHECK (detail_root IS NULL OR length(detail_root) = 32);
CREATE INDEX audit_analysis_detail_root_idx ON audit_analysis(detail_root) WHERE detail_root IS NOT NULL;
