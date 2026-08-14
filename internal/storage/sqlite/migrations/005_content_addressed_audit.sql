DROP TABLE IF EXISTS token_links;
DROP TABLE IF EXISTS parsed_results;
DROP TABLE IF EXISTS body_chunks;
DROP TABLE IF EXISTS body_streams;
DROP TABLE IF EXISTS http_headers;
DROP TABLE IF EXISTS http_stages;
DROP TABLE IF EXISTS audit_records;
DROP TABLE IF EXISTS audit_gaps;

CREATE TABLE audit_records (
    audit_id TEXT PRIMARY KEY,
    schema_generation INTEGER NOT NULL DEFAULT 2 CHECK (schema_generation = 2),
    started_at_ns INTEGER NOT NULL,
    ended_at_ns INTEGER,
    route_id TEXT NOT NULL,
    protocol TEXT NOT NULL,
    parser_name TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    request_uri_enc BLOB NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('available', 'strict')),
    status_code INTEGER CHECK (status_code IS NULL OR status_code BETWEEN 100 AND 599),
    ttft_ns INTEGER CHECK (ttft_ns IS NULL OR ttft_ns >= 0),
    forward_status TEXT NOT NULL CHECK (forward_status IN (
        'in_progress', 'completed', 'rejected', 'client_cancelled',
        'newapi_error', 'proxy_error', 'interrupted'
    )),
    capture_status TEXT NOT NULL CHECK (capture_status IN ('pending', 'complete', 'partial', 'failed')),
    parse_status TEXT NOT NULL CHECK (parse_status IN ('pending', 'processing', 'ok', 'partial', 'error', 'skipped')),
    blocked_by TEXT,
    block_code TEXT,
    error_code TEXT,
    newapi_request_id TEXT CHECK (
        newapi_request_id IS NULL OR (
            length(newapi_request_id) BETWEEN 1 AND 128
            AND trim(newapi_request_id) = newapi_request_id
            AND instr(newapi_request_id, char(0)) = 0
            AND instr(newapi_request_id, char(10)) = 0
            AND instr(newapi_request_id, char(13)) = 0
        )
    ),
    caller_status TEXT NOT NULL DEFAULT 'none'
        CHECK (caller_status IN ('none', 'pending', 'resolved', 'unresolved')),
    caller_attempts INTEGER NOT NULL DEFAULT 0 CHECK (caller_attempts >= 0),
    caller_next_at_ns INTEGER,
    caller_updated_at_ns INTEGER,
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
    audit_id TEXT NOT NULL,
    stage TEXT NOT NULL CHECK (stage IN (
        'request_for_newapi_received_from_nginx',
        'request_sent_to_newapi',
        'response_received_from_newapi',
        'response_from_newapi_sent_to_nginx'
    )),
    state TEXT NOT NULL CHECK (state IN ('not_started', 'streaming', 'complete', 'partial')),
    proto TEXT NOT NULL,
    method TEXT NOT NULL,
    host TEXT NOT NULL,
    status_code INTEGER CHECK (status_code IS NULL OR status_code BETWEEN 100 AND 599),
    content_length INTEGER CHECK (content_length IS NULL OR content_length >= -1),
    started_at_ns INTEGER NOT NULL,
    ended_at_ns INTEGER,
    error_code TEXT,
    PRIMARY KEY (audit_id, stage),
    FOREIGN KEY (audit_id) REFERENCES audit_records(audit_id) ON DELETE CASCADE
);

CREATE TABLE http_headers (
    audit_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('header', 'trailer')),
    name TEXT NOT NULL,
    value_index INTEGER NOT NULL CHECK (value_index >= 0),
    value_length INTEGER NOT NULL CHECK (value_length >= 0),
    value_enc BLOB NOT NULL,
    PRIMARY KEY (audit_id, stage, kind, name, value_index),
    FOREIGN KEY (audit_id, stage) REFERENCES http_stages(audit_id, stage) ON DELETE CASCADE
);

CREATE TABLE body_streams (
    audit_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    source_stage TEXT NOT NULL,
    observed_length INTEGER NOT NULL CHECK (observed_length >= 0),
    stored_length INTEGER NOT NULL CHECK (stored_length >= 0 AND stored_length <= observed_length),
    sha256 BLOB CHECK (sha256 IS NULL OR length(sha256) = 32),
    hash_complete INTEGER NOT NULL CHECK (hash_complete IN (0, 1)),
    eof_seen INTEGER NOT NULL CHECK (eof_seen IN (0, 1)),
    state TEXT NOT NULL CHECK (state IN ('not_started', 'streaming', 'complete', 'partial')),
    retention_state TEXT NOT NULL CHECK (retention_state IN ('pending', 'metadata', 'full')),
    first_observed_at_ns INTEGER,
    last_observed_at_ns INTEGER,
    chunk_count INTEGER NOT NULL DEFAULT 0 CHECK (chunk_count >= 0),
    stream_event_count INTEGER NOT NULL DEFAULT 0 CHECK (stream_event_count >= 0),
    stream_timeline_complete INTEGER NOT NULL DEFAULT 1 CHECK (stream_timeline_complete IN (0, 1)),
    error_code TEXT,
    CHECK (hash_complete = 0 OR eof_seen = 1),
    CHECK ((first_observed_at_ns IS NULL AND last_observed_at_ns IS NULL) OR
           (first_observed_at_ns IS NOT NULL AND last_observed_at_ns >= first_observed_at_ns)),
    PRIMARY KEY (audit_id, stage),
    FOREIGN KEY (audit_id, stage) REFERENCES http_stages(audit_id, stage) ON DELETE CASCADE,
    FOREIGN KEY (audit_id, source_stage) REFERENCES http_stages(audit_id, stage) ON DELETE CASCADE
);

CREATE TABLE body_chunks (
    audit_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    seq INTEGER NOT NULL CHECK (seq >= 0),
    "offset" INTEGER NOT NULL CHECK ("offset" >= 0),
    plaintext_length INTEGER NOT NULL CHECK (plaintext_length >= 0),
    encoded_length INTEGER NOT NULL CHECK (encoded_length >= 0),
    observed_at_ns INTEGER NOT NULL,
    compression TEXT NOT NULL CHECK (compression IN ('none', 'gzip')),
    data_enc BLOB NOT NULL,
    PRIMARY KEY (audit_id, stage, seq),
    FOREIGN KEY (audit_id, stage) REFERENCES body_streams(audit_id, stage) ON DELETE CASCADE
);

CREATE TABLE parsed_results (
    audit_id TEXT PRIMARY KEY,
    parser_name TEXT NOT NULL,
    parser_version TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('ok', 'partial', 'error', 'skipped')),
    request_model TEXT,
    response_model TEXT,
    requested_stream INTEGER CHECK (requested_stream IS NULL OR requested_stream IN (0, 1)),
    observed_stream INTEGER CHECK (observed_stream IS NULL OR observed_stream IN (0, 1)),
    response_id TEXT,
    usage_input INTEGER CHECK (usage_input IS NULL OR usage_input >= 0),
    usage_output INTEGER CHECK (usage_output IS NULL OR usage_output >= 0),
    usage_total INTEGER CHECK (usage_total IS NULL OR usage_total >= 0),
    error_type TEXT,
    error_code TEXT,
    message_count INTEGER CHECK (message_count IS NULL OR message_count >= 0),
    tool_call_count INTEGER CHECK (tool_call_count IS NULL OR tool_call_count >= 0),
    has_tool_call INTEGER CHECK (has_tool_call IS NULL OR has_tool_call IN (0, 1)),
    parsed_json_enc BLOB,
    parsed_at_ns INTEGER NOT NULL,
    FOREIGN KEY (audit_id) REFERENCES audit_records(audit_id) ON DELETE CASCADE
);

CREATE TABLE content_objects (
    object_hash BLOB PRIMARY KEY CHECK (length(object_hash) = 32),
    semantic_hash BLOB NOT NULL CHECK (length(semantic_hash) = 32),
    kind TEXT NOT NULL CHECK (length(kind) BETWEEN 1 AND 128),
    compression TEXT NOT NULL CHECK (compression IN ('none', 'gzip')),
    plaintext_length INTEGER NOT NULL CHECK (plaintext_length >= 0),
    encoded_length INTEGER NOT NULL CHECK (encoded_length >= 0),
    data_enc BLOB NOT NULL,
    created_at_ns INTEGER NOT NULL CHECK (created_at_ns > 0)
);

CREATE INDEX content_objects_semantic_idx
    ON content_objects(semantic_hash, kind);

CREATE TABLE binary_objects (
    binary_hash BLOB PRIMARY KEY CHECK (length(binary_hash) = 32),
    media_type TEXT NOT NULL CHECK (length(media_type) BETWEEN 1 AND 255),
    compression TEXT NOT NULL CHECK (compression IN ('none', 'gzip')),
    plaintext_length INTEGER NOT NULL CHECK (plaintext_length >= 0),
    encoded_length INTEGER NOT NULL CHECK (encoded_length >= 0),
    data_enc BLOB NOT NULL,
    created_at_ns INTEGER NOT NULL CHECK (created_at_ns > 0)
);

CREATE TABLE content_binary_refs (
    object_hash BLOB NOT NULL,
    json_pointer TEXT NOT NULL,
    binary_hash BLOB NOT NULL,
    media_type TEXT NOT NULL,
    encoding TEXT NOT NULL CHECK (encoding IN ('data_url', 'base64')),
    PRIMARY KEY (object_hash, json_pointer, binary_hash),
    FOREIGN KEY (object_hash) REFERENCES content_objects(object_hash) ON DELETE CASCADE,
    FOREIGN KEY (binary_hash) REFERENCES binary_objects(binary_hash) ON DELETE RESTRICT
);

CREATE TABLE content_external_refs (
    object_hash BLOB NOT NULL,
    json_pointer TEXT NOT NULL,
    ref_kind TEXT NOT NULL,
    value_hash BLOB NOT NULL CHECK (length(value_hash) = 32),
    value_enc BLOB NOT NULL,
    PRIMARY KEY (object_hash, json_pointer, ref_kind),
    FOREIGN KEY (object_hash) REFERENCES content_objects(object_hash) ON DELETE CASCADE
);

CREATE INDEX content_external_refs_hash_idx
    ON content_external_refs(ref_kind, value_hash);

CREATE TABLE conversations (
    conversation_id TEXT PRIMARY KEY,
    protocol TEXT NOT NULL,
    key_hash BLOB CHECK (key_hash IS NULL OR length(key_hash) = 32),
    created_at_ns INTEGER NOT NULL,
    updated_at_ns INTEGER NOT NULL CHECK (updated_at_ns >= created_at_ns)
);

CREATE UNIQUE INDEX conversations_key_idx
    ON conversations(protocol, key_hash)
    WHERE key_hash IS NOT NULL;

CREATE TABLE turns (
    turn_id TEXT PRIMARY KEY,
    audit_id TEXT NOT NULL UNIQUE,
    conversation_id TEXT NOT NULL,
    parent_turn_id TEXT,
    parent_base TEXT NOT NULL CHECK (parent_base IN ('root', 'request', 'post_turn')),
    link_reason TEXT NOT NULL CHECK (link_reason IN (
        'root', 'previous_response_id', 'conversation_key', 'retry',
        'continuation', 'context_edit', 'branch', 'retention_checkpoint'
    )),
    link_confidence INTEGER NOT NULL CHECK (link_confidence BETWEEN 0 AND 100),
    request_layout TEXT NOT NULL,
    response_layout TEXT NOT NULL,
    request_envelope_hash BLOB NOT NULL CHECK (length(request_envelope_hash) = 32),
    response_envelope_hash BLOB NOT NULL CHECK (length(response_envelope_hash) = 32),
    request_item_count INTEGER NOT NULL CHECK (request_item_count >= 0),
    response_item_count INTEGER NOT NULL CHECK (response_item_count >= 0),
    request_sequence_hash BLOB NOT NULL CHECK (length(request_sequence_hash) = 32),
    response_sequence_hash BLOB NOT NULL CHECK (length(response_sequence_hash) = 32),
    request_reconstruction_hash BLOB NOT NULL CHECK (length(request_reconstruction_hash) = 32),
    response_reconstruction_hash BLOB NOT NULL CHECK (length(response_reconstruction_hash) = 32),
    reconstruction_status TEXT NOT NULL CHECK (reconstruction_status IN ('verified', 'failed')),
    previous_response_id TEXT,
    response_id TEXT,
    created_at_ns INTEGER NOT NULL,
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
    turn_id TEXT NOT NULL,
    op_index INTEGER NOT NULL CHECK (op_index >= 0),
    operation TEXT NOT NULL CHECK (operation IN ('retain', 'delete', 'insert')),
    item_count INTEGER NOT NULL CHECK (item_count > 0),
    slot TEXT,
    object_hash BLOB,
    semantic_hash BLOB,
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
    turn_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    slot TEXT NOT NULL,
    object_hash BLOB NOT NULL CHECK (length(object_hash) = 32),
    semantic_hash BLOB NOT NULL CHECK (length(semantic_hash) = 32),
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
    audit_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    event_count INTEGER NOT NULL CHECK (event_count >= 0),
    first_event_at_ns INTEGER,
    last_event_at_ns INTEGER,
    timeline_complete INTEGER NOT NULL CHECK (timeline_complete IN (0, 1)),
    compression TEXT NOT NULL CHECK (compression IN ('none', 'gzip')),
    plaintext_length INTEGER NOT NULL CHECK (plaintext_length >= 0),
    timeline_enc BLOB,
    PRIMARY KEY (audit_id, stage),
    FOREIGN KEY (audit_id, stage) REFERENCES http_stages(audit_id, stage) ON DELETE CASCADE
);

CREATE TABLE integrity_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN (
        'capture_finalized', 'semantic_compacted', 'reconstruction_failed'
    )),
    previous_mac BLOB CHECK (previous_mac IS NULL OR length(previous_mac) = 32),
    payload_digest BLOB NOT NULL CHECK (length(payload_digest) = 32),
    event_mac BLOB NOT NULL CHECK (length(event_mac) = 32),
    created_at_ns INTEGER NOT NULL,
    UNIQUE (audit_id, event_type)
);

CREATE TABLE token_links (
    audit_id TEXT PRIMARY KEY,
    newapi_user_id INTEGER NOT NULL CHECK (newapi_user_id > 0),
    username TEXT NOT NULL,
    newapi_token_id INTEGER NOT NULL CHECK (newapi_token_id >= 0),
    token_name TEXT NOT NULL,
    linked_at_ns INTEGER NOT NULL CHECK (linked_at_ns > 0),
    FOREIGN KEY (audit_id) REFERENCES audit_records(audit_id) ON DELETE CASCADE
);

CREATE TABLE audit_gaps (
    id INTEGER PRIMARY KEY,
    started_at_ns INTEGER NOT NULL,
    ended_at_ns INTEGER NOT NULL,
    reason TEXT NOT NULL CHECK (reason IN (
        'db_unavailable', 'queue_full', 'encryption_error',
        'write_error', 'process_exit'
    )),
    request_count INTEGER NOT NULL CHECK (request_count > 0),
    detail TEXT NOT NULL,
    created_at_ns INTEGER NOT NULL
);
