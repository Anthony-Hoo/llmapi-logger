CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at_ns INTEGER NOT NULL
);

CREATE TABLE audit_records (
    audit_id TEXT PRIMARY KEY,
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
    observed_length INTEGER NOT NULL CHECK (observed_length >= 0),
    stored_length INTEGER NOT NULL CHECK (stored_length >= 0 AND stored_length <= observed_length),
    sha256 BLOB CHECK (sha256 IS NULL OR length(sha256) = 32),
    hash_complete INTEGER NOT NULL CHECK (hash_complete IN (0, 1)),
    eof_seen INTEGER NOT NULL CHECK (eof_seen IN (0, 1)),
    state TEXT NOT NULL CHECK (state IN ('not_started', 'streaming', 'complete', 'partial')),
    error_code TEXT,
    CHECK (hash_complete = 0 OR eof_seen = 1),
    PRIMARY KEY (audit_id, stage),
    FOREIGN KEY (audit_id, stage) REFERENCES http_stages(audit_id, stage) ON DELETE CASCADE
);

CREATE TABLE body_chunks (
    audit_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    seq INTEGER NOT NULL CHECK (seq >= 0),
    "offset" INTEGER NOT NULL CHECK ("offset" >= 0),
    plaintext_length INTEGER NOT NULL CHECK (plaintext_length >= 0),
    observed_at_ns INTEGER NOT NULL,
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
