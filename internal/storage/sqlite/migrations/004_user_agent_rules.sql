CREATE TABLE user_agent_rules (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    model_pattern TEXT NOT NULL CHECK (length(model_pattern) BETWEEN 1 AND 2048),
    user_agent_pattern TEXT NOT NULL CHECK (length(user_agent_pattern) BETWEEN 1 AND 2048),
    created_at_ns INTEGER NOT NULL CHECK (created_at_ns > 0),
    updated_at_ns INTEGER NOT NULL CHECK (updated_at_ns >= created_at_ns)
);

INSERT INTO user_agent_rules (
    id, name, enabled, model_pattern, user_agent_pattern, created_at_ns, updated_at_ns
) VALUES (
    1,
    'GPT models require Codex clients',
    1,
    '^gpt',
    '^(codex-tui|Codex Desktop)',
    CAST(strftime('%s', 'now') AS INTEGER) * 1000000000,
    CAST(strftime('%s', 'now') AS INTEGER) * 1000000000
);
