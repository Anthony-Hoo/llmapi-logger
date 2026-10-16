-- NewAPI actual billing (doc/features/21-newapi-billing.md). The billing
-- snapshot lives in the same token_links row as the caller identity because
-- both come from the same NewAPI log lookup. Like the identity it stays out of
-- the integrity event chain and is deleted with its audit by the cascade.
--
-- SQLite cannot add a table-level CHECK to an existing table, so token_links is
-- rebuilt. Links that existed before this migration have no billing yet and
-- become 'unchecked'; the NewAPI worker backfills them at low priority.
CREATE TABLE token_links_new (
    audit_id TEXT PRIMARY KEY,
    newapi_user_id INTEGER NOT NULL CHECK (newapi_user_id > 0),
    username TEXT NOT NULL,
    newapi_token_id INTEGER NOT NULL CHECK (newapi_token_id >= 0),
    token_name TEXT NOT NULL,
    linked_at_ns INTEGER NOT NULL CHECK (linked_at_ns > 0),
    billing_state TEXT NOT NULL DEFAULT 'unchecked'
        CHECK (billing_state IN ('unchecked', 'billed', 'unbilled')),
    quota INTEGER CHECK (quota IS NULL OR quota >= 0),
    quota_per_unit REAL CHECK (quota_per_unit IS NULL OR quota_per_unit > 0),
    billed_prompt_tokens INTEGER CHECK (billed_prompt_tokens IS NULL OR billed_prompt_tokens >= 0),
    billed_completion_tokens INTEGER CHECK (billed_completion_tokens IS NULL OR billed_completion_tokens >= 0),
    billing_attempts INTEGER NOT NULL DEFAULT 0 CHECK (billing_attempts >= 0),
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

INSERT INTO token_links_new (
    audit_id, newapi_user_id, username, newapi_token_id, token_name, linked_at_ns, billing_state
)
SELECT audit_id, newapi_user_id, username, newapi_token_id, token_name, linked_at_ns, 'unchecked'
FROM token_links;

DROP TABLE token_links;
ALTER TABLE token_links_new RENAME TO token_links;

-- The backfill reads the newest unchecked link first, one at a time.
CREATE INDEX token_links_unchecked_idx
    ON token_links (linked_at_ns DESC, audit_id)
    WHERE billing_state = 'unchecked';
