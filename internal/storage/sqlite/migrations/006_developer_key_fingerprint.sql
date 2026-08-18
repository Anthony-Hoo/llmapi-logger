-- Developer sessions authenticate with a NewAPI user API key and may only read
-- the audits that key produced. api_key_fpr is the keyed HMAC-SHA-256 tag of the
-- inbound credential, derived from the audit master key, and is NULL when the
-- request carried no credential.
--
-- The column is an access-control index, not evidence: it stays out of the
-- integrity event chain, so capturePayloadDigest must never select it. Adding it
-- there would change the recomputed digest of every historical audit and fail
-- chain verification on existing databases.
ALTER TABLE audit_records ADD COLUMN api_key_fpr BLOB
    CHECK (api_key_fpr IS NULL OR length(api_key_fpr) = 32);

-- Ordered to serve the developer list query directly: scope first, then the
-- keyset ordering the list is fixed to.
CREATE INDEX IF NOT EXISTS audit_records_api_key_fpr_idx
    ON audit_records (api_key_fpr, started_at_ns, audit_id)
    WHERE api_key_fpr IS NOT NULL;
