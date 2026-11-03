-- upstream_error_class is a derived, unsigned classification of an upstream
-- policy rejection (for example a provider safety/policy block surfaced by
-- NewAPI). It is display/filter metadata only: it must never take part in
-- capturePayloadDigest, appendParsedResultDigest, or any integrity event, or
-- every historical audit would fail chain verification on upgrade. See
-- doc/features/04-sqlite-storage-and-migrations.md for the api_key_fpr lesson.
ALTER TABLE parsed_results ADD COLUMN upstream_error_class TEXT;
