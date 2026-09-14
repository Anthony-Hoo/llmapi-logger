-- Scheduling metadata is mutable and is not part of captured HTTP evidence.
ALTER TABLE audit_records ADD COLUMN parse_save_failures INTEGER NOT NULL DEFAULT 0
    CHECK (parse_save_failures >= 0);
ALTER TABLE audit_records ADD COLUMN parse_next_at_ns INTEGER;
