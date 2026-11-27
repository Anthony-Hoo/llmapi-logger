-- Index turns by creation time. A turn without a conversation key looks for
-- its parent among the 32 newest earlier turns of its protocol
-- (chooseTurnParent); without an index leading with created_at_ns that read
-- every turn and sorted them inside the writer's transaction
-- (doc/design/issue-59-unified-write-cold-archive.md, C.6). turn_id is the
-- query's tie-breaker, so the index yields the rows already in its order.
-- IF NOT EXISTS lets an operator build the index beforehand with
-- CREATE INDEX CONCURRENTLY on a database too large to build it at start-up.
CREATE INDEX IF NOT EXISTS turns_created_idx
    ON turns(created_at_ns, turn_id);
