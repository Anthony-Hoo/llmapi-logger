-- Drop the content_objects (semantic_hash, kind) index created by 001.
-- Every query on content_objects looks objects up by object_hash, so nothing
-- reads this index, while its random keys dirty a random leaf page on every
-- object insert (doc/design/issue-59-unified-write-cold-archive.md, A.3).
-- IF EXISTS keeps the migration safe on a database where an operator already
-- dropped it by hand.
DROP INDEX IF EXISTS content_objects_semantic_idx;
