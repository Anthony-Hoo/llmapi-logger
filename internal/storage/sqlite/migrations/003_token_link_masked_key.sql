-- Preserve the masked credential returned by NewAPI alongside the existing
-- token id and name snapshot. Existing links predate this field and therefore
-- use an empty string until they are explicitly refreshed.
ALTER TABLE token_links
ADD COLUMN masked_key TEXT NOT NULL DEFAULT '';
