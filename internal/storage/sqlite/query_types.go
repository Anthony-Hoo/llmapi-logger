package sqlite

import "llmapi-logger/internal/storage"

// AuditQueryFilter contains the narrow, non-secret fields supported by the
// local audit browser. Empty values mean that the filter is not applied.
type AuditQueryFilter = storage.AuditQueryFilter

// AuditQueryCursor is the keyset cursor for the fixed newest-first ordering.
// Both fields must be provided together by callers.
type AuditQueryCursor = storage.AuditQueryCursor

// AuditListRow is one non-secret audit summary. It intentionally excludes the
// encrypted request URI, Header values, Body chunks, and parsed JSON.
type AuditListRow = storage.AuditListRow

// AuditListPage contains a keyset-paginated result. HasMore is computed by
// reading one extra row and does not require an additional COUNT query.
type AuditListPage = storage.AuditListPage

// HeaderEvidence is the encrypted value and its stable identity for one saved
// Header or Trailer entry. It is only consumed by the query service, which
// authenticates and decrypts the value before building the protected detail
// response.
type HeaderEvidence = storage.HeaderEvidence

// ParsedResultSummary is the narrow, non-secret projection of parsed_results.
type ParsedResultSummary = storage.ParsedResultSummary

// TokenLinkSummary contains only the NewAPI request, user, and token identity
// copied from the global system log.
type TokenLinkSummary = storage.TokenLinkSummary

// AuditQueryDetail is the encrypted evidence projection used only by the
// authenticated management query service. RequestURIEnc and Header ValueEnc
// and ParsedResult.ParsedJSONEnc must never be copied into list DTOs or
// returned without decryption.
type AuditQueryDetail = storage.AuditQueryDetail

// TurnGraph is a transactionally consistent encrypted projection of one
// content-addressed turn. RequestRefs has already been reconstructed by
// applying the complete parent/delta chain, but object plaintext remains
// encrypted for the query service to authenticate and open.
type TurnGraph = storage.TurnGraph

// RawBodyMetadata describes one captured Body stream without containing Body
// bytes or ciphertext.
type RawBodyMetadata = storage.RawBodyMetadata

// StoredStreamTimeline is the encrypted logical SSE timing sequence for one
// stage together with the observed body bound used during verification.
type StoredStreamTimeline = storage.StoredStreamTimeline
