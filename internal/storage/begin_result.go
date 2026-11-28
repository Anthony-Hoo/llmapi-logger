package storage

import "errors"

// ErrInboundStageNotStored is returned by BeginAudit, wrapped, when the start
// row is committed but the inbound stage row carried in AuditRecord.Inbound
// was rejected and rolled back on its own. The audit is admitted exactly as
// if BeginAudit had returned nil: the start record exists, already marked as
// a failed capture. The caller must treat it as success for admission and
// must not merge the request pair in memory for this audit: with no
// request_received stage row, a request_sent body merged into it could not be
// stored, and the request body would be lost where the legacy path keeps the
// request_sent copy.
var ErrInboundStageNotStored = errors.New("storage: inbound stage not stored")
