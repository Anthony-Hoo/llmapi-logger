package storage

import (
	"llmapi-logger/internal/auditmodel"
)

// ParsedAudit atomically persists the narrow parser summary and, when
// available, one verified content-addressed turn graph.
type ParsedAudit struct {
	Result ParsedResult
	Turn   *auditmodel.PreparedTurn
}
