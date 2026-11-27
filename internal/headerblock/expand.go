package headerblock

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// Expand is the single read entry point for the saved Headers of one audit.
// It dispatches on the capture version: version 1 decrypts each per-value row
// with the AAD the capture session wrote and the query service verifies
// today, (audit_id, "header", stage, kind, name, value_index); version 2 opens
// and strictly decodes the block and checks its stage set against
// src.StageSet. Both return the flat list in the order Flatten defines, with
// fresh value slices the caller may clear. Any authentication, length, shape
// or version mismatch returns an error wrapping ErrIntegrity.
func Expand(c security.Cipher, auditID string, src storage.HeaderSource) ([]Value, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: nil cipher", ErrIntegrity)
	}
	switch src.CaptureVersion {
	case storage.CaptureVersion1:
		if src.Block != nil {
			return nil, fmt.Errorf("%w: version 1 audit with a header block", ErrIntegrity)
		}
		return expandRows(c, auditID, src.Rows)
	case storage.CaptureVersion2:
		if len(src.Rows) != 0 {
			return nil, fmt.Errorf("%w: version 2 audit with header rows", ErrIntegrity)
		}
		return expandBlock(c, auditID, src.Block, src.StageSet)
	default:
		return nil, fmt.Errorf("%w: unknown capture version %d", ErrIntegrity, src.CaptureVersion)
	}
}

func expandRows(c security.Cipher, auditID string, rows []storage.HeaderEvidence) ([]Value, error) {
	ordered := slices.Clone(rows)
	for _, row := range ordered {
		if storage.StageOrder(row.Stage) < 0 || (row.Kind != storage.HeaderKindHeader && row.Kind != storage.HeaderKindTrailer) {
			return nil, fmt.Errorf("%w: header row with unknown stage or kind", ErrIntegrity)
		}
	}
	slices.SortStableFunc(ordered, func(left, right storage.HeaderEvidence) int {
		return cmp.Or(
			cmp.Compare(storage.StageOrder(left.Stage), storage.StageOrder(right.Stage)),
			strings.Compare(left.Kind, right.Kind),
			strings.Compare(left.Name, right.Name),
			cmp.Compare(left.ValueIndex, right.ValueIndex),
		)
	})
	values := make([]Value, 0, len(ordered))
	for _, row := range ordered {
		aad, err := security.AAD(auditID, "header", row.Stage, row.Kind, row.Name, strconv.Itoa(row.ValueIndex))
		if err != nil {
			clearValues(values)
			return nil, fmt.Errorf("%w: header AAD", ErrIntegrity)
		}
		plaintext, err := c.Decrypt(aad, row.ValueEnc)
		if err != nil || len(plaintext) != row.ValueLength {
			clear(plaintext)
			clearValues(values)
			return nil, fmt.Errorf("%w: header row does not authenticate", ErrIntegrity)
		}
		if plaintext == nil {
			plaintext = []byte{}
		}
		values = append(values, Value{Stage: row.Stage, Kind: row.Kind, Name: row.Name, ValueIndex: row.ValueIndex, Value: plaintext})
	}
	return values, nil
}

func expandBlock(c security.Cipher, auditID string, block *storage.HeaderBlockEvidence, stageSet []string) ([]Value, error) {
	if block == nil {
		// No block means no stage has a section, which matches only an audit
		// without stage rows.
		if err := CheckStageSet(nil, stageSet); err != nil {
			return nil, err
		}
		return []Value{}, nil
	}
	stages, err := OpenBlock(c, auditID, *block)
	if err != nil {
		return nil, err
	}
	if err := CheckStageSet(stages, stageSet); err != nil {
		clearStages(stages)
		return nil, err
	}
	values := Flatten(stages)
	if values == nil {
		values = []Value{}
	}
	return values, nil
}

func clearValues(values []Value) {
	for _, value := range values {
		clear(value.Value)
	}
}

func clearStages(stages []Stage) {
	for _, stage := range stages {
		for _, fields := range [2][]Field{stage.Headers, stage.Trailers} {
			for _, field := range fields {
				for _, value := range field.Values {
					clear(value)
				}
			}
		}
	}
}
