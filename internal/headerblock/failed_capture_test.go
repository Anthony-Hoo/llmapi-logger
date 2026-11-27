package headerblock

import (
	"bytes"
	"errors"
	"net/http"
	"testing"

	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// A failed capture may leave the block's stages and the stage rows apart. It
// stays readable: a stage without a section has no Headers, a section without
// a stage row is shown. A capture that is not failed keeps the strict check,
// and nothing else is relaxed.
func TestExpandOfAFailedCapture(t *testing.T) {
	c, err := security.NewAESGCM(bytes.Repeat([]byte{0x33}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	const auditID = "audit-failed"
	block, err := SealBlock(c, auditID, []Stage{
		{Name: storage.StageRequestReceived, Headers: Snapshot(http.Header{"User-Agent": {"client/1"}})},
		{Name: storage.StageRequestSent, Headers: Snapshot(http.Header{"Accept": {"*/*"}})},
	})
	if err != nil {
		t.Fatal(err)
	}
	evidence := &storage.HeaderBlockEvidence{Compression: block.Compression, PlaintextLength: block.PlaintextLength, DataEnc: block.DataEnc}
	rr, rs, resp := storage.StageRequestReceived, storage.StageRequestSent, storage.StageResponseReceived
	for _, test := range []struct {
		name     string
		block    *storage.HeaderBlockEvidence
		stageSet []string
		stages   []string // stages whose Headers are returned
	}{
		{"section without a stage row", evidence, []string{rr}, []string{rr, rs}},
		{"stage row without a section", evidence, []string{rr, rs, resp}, []string{rr, rs}},
		{"stage row without a block", nil, []string{rr}, nil},
		{"matching", evidence, []string{rr, rs}, []string{rr, rs}},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := storage.HeaderSource{CaptureVersion: storage.CaptureVersion2, Block: test.block, StageSet: test.stageSet, CaptureFailed: true}
			values, err := Expand(c, auditID, source)
			if err != nil {
				t.Fatalf("failed capture: %v", err)
			}
			var stages []string
			for _, value := range values {
				if len(stages) == 0 || stages[len(stages)-1] != value.Stage {
					stages = append(stages, value.Stage)
				}
			}
			if len(stages) != len(test.stages) || (len(stages) > 0 && stages[len(stages)-1] != test.stages[len(test.stages)-1]) {
				t.Fatalf("stages %v, want %v", stages, test.stages)
			}
			// An audit startup recovery finalized as interrupted reads the
			// same way.
			interrupted := source
			interrupted.CaptureFailed, interrupted.Interrupted = false, true
			if again, err := Expand(c, auditID, interrupted); err != nil || len(again) != len(values) {
				t.Fatalf("interrupted: %d values, %v", len(again), err)
			}
			source.CaptureFailed = false
			if _, err := Expand(c, auditID, source); test.name != "matching" && !errors.Is(err, ErrIntegrity) {
				t.Fatalf("capture not failed: %v", err)
			}
		})
	}
	// Authentication, strict decoding and a valid stage set still hold.
	tampered := *evidence
	tampered.DataEnc = append([]byte(nil), evidence.DataEnc...)
	tampered.DataEnc[0] ^= 1
	for name, source := range map[string]storage.HeaderSource{
		"tampered block":    {CaptureVersion: 2, Block: &tampered, StageSet: []string{rr, rs}, CaptureFailed: true},
		"other audit":       {CaptureVersion: 2, Block: evidence, StageSet: []string{rr, rs}, CaptureFailed: true},
		"repeated stage":    {CaptureVersion: 2, Block: evidence, StageSet: []string{rr, rr}, CaptureFailed: true},
		"unknown stage":     {CaptureVersion: 2, Block: evidence, StageSet: []string{"elsewhere"}, CaptureFailed: true},
		"rows beside block": {CaptureVersion: 2, Block: evidence, Rows: []storage.HeaderEvidence{{Stage: rr, Kind: storage.HeaderKindHeader}}, CaptureFailed: true},
	} {
		id := auditID
		if name == "other audit" {
			id = "another-audit"
		}
		if _, err := Expand(c, id, source); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
