package conversation

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestUnknownBoundsLargeProviderPayload(t *testing.T) {
	t.Parallel()

	part := Unknown(map[string]any{"type": "image", "data": strings.Repeat("A", maxUnknownDataBytes*2)})
	if len(part.Data) > maxUnknownDataBytes+len("...[truncated]") || !strings.HasSuffix(part.Data, "...[truncated]") || !utf8.ValidString(part.Data) {
		t.Fatalf("unexpected bounded unknown part: length=%d suffix=%q", len(part.Data), part.Data[max(0, len(part.Data)-32):])
	}
}
