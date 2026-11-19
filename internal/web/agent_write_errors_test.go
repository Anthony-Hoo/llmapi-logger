package web

import (
	"errors"
	"fmt"
	"testing"

	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/sessionanalysis"
)

// A settings write refused because the saved section could not be read is a
// retryable upstream failure, not INTERNAL: nothing was written.
func TestSettingsReadFailureIsUpstreamUnavailable(t *testing.T) {
	err := fmt.Errorf("%w: %w", sessionanalysis.ErrSettingsUnavailable, errors.New("connection reset"))
	if failure := agentWriteFailure(err); failure.Code != agentapi.CodeUpstreamUnavailable || len(failure.Details) != 0 {
		t.Fatalf("failure = %+v", failure)
	}
}
