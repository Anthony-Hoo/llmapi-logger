package app

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"llmapi-logger/internal/config"
)

func TestWeakAdminTokenWarnsWithoutLoggingTheToken(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buffer, nil))

	const weak = "short-token"
	warnWeakAdminToken(config.Config{AdminToken: weak}, logger)
	output := buffer.String()
	if !strings.Contains(output, "weak_admin_token") || !strings.Contains(output, `"config_key":"admin_token"`) {
		t.Fatalf("weak token warning = %q", output)
	}
	if strings.Contains(output, weak) {
		t.Fatalf("warning logged the token: %q", output)
	}

	buffer.Reset()
	strong := strings.Repeat("a", config.RecommendedAdminTokenBytes)
	warnWeakAdminToken(config.Config{AdminToken: strong}, logger)
	if buffer.Len() != 0 {
		t.Fatalf("a token of the recommended length must not warn, got %q", buffer.String())
	}
}
