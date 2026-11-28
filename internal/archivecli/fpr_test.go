package archivecli

import (
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"llmapi-logger/internal/storage"
)

func TestFpr(t *testing.T) {
	s := newScenario(t, true)
	keyFile := filepath.Join(t.TempDir(), "known.txt")
	writeFile(t, keyFile, authKey("c1")+"\r\n")

	// Fingerprints only.
	out := run(t, "fpr", "--key", s.keyPath, "--known-key-file", keyFile).want(t, ExitOK)
	raw := s.keys.Archive.CredentialFingerprint([]byte(authKey("c1")))
	bearer := s.keys.Archive.CredentialFingerprint([]byte("Bearer " + authKey("c1")))
	want := "raw          " + hex.EncodeToString(raw[:]) + "\nbearer       " + hex.EncodeToString(bearer[:]) +
		"\napi_key_fpr  " + hex.EncodeToString(s.keys.Credential.Fingerprint(authKey("c1"))) + "\n"
	if out.stdout != want {
		t.Fatalf("fpr:\n%s\nwant\n%s", out.stdout, want)
	}

	// Searching the archive: the Authorization header (bearer form) and
	// api_key_fpr of c1.
	search := run(t, "fpr", "--key", s.keyPath, "--known-key-file", keyFile, "--dir", s.root).want(t, ExitOK)
	for _, line := range []string{
		"match c1 revision 1 header " + storage.StageRequestReceived + " header Authorization bearer",
		"match c1 revision 1 api_key_fpr api_key_fpr",
		"fpr: 2 matches in 1 audits",
	} {
		if !strings.Contains(search.stdout, line) {
			t.Fatalf("search lacks %q:\n%s", line, search.stdout)
		}
	}

	// Piped standard input, the x-api-key of the version 1 audit c4.
	piped := runWith(t, apiKey("c4")+"\n", nil, "fpr", "--key", s.keyPath, "--dir", s.root, "--conversation", "conv_other").want(t, ExitOK)
	if !strings.Contains(piped.stdout, "match c4 revision 1 header "+storage.StageRequestReceived+" header x-api-key raw") {
		t.Fatalf("piped:\n%s", piped.stdout)
	}
	// A terminal, read without echo: the query parameter and the User-Agent.
	terminal := &fakeTerminal{line: []byte(queryKey("c3"))}
	typed := runWith(t, "", terminal, "fpr", "--key", s.keyPath, "--dir", s.root, "--audit", "c3").want(t, ExitOK)
	if terminal.reads != 1 || !strings.Contains(typed.stdout, "match c3 revision 1 request_uri key raw") || !strings.Contains(typed.stderr, "input hidden") {
		t.Fatalf("typed:\n%s\n%s", typed.stdout, typed.stderr)
	}
	agent := runWith(t, credentialMarker+"-ua-c2\n", nil, "fpr", "--key", s.keyPath, "--dir", s.root, "--audit", "c2").want(t, ExitOK)
	if !strings.Contains(agent.stdout, "match c2 revision 2 user_agent raw") || !strings.Contains(agent.stdout, "match c2 revision 1 user_agent raw") {
		t.Fatalf("user agent:\n%s", agent.stdout)
	}

	// No match, an empty key, and the wrong master key.
	runWith(t, credentialMarker+"none\n", nil, "fpr", "--key", s.keyPath, "--dir", s.root).want(t, ExitNotFound)
	runWith(t, "\n", nil, "fpr", "--key", s.keyPath).want(t, ExitUsage)
	wrong := runWith(t, authKey("c1")+"\n", nil, "fpr", "--key", s.otherKeyFile(), "--dir", s.root).want(t, ExitFailed)
	if !strings.Contains(wrong.stderr, "key_mismatch") {
		t.Fatalf("wrong key: %s", wrong.stderr)
	}
}
