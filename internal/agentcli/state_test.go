package agentcli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCredentialsReplacedAtomically(t *testing.T) {
	h := newHarness(t)
	first := &credentials{Server: "https://audit.example.com", Token: testToken, ExpiresAt: "2030-01-01T00:00:00Z"}
	if err := saveCredentials(h.env, first); err != nil {
		t.Fatal(err)
	}
	second := *first
	second.Server = "https://other.example.com"
	if err := saveCredentials(h.env, &second); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadCredentials(h.env, true)
	if err != nil || loaded.Server != "https://other.example.com" || loaded.Token != testToken {
		t.Fatalf("loaded %+v %v", loaded, err)
	}
	entries, _ := os.ReadDir(h.home)
	if len(entries) != 1 || entries[0].Name() != credentialsFile {
		var names []string
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("state directory holds %v", names)
	}
	assertPrivate(t, filepath.Join(h.home, credentialsFile))
	assertPrivateDir(t, h.home)
}

func TestWriteAtomicLeavesNothingOnFailure(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "x.json")
	writeFile(t, target, "keep")
	_, _, err := writeAtomic(target, true, func(writer io.Writer) error {
		_, _ = writer.Write([]byte("partial"))
		return os.ErrClosed
	})
	if err == nil {
		t.Fatal("no error")
	}
	if data, _ := os.ReadFile(target); string(data) != "keep" {
		t.Fatalf("target changed to %q", data)
	}
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), tempPrefix) {
			t.Fatalf("temporary file %s left", entry.Name())
		}
	}
}
