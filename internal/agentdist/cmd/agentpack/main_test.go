package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"llmapi-logger/internal/agentdist"
)

// TestRunPacksPrebuiltBinariesReproducibly runs the program twice over the
// repository's Skill with placeholder binaries and compares the output.
func TestRunPacksPrebuiltBinariesReproducibly(t *testing.T) {
	binDir := t.TempDir()
	for _, platform := range agentdist.Platforms {
		if err := os.WriteFile(filepath.Join(binDir, binaryFile(platform)), []byte("binary "+platform.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	skill := filepath.Join("..", "..", "..", "..", "skill", agentdist.SkillName)
	var outputs []string
	for run := 0; run < 2; run++ {
		out := filepath.Join(t.TempDir(), agentdist.PackageDirName)
		var stdout, stderr bytes.Buffer
		if err := run_(t, []string{"-skill", skill, "-bin-dir", binDir, "-out", out}, &stdout, &stderr); err != nil {
			t.Fatalf("run %d: %v; stderr %s", run, err, stderr.String())
		}
		if !strings.Contains(stdout.String(), agentdist.ManifestFile) {
			t.Fatalf("summary lacks the manifest: %s", stdout.String())
		}
		outputs = append(outputs, out)
	}
	entries, err := os.ReadDir(outputs[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(agentdist.Platforms)+1 {
		t.Fatalf("%d files written", len(entries))
	}
	for _, entry := range entries {
		left, _ := os.ReadFile(filepath.Join(outputs[0], entry.Name()))
		right, err := os.ReadFile(filepath.Join(outputs[1], entry.Name()))
		if err != nil || !bytes.Equal(left, right) {
			t.Fatalf("%s differs between the two runs", entry.Name())
		}
	}
	manifest, err := os.ReadFile(filepath.Join(outputs[0], agentdist.ManifestFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agentdist.ParseManifest(manifest); err != nil {
		t.Fatalf("manifest: %v", err)
	}
}

func TestRunRejectsArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run_(t, []string{"extra"}, &stdout, &stderr); err == nil {
		t.Fatal("a positional argument was accepted")
	}
	if err := run_(t, []string{"-bin-dir", t.TempDir(), "-out", filepath.Join(t.TempDir(), "out"), "-skill", filepath.Join("..", "..", "..", "..", "skill", agentdist.SkillName)}, &stdout, &stderr); err == nil {
		t.Fatal("missing binaries were accepted")
	}
}

func run_(t *testing.T, args []string, stdout, stderr *bytes.Buffer) error {
	t.Helper()
	return run(args, stdout, stderr)
}
