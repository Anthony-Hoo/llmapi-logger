// Command agentpack builds the llmapi-audit Skill packages: it cross-compiles
// cmd/llmaudit for every platform, assembles one reproducible archive per
// platform and writes manifest.json (doc/features/25-agent-access-contract.md
// section 5). The Dockerfile and scripts/build.* run it from the repository
// root:
//
//	go run ./internal/agentdist/cmd/agentpack -out bin/agent-packages
//
// With -bin-dir it packs binaries built elsewhere instead, named
// llmaudit-<os>-<arch>[.exe].
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"llmapi-logger/internal/agentdist"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "agentpack:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("agentpack", flag.ContinueOnError)
	flags.SetOutput(stderr)
	skillDir := flags.String("skill", filepath.Join("skill", agentdist.SkillName), "Skill source directory")
	outDir := flags.String("out", filepath.Join("bin", agentdist.PackageDirName), "output directory for the archives and manifest.json")
	binDir := flags.String("bin-dir", "", "directory of prebuilt llmaudit-<os>-<arch>[.exe] binaries; empty builds them with go build")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected arguments")
	}

	binaries := map[agentdist.Platform]string{}
	source := *binDir
	if source == "" {
		temp, err := os.MkdirTemp("", "agentpack-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(temp)
		for _, platform := range agentdist.Platforms {
			if err := buildClient(platform, filepath.Join(temp, binaryFile(platform)), stderr); err != nil {
				return err
			}
		}
		source = temp
	}
	for _, platform := range agentdist.Platforms {
		binaries[platform] = filepath.Join(source, binaryFile(platform))
	}

	manifest, err := agentdist.Pack(agentdist.PackOptions{SkillDir: *skillDir, Binaries: binaries, OutDir: *outDir})
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Wrote %s:\n", *outDir)
	for _, pkg := range manifest.Packages {
		fmt.Fprintf(stdout, "  %-40s %9d bytes  sha256 %s\n", pkg.File, pkg.Size, pkg.SHA256)
	}
	fmt.Fprintf(stdout, "  %s (version %s, min_compatible %s)\n", agentdist.ManifestFile, manifest.Version, manifest.MinCompatible)
	return nil
}

func binaryFile(platform agentdist.Platform) string {
	name := "llmaudit-" + platform.String()
	if platform.Windows() {
		name += ".exe"
	}
	return name
}

// buildClient cross-compiles cmd/llmaudit. -trimpath and -buildvcs=false keep
// the binary independent of the checkout's location and Git state.
func buildClient(platform agentdist.Platform, output string, stderr io.Writer) error {
	command := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w", "-o", output, "./cmd/llmaudit")
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+platform.OS, "GOARCH="+platform.Arch)
	command.Stdout = stderr
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("go build for %s: %w", platform, err)
	}
	return nil
}
