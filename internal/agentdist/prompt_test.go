package agentdist

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

var updateGolden = flag.Bool("update", false, "rewrite the golden install prompts in testdata/")

const testSignature = "MTc2NzMyNjI0NS5leGFtcGxlLXNpZ25hdHVyZQ"

func promptInput(platform Platform, agent, skillsDir string) PromptInput {
	version := "0.1.0"
	return PromptInput{
		ServerURL:  "https://audit.example.com",
		LinkPrefix: LinkPrefix("https://audit.example.com", testSignature),
		Package: Package{OS: platform.OS, Arch: platform.Arch, File: PackageFileName(version, platform),
			SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Size: 3456789},
		Version:   version,
		Agent:     agent,
		SkillsDir: skillsDir,
		ExpiresAt: time.Date(2026, time.January, 2, 3, 34, 5, 0, time.UTC),
	}
}

var (
	windowsAMD64 = Platform{OS: "windows", Arch: "amd64"}
	linuxAMD64   = Platform{OS: "linux", Arch: "amd64"}
	darwinARM64  = Platform{OS: "darwin", Arch: "arm64"}
)

func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *updateGolden {
		writeTestFile(t, path, got)
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s (run go test -run Golden -update to create it): %v", path, err)
	}
	if normalized := strings.ReplaceAll(string(want), "\r\n", "\n"); normalized != got {
		t.Fatalf("%s differs from the generated prompt; rerun with -update if the change is intended.\n--- got ---\n%s", path, got)
	}
}

func mustPrompt(t *testing.T, input PromptInput) string {
	t.Helper()
	prompt, err := InstallPrompt(input)
	if err != nil {
		t.Fatalf("InstallPrompt: %v", err)
	}
	return prompt
}

func TestInstallPromptGoldenPOSIX(t *testing.T) {
	checkGolden(t, "prompt-linux-amd64-claude-code.golden", mustPrompt(t, promptInput(linuxAMD64, AgentClaudeCode, "")))
}

func TestInstallPromptGoldenWindows(t *testing.T) {
	checkGolden(t, "prompt-windows-amd64-codex-custom.golden", mustPrompt(t, promptInput(windowsAMD64, AgentCodex, `C:\Tools\agent skills`)))
}

func TestInstallPromptGoldenDarwin(t *testing.T) {
	checkGolden(t, "prompt-darwin-arm64-other-custom.golden", mustPrompt(t, promptInput(darwinARM64, AgentOther, "/Users/example/agent-skills/llmapi-audit/")))
}

// promptCases covers every agent on every platform family, default and
// custom directories.
func promptCases() map[string]PromptInput {
	cases := map[string]PromptInput{}
	for kind := range agents {
		for _, platform := range Platforms {
			custom := "/opt/example skills"
			if platform.Windows() {
				custom = `D:\example\skills`
			}
			if kind != AgentOther {
				cases[kind+"/"+platform.String()+"/default"] = promptInput(platform, kind, "")
			}
			cases[kind+"/"+platform.String()+"/custom"] = promptInput(platform, kind, custom)
		}
	}
	return cases
}

var stepPattern = regexp.MustCompile(`(?m)^(\d+)\. `)

// commandLines are the indented command lines of the steps.
func commandLines(prompt string) []string {
	var lines []string
	for _, line := range strings.Split(prompt, "\n") {
		if !strings.HasPrefix(line, "   ") {
			continue
		}
		line = strings.TrimSpace(line)
		line = strings.TrimPrefix(line, "Then run: ")
		line = strings.TrimPrefix(line, "If unzip is not installed, run this instead: ")
		if line == "" || strings.HasPrefix(line, "Check:") || strings.HasPrefix(line, "- ") || strings.HasPrefix(line, "If ") || strings.HasPrefix(line, "The command ") {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

func installDirOf(t *testing.T, prompt string) string {
	t.Helper()
	match := regexp.MustCompile(`(?m)^Final install directory: (.+)$`).FindStringSubmatch(prompt)
	if match == nil {
		t.Fatal("the prompt does not show the final install directory")
	}
	return match[1]
}

func TestInstallPromptRequirements(t *testing.T) {
	for name, input := range promptCases() {
		t.Run(name, func(t *testing.T) {
			prompt := mustPrompt(t, input)
			platform := input.Package.Platform()

			// Numbered steps in order.
			steps := stepPattern.FindAllStringSubmatch(prompt, -1)
			if len(steps) < 8 {
				t.Fatalf("only %d numbered steps", len(steps))
			}
			for index, step := range steps {
				if step[1] != strconv.Itoa(index+1) {
					t.Fatalf("step %d is numbered %s", index+1, step[1])
				}
			}
			for _, phrase := range []string{
				"in order, one at a time",
				"stop at once",
				"do not continue with later steps",
				"Tell the user which step failed",
				// Never another source or method.
				"Use only the download link in this prompt",
				"never switch to another install method",
				// The digest.
				input.Package.SHA256,
				"If it differs in any character, stop",
				// The layout of the archive.
				"The archive's top level is the directory llmapi-audit/ itself",
				"never nested twice",
				// Replacement only of a previous install, by its marker.
				"previous-install: it is an earlier install of this Skill (it contains scripts",
				"foreign: something else is there. Stop. Delete nothing",
				// Nothing outside, never the parent.
				"Change nothing outside the install directory",
				"Never delete or modify its parent directory",
				// Login in the browser, no credential.
				"authorizes this machine in the browser",
				"It never asks for a password, an API key or a token",
				"you must not ask the user for one",
				// New session.
				"new session",
				// HTTP 410 means expired.
				"410",
			} {
				if !strings.Contains(prompt, phrase) {
					t.Errorf("prompt lacks %q", phrase)
				}
			}

			install := installDirOf(t, prompt)
			if !strings.HasSuffix(install, SkillName) || strings.HasSuffix(strings.TrimSuffix(install, SkillName), SkillName+"/") || strings.HasSuffix(strings.TrimSuffix(install, SkillName), SkillName+`\`) {
				t.Fatalf("install directory %q does not end in exactly one %s", install, SkillName)
			}
			parent := install[:len(install)-len(SkillName)-1]
			if !strings.Contains(prompt, "Never delete or modify its parent directory "+parent+" ") {
				t.Errorf("the parent directory %q is not named", parent)
			}

			// The last step verifies with whoami; the login step comes right before.
			last := prompt[strings.LastIndex(prompt, "\n"+strconv.Itoa(len(steps))+". "):]
			if !strings.Contains(last, " whoami") {
				t.Fatalf("the last step is not whoami: %q", last)
			}
			if !strings.Contains(prompt[strings.LastIndex(prompt, "\n"+strconv.Itoa(len(steps)-1)+". "):], " login --server ") {
				t.Fatal("the step before the last is not the login")
			}

			// Every command that deletes targets the install or the work directory
			// only: on POSIX the private one mktemp creates (its printed path
			// replaces the placeholder), on Windows the one in the user's TEMP.
			work := `$env:TEMP\llmapi-audit-install-` + input.Package.SHA256[:12]
			if !platform.Windows() {
				work = posixWorkDir
				if !strings.Contains(prompt, `mktemp -d "${TMPDIR:-/tmp}/llmapi-audit-install.XXXXXXXX"`) || strings.Contains(prompt, "mkdir -p -- \"${TMPDIR") {
					t.Error("the POSIX work directory is not created with mktemp -d")
				}
				// Its removal refuses anything but a path of mktemp's shape: the
				// base name is llmapi-audit-install. and eight letters or digits
				// (TestPosixWorkRemovalInShell runs it).
				guard := `d="LLMAPI_WORK_DIR"; b=; case "$d" in */./*|*/../*|*/.|*/..|*//*) ;; /*) b="${d##*/}" ;; esac; case "$b" in llmapi-audit-install.` +
					strings.Repeat("[A-Za-z0-9]", 8) + `) rm -rf -- "$d" ;; *)`
				if !strings.Contains(prompt, guard) || strings.Count(prompt, `rm -rf -- "$d"`) != 1 || strings.Contains(prompt, "????????") {
					t.Error("the POSIX work directory is removed without the guard")
				}
			}
			for _, line := range commandLines(prompt) {
				for _, deletion := range regexp.MustCompile(`(?:rm -rf -- |Remove-Item -LiteralPath )("[^"]*")`).FindAllStringSubmatch(line, -1) {
					target := strings.Trim(deletion[1], `"`)
					// "$d" is the guarded work directory of the POSIX removal.
					if target == "$d" && !platform.Windows() && strings.HasPrefix(line, `d="`+work+`"; `) {
						continue
					}
					if target != install && target != work {
						t.Errorf("deletes %q, which is neither the install directory nor the work directory", target)
					}
				}
				if strings.Contains(line, "rm -r") && !strings.Contains(line, "rm -rf -- ") {
					t.Errorf("unguarded rm: %q", line)
				}
				if strings.Contains(line, "Remove-Item") && !strings.Contains(line, "-LiteralPath") {
					t.Errorf("Remove-Item without -LiteralPath: %q", line)
				}
			}

			// Exactly one download URL, the signed link to this package.
			link := input.LinkPrefix + input.Package.File
			urls := regexp.MustCompile(`https?://[^\s"]+`).FindAllString(prompt, -1)
			downloads := 0
			for _, found := range urls {
				switch {
				case found == link:
					downloads++
				case found == input.ServerURL:
				case strings.HasPrefix(found, input.ServerURL+"/api/"):
					t.Errorf("unexpected server API URL %q", found)
				default:
					t.Errorf("unexpected URL %q", found)
				}
			}
			if downloads != 1 {
				t.Fatalf("the signed link appears %d times", downloads)
			}

			if platform.Windows() {
				if strings.Contains(strings.Join(commandLines(prompt), "\n"), "'") {
					t.Error("a Windows command contains a single quote, which breaks the bash wrapping the prompt suggests")
				}
				for _, word := range []string{"Get-FileHash", "Expand-Archive", "llmaudit.exe", "PowerShell"} {
					if !strings.Contains(prompt, word) {
						t.Errorf("Windows prompt lacks %s", word)
					}
				}
				if strings.Contains(prompt, "sha256sum") || strings.Contains(prompt, "unzip") {
					t.Error("Windows prompt uses POSIX tools")
				}
			} else {
				for _, word := range []string{"curl", "unzip", "chmod 755", "POSIX shell"} {
					if !strings.Contains(prompt, word) {
						t.Errorf("POSIX prompt lacks %s", word)
					}
				}
				digestTool := "sha256sum"
				if platform.OS == "darwin" {
					digestTool = "shasum -a 256"
				}
				if !strings.Contains(prompt, digestTool) {
					t.Errorf("prompt lacks %s", digestTool)
				}
				if strings.Contains(prompt, "Get-FileHash") || strings.Contains(prompt, ".exe") {
					t.Error("POSIX prompt uses Windows tools")
				}
			}
		})
	}
}

func TestInstallPromptDefaultDirectories(t *testing.T) {
	want := map[string]string{
		AgentClaudeCode: "$HOME/.claude/skills/llmapi-audit",
		AgentCodex:      "$HOME/.agents/skills/llmapi-audit",
		AgentCursor:     "$HOME/.cursor/skills/llmapi-audit",
		AgentGeminiCLI:  "$HOME/.gemini/skills/llmapi-audit",
	}
	for agent, dir := range want {
		if got := installDirOf(t, mustPrompt(t, promptInput(linuxAMD64, agent, ""))); got != dir {
			t.Errorf("%s: install directory %q, want %q", agent, got, dir)
		}
		windowsDir := strings.ReplaceAll(dir, "/", `\`)
		if got := installDirOf(t, mustPrompt(t, promptInput(windowsAMD64, agent, ""))); got != windowsDir {
			t.Errorf("%s on Windows: install directory %q, want %q", agent, got, windowsDir)
		}
	}
}

func TestInstallPromptCustomDirectories(t *testing.T) {
	cases := []struct {
		platform Platform
		input    string
		want     string
	}{
		{linuxAMD64, "/opt/skills", "/opt/skills/llmapi-audit"},
		{linuxAMD64, "/opt/skills/", "/opt/skills/llmapi-audit"},
		{linuxAMD64, "/opt/skills/llmapi-audit", "/opt/skills/llmapi-audit"},
		{linuxAMD64, "/home/名前/skills", "/home/名前/skills/llmapi-audit"},
		{darwinARM64, "/Users/example/Library/Agent Skills", "/Users/example/Library/Agent Skills/llmapi-audit"},
		{windowsAMD64, `C:\Tools\skills`, `C:\Tools\skills\llmapi-audit`},
		{windowsAMD64, `c:/Tools/skills/`, `C:\Tools\skills\llmapi-audit`},
		{windowsAMD64, `D:\skills\llmapi-audit\`, `D:\skills\llmapi-audit`},
		// The Skill directory itself in another letter case is not nested.
		{windowsAMD64, `C:\Tools\skills\LLMAPI-AUDIT`, `C:\Tools\skills\llmapi-audit`},
		{darwinARM64, "/Users/example/skills/LlmApi-Audit", "/Users/example/skills/llmapi-audit"},
		{linuxAMD64, "/opt/skills/Llmapi-Audit/", "/opt/skills/llmapi-audit"},
	}
	for _, c := range cases {
		prompt, err := InstallPrompt(promptInput(c.platform, AgentClaudeCode, c.input))
		if err != nil {
			t.Errorf("%q: %v", c.input, err)
			continue
		}
		if got := installDirOf(t, prompt); got != c.want {
			t.Errorf("%q: install directory %q, want %q", c.input, got, c.want)
		}
	}
}

func TestInstallPromptRejectsBadSkillsDir(t *testing.T) {
	posix := []string{
		"relative/skills", "~/skills", "./skills", "/opt/../etc", "/opt/./skills", "/opt//skills", "/",
		"/opt/skills\n/etc", "/opt/skills\r", "/opt/sk\x00ills", "/opt/sk\x1bills", "/opt/sk\tills",
		`/opt/"skills"`, "/opt/'skills'", "/opt/`id`", "/opt/$(id)", "/opt/${HOME}", "/opt/skills;rm",
		"/opt/skills&", "/opt/a|b", "/opt/a<b", "/opt/a>b", "/opt/a(b)", "/opt/*", "/opt/a?", "/opt/a[1]",
		"/opt/a{b}", "/opt/a!b", "/opt/a#b", "/opt/a%b", "/opt/a^b", "/opt/a~b", "/opt/a=b", "/opt/a,b",
		`/opt/a\b`, "/opt/a:b", "/opt/ skills", "/opt/skills /x", "/llmapi-audit", "/LLMAPI-Audit", "C:\\skills",
		"/" + strings.Repeat("a", 250),
	}
	windows := []string{
		`skills`, `\skills`, `\\server\share\skills`, `C:`, `C:\`, `C:skills`, `1:\skills`, `C:\a\..\b`,
		`C:\a\.\b`, `C:\a\\b`, `C:\a:b`, `C:\a.\b`, `C:\%USERPROFILE%\skills`, `C:\a&b`, `C:\a^b`, `C:\a!b`,
		"C:\\a\nb", `C:\a"b`, `C:\a'b`, "C:\\a`b", `C:\$env:TEMP`, `C:\a;b`, `C:\a|b`, `/opt/skills`,
		`C:\llmapi-audit`, `C:\LLMAPI-AUDIT`,
	}
	check := func(platform Platform, value string) {
		prompt, err := InstallPrompt(promptInput(platform, AgentClaudeCode, value))
		var inputErr *InputError
		if err == nil || prompt != "" || !errors.As(err, &inputErr) || inputErr.Field != "skills_dir" {
			t.Errorf("%s %q: prompt %d bytes, error %v", platform, value, len(prompt), err)
		}
	}
	for _, value := range posix {
		check(linuxAMD64, value)
	}
	for _, value := range windows {
		check(windowsAMD64, value)
	}
}

func TestInstallPromptRejectsBadInput(t *testing.T) {
	mutations := map[string]func(*PromptInput){
		"agent":             func(input *PromptInput) { input.Agent = "copilot" },
		"other without dir": func(input *PromptInput) { input.Agent = AgentOther },
		"platform":          func(input *PromptInput) { input.Package.OS = "plan9" },
		"server scheme":     func(input *PromptInput) { input.ServerURL = "ftp://audit.example.com" },
		"server quote":      func(input *PromptInput) { input.ServerURL = `https://audit.example.com/"` },
		"server query":      func(input *PromptInput) { input.ServerURL = "https://audit.example.com/?x" },
		"server user":       func(input *PromptInput) { input.ServerURL = "https://u@audit.example.com" },
		"prefix elsewhere":  func(input *PromptInput) { input.LinkPrefix = "https://mirror.example.com/api/agent/v1/dl/x/" },
		"prefix no slash":   func(input *PromptInput) { input.LinkPrefix = strings.TrimSuffix(input.LinkPrefix, "/") },
		"prefix quote":      func(input *PromptInput) { input.LinkPrefix += `"` },
		"file traversal":    func(input *PromptInput) { input.Package.File = "../x.zip" },
		"sha":               func(input *PromptInput) { input.Package.SHA256 = "abc" },
		"size":              func(input *PromptInput) { input.Package.Size = 0 },
		"version":           func(input *PromptInput) { input.Version = "1.0.0;x" },
	}
	for name, mutate := range mutations {
		input := promptInput(linuxAMD64, AgentClaudeCode, "")
		mutate(&input)
		if prompt, err := InstallPrompt(input); err == nil || prompt != "" {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestInstallPromptIsPure(t *testing.T) {
	input := promptInput(windowsAMD64, AgentCursor, "")
	if mustPrompt(t, input) != mustPrompt(t, input) {
		t.Fatal("the same input gave two prompts")
	}
}
