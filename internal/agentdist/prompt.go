package agentdist

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"
)

// Agent kinds accepted by the install-links request.
const (
	AgentClaudeCode = "claude-code"
	AgentCodex      = "codex"
	AgentCursor     = "cursor"
	AgentGeminiCLI  = "gemini-cli"
	AgentOther      = "other"
)

// agentInfo is what the prompt says about one agent product.
type agentInfo struct {
	// Name is how the prompt refers to the product.
	Name string
	// SkillsDir is the default user-level skills directory relative to the
	// home directory, with forward slashes; empty means the request must give
	// skills_dir.
	SkillsDir string
}

// agents lists the accepted agent kinds.
//
// UNVERIFIED: the default skills directories come from the design discussion
// and have not been checked against each product's documentation or a real
// installation. Confirm every row before release; a wrong row installs the
// Skill where the product never looks (the install itself stays safe, because
// the prompt only ever writes the llmapi-audit directory).
var agents = map[string]agentInfo{
	AgentClaudeCode: {Name: "Claude Code", SkillsDir: ".claude/skills"},
	AgentCodex:      {Name: "Codex", SkillsDir: ".agents/skills"},
	AgentCursor:     {Name: "Cursor", SkillsDir: ".cursor/skills"},
	AgentGeminiCLI:  {Name: "Gemini CLI", SkillsDir: ".gemini/skills"},
	AgentOther:      {Name: "your agent"},
}

// ValidAgent reports whether kind is one of the accepted agent kinds.
func ValidAgent(kind string) bool {
	_, ok := agents[kind]
	return ok
}

// InputError is an invalid install-links input. Field is the request field:
// agent, platform or skills_dir. The web layer answers it as a 400 with that
// field; Message is safe to show.
type InputError struct {
	Field   string
	Message string
}

func (err *InputError) Error() string { return err.Field + ": " + err.Message }

// PromptInput is everything the install prompt depends on.
type PromptInput struct {
	// ServerURL is the management plane's base URL as the user's agent
	// reaches it, for example https://audit.example.com; it may have a path.
	ServerURL string
	// LinkPrefix is the signed link without the file name:
	// ServerURL + "/api/agent/v1/dl/<signature>/".
	LinkPrefix string
	// Package is the manifest entry of the chosen platform.
	Package Package
	// Version is the package version (the manifest's version).
	Version string
	// Agent is one of the Agent* kinds.
	Agent string
	// SkillsDir optionally replaces the agent's default skills directory; an
	// absolute path for Package's platform.
	SkillsDir string
	// ExpiresAt is the link's expiry, printed so the agent can tell an
	// expired link from another failure.
	ExpiresAt time.Time
}

// paths are the shell expressions of every path the prompt uses, already
// quoted for the platform's shell.
type paths struct {
	skills  string // the skills directory (parent of install)
	install string // always ends in llmapi-audit
	work    string // temporary work directory
	// workShown names the work directory in the rules of the prompt.
	workShown string
	zip       string
	extract   string
	binary    string
	shown     string // install directory as shown to the user
	parent    string // skills directory as shown to the user
}

// InstallPrompt returns the text an AI agent executes step by step to install
// the Skill. It is a pure function of its input. Invalid input returns an
// error and no prompt; an *InputError names the request field at fault.
func InstallPrompt(input PromptInput) (string, error) {
	info, ok := agents[input.Agent]
	if !ok {
		return "", &InputError{Field: "agent", Message: "agent must be one of claude-code, codex, cursor, gemini-cli, other"}
	}
	platform := input.Package.Platform()
	if _, ok := ParsePlatform(platform.String()); !ok {
		return "", &InputError{Field: "platform", Message: "platform must be one of " + platformList()}
	}
	server, err := cleanServerURL(input.ServerURL)
	if err != nil {
		return "", err
	}
	if !ValidFileName(input.Package.File) || !sha256Pattern.MatchString(input.Package.SHA256) || input.Package.Size <= 0 {
		return "", errors.New("agentdist: invalid package entry")
	}
	if input.Version == "" || !versionSafe(input.Version) {
		return "", errors.New("agentdist: invalid version")
	}
	prefix := input.LinkPrefix
	if !strings.HasPrefix(prefix, server+"/api/agent/v1/dl/") || !strings.HasSuffix(prefix, "/") || !shellSafeURL(prefix) {
		return "", errors.New("agentdist: link prefix does not belong to the server URL")
	}
	var skillsDir string
	switch {
	case input.SkillsDir != "":
		skillsDir, err = cleanSkillsDir(input.SkillsDir, platform)
		if err != nil {
			return "", err
		}
	case info.SkillsDir == "":
		return "", &InputError{Field: "skills_dir", Message: "skills_dir is required for agent other: give the absolute path of the directory your agent loads skills from"}
	}
	p := buildPaths(platform, info, skillsDir, input.Package)
	if platform.Windows() {
		return windowsPrompt(input, info, server, p), nil
	}
	return posixPrompt(input, info, server, p), nil
}

func platformList() string {
	names := make([]string, 0, len(Platforms))
	for _, platform := range Platforms {
		names = append(names, platform.String())
	}
	return strings.Join(names, ", ")
}

// cleanServerURL accepts an http or https URL with a host, an optional path,
// and no user info, query or fragment, made only of characters that are
// literal inside double quotes in both POSIX shells and PowerShell. The
// trailing slash is removed.
func cleanServerURL(raw string) (string, error) {
	invalid := errors.New("agentdist: server URL must be http(s)://host[/path] without user info, query, fragment or shell metacharacters")
	if !shellSafeURL(raw) {
		return "", invalid
	}
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.Contains(raw, "#") {
		return "", invalid
	}
	return strings.TrimRight(raw, "/"), nil
}

// shellSafeURL allows letters, digits and - . _ ~ : / % [ ]: no quote, space,
// $, backtick, backslash or any other character a shell would interpret
// inside double quotes.
func shellSafeURL(value string) bool {
	if value == "" || len(value) > 2048 {
		return false
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		switch {
		case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z', char >= '0' && char <= '9':
		case strings.IndexByte("-._~:/%[]", char) >= 0:
		default:
			return false
		}
	}
	return true
}

// cleanSkillsDir validates a custom skills directory for platform and returns
// it without trailing separators. It must be absolute (/... on Linux and
// macOS, X:\... on Windows), with no "." or ".." segment, and only letters,
// digits, spaces and . _ - + besides the separators: that excludes newlines,
// control characters, quotes and every shell metacharacter. When the path
// already ends in llmapi-audit, in any letter case (Windows and the default
// macOS file systems ignore case; Linux is treated the same to be safe), its
// parent is the skills directory, so the Skill is never nested in a second
// llmapi-audit directory.
func cleanSkillsDir(raw string, platform Platform) (string, error) {
	fail := func(message string) (string, error) {
		return "", &InputError{Field: "skills_dir", Message: message}
	}
	if len(raw) > 240 {
		return fail("skills_dir is longer than 240 characters")
	}
	for _, char := range raw {
		switch {
		case unicode.IsLetter(char), unicode.IsDigit(char):
		case char == ' ' || char == '.' || char == '_' || char == '-' || char == '+':
		case char == '/' || char == '\\' || char == ':':
		default:
			return fail("skills_dir may contain only letters, digits, spaces, . _ - + and path separators")
		}
	}
	var separator, root, rest string
	if platform.Windows() {
		path := strings.ReplaceAll(raw, "/", `\`)
		if len(path) < 3 || !isASCIILetter(path[0]) || path[1] != ':' || path[2] != '\\' {
			return fail(`skills_dir must be an absolute Windows path such as C:\Users\name\.claude\skills`)
		}
		separator, root, rest = `\`, strings.ToUpper(path[:1])+`:\`, path[3:]
	} else {
		if strings.Contains(raw, `\`) || !strings.HasPrefix(raw, "/") {
			return fail("skills_dir must be an absolute path such as /home/name/.claude/skills")
		}
		separator, root, rest = "/", "/", raw[1:]
	}
	if strings.Contains(rest, ":") {
		return fail("skills_dir may contain ':' only after the drive letter")
	}
	rest = strings.TrimRight(rest, separator)
	if rest == "" {
		return fail("skills_dir must not be the root of a drive or file system")
	}
	segments := strings.Split(rest, separator)
	for _, segment := range segments {
		switch {
		case segment == "":
			return fail("skills_dir must not contain empty path segments")
		case segment == "." || segment == "..":
			return fail("skills_dir must not contain . or .. segments")
		case strings.TrimSpace(segment) != segment:
			return fail("skills_dir segments must not start or end with a space")
		case platform.Windows() && strings.HasSuffix(segment, "."):
			return fail("skills_dir segments must not end with a dot on Windows")
		}
	}
	if strings.EqualFold(segments[len(segments)-1], SkillName) {
		segments = segments[:len(segments)-1]
		if len(segments) == 0 {
			return fail("skills_dir must not be the root of a drive or file system")
		}
	}
	return root + strings.Join(segments, separator), nil
}

func isASCIILetter(char byte) bool {
	return (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z')
}

// shortDigest names the Windows work directory after the package, so a rerun
// of the same prompt reuses (and first clears) the same directory and nothing
// else. It lives in $env:TEMP, which is the user's own directory.
func shortDigest(pkg Package) string { return pkg.SHA256[:12] }

// posixWorkDir stands for the work directory in the POSIX prompt. Step 1
// creates it with mktemp -d (private, with a random name, in the shared
// temporary directory) and the agent writes the printed path in its place:
// a fixed path there could be created first by another local user.
const posixWorkDir = "LLMAPI_WORK_DIR"

func buildPaths(platform Platform, info agentInfo, custom string, pkg Package) paths {
	var p paths
	work := "llmapi-audit-install-" + shortDigest(pkg)
	if platform.Windows() {
		skills := custom
		if skills == "" {
			skills = `$HOME\` + strings.ReplaceAll(info.SkillsDir, "/", `\`)
		}
		install := skills + `\` + SkillName
		p.skills, p.install = quote(skills), quote(install)
		p.work = quote(`$env:TEMP\` + work)
		p.workShown = `$env:TEMP\` + work
		p.zip = quote(`$env:TEMP\` + work + `\` + pkg.File)
		p.extract = quote(`$env:TEMP\` + work + `\extract`)
		p.binary = quote(install + `\scripts\` + platform.BinaryName())
		p.shown, p.parent = install, skills
		return p
	}
	skills := custom
	if skills == "" {
		skills = "$HOME/" + info.SkillsDir
	}
	install := skills + "/" + SkillName
	p.skills, p.install = quote(skills), quote(install)
	p.work = quote(posixWorkDir)
	p.workShown = posixWorkDir + " (the private directory step 1 creates with mktemp)"
	p.zip = quote(posixWorkDir + "/" + pkg.File)
	p.extract = quote(posixWorkDir + "/extract")
	p.binary = quote(install + "/scripts/" + platform.BinaryName())
	p.shown, p.parent = install, skills
	return p
}

// quote double-quotes a path. Every input was validated to contain no quote,
// backtick or other character that is special inside double quotes, apart
// from the $HOME, $env:TEMP and ${TMPDIR:-/tmp} the prompt itself writes.
func quote(path string) string { return `"` + path + `"` }

// steps numbers the steps as they are added.
type steps struct {
	builder *strings.Builder
	next    int
}

func (s *steps) add(title string, lines ...string) {
	s.next++
	fmt.Fprintf(s.builder, "%d. %s\n", s.next, title)
	for _, line := range lines {
		if line == "" {
			s.builder.WriteString("\n")
			continue
		}
		s.builder.WriteString("   " + line + "\n")
	}
	s.builder.WriteString("\n")
}

func header(builder *strings.Builder, input PromptInput, info agentInfo, server string, p paths, shellNote string) {
	platform := input.Package.Platform()
	fmt.Fprintf(builder, "Install the llmapi-audit Skill (version %s, %s) for %s, so that you can query the LLM API audit server at %s through its command-line client llmaudit.\n\n", input.Version, platform, info.Name, server)
	builder.WriteString("Rules for this whole task:\n")
	builder.WriteString("- Execute the numbered steps below in order, one at a time, running each command exactly as written. Do not skip, merge or reorder steps.\n")
	builder.WriteString("- If a command fails or a step's check does not hold, stop at once. Do not try to repair it and do not continue with later steps. Tell the user which step failed and show the exact output.\n")
	builder.WriteString("- Use only the download link in this prompt. Never fetch the package from any other address, mirror or repository, and never switch to another install method (a package manager, a git clone, building from source, copying files by hand).\n")
	fmt.Fprintf(builder, "- Change nothing outside the install directory %s. Never delete or modify its parent directory %s or anything else in it. The one exception is the temporary work directory %s, which this prompt creates and removes.\n", p.shown, p.parent, p.workShown)
	builder.WriteString("- Nothing here asks for a password, an API key or a token, and you must not ask the user for one. The login in a later step is authorized by the user in the browser.\n")
	if shellNote != "" {
		builder.WriteString("- " + shellNote + "\n")
	}
	builder.WriteString("\n")
	fmt.Fprintf(builder, "Final install directory: %s\n", p.shown)
	fmt.Fprintf(builder, "Package file: %s (%d bytes)\n", input.Package.File, input.Package.Size)
	fmt.Fprintf(builder, "Expected SHA-256: %s\n", input.Package.SHA256)
	if !input.ExpiresAt.IsZero() {
		fmt.Fprintf(builder, "The download link is valid until %s. HTTP 410 (Gone) means it has expired: stop and ask the user to generate a new install prompt on the Agent access page of the web UI. HTTP 404 means the link or file is not valid: stop and report it.\n", input.ExpiresAt.UTC().Format(time.RFC3339))
	}
	fmt.Fprintf(builder, "The archive's top level is the directory llmapi-audit/ itself: it contains llmapi-audit/SKILL.md, llmapi-audit/VERSION, llmapi-audit/references/ and llmapi-audit/scripts/%s. It is extracted into a work directory and then moved to the install directory as a whole, so it is never nested twice.\n\n", platform.BinaryName())
}

func footer(builder *strings.Builder, info agentInfo, p paths) {
	fmt.Fprintf(builder, "When every step has succeeded, tell the user: the llmapi-audit Skill is installed in %s, the role and tier that whoami reported, and that %s should be started in a new session (or have its skills reloaded) before the Skill is available, because agents load skills when a session starts.\n", p.shown, info.Name)
}

func posixPrompt(input PromptInput, info agentInfo, server string, p paths) string {
	var builder strings.Builder
	header(&builder, input, info, server, p, "Run the commands in a POSIX shell (sh, bash or zsh). Every command is complete on its own; nothing depends on shell variables from an earlier step. The one value carried from step to step is the work directory path that step 1 prints: write it in place of "+posixWorkDir+" in every later command, inside the double quotes as shown.")
	link := input.LinkPrefix + input.Package.File
	platform := input.Package.Platform()
	digest := "sha256sum " + p.zip
	if platform.OS == "darwin" {
		digest = "shasum -a 256 " + p.zip
	}
	s := &steps{builder: &builder}
	s.add("Create a private work directory with a random name:",
		`mktemp -d "${TMPDIR:-/tmp}/llmapi-audit-install.XXXXXXXX"`,
		"Check: the command exits with status 0 and prints one absolute path made only of letters, digits and the characters / . _ -. If nothing is printed or the path has any other character (a space, for example), stop.",
		"From now on write that exact path wherever a command says "+posixWorkDir+". Never run a command that still contains "+posixWorkDir+" itself.")
	s.add("Download the package from the link in this prompt, and only from it:",
		"curl -fsS --max-redirs 0 -o "+p.zip+` "`+link+`"`,
		"Check: the command exits with status 0. If curl reports HTTP 410, the link has expired; if it reports another error, stop either way.")
	s.add("Verify the SHA-256 digest of the download:",
		digest,
		"Check: the first field printed is exactly "+input.Package.SHA256+". If it differs in any character, stop: do not extract or run the file, and tell the user the digest did not match.")
	s.add("Extract the archive into the work directory:",
		"unzip -q "+p.zip+" -d "+p.extract,
		"If unzip is not installed, run this instead: python3 -m zipfile -e "+p.zip+" "+p.extract,
		"If neither unzip nor python3 is available, stop and ask the user to install unzip.",
		"Then run: ls -A "+p.extract+" && ls "+quote(strings.Trim(p.extract, `"`)+"/llmapi-audit/scripts/"+platform.BinaryName()),
		"Check: the first listing shows exactly one entry, llmapi-audit, and the second command finds the file.")
	s.add("Check what is at the install directory now:",
		"if [ -L "+p.install+" ]; then echo foreign; ls -la "+p.install+"; elif [ ! -e "+p.install+" ]; then echo absent; elif [ -f "+quote(p.shown+"/scripts/"+platform.BinaryName())+" ]; then echo previous-install; else echo foreign; ls -la "+p.install+"; fi",
		"- absent: nothing is there; continue with the next step.",
		"- previous-install: it is an earlier install of this Skill (it contains scripts/"+platform.BinaryName()+"). Remove that directory, and only it:",
		"  rm -rf -- "+p.install,
		"- foreign: something else is there. Stop. Delete nothing, and show the user the listing so they can decide what to do.")
	s.add("Move the extracted Skill into place (the skills directory is created if it does not exist; nothing else in it is touched):",
		"mkdir -p -- "+p.skills+" && [ ! -e "+p.install+" ] && mv -- "+quote(strings.Trim(p.extract, `"`)+"/llmapi-audit")+" "+p.install+" && chmod 755 "+p.binary,
		"Check: the command exits with status 0.")
	// The removal refuses any path that is not a work directory mktemp made,
	// whatever the agent wrote in place of the placeholder.
	s.add("Remove the work directory (the command refuses a path that is not the one step 1 created):",
		"case "+p.work+" in */llmapi-audit-install.????????) rm -rf -- "+p.work+" ;; *) echo \"refused: not the work directory from step 1\" >&2; false ;; esac",
		"Check: the command exits with status 0.")
	s.add("Check that the client runs on this machine:",
		p.binary+" --help",
		"Check: it exits with status 0 and prints the usage of llmaudit.")
	loginStep(s, server, p.binary)
	s.add("Verify the login:",
		p.binary+" whoami",
		`Check: the output is one JSON object with "ok":true. Note data.role, data.tier and data.expires_at for your report.`)
	footer(&builder, info, p)
	return builder.String()
}

func windowsPrompt(input PromptInput, info agentInfo, server string, p paths) string {
	var builder strings.Builder
	header(&builder, input, info, server, p, "Every command below is one complete PowerShell command and contains no single quote. If your shell tool runs PowerShell, run it as written; if it runs bash or another shell, run it as: powershell -NoProfile -Command '<the command>'. Nothing depends on variables from an earlier step.")
	link := input.LinkPrefix + input.Package.File
	platform := input.Package.Platform()
	extracted := quote(strings.Trim(p.extract, `"`) + `\llmapi-audit`)
	s := &steps{builder: &builder}
	s.add("Create an empty work directory (a leftover one from an earlier run of this prompt is removed first):",
		"if (Test-Path -LiteralPath "+p.work+") { Remove-Item -LiteralPath "+p.work+" -Recurse -Force }; New-Item -ItemType Directory -Path "+p.work+" | Out-Null",
		"Check: the command reports no error.")
	s.add("Download the package from the link in this prompt, and only from it:",
		`$ProgressPreference = "SilentlyContinue"; Invoke-WebRequest -UseBasicParsing -MaximumRedirection 0 -Uri "`+link+`" -OutFile `+p.zip,
		"Check: the command reports no error. If it reports 410 (Gone), the link has expired; if it reports another error, stop either way.")
	s.add("Verify the SHA-256 digest of the download:",
		"(Get-FileHash -Algorithm SHA256 -LiteralPath "+p.zip+").Hash.ToLowerInvariant()",
		"Check: the output is exactly "+input.Package.SHA256+". If it differs in any character, stop: do not extract or run the file, and tell the user the digest did not match.")
	s.add("Extract the archive into the work directory:",
		"Expand-Archive -LiteralPath "+p.zip+" -DestinationPath "+p.extract,
		"Then run: Get-ChildItem -Force -Name -LiteralPath "+p.extract+"; Test-Path -PathType Leaf -LiteralPath "+quote(strings.Trim(extracted, `"`)+`\scripts\`+platform.BinaryName()),
		"Check: the listing shows exactly one entry, llmapi-audit, followed by True.")
	s.add("Check what is at the install directory now:",
		"if (-not (Test-Path -LiteralPath "+p.install+")) { \"absent\" } elseif ((Get-Item -Force -LiteralPath "+p.install+").Attributes -band [IO.FileAttributes]::ReparsePoint) { \"foreign\"; Get-ChildItem -Force -LiteralPath "+p.install+" } elseif (Test-Path -PathType Leaf -LiteralPath "+quote(p.shown+`\scripts\`+platform.BinaryName())+") { \"previous-install\" } else { \"foreign\"; Get-ChildItem -Force -LiteralPath "+p.install+" }",
		"- absent: nothing is there; continue with the next step.",
		"- previous-install: it is an earlier install of this Skill (it contains scripts\\"+platform.BinaryName()+"). Remove that directory, and only it:",
		"  Remove-Item -LiteralPath "+p.install+" -Recurse -Force",
		"- foreign: something else is there. Stop. Delete nothing, and show the user the listing so they can decide what to do.")
	s.add("Move the extracted Skill into place (the skills directory is created if it does not exist; nothing else in it is touched):",
		"if (Test-Path -LiteralPath "+p.install+") { throw \"the install directory still exists\" }; New-Item -ItemType Directory -Force -Path "+p.skills+" | Out-Null; Move-Item -LiteralPath "+extracted+" -Destination "+p.install,
		"Check: the command reports no error.")
	s.add("Remove the work directory:",
		"Remove-Item -LiteralPath "+p.work+" -Recurse -Force")
	s.add("Check that the client runs on this machine:",
		"& "+p.binary+" --help",
		"Check: it prints the usage of llmaudit and reports no error.")
	loginStep(s, server, "& "+p.binary)
	s.add("Verify the login:",
		"& "+p.binary+" whoami",
		`Check: the output is one JSON object with "ok":true. Note data.role, data.tier and data.expires_at for your report.`)
	footer(&builder, info, p)
	return builder.String()
}

func loginStep(s *steps, server, binary string) {
	s.add("Log in. The user authorizes this machine in the browser:",
		binary+` login --server "`+server+`"`,
		"The command opens the server's authorization page in the browser and waits up to 5 minutes while the user signs in there and approves. It never asks for a password, an API key or a token, and you must not ask the user for any of them.",
		"If your environment cannot open a browser or cannot keep a command running that long, ask the user to run this exact command themselves in a terminal and to tell you when it has finished. Adding --no-browser makes it print an address the user can open in any browser; the page then shows a one-time code that the user types into the terminal themselves.",
		"Check: the command exits successfully. If it reports LOGIN_TIMEOUT or LOGIN_DENIED, stop and tell the user.")
}
