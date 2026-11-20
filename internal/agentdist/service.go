package agentdist

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"llmapi-logger/internal/agentapi"
)

// PackageDirName is the package directory's name next to the server binary.
// In the container image the binary is /audit-proxy, so the packages live in
// /agent-packages; scripts/build.* write bin/agent-packages next to the
// binaries they build.
const PackageDirName = "agent-packages"

// DownloadsPerLink is how many downloads one signed link allows over its
// lifetime (contract section 7).
const DownloadsPerLink = 30

// maxTrackedLinks bounds the download counter. Only links that verify are
// counted, keyed by their nonce, and only authenticated users can mint them,
// so this is a guard against a runaway client rather than against forgery.
// A full counter only drops the entries of expired links; a link it does not
// track yet then waits (contract section 0.1 items 141 and 165).
const maxTrackedLinks = 4096

// ErrNoPackages means the package directory holds no usable packages: they
// were not built, the manifest is invalid, or a file does not match it.
// LoadError says which.
var ErrNoPackages = errors.New("agentdist: no agent packages are available on this server")

// DefaultPackageDir is the agent-packages directory next to the running
// executable.
func DefaultPackageDir() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(executable); err == nil {
		executable = resolved
	}
	return filepath.Join(filepath.Dir(executable), PackageDirName), nil
}

// Options configures a Service.
type Options struct {
	// PackageDir holds manifest.json and the archives it lists. Empty means
	// DefaultPackageDir.
	PackageDir string
	// AdminToken derives the link-signing key; it must not be empty.
	AdminToken string
	// Now is the clock of the signer and the download counter; nil is
	// time.Now.
	Now func() time.Time
}

// Service is the distribution side of agent access: it mints install links
// with their prompt and serves the signed downloads. It is safe for
// concurrent use. The package directory is read once, in New: the packages
// are built into the image and never change while the process runs.
type Service struct {
	root     string
	signer   *Signer
	now      func() time.Time
	manifest *Manifest
	loadErr  error

	mu        sync.Mutex
	downloads map[string]*linkUse
	// issued counts install links per web session identity.
	issued map[string]*linkUse
}

// Install links one web session identity may request per window (contract
// section 7). Only a request that issues a link counts: one refused for its
// arguments (CheckInstallLink) or for the limit itself is not counted.
const (
	InstallLinksPerWindow = 20
	InstallLinkWindow     = 10 * time.Minute
)

// AllowInstallLink counts one install-link request for key (the web session
// identity) in a fixed window that starts at its first request, and reports
// how long to wait when the window is full; a refused request is not
// counted. Expired windows are dropped on the way, and at most
// maxTrackedLinks identities are tracked (a new one beyond that waits for
// the oldest window).
func (service *Service) AllowInstallLink(key string) (bool, time.Duration) {
	now := service.now()
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.issued == nil {
		service.issued = map[string]*linkUse{}
	}
	var soonest time.Time
	for tracked, use := range service.issued {
		if !now.Before(use.expires) {
			delete(service.issued, tracked)
		} else if soonest.IsZero() || use.expires.Before(soonest) {
			soonest = use.expires
		}
	}
	use := service.issued[key]
	if use == nil {
		if len(service.issued) >= maxTrackedLinks {
			return false, soonest.Sub(now)
		}
		use = &linkUse{expires: now.Add(InstallLinkWindow)}
		service.issued[key] = use
	}
	if use.count >= InstallLinksPerWindow {
		return false, use.expires.Sub(now)
	}
	use.count++
	return true, 0
}

type linkUse struct {
	count   int
	expires time.Time
}

// New builds the service. Only a missing admin token is an error: a missing
// or broken package directory leaves the service without packages (every
// download is not found and InstallLink reports ErrNoPackages), and
// LoadError says why, so that an optional feature never stops the server.
func New(options Options) (*Service, error) {
	now := options.Now
	if now == nil {
		now = time.Now
	}
	signer, err := NewSigner(options.AdminToken, now)
	if err != nil {
		return nil, err
	}
	dir := options.PackageDir
	if dir == "" {
		dir, err = DefaultPackageDir()
		if err != nil {
			return nil, fmt.Errorf("agentdist: cannot locate the package directory: %w", err)
		}
	}
	service := &Service{root: dir, signer: signer, now: now, downloads: map[string]*linkUse{}}
	service.manifest, service.loadErr = loadPackages(dir)
	return service, nil
}

// PackageDir is the directory the service reads.
func (service *Service) PackageDir() string { return service.root }

// LoadError is nil when packages are available, otherwise an error wrapping
// ErrNoPackages that says what is wrong (safe to log; it holds no secret).
func (service *Service) LoadError() error { return service.loadErr }

// Manifest returns a copy of the loaded manifest, or ErrNoPackages.
func (service *Service) Manifest() (Manifest, error) {
	if service.manifest == nil {
		return Manifest{}, service.loadErr
	}
	copied := *service.manifest
	copied.Packages = append([]Package(nil), service.manifest.Packages...)
	return copied, nil
}

// loadPackages reads and validates the manifest and checks every archive's
// size and SHA-256 against it, all through an os.Root so nothing outside dir
// is opened. The manifest version must be the version this server's client
// is (agentapi.LatestVersion): stale packages are not served.
func loadPackages(dir string) (*Manifest, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s does not exist (packages were not built)", ErrNoPackages, PackageDirName)
		}
		return nil, fmt.Errorf("%w: cannot open the package directory", ErrNoPackages)
	}
	defer root.Close()
	data, err := readLimited(root, ManifestFile, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read %s", ErrNoPackages, ManifestFile)
	}
	manifest, err := ParseManifest(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoPackages, err)
	}
	if manifest.Version != agentapi.LatestVersion || manifest.MinCompatible != agentapi.MinVersion {
		return nil, fmt.Errorf("%w: packages are version %s (min %s), the server expects %s (min %s)",
			ErrNoPackages, manifest.Version, manifest.MinCompatible, agentapi.LatestVersion, agentapi.MinVersion)
	}
	for _, pkg := range manifest.Packages {
		size, digest, err := digestFile(root, pkg.File)
		if err != nil {
			return nil, fmt.Errorf("%w: cannot read %s", ErrNoPackages, pkg.File)
		}
		if size != pkg.Size || digest != pkg.SHA256 {
			return nil, fmt.Errorf("%w: %s does not match the manifest", ErrNoPackages, pkg.File)
		}
	}
	return manifest, nil
}

func readLimited(root *os.Root, name string, limit int64) ([]byte, error) {
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("file too large")
	}
	return data, nil
}

func digestFile(root *os.Root, name string) (int64, string, error) {
	file, err := root.Open(name)
	if err != nil {
		return 0, "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return 0, "", errors.New("not a regular file")
	}
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return 0, "", err
	}
	return size, hex.EncodeToString(hash.Sum(nil)), nil
}

// InstallLinkRequest is the body of POST /api/v1/agent-access/install-links.
type InstallLinkRequest struct {
	// Agent is claude-code, codex, cursor, gemini-cli or other.
	Agent string `json:"agent"`
	// Platform is <os>-<arch>: windows-amd64, linux-amd64, linux-arm64,
	// darwin-arm64 or darwin-amd64.
	Platform string `json:"platform"`
	// SkillsDir optionally replaces the agent's default skills directory; it
	// is required for agent other.
	SkillsDir string `json:"skills_dir,omitempty"`
}

// InstallLinkResponse is the response of the same endpoint.
type InstallLinkResponse struct {
	Prompt    string `json:"prompt"`
	ExpiresAt string `json:"expires_at"`
	// File is the package the prompt downloads; for the link_issued audit row.
	File string `json:"-"`
}

// InstallLink mints a download link and returns the install prompt that
// uses it. serverURL is the base URL the user's agent reaches the management
// plane at: agent_access.public_url, or the address the user is browsing
// when it is empty (the web layer decides). Errors: *InputError for a bad
// agent, platform or skills_dir (answer 400 with its Field), ErrNoPackages
// when packages are not available, any other error for a server URL that
// cannot be put into a shell command.
func (service *Service) InstallLink(serverURL string, request InstallLinkRequest) (InstallLinkResponse, error) {
	pkg, server, err := service.checkInstallLink(serverURL, request)
	if err != nil {
		return InstallLinkResponse{}, err
	}
	signature, expires := service.signer.Mint()
	prompt, err := InstallPrompt(PromptInput{
		ServerURL:  server,
		LinkPrefix: LinkPrefix(server, signature),
		Package:    pkg,
		Version:    service.manifest.Version,
		Agent:      request.Agent,
		SkillsDir:  request.SkillsDir,
		ExpiresAt:  expires,
	})
	if err != nil {
		return InstallLinkResponse{}, err
	}
	return InstallLinkResponse{Prompt: prompt, ExpiresAt: expires.Format(time.RFC3339), File: pkg.File}, nil
}

// CheckInstallLink answers what InstallLink would answer for this input,
// with the same errors, but mints nothing. The web layer calls it before it
// counts the request, so that only a request that issues a link uses the
// install-link budget.
func (service *Service) CheckInstallLink(serverURL string, request InstallLinkRequest) error {
	_, _, err := service.checkInstallLink(serverURL, request)
	return err
}

func (service *Service) checkInstallLink(serverURL string, request InstallLinkRequest) (Package, string, error) {
	info, ok := agents[request.Agent]
	if !ok {
		return Package{}, "", &InputError{Field: "agent", Message: "agent must be one of claude-code, codex, cursor, gemini-cli, other"}
	}
	platform, ok := ParsePlatform(request.Platform)
	if !ok {
		return Package{}, "", &InputError{Field: "platform", Message: "platform must be one of " + platformList()}
	}
	if service.manifest == nil {
		return Package{}, "", service.loadErr
	}
	pkg, ok := service.manifest.Find(platform)
	if !ok {
		return Package{}, "", fmt.Errorf("%w: no package for %s", ErrNoPackages, platform)
	}
	server, err := cleanServerURL(serverURL)
	if err != nil {
		return Package{}, "", err
	}
	// skills_dir last, where InstallPrompt checked it before, so every
	// request is answered as it was.
	switch {
	case request.SkillsDir != "":
		if _, err := cleanSkillsDir(request.SkillsDir, platform); err != nil {
			return Package{}, "", err
		}
	case info.SkillsDir == "":
		return Package{}, "", &InputError{Field: "skills_dir", Message: "skills_dir is required for agent other: give the absolute path of the directory your agent loads skills from"}
	}
	return pkg, server, nil
}

// LinkPrefix is the signed link without the file name.
func LinkPrefix(serverURL, signature string) string {
	return strings.TrimRight(serverURL, "/") + agentapi.PathPrefix + "/dl/" + signature + "/"
}

// DownloadResult says what ServeDownload answered, for the package_downloaded
// audit row and logs. File is empty when the request named no listed file.
type DownloadResult struct {
	Status int
	Code   agentapi.Code // empty when the file was served
	File   string
	Served bool
}

// ServeDownload answers GET /api/agent/v1/dl/<signature>/<file> with the
// signature and file name the dispatcher already split out of the path. It
// writes the whole response:
//
//   - signature that does not verify, a file name outside [A-Za-z0-9._-], a
//     file that is neither manifest.json nor listed in it, or no packages on
//     this server: 404 NOT_FOUND, all alike;
//   - a correctly signed but expired link: 410 LINK_EXPIRED;
//   - more than DownloadsPerLink downloads with one link: 429 RATE_LIMITED
//     with Retry-After until the link expires;
//   - a link not counted yet while maxTrackedLinks live links are counted:
//     429 RATE_LIMITED with Retry-After until the soonest of them expires;
//   - otherwise 200 with the file.
//
// Files are opened through an os.Root of the package directory, so a path
// can never leave it even if the checks above had a gap. The caller has
// already answered FEATURE_DISABLED when agent access is off.
func (service *Service) ServeDownload(writer http.ResponseWriter, request *http.Request, signature, file string) DownloadResult {
	link, err := service.signer.VerifyLink(signature)
	expires := link.Expires
	switch {
	case errors.Is(err, ErrLinkExpired):
		return writeDownloadFailure(writer, agentapi.HTTPStatus(agentapi.CodeLinkExpired), agentapi.CodeLinkExpired,
			"this download link has expired",
			"Ask the user to generate a new install prompt on the Agent access page of the web UI.",
			nil, "")
	case err != nil:
		return notFound(writer)
	}
	if !ValidFileName(file) || service.manifest == nil || !service.manifest.Lists(file) {
		return notFound(writer)
	}
	switch outcome, wait := service.allowDownload(link.Nonce, expires); outcome {
	case downloadAllowed:
	case downloadTrackerFull:
		writer.Header().Set("Retry-After", retryAfterSeconds(wait))
		return writeDownloadFailure(writer, http.StatusTooManyRequests, agentapi.CodeRateLimited,
			"too many download links are in use on this server right now", "Wait for the number of seconds in Retry-After and download again with the same link.", nil, file)
	default:
		writer.Header().Set("Retry-After", retryAfterSeconds(wait+time.Second))
		return writeDownloadFailure(writer, http.StatusTooManyRequests, agentapi.CodeRateLimited,
			"this download link has been used too many times", "Ask the user to generate a new install prompt on the Agent access page of the web UI.", nil, file)
	}
	root, err := os.OpenRoot(service.root)
	if err != nil {
		return notFound(writer)
	}
	defer root.Close()
	handle, err := root.Open(file)
	if err != nil {
		return notFound(writer)
	}
	defer handle.Close()
	info, err := handle.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return notFound(writer)
	}
	header := writer.Header()
	if file == ManifestFile {
		header.Set("Content-Type", "application/json; charset=utf-8")
	} else {
		header.Set("Content-Type", "application/zip")
		header.Set("Content-Disposition", `attachment; filename="`+file+`"`)
	}
	header.Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	header.Set("Cache-Control", "no-store")
	header.Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	if request.Method != http.MethodHead {
		_, _ = io.Copy(writer, handle)
	}
	return DownloadResult{Status: http.StatusOK, File: file, Served: true}
}

func notFound(writer http.ResponseWriter) DownloadResult {
	return writeDownloadFailure(writer, http.StatusNotFound, agentapi.CodeNotFound, "not found",
		"Check that the whole link was copied; if it still fails, ask the user to generate a new install prompt on the Agent access page.", nil, "")
}

func writeDownloadFailure(writer http.ResponseWriter, status int, code agentapi.Code, message, hint string, details map[string]any, file string) DownloadResult {
	body, _ := json.Marshal(agentapi.Failure(code, message, hint, details))
	header := writer.Header()
	header.Set("Content-Type", "application/json; charset=utf-8")
	header.Set("Cache-Control", "no-store")
	header.Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(body, '\n'))
	return DownloadResult{Status: status, Code: code, File: file}
}

// The answers of allowDownload.
const (
	downloadAllowed = iota
	downloadLinkUsedUp
	downloadTrackerFull
)

// allowDownload counts one download for a verified link, keyed by its nonce
// (the decoded, verified payload), so that no re-spelling of the request can
// open a second budget. Entries of expired links are dropped on the way, and
// only those: a live link keeps its count until it expires, so no link ever
// gets more than DownloadsPerLink downloads. When the tracker is still full,
// a link it does not track yet is refused (downloadTrackerFull) until the
// soonest entry expires; wait is that time. That needs more than
// maxTrackedLinks links, each downloaded at least once, within one link
// lifetime, and only signed-in web sessions can issue links (20 per 10
// minutes per identity). For a link that is used up, wait is the time until
// it expires.
func (service *Service) allowDownload(nonce string, expires time.Time) (int, time.Duration) {
	now := service.now()
	service.mu.Lock()
	defer service.mu.Unlock()
	var soonest time.Time
	for key, use := range service.downloads {
		if !now.Before(use.expires) {
			delete(service.downloads, key)
		} else if soonest.IsZero() || use.expires.Before(soonest) {
			soonest = use.expires
		}
	}
	use := service.downloads[nonce]
	if use == nil {
		if len(service.downloads) >= maxTrackedLinks {
			return downloadTrackerFull, soonest.Sub(now)
		}
		use = &linkUse{expires: expires}
		service.downloads[nonce] = use
	}
	if use.count >= DownloadsPerLink {
		return downloadLinkUsedUp, expires.Sub(now)
	}
	use.count++
	return downloadAllowed, 0
}

// retryAfterSeconds is wait in whole seconds, rounded down so it is never
// longer than wait, and at least one.
func retryAfterSeconds(wait time.Duration) string {
	seconds := int(wait / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return strconv.Itoa(seconds)
}
