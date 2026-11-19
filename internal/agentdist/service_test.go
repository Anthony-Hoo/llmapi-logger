package agentdist

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/agentapi"
)

func newTestService(t *testing.T) (*Service, *clock, string, *Manifest) {
	t.Helper()
	dir, manifest := packedDir(t)
	clk := newClock()
	service, err := New(Options{PackageDir: dir, AdminToken: testAdminToken, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	if service.LoadError() != nil {
		t.Fatalf("packages not loaded: %v", service.LoadError())
	}
	return service, clk, dir, manifest
}

func download(service *Service, signature, file string) (*httptest.ResponseRecorder, DownloadResult) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/agent/v1/dl/x/y", nil)
	result := service.ServeDownload(recorder, request, signature, file)
	return recorder, result
}

func failureOf(t *testing.T, recorder *httptest.ResponseRecorder) agentapi.ErrorBody {
	t.Helper()
	var envelope agentapi.ErrorEnvelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil || envelope.OK {
		t.Fatalf("body is not a failure envelope: %q", recorder.Body.String())
	}
	return envelope.Error
}

func TestServeDownloadServesListedFiles(t *testing.T) {
	service, _, dir, manifest := newTestService(t)
	signature, _ := service.signer.Mint()
	for _, pkg := range manifest.Packages {
		recorder, result := download(service, signature, pkg.File)
		if recorder.Code != http.StatusOK || !result.Served || result.File != pkg.File {
			t.Fatalf("%s: status %d, result %+v", pkg.File, recorder.Code, result)
		}
		want, _ := os.ReadFile(filepath.Join(dir, pkg.File))
		if recorder.Body.String() != string(want) {
			t.Fatalf("%s: body differs from the file", pkg.File)
		}
		if recorder.Header().Get("Content-Type") != "application/zip" || recorder.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: headers %v", pkg.File, recorder.Header())
		}
	}
	recorder, result := download(service, signature, ManifestFile)
	if recorder.Code != http.StatusOK || !result.Served {
		t.Fatalf("manifest: status %d", recorder.Code)
	}
	if _, err := ParseManifest(recorder.Body.Bytes()); err != nil {
		t.Fatalf("served manifest does not parse: %v", err)
	}
}

func TestServeDownloadBadSignatureIsNotFound(t *testing.T) {
	service, clk, _, manifest := newTestService(t)
	file := manifest.Packages[0].File
	other, _ := NewSigner("another-admin-token", clk.Now)
	foreign, _ := other.Mint()
	good, _ := service.signer.Mint()
	for name, signature := range map[string]string{
		"empty":       "",
		"garbage":     "abc",
		"other key":   foreign,
		"truncated":   good[:len(good)-2],
		"appended":    good + "A",
		"uppercased":  strings.ToUpper(good),
		"with slash":  good + "/x",
		"with dotdot": "..",
	} {
		recorder, result := download(service, signature, file)
		if recorder.Code != http.StatusNotFound || result.Served || failureOf(t, recorder).Code != agentapi.CodeNotFound {
			t.Errorf("%s: status %d, body %q", name, recorder.Code, recorder.Body.String())
		}
	}
	// An expired link under a foreign key is still just not found.
	clk.advance(time.Hour)
	if recorder, _ := download(service, foreign, file); recorder.Code != http.StatusNotFound {
		t.Fatalf("expired foreign signature: status %d", recorder.Code)
	}
}

func TestServeDownloadExpiredIsGone(t *testing.T) {
	service, clk, _, manifest := newTestService(t)
	signature, _ := service.signer.Mint()
	clk.advance(LinkLifetime)
	recorder, result := download(service, signature, manifest.Packages[0].File)
	if recorder.Code != http.StatusGone || result.Served {
		t.Fatalf("status %d, want 410", recorder.Code)
	}
	body := failureOf(t, recorder)
	if body.Code != agentapi.CodeLinkExpired || !strings.Contains(body.Hint, "Agent access page") {
		t.Fatalf("expired body %+v", body)
	}
}

func TestServeDownloadRefusesUnlistedAndTraversal(t *testing.T) {
	service, _, dir, _ := newTestService(t)
	// A file that exists in the directory but is not in the manifest.
	writeTestFile(t, filepath.Join(dir, "extra.zip"), "not listed")
	writeTestFile(t, filepath.Join(filepath.Dir(dir), "outside.zip"), "outside")
	signature, _ := service.signer.Mint()
	for _, file := range []string{
		"extra.zip", "outside.zip", "../outside.zip", "..", ".", "", "/etc/passwd", `C:\Windows\win.ini`,
		`..\outside.zip`, "a/b", "%2e%2e", "manifest.json/", "./manifest.json", "MANIFEST.JSON",
		".agentpack-x", "manifest.json\x00", "llmapi-audit-" + agentapi.LatestVersion + "-plan9-amd64.zip",
	} {
		recorder, result := download(service, signature, file)
		if recorder.Code != http.StatusNotFound || result.Served {
			t.Errorf("%q: status %d", file, recorder.Code)
		}
	}
}

func TestServeDownloadCounterPerLink(t *testing.T) {
	service, clk, _, manifest := newTestService(t)
	file := manifest.Packages[0].File
	signature, expires := service.signer.Mint()
	for attempt := 1; attempt <= DownloadsPerLink; attempt++ {
		if recorder, _ := download(service, signature, file); recorder.Code != http.StatusOK {
			t.Fatalf("download %d: status %d", attempt, recorder.Code)
		}
	}
	clk.advance(10 * time.Minute)
	recorder, result := download(service, signature, ManifestFile)
	if recorder.Code != http.StatusTooManyRequests || result.Code != agentapi.CodeRateLimited {
		t.Fatalf("download %d: status %d", DownloadsPerLink+1, recorder.Code)
	}
	wantRetry := int(expires.Sub(clk.now).Seconds()) + 1
	if got := recorder.Header().Get("Retry-After"); got != strconv.Itoa(wantRetry) {
		t.Fatalf("Retry-After %q, want %d", got, wantRetry)
	}
	// Another link has its own budget.
	fresh, _ := service.signer.Mint()
	if recorder, _ := download(service, fresh, file); recorder.Code != http.StatusOK {
		t.Fatalf("fresh link: status %d", recorder.Code)
	}
	// Failed verifications are not counted and do not create entries.
	for attempt := 0; attempt < 100; attempt++ {
		download(service, "bad", file)
	}
	service.mu.Lock()
	tracked := len(service.downloads)
	service.mu.Unlock()
	if tracked != 2 {
		t.Fatalf("tracked %d links, want 2", tracked)
	}
	// Entries of expired links are dropped.
	clk.advance(LinkLifetime)
	download(service, "bad", file)
	newest, _ := service.signer.Mint()
	download(service, newest, file)
	service.mu.Lock()
	tracked = len(service.downloads)
	service.mu.Unlock()
	if tracked != 1 {
		t.Fatalf("tracked %d links after expiry, want 1", tracked)
	}
}

func TestNoPackages(t *testing.T) {
	clk := newClock()
	service, err := New(Options{PackageDir: filepath.Join(t.TempDir(), "missing"), AdminToken: testAdminToken, Now: clk.Now})
	if err != nil {
		t.Fatalf("a missing package directory must not fail New: %v", err)
	}
	if !errors.Is(service.LoadError(), ErrNoPackages) {
		t.Fatalf("LoadError = %v", service.LoadError())
	}
	if _, err := service.Manifest(); !errors.Is(err, ErrNoPackages) {
		t.Fatalf("Manifest error = %v", err)
	}
	signature, _ := service.signer.Mint()
	for _, file := range []string{ManifestFile, PackageFileName(agentapi.LatestVersion, Platforms[0])} {
		if recorder, _ := download(service, signature, file); recorder.Code != http.StatusNotFound {
			t.Fatalf("%s without packages: status %d", file, recorder.Code)
		}
	}
	if _, err := service.InstallLink("https://audit.example.com", InstallLinkRequest{Agent: AgentClaudeCode, Platform: "linux-amd64"}); !errors.Is(err, ErrNoPackages) {
		t.Fatalf("InstallLink without packages: %v", err)
	}
	if _, err := New(Options{PackageDir: t.TempDir(), AdminToken: ""}); err == nil {
		t.Fatal("empty admin token accepted")
	}
}

func TestBrokenPackagesAreNotServed(t *testing.T) {
	cases := map[string]func(t *testing.T, dir string, manifest *Manifest){
		"tampered archive": func(t *testing.T, dir string, manifest *Manifest) {
			path := filepath.Join(dir, manifest.Packages[1].File)
			data, _ := os.ReadFile(path)
			data[len(data)/2] ^= 0xff
			writeTestFile(t, path, string(data))
		},
		"missing archive": func(t *testing.T, dir string, manifest *Manifest) {
			if err := os.Remove(filepath.Join(dir, manifest.Packages[2].File)); err != nil {
				t.Fatal(err)
			}
		},
		"invalid manifest": func(t *testing.T, dir string, _ *Manifest) {
			writeTestFile(t, filepath.Join(dir, ManifestFile), `{"version":"x"}`)
		},
		"stale version": func(t *testing.T, dir string, manifest *Manifest) {
			stale := *manifest
			stale.Version, stale.MinCompatible = "0.0.1", "0.0.1"
			stale.Packages = nil
			for _, pkg := range manifest.Packages {
				pkg.File = PackageFileName("0.0.1", pkg.Platform())
				stale.Packages = append(stale.Packages, pkg)
			}
			encoded, _ := stale.Encode()
			writeTestFile(t, filepath.Join(dir, ManifestFile), string(encoded))
		},
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			dir, manifest := packedDir(t)
			breakIt(t, dir, manifest)
			service, err := New(Options{PackageDir: dir, AdminToken: testAdminToken})
			if err != nil {
				t.Fatal(err)
			}
			if !errors.Is(service.LoadError(), ErrNoPackages) {
				t.Fatalf("LoadError = %v", service.LoadError())
			}
			signature, _ := service.signer.Mint()
			if recorder, _ := download(service, signature, ManifestFile); recorder.Code != http.StatusNotFound {
				t.Fatalf("status %d", recorder.Code)
			}
		})
	}
}

func TestInstallLink(t *testing.T) {
	service, clk, _, manifest := newTestService(t)
	response, err := service.InstallLink("https://audit.example.com/audit/", InstallLinkRequest{Agent: AgentCodex, Platform: "darwin-arm64"})
	if err != nil {
		t.Fatal(err)
	}
	if response.ExpiresAt != clk.now.Add(LinkLifetime).Format(time.RFC3339) {
		t.Fatalf("expires_at %q", response.ExpiresAt)
	}
	pkg, _ := manifest.Find(Platform{OS: "darwin", Arch: "arm64"})
	if response.File != pkg.File {
		t.Fatalf("File %q, want %q", response.File, pkg.File)
	}
	prefix := "https://audit.example.com/audit/api/agent/v1/dl/"
	start := strings.Index(response.Prompt, prefix)
	if start < 0 {
		t.Fatalf("prompt has no link under %s", prefix)
	}
	rest := response.Prompt[start+len(prefix):]
	signature := rest[:strings.IndexByte(rest, '/')]
	if !strings.HasPrefix(rest[len(signature)+1:], pkg.File+`"`) {
		t.Fatal("the link does not name the package file")
	}
	if _, err := service.signer.Verify(signature); err != nil {
		t.Fatalf("the link's signature does not verify: %v", err)
	}
	if recorder, _ := download(service, signature, pkg.File); recorder.Code != http.StatusOK {
		t.Fatalf("downloading through the link: status %d", recorder.Code)
	}

	inputErrors := map[string]InstallLinkRequest{
		"agent":      {Agent: "copilot", Platform: "linux-amd64"},
		"platform":   {Agent: AgentCursor, Platform: "linux-386"},
		"skills_dir": {Agent: AgentOther, Platform: "linux-amd64"},
	}
	for field, request := range inputErrors {
		_, err := service.InstallLink("https://audit.example.com", request)
		var inputErr *InputError
		if !errors.As(err, &inputErr) || inputErr.Field != field {
			t.Errorf("%s: error %v", field, err)
		}
	}
	bad := InstallLinkRequest{Agent: AgentOther, Platform: "linux-amd64", SkillsDir: "relative/skills"}
	if _, err := service.InstallLink("https://audit.example.com", bad); err == nil {
		t.Fatal("a relative skills_dir was accepted")
	}
	for _, server := range []string{"", "ftp://audit.example.com", "https://user@audit.example.com", "https://audit.example.com/?a=b", "https://audit.example.com/#x", `https://audit.example.com/"x`, "https://audit.example.com/$(x)", "https://audit.example.com/a b"} {
		if _, err := service.InstallLink(server, InstallLinkRequest{Agent: AgentCodex, Platform: "linux-amd64"}); err == nil {
			t.Errorf("server URL %q accepted", server)
		}
	}
}

func TestDefaultPackageDir(t *testing.T) {
	dir, err := DefaultPackageDir()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(dir) != PackageDirName || !filepath.IsAbs(dir) {
		t.Fatalf("DefaultPackageDir = %q", dir)
	}
}
