package agentdist

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

// TestLinksMintedInOneSecondHaveSeparateBudgets: two install prompts minted
// in the same second carry different links, and using up one link's 30
// downloads leaves the other's untouched.
func TestLinksMintedInOneSecondHaveSeparateBudgets(t *testing.T) {
	dir, _ := packedDir(t)
	c := newClock()
	service, err := New(Options{PackageDir: dir, AdminToken: testAdminToken, Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.InstallLink("https://audit.example.com", InstallLinkRequest{Agent: AgentClaudeCode, Platform: "linux-amd64"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.InstallLink("https://audit.example.com", InstallLinkRequest{Agent: AgentClaudeCode, Platform: "linux-amd64"})
	if err != nil {
		t.Fatal(err)
	}
	signatureOf := func(prompt string) string {
		marker := "/api/agent/v1/dl/"
		start := strings.Index(prompt, marker)
		if start < 0 {
			t.Fatal("no link in the prompt")
		}
		rest := prompt[start+len(marker):]
		return rest[:strings.IndexByte(rest, '/')]
	}
	one, two := signatureOf(first.Prompt), signatureOf(second.Prompt)
	if one == two || first.ExpiresAt != second.ExpiresAt {
		t.Fatalf("links of one second: %s and %s", one, two)
	}
	for index := 0; index < DownloadsPerLink; index++ {
		if result := service.ServeDownload(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), one, first.File); result.Status != http.StatusOK {
			t.Fatalf("download %d of the first link = %d", index+1, result.Status)
		}
	}
	if result := service.ServeDownload(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), one, first.File); result.Status != http.StatusTooManyRequests {
		t.Fatalf("31st download of the first link = %d", result.Status)
	}
	if result := service.ServeDownload(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), two, second.File); result.Status != http.StatusOK {
		t.Fatalf("first download of the second link after the first's 30 = %d %s", result.Status, result.Code)
	}
}

// TestDownloadBudgetIsKeptPerNonce: the counter is keyed by the verified
// nonce, not by the request's spelling, and re-spellings of a link are
// refused without creating an entry.
func TestDownloadBudgetIsKeptPerNonce(t *testing.T) {
	service, _, _, manifest := newTestService(t)
	file := manifest.Packages[0].File
	signature, _ := service.signer.Mint()
	link, err := service.signer.VerifyLink(signature)
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{signature[:9] + "\n" + signature[9:], signature + "\r\n", "\r" + signature, signature + "="} {
		if recorder, _ := download(service, variant, file); recorder.Code != http.StatusNotFound {
			t.Fatalf("re-spelling %q: status %d", variant, recorder.Code)
		}
	}
	if recorder, _ := download(service, signature, file); recorder.Code != http.StatusOK {
		t.Fatalf("canonical: status %d", recorder.Code)
	}
	service.mu.Lock()
	use, tracked := service.downloads[link.Nonce], len(service.downloads)
	service.mu.Unlock()
	if tracked != 1 || use == nil || use.count != 1 {
		t.Fatalf("tracker has %d entries, nonce entry %+v", tracked, use)
	}
}

// TestFullDownloadTrackerDoesNotRefuseFreshLinks: with the counter full of
// live links, a fresh link is still served; entries of expired links go
// first, then the entry that expires first.
func TestFullDownloadTrackerDoesNotRefuseFreshLinks(t *testing.T) {
	service, clk, _, manifest := newTestService(t)
	file := manifest.Packages[0].File
	fill := func(expires time.Time) {
		service.mu.Lock()
		defer service.mu.Unlock()
		for index := len(service.downloads); index < maxTrackedLinks; index++ {
			service.downloads[fmt.Sprintf("filler-%d", index)] = &linkUse{count: 1, expires: expires}
		}
	}
	// Full of live entries that all outlive the fresh link's minting.
	fill(clk.now.Add(LinkLifetime))
	fresh, _ := service.signer.Mint()
	if recorder, _ := download(service, fresh, file); recorder.Code != http.StatusOK {
		t.Fatalf("fresh link with a full tracker: status %d %s", recorder.Code, recorder.Body.String())
	}
	service.mu.Lock()
	if len(service.downloads) > maxTrackedLinks {
		t.Fatalf("tracker grew to %d", len(service.downloads))
	}
	service.mu.Unlock()
	// The fresh link keeps its own budget while others are added.
	for attempt := 2; attempt <= DownloadsPerLink; attempt++ {
		if recorder, _ := download(service, fresh, file); recorder.Code != http.StatusOK {
			t.Fatalf("download %d of the fresh link: status %d", attempt, recorder.Code)
		}
	}
	if recorder, _ := download(service, fresh, file); recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("download %d of the fresh link: status %d", DownloadsPerLink+1, recorder.Code)
	}
	// Entries of links that have expired make room before any live one.
	clk.advance(LinkLifetime + time.Second)
	service.mu.Lock()
	service.downloads = map[string]*linkUse{}
	service.mu.Unlock()
	fill(clk.now.Add(-time.Second))
	live, _ := service.signer.Mint()
	if recorder, _ := download(service, live, file); recorder.Code != http.StatusOK {
		t.Fatalf("live link with a tracker full of expired entries: status %d", recorder.Code)
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if len(service.downloads) != 1 {
		t.Fatalf("expired entries were kept: %d tracked", len(service.downloads))
	}
}

// TestConcurrentDownloadsRespectCap: 100 concurrent downloads with one link,
// exactly DownloadsPerLink succeed and the rest are refused.
func TestConcurrentDownloadsRespectCap(t *testing.T) {
	dir, manifest := packedDir(t)
	c := newClock()
	service, err := New(Options{PackageDir: dir, AdminToken: testAdminToken, Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	signature, _ := service.signer.Mint()
	file := manifest.Packages[0].File
	var ok, limited atomic.Int64
	var wait sync.WaitGroup
	for index := 0; index < 100; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			request := httptest.NewRequest(http.MethodGet, "/api/agent/v1/dl/"+signature+"/"+file, nil)
			switch service.ServeDownload(httptest.NewRecorder(), request, signature, file).Status {
			case http.StatusOK:
				ok.Add(1)
			case http.StatusTooManyRequests:
				limited.Add(1)
			}
		}()
	}
	wait.Wait()
	if ok.Load() != DownloadsPerLink || limited.Load() != 100-DownloadsPerLink {
		t.Fatalf("200: %d, 429: %d", ok.Load(), limited.Load())
	}
}
