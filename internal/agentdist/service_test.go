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

// TestFullDownloadTrackerNeverDropsALiveLink (contract section 0.1 items 141
// and 165): with the counter full of live links, a link it does not track
// yet is refused with RATE_LIMITED and a Retry-After no longer than the time
// until the soonest entry expires; a link it already tracks keeps its count
// up to the cap; entries of expired links make room, and as soon as one
// entry expires a fresh link is served again.
func TestFullDownloadTrackerNeverDropsALiveLink(t *testing.T) {
	service, clk, _, manifest := newTestService(t)
	file := manifest.Packages[0].File
	tracked, _ := service.signer.Mint()
	if recorder, _ := download(service, tracked, file); recorder.Code != http.StatusOK {
		t.Fatalf("first download: status %d", recorder.Code)
	}
	// Full of live entries; the soonest expires in 90 seconds.
	service.mu.Lock()
	for index := len(service.downloads); index < maxTrackedLinks; index++ {
		expires := clk.now.Add(LinkLifetime)
		if index == 1 {
			expires = clk.now.Add(90 * time.Second)
		}
		service.downloads[fmt.Sprintf("filler-%d", index)] = &linkUse{count: 1, expires: expires}
	}
	service.mu.Unlock()
	fresh, _ := service.signer.Mint()
	recorder, result := download(service, fresh, file)
	if recorder.Code != http.StatusTooManyRequests || result.Code != agentapi.CodeRateLimited || result.Served {
		t.Fatalf("fresh link with a full tracker: %d %s", recorder.Code, recorder.Body.String())
	}
	if retry, err := strconv.Atoi(recorder.Header().Get("Retry-After")); err != nil || retry < 1 || retry > 90 {
		t.Fatalf("Retry-After = %q, want at most the 90 seconds until the soonest entry expires", recorder.Header().Get("Retry-After"))
	}
	service.mu.Lock()
	if len(service.downloads) != maxTrackedLinks || service.downloads["filler-1"] == nil {
		t.Fatalf("a refused link changed the tracker: %d entries", len(service.downloads))
	}
	service.mu.Unlock()
	// The tracked link keeps its count and its cap.
	for attempt := 2; attempt <= DownloadsPerLink; attempt++ {
		if recorder, _ := download(service, tracked, file); recorder.Code != http.StatusOK {
			t.Fatalf("download %d of the tracked link: status %d", attempt, recorder.Code)
		}
	}
	if recorder, _ := download(service, tracked, file); recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("download %d of the tracked link: status %d", DownloadsPerLink+1, recorder.Code)
	}
	// As soon as the soonest entry expires, the fresh link is served.
	clk.advance(90 * time.Second)
	if recorder, _ := download(service, fresh, file); recorder.Code != http.StatusOK {
		t.Fatalf("fresh link after one entry expired: status %d %s", recorder.Code, recorder.Body.String())
	}
	service.mu.Lock()
	if len(service.downloads) != maxTrackedLinks {
		t.Fatalf("tracker holds %d entries", len(service.downloads))
	}
	service.mu.Unlock()
	// Entries of links that have expired make room before anything else.
	clk.advance(LinkLifetime)
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

// TestFullDownloadTrackerKeepsEveryLinkAtItsCap is the reviewer's case: two
// links that expire first, drained, then more than maxTrackedLinks other live
// links each downloaded once, then the first two drained again and again.
// Neither ever gets more than DownloadsPerLink downloads, and a link that is
// refused because the tracker is full is served once an entry expires.
func TestFullDownloadTrackerKeepsEveryLinkAtItsCap(t *testing.T) {
	service, clk, _, manifest := newTestService(t)
	file := manifest.Packages[0].File
	drain := func(signature string) int {
		served := 0
		for served < 1000 {
			if recorder, _ := download(service, signature, file); recorder.Code != http.StatusOK {
				break
			}
			served++
		}
		return served
	}
	first, _ := service.signer.Mint()
	clk.advance(time.Second)
	second, _ := service.signer.Mint()
	clk.advance(time.Second)
	served := map[string]int{first: drain(first), second: drain(second)}
	refused := ""
	for index := 0; index < maxTrackedLinks; index++ {
		other, _ := service.signer.Mint()
		if recorder, _ := download(service, other, file); recorder.Code != http.StatusOK {
			refused = other
		}
	}
	if refused == "" {
		t.Fatal("no fresh link was refused although the tracker was full")
	}
	for cycle := 0; cycle < 10; cycle++ {
		served[first] += drain(first)
		served[second] += drain(second)
	}
	if served[first] != DownloadsPerLink || served[second] != DownloadsPerLink {
		t.Fatalf("served %d and %d downloads, cap %d", served[first], served[second], DownloadsPerLink)
	}
	service.mu.Lock()
	if len(service.downloads) > maxTrackedLinks {
		t.Fatalf("tracker grew to %d", len(service.downloads))
	}
	service.mu.Unlock()
	// The first link expires; the refused one is then served.
	clk.advance(LinkLifetime - 2*time.Second)
	if recorder, _ := download(service, refused, file); recorder.Code != http.StatusOK {
		t.Fatalf("refused link after the first entry expired: %d", recorder.Code)
	}
}

// TestCheckInstallLinkMatchesInstallLink: CheckInstallLink refuses exactly
// what InstallLink refuses, with the same error, and mints nothing.
func TestCheckInstallLinkMatchesInstallLink(t *testing.T) {
	service, _, _, _ := newTestService(t)
	cases := []struct {
		server  string
		request InstallLinkRequest
	}{
		{"https://audit.example.com", InstallLinkRequest{Agent: AgentCodex, Platform: "linux-amd64"}},
		{"https://audit.example.com", InstallLinkRequest{Agent: "copilot", Platform: "linux-amd64"}},
		{"https://audit.example.com", InstallLinkRequest{Agent: AgentCodex, Platform: "linux-386"}},
		{"https://audit.example.com", InstallLinkRequest{Agent: AgentOther, Platform: "linux-amd64"}},
		{"https://audit.example.com", InstallLinkRequest{Agent: AgentOther, Platform: "linux-amd64", SkillsDir: "relative"}},
		{"https://audit.example.com", InstallLinkRequest{Agent: AgentOther, Platform: "windows-amd64", SkillsDir: `C:\Tools\skills`}},
		{"https://audit.example.com/$(x)", InstallLinkRequest{Agent: AgentCodex, Platform: "linux-amd64"}},
		// A server address within the 2048 characters of cleanServerURL that
		// leaves no room for the signed link in the prompt (contract section
		// 0.1 item 143).
		{"http://" + strings.Repeat("a", 1990) + ".example", InstallLinkRequest{Agent: AgentCodex, Platform: "linux-amd64"}},
	}
	// The order of the checks is InstallLink's: without packages a bad
	// skills_dir is still answered as no packages, as before.
	empty, err := New(Options{PackageDir: filepath.Join(t.TempDir(), "missing"), AdminToken: testAdminToken})
	if err != nil {
		t.Fatal(err)
	}
	if err := empty.CheckInstallLink("https://audit.example.com", InstallLinkRequest{Agent: AgentOther, Platform: "linux-amd64", SkillsDir: "relative"}); !errors.Is(err, ErrNoPackages) {
		t.Fatalf("no packages and a bad skills_dir: %v, want ErrNoPackages", err)
	}
	for _, tc := range cases {
		checked := service.CheckInstallLink(tc.server, tc.request)
		_, issued := service.InstallLink(tc.server, tc.request)
		if (checked == nil) != (issued == nil) || (checked != nil && checked.Error() != issued.Error()) {
			t.Errorf("%+v at %s: CheckInstallLink %v, InstallLink %v", tc.request, tc.server, checked, issued)
		}
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
