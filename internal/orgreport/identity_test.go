package orgreport

import "testing"

func TestNormalizeRemote(t *testing.T) {
	tests := map[string]string{
		"git@git.example.com:Team/Repo.git":               "git.example.com/team/repo",
		"ssh://git@git.example.com/team/repo":             "git.example.com/team/repo",
		"ssh://git@git.example.com:2222/team/repo.git":    "git.example.com/team/repo",
		"https://user@git.example.com:8443/team/repo.git": "git.example.com/team/repo",
		"https://git.example.com/team/repo/":              "git.example.com/team/repo",
		"http://git.example.com/group/sub/repo.git":       "git.example.com/group/sub/repo",
		"git://git.example.com/team/repo":                 "git.example.com/team/repo",
		"  git@git.example.com:team/repo  ":               "git.example.com/team/repo",
		"C:\\work\\repo":                                  "",
		"C:/work/repo":                                    "",
		"/srv/git/repo.git":                               "",
		"file:///srv/git/repo.git":                        "",
		"":                                                "",
		"https://git.example.com":                         "",
		"git@git.example.com:":                            "",
	}
	for input, want := range tests {
		if got := NormalizeRemote(input); got != want {
			t.Errorf("NormalizeRemote(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNormalizePath(t *testing.T) {
	tests := map[string]string{
		`C:\Users\Dev\Repo\`:  "c:/users/dev/repo",
		`"D:\work\a b"`:       "d:/work/a b",
		"/home/dev//repo/":    "/home/dev/repo",
		"/":                   "/",
		"  ":                  "",
		"/bad\npath":          "",
		`\\server\share\repo`: "//server/share/repo",
	}
	for input, want := range tests {
		if got := NormalizePath(input); got != want {
			t.Errorf("NormalizePath(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestResolveRootAndRepoName(t *testing.T) {
	roots := []string{"/home/dev/repo", "/home/dev/repo/vendor/lib", "/home/dev/repository"}
	tests := map[string]string{
		"/home/dev/repo/pkg":            "/home/dev/repo",
		"/home/dev/repo/vendor/lib/src": "/home/dev/repo/vendor/lib",
		"/home/dev/repository":          "/home/dev/repository",
		"/home/dev/repo-other":          "/home/dev/repo-other",
	}
	for cwd, want := range tests {
		if got := ResolveRoot(cwd, roots); got != want {
			t.Errorf("ResolveRoot(%q) = %q, want %q", cwd, got, want)
		}
	}
	if RepoName("git.example.com/team/repo") != "repo" || RepoName("c:/work/app/") != "app" || RepoName("solo") != "solo" {
		t.Fatal("RepoName")
	}
}

func TestIdentitySourceAndHash(t *testing.T) {
	identity := Identity{Cwd: "/x"}
	identity.Finish()
	if identity.Source != SourceCwd || identity.Empty() || !identity.HasPath() {
		t.Fatalf("identity = %+v", identity)
	}
	identity.AddRoot("/x")
	identity.AddRoot("/x")
	identity.AddRemote("git@git.example.com:a/b.git")
	identity.AddRemote("https://git.example.com/a/b")
	identity.Finish()
	if identity.Source != SourceCodexTurnMetadata || len(identity.Roots) != 1 || len(identity.Remotes) != 1 {
		t.Fatalf("identity = %+v", identity)
	}
	empty := Identity{}
	empty.Finish()
	if empty.Source != SourceNone || !empty.Empty() {
		t.Fatalf("empty = %+v", empty)
	}
	// sha1("git-remote:git.example.com/a/b") computed independently.
	if got := OpenCodeProjectHash("git.example.com/a/b"); len(got) != 40 {
		t.Fatalf("hash = %q", got)
	}
}
