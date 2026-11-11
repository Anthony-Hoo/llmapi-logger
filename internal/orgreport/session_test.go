package orgreport

import (
	"context"
	"testing"
)

func sessionCatalog(t *testing.T) *Compiled {
	t.Helper()
	compiled, err := Compile(Catalog{
		Groups: []Group{{ID: 1, Name: "payments", Enabled: true}},
		Projects: []Project{
			{ID: 10, Name: "orders", Enabled: true, Rules: []Rule{{Kind: RuleRepoURL, Pattern: "git.example.test/acme/orders"}}},
			{ID: 11, Name: "billing", Enabled: true, Rules: []Rule{{Kind: RuleRepoName, Pattern: "billing"}}},
			{ID: 12, Name: "ledger", GroupID: groupID(1), Enabled: true, Rules: []Rule{{Kind: RulePathGlob, Pattern: "/work/ledger/**"}}},
		},
		Members:    []Member{{UserID: 7, GroupID: 1}},
		Principals: []Principal{{Kind: PrincipalToken, ID: 900, Class: ClassService}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

// sessionRequests builds one session's requests in start order; each element
// is the identity key the request carries ("" for none).
func sessionRequests(userID, tokenID int64, keys ...string) []Request {
	requests := make([]Request, 0, len(keys))
	for index, key := range keys {
		requests = append(requests, Request{
			AuditID: string(rune('a' + index)), StartNS: int64(index + 1), UserID: userID, TokenID: tokenID,
			RootKey: "root", NodeKey: "node", IdentityKey: key,
		})
	}
	return requests
}

func TestResolveSessionReducesToOneBooking(t *testing.T) {
	compiled := sessionCatalog(t)
	identities := map[string]Identity{
		"orders":  {Remotes: []string{"git.example.test/acme/orders"}, Roots: []string{"/work/orders"}},
		"billing": {Roots: []string{"/work/billing"}},
		"other":   {Cwd: "/tmp/scratch"},
		"ledger":  {Cwd: "/work/ledger/api"},
	}
	for _, test := range []struct {
		name      string
		requests  []Request
		extracted int
		want      SessionProject
	}{
		{
			name: "the project with most requests wins", requests: sessionRequests(5, 50, "orders", "billing", "billing"), extracted: 3,
			want: SessionProject{Known: true, Project: 11, Name: "billing", Level: LevelRoot},
		},
		{
			name: "a tie goes to the project seen first", requests: sessionRequests(5, 50, "orders", "billing"), extracted: 2,
			want: SessionProject{Known: true, Project: 10, Name: "orders", Level: LevelRemote},
		},
		{
			name: "a matched project beats unmatched requests", requests: sessionRequests(5, 50, "other", "other", "orders"), extracted: 3,
			want: SessionProject{Known: true, Project: 10, Name: "orders", Level: LevelRemote},
		},
		{
			name: "requests without identity inherit their node's", requests: sessionRequests(5, 50, "", "orders", ""), extracted: 1,
			want: SessionProject{Known: true, Project: 10, Name: "orders", Level: LevelRemote},
		},
		{
			name: "a path that matches no rule is unattributed", requests: sessionRequests(5, 50, "other"), extracted: 1,
			want: SessionProject{Known: true, Project: ProjectUnattributed},
		},
		{
			name: "an identity that cannot be opened is unattributed", requests: sessionRequests(5, 50, "sealed"), extracted: 1,
			want: SessionProject{Known: true, Project: ProjectUnattributed},
		},
		{
			name: "no signal on any extracted request is no context", requests: sessionRequests(5, 50, "", ""), extracted: 2,
			want: SessionProject{Known: true, Project: ProjectNoContext},
		},
		{
			name: "no signal with requests still to extract is unknown", requests: sessionRequests(5, 50, "", ""), extracted: 1,
			want: SessionProject{Known: false, Project: ProjectNoContext},
		},
		{
			name: "a group project applies to its members only", requests: sessionRequests(7, 70, "ledger"), extracted: 1,
			want: SessionProject{Known: true, Project: 12, Name: "ledger", Level: LevelCwd},
		},
		{
			name: "the same path outside the group is unattributed", requests: sessionRequests(5, 50, "ledger"), extracted: 1,
			want: SessionProject{Known: true, Project: ProjectUnattributed},
		},
		{
			name: "a service token is marked and still booked", requests: sessionRequests(5, 900, "orders"), extracted: 1,
			want: SessionProject{Known: true, Project: 10, Name: "orders", Level: LevelRemote, Service: true},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := ResolveSession(test.requests, test.extracted, identities, compiled); got != test.want {
				t.Fatalf("got %+v, want %+v", got, test.want)
			}
		})
	}
	if got := ResolveSession(nil, 0, identities, compiled); got.Known || got.Project != ProjectNoContext {
		t.Fatalf("empty session = %+v", got)
	}
}

// A working directory maps to a repository root seen in the same session.
func TestResolveSessionMapsCwdToASessionRoot(t *testing.T) {
	compiled, err := Compile(Catalog{Projects: []Project{
		{ID: 1, Name: "mono", Enabled: true, Rules: []Rule{{Kind: RulePathGlob, Pattern: "/srv/mono"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	identities := map[string]Identity{
		"root": {Roots: []string{"/srv/mono"}},
		"cwd":  {Cwd: "/srv/mono/services/api"},
	}
	requests := []Request{
		{AuditID: "a", StartNS: 1, UserID: 3, RootKey: "r", NodeKey: "main", IdentityKey: "root"},
		{AuditID: "b", StartNS: 2, UserID: 3, RootKey: "r", NodeKey: "sub", IdentityKey: "cwd"},
		{AuditID: "c", StartNS: 3, UserID: 3, RootKey: "r", NodeKey: "sub", IdentityKey: "cwd"},
	}
	got := ResolveSession(requests, 3, identities, compiled)
	if !got.Known || got.Project != 1 || got.Level != LevelRoot {
		t.Fatalf("got %+v", got)
	}
	if requests[1].Project != 1 || requests[2].Project != 1 {
		t.Fatalf("cwd requests = %d, %d", requests[1].Project, requests[2].Project)
	}
}

type sessionData struct {
	input SessionInput
	root  []byte
	key   []byte
}

func (data *sessionData) LoadOrgRequests(context.Context, int64, int64) ([]Request, error) {
	return nil, nil
}

func (data *sessionData) LoadOrgIdentities(context.Context, int64, int64) ([]SealedIdentity, error) {
	return nil, nil
}

func (data *sessionData) LoadOrgSession(_ context.Context, root, key []byte) (SessionInput, error) {
	data.root, data.key = root, key
	return data.input, nil
}

func TestServiceResolveSessionReadsOneSession(t *testing.T) {
	data := &sessionData{input: SessionInput{Requests: sessionRequests(5, 50, "", ""), Extracted: 2}}
	service, err := NewService(context.Background(), Options{Settings: testSettings(), Data: data})
	if err != nil {
		t.Fatal(err)
	}
	got, err := service.ResolveSession(context.Background(), []byte("root"), []byte("key"))
	if err != nil || !got.Known || got.Project != ProjectNoContext || string(data.root) != "root" || string(data.key) != "key" {
		t.Fatalf("got %+v, %v", got, err)
	}
	if service.ProjectName(404) != "" {
		t.Fatal("unknown project has a name")
	}
	bare, err := NewService(context.Background(), Options{Settings: testSettings()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bare.ResolveSession(context.Background(), []byte("root"), nil); err != ErrUnavailable {
		t.Fatalf("no data store: %v", err)
	}
}
