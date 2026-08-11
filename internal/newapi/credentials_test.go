package newapi

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestMaskTokenKeyMatchesNewAPI(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{key: "", want: ""},
		{key: "a", want: "*"},
		{key: "abcd", want: "****"},
		{key: "abcde", want: "ab****de"},
		{key: "abcdefgh", want: "ab****gh"},
		{key: "abcdefghi", want: "abcd**********fghi"},
		{key: "5wmMmiddle-secret-materialo3PP", want: "5wmM**********o3PP"},
	}
	for _, test := range tests {
		if got := MaskTokenKey(test.key); got != test.want {
			t.Errorf("MaskTokenKey(%q) = %q, want %q", test.key, got, test.want)
		}
		if remasked := MaskTokenKey(test.want); remasked != test.want {
			t.Errorf("MaskTokenKey is not stable for masked value %q: got %q", test.want, remasked)
		}
	}
}

func TestLookupRequestUsesNewAPICredentialPriority(t *testing.T) {
	keys := map[string]string{
		"authorization": "auth000000000000a001",
		"anthropic":     "anth000000000000b002",
		"query":         "quer000000000000c003",
		"google":        "goog000000000000d004",
	}
	catalog := catalogWithRawKeys(keys)

	tests := []struct {
		name    string
		path    string
		headers map[string]string
		wantID  int64
	}{
		{
			name:    "authorization accepts sk prefix and channel suffix",
			path:    "/v1/chat/completions",
			headers: map[string]string{"Authorization": "Bearer sk-" + keys["authorization"] + "-channel-7"},
			wantID:  1,
		},
		{
			name: "anthropic x-api-key overrides authorization",
			path: "/v1/messages",
			headers: map[string]string{
				"Authorization": "Bearer " + keys["authorization"],
				"x-api-key":     " sk-" + keys["anthropic"] + "-channel-8 ",
			},
			wantID: 2,
		},
		{
			name: "models root uses anthropic precedence",
			path: "/v1/models",
			headers: map[string]string{
				"Authorization":  "Bearer " + keys["authorization"],
				"x-api-key":      keys["anthropic"],
				"x-goog-api-key": keys["google"],
			},
			wantID: 2,
		},
		{
			name:    "gemini query overrides authorization",
			path:    "/v1beta/models/gemini:generateContent?key=sk-" + keys["query"] + "-channel-9",
			headers: map[string]string{"Authorization": "Bearer " + keys["authorization"]},
			wantID:  3,
		},
		{
			name: "gemini google header overrides query",
			path: "/v1beta/models/gemini:generateContent?key=" + keys["query"],
			headers: map[string]string{
				"Authorization":  "Bearer " + keys["authorization"],
				"x-goog-api-key": " sk-" + keys["google"] + "-channel-10 ",
			},
			wantID: 4,
		},
		{
			name: "gemini precedence follows x-goog then query then x-api-key then authorization",
			path: "/v1/models/gemini?key=" + keys["query"],
			headers: map[string]string{
				"Authorization":  "Bearer " + keys["authorization"],
				"x-api-key":      keys["anthropic"],
				"x-goog-api-key": keys["google"],
			},
			wantID: 4,
		},
		{
			name: "ordinary OpenAI path ignores protocol-specific alternatives",
			path: "/v1/chat/completions?key=" + keys["query"],
			headers: map[string]string{
				"Authorization":  "Bearer " + keys["authorization"],
				"x-api-key":      keys["anthropic"],
				"x-goog-api-key": keys["google"],
			},
			wantID: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "http://proxy.example.test"+test.path, nil)
			for name, value := range test.headers {
				request.Header.Set(name, value)
			}
			token, found := catalog.LookupRequest(request)
			if !found || token.ID != test.wantID {
				t.Fatalf("LookupRequest() = (%#v, %v), want token id %d", token, found, test.wantID)
			}
		})
	}
}

func TestLookupRequestDoesNotAssociateMaskedOrUnsupportedCredentials(t *testing.T) {
	rawKey := "auth000000000000a001"
	catalog := catalogWithRawKeys(map[string]string{"authorization": rawKey})

	maskedRequest := httptest.NewRequest(http.MethodPost, "http://proxy.example.test/v1/chat/completions", nil)
	maskedRequest.Header.Set("Authorization", "Bearer "+MaskTokenKey(rawKey))
	if token, found := catalog.LookupRequest(maskedRequest); found {
		t.Fatalf("masked request credential unexpectedly matched %#v", token)
	}

	unsupported := httptest.NewRequest(http.MethodPost, "http://proxy.example.test/v1/chat/completions", nil)
	unsupported.Header.Set("x-api-key", rawKey)
	if token, found := catalog.LookupRequest(unsupported); found {
		t.Fatalf("ordinary OpenAI x-api-key unexpectedly matched %#v", token)
	}

	if token, found := catalog.LookupRequest(nil); found {
		t.Fatalf("nil request unexpectedly matched %#v", token)
	}
}

func TestMaskedKeyCollisionNeverAssociates(t *testing.T) {
	first := "same111111111111tail"
	second := "same222222222222tail"
	unique := "uniq333333333333last"
	if MaskTokenKey(first) != MaskTokenKey(second) {
		t.Fatal("test fixture does not create a masked-key collision")
	}

	catalog := &Catalog{}
	catalog.snapshot.Store(newCatalogSnapshot([]Token{
		{ID: 1, Name: "first", MaskedKey: MaskTokenKey(first)},
		{ID: 2, Name: "second", MaskedKey: MaskTokenKey(second)},
		{ID: 3, Name: "unique", MaskedKey: MaskTokenKey(unique)},
	}, time.Now()))

	if token, found := catalog.LookupCredential("Bearer sk-" + first + "-channel"); found {
		t.Fatalf("ambiguous masked key unexpectedly matched %#v", token)
	}
	if token, found := catalog.LookupCredential("Bearer sk-" + second + "-channel"); found {
		t.Fatalf("ambiguous masked key unexpectedly matched %#v", token)
	}
	token, found := catalog.LookupCredential("Bearer sk-" + unique + "-channel")
	if !found || token.ID != 3 {
		t.Fatalf("unique masked key = (%#v, %v), want id 3", token, found)
	}
	if len(catalog.List()) != 3 {
		t.Fatal("collision handling removed rows from the display list")
	}
}

func TestCatalogSnapshotAndLookupAreConcurrentSafe(t *testing.T) {
	firstKey := "first000000000000one1"
	secondKey := "seco000000000000two2"
	catalog := &Catalog{}
	catalog.snapshot.Store(newCatalogSnapshot([]Token{{ID: 1, MaskedKey: MaskTokenKey(firstKey)}}, time.Now()))

	var waitGroup sync.WaitGroup
	for reader := 0; reader < 8; reader++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for iteration := 0; iteration < 500; iteration++ {
				_ = catalog.List()
				_, _ = catalog.LookupCredential("Bearer " + firstKey)
				_, _ = catalog.LookupCredential("Bearer " + secondKey)
			}
		}()
	}
	for iteration := 0; iteration < 500; iteration++ {
		if iteration%2 == 0 {
			catalog.snapshot.Store(newCatalogSnapshot([]Token{{ID: 1, MaskedKey: MaskTokenKey(firstKey)}}, time.Now()))
		} else {
			catalog.snapshot.Store(newCatalogSnapshot([]Token{{ID: 2, MaskedKey: MaskTokenKey(secondKey)}}, time.Now()))
		}
	}
	waitGroup.Wait()
}

func catalogWithRawKeys(keys map[string]string) *Catalog {
	tokens := []Token{
		{ID: 1, Name: "authorization", MaskedKey: MaskTokenKey(keys["authorization"])},
		{ID: 2, Name: "anthropic", MaskedKey: MaskTokenKey(keys["anthropic"])},
		{ID: 3, Name: "query", MaskedKey: MaskTokenKey(keys["query"])},
		{ID: 4, Name: "google", MaskedKey: MaskTokenKey(keys["google"])},
	}
	catalog := &Catalog{}
	catalog.snapshot.Store(newCatalogSnapshot(tokens, time.Now()))
	return catalog
}
