package headerblock

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"net/http"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

const testAuditID = "aud_headerblock_test"

// testKey is a synthetic key used only by these tests and the vectors.
func testKey() []byte {
	key := make([]byte, security.KeySize)
	for index := range key {
		key[index] = byte(index)
	}
	return key
}

func testCipher(t testing.TB) *security.AESGCM {
	t.Helper()
	c, err := security.NewAESGCM(testKey())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func values(texts ...string) [][]byte {
	out := make([][]byte, len(texts))
	for index, text := range texts {
		out[index] = []byte(text)
	}
	return out
}

func TestSnapshotReplaysTheLegacyLoop(t *testing.T) {
	headers := http.Header{
		"X-B":          {"2"},
		"Accept":       {"a", "", "c"},
		"x-lower-only": {"lost"}, // Values canonicalizes: no canonical key, no values
		"X-Dup":        {"canonical"},
		"x-dup":        {"ignored"}, // reads X-Dup's values, as legacy does
		"X-Empty":      {},
	}
	got := Snapshot(headers)
	want := []Field{
		{Name: "Accept", Values: values("a", "", "c")},
		{Name: "X-B", Values: values("2")},
		{Name: "X-Dup", Values: values("canonical")},
		{Name: "x-dup", Values: values("canonical")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Snapshot = %q, want %q", got, want)
	}
	headers["Accept"][0] = "changed"
	if string(got[0].Values[0]) != "a" {
		t.Fatal("Snapshot must deep-copy the values")
	}
	if Snapshot(nil) != nil || len(Snapshot(http.Header{"x-only": {"v"}})) != 0 {
		t.Fatal("a Header without readable values must snapshot to no fields")
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	stages := []Stage{
		{Name: storage.StageRequestReceived,
			Headers:  []Field{{Name: "Content-Type", Values: values("application/json")}, {Name: "X-Multi", Values: values("1", "", "\xff\xfe")}},
			Trailers: []Field{{Name: "X-Trailer", Values: values("t")}}},
		{Name: storage.StageResponseReceived},
		{Name: storage.StageResponseSent, Headers: []Field{{Name: "", Values: values("empty name")}}},
	}
	plaintext, err := Encode(stages)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	// Decoding gives nil for an empty kind; compare through re-encoding and
	// through the flat list.
	again, err := Encode(decoded)
	if err != nil || !bytes.Equal(again, plaintext) {
		t.Fatalf("Encode(Decode(p)) != p: %v", err)
	}
	if !reflect.DeepEqual(Flatten(decoded), Flatten(stages)) {
		t.Fatal("decoded block flattens differently")
	}
	empty, err := Encode(nil)
	if err != nil || !bytes.Equal(empty, []byte("LLHB\x01")) {
		t.Fatalf("empty block = %x, %v", empty, err)
	}
	if stages, err := Decode(empty); err != nil || len(stages) != 0 {
		t.Fatalf("empty block decodes to %v, %v", stages, err)
	}
}

func randomStages(random *rand.Rand) []Stage {
	var stages []Stage
	for _, name := range stageNames {
		if random.IntN(3) == 0 {
			continue
		}
		stage := Stage{Name: name}
		for kind := 0; kind < 2; kind++ {
			names := map[string]bool{}
			for range random.IntN(6) {
				names[randomBytes(random, 1+random.IntN(8))] = true
			}
			sorted := make([]string, 0, len(names))
			for headerName := range names {
				sorted = append(sorted, headerName)
			}
			sort.Strings(sorted)
			var fields []Field
			for _, headerName := range sorted {
				field := Field{Name: headerName}
				for range 1 + random.IntN(3) {
					field.Values = append(field.Values, []byte(randomBytes(random, random.IntN(20))))
				}
				fields = append(fields, field)
			}
			if kind == 0 {
				stage.Headers = fields
			} else {
				stage.Trailers = fields
			}
		}
		stages = append(stages, stage)
	}
	return stages
}

func randomBytes(random *rand.Rand, length int) string {
	out := make([]byte, length)
	for index := range out {
		out[index] = byte(random.IntN(256))
	}
	return string(out)
}

func TestEncodeDecodeRandomRoundTrips(t *testing.T) {
	random := rand.New(rand.NewPCG(59, 3))
	for round := 0; round < 500; round++ {
		stages := randomStages(random)
		plaintext, err := Encode(stages)
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		decoded, err := Decode(plaintext)
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		again, err := Encode(decoded)
		if err != nil || !bytes.Equal(again, plaintext) {
			t.Fatalf("round %d: re-encoding differs", round)
		}
		if !reflect.DeepEqual(Flatten(decoded), Flatten(stages)) {
			t.Fatalf("round %d: flat lists differ", round)
		}
	}
}

func TestEncodeRejectsNonCanonicalInput(t *testing.T) {
	cases := map[string][]Stage{
		"unknown stage":      {{Name: "elsewhere"}},
		"stages reversed":    {{Name: storage.StageRequestSent}, {Name: storage.StageRequestReceived}},
		"stage repeated":     {{Name: storage.StageRequestSent}, {Name: storage.StageRequestSent}},
		"names unsorted":     {{Name: storage.StageRequestSent, Headers: []Field{{Name: "b", Values: values("1")}, {Name: "a", Values: values("1")}}}},
		"names repeated":     {{Name: storage.StageRequestSent, Headers: []Field{{Name: "a", Values: values("1")}, {Name: "a", Values: values("2")}}}},
		"name without value": {{Name: storage.StageRequestSent, Trailers: []Field{{Name: "a"}}}},
	}
	for name, stages := range cases {
		if _, err := Encode(stages); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// block builds plaintexts for the decoder rejection cases.
type block struct{ data []byte }

func newBlock() *block                    { return &block{data: []byte("LLHB\x01")} }
func (b *block) raw(bytes ...byte) *block { b.data = append(b.data, bytes...); return b }
func (b *block) u32(value uint32) *block {
	b.data = binary.BigEndian.AppendUint32(b.data, value)
	return b
}
func (b *block) str(text string) *block { return b.u32(uint32(len(text))).raw([]byte(text)...) }

// name appends one name entry with the given values.
func (b *block) name(text string, vals ...string) *block {
	b.str(text).u32(uint32(len(vals)))
	for _, value := range vals {
		b.str(value)
	}
	return b
}

func TestDecodeRejectsEveryRuleViolation(t *testing.T) {
	type rejection struct {
		plaintext []byte
		rule      string // the message of the rule that must fire
	}
	cases := map[string]rejection{
		"empty":                     {nil, "missing block magic"},
		"magic only":                {[]byte("LLHB"), "missing block magic"},
		"wrong magic":               {[]byte("LLHC\x01"), "missing block magic"},
		"version 0":                 {[]byte("LLHB\x00"), "unsupported block version"},
		"version 2":                 {[]byte("LLHB\x02"), "unsupported block version"},
		"stage code 0":              {newBlock().raw(0).u32(0).u32(0).data, "unknown stage code"},
		"stage code 5":              {newBlock().raw(5).u32(0).u32(0).data, "unknown stage code"},
		"stage repeated":            {newBlock().raw(1).u32(0).u32(0).raw(1).u32(0).u32(0).data, "stage codes not strictly increasing"},
		"stages decreasing":         {newBlock().raw(2).u32(0).u32(0).raw(1).u32(0).u32(0).data, "stage codes not strictly increasing"},
		"stage without sections":    {newBlock().raw(1).data, "truncated integer"},
		"stage without trailers":    {newBlock().raw(1).u32(0).data, "truncated integer"},
		"truncated name count":      {newBlock().raw(1).raw(0, 0).data, "truncated integer"},
		"name count beyond data":    {newBlock().raw(1).u32(1).u32(0).data, "name count beyond the block"},
		"name count over the limit": {newBlock().raw(1).u32(0xffffffff).u32(0).data, "integer over the plaintext limit"},
		"name length over the limit": {newBlock().raw(1).u32(1).u32(MaxPlaintextLength + 1).raw(make([]byte, 12)...).data,
			"integer over the plaintext limit"},
		"name length beyond data":  {newBlock().raw(1).u32(1).u32(200).raw(make([]byte, 20)...).u32(0).data, "length beyond the block"},
		"names decreasing":         {newBlock().raw(1).u32(2).name("b", "1").name("a", "1").u32(0).data, "names not strictly increasing"},
		"names repeated":           {newBlock().raw(1).u32(2).name("a", "1").name("a", "2").u32(0).data, "names not strictly increasing"},
		"name without values":      {newBlock().raw(1).u32(1).str("a").u32(0).raw(make([]byte, 8)...).u32(0).data, "name without values"},
		"value count beyond data":  {newBlock().raw(1).u32(1).str("a").u32(9).str("1").u32(0).data, "value count beyond the block"},
		"value length beyond data": {newBlock().raw(1).u32(1).str("a").u32(1).u32(50).raw('x').u32(0).data, "length beyond the block"},
		"trailing byte":            {newBlock().raw(1).u32(0).u32(0).raw(0).data, "unknown stage code"},
		"trailing stage code only": {newBlock().raw(1).u32(0).u32(0).raw(2).data, "truncated integer"},
		"trailer names decreasing": {newBlock().raw(4).u32(0).u32(2).name("z", "1").name("y", "1").data, "names not strictly increasing"},
		"truncated after a value":  {newBlock().raw(1).u32(1).name("a", "1").data, "truncated integer"},
	}
	for name, testCase := range cases {
		_, err := Decode(testCase.plaintext)
		if !errors.Is(err, ErrIntegrity) || !strings.Contains(err.Error(), testCase.rule) {
			t.Errorf("%s: got %v, want the %q rule", name, err, testCase.rule)
		}
	}
	// A well-formed sibling of the cases above decodes, so the rejections are
	// about the rule each case breaks.
	valid := newBlock().raw(1).u32(2).name("a", "1").name("b", "", "2").u32(0).raw(4).u32(0).u32(1).name("t", "x").data
	if _, err := Decode(valid); err != nil {
		t.Fatalf("valid sibling rejected: %v", err)
	}
}

func TestDecodeRejectsBlocksOverTheLimit(t *testing.T) {
	plaintext := make([]byte, MaxPlaintextLength+1)
	copy(plaintext, "LLHB\x01")
	if _, err := Decode(plaintext); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("oversized block: %v", err)
	}
	if _, _, _, err := Seal(testCipher(t), testAuditID, plaintext); err == nil {
		t.Fatal("Seal accepted an oversized block")
	}
}

func TestSealOpenRoundTripAndRejections(t *testing.T) {
	c := testCipher(t)
	small, _ := Encode([]Stage{{Name: storage.StageRequestReceived, Headers: []Field{{Name: "A", Values: values("1")}}}})
	large, _ := Encode(realisticStages())
	for name, plaintext := range map[string][]byte{"small": small, "large": large} {
		compression, length, enc, err := Seal(c, testAuditID, plaintext)
		if err != nil {
			t.Fatal(err)
		}
		wantCompression := map[string]string{"small": "none", "large": "gzip"}[name]
		if compression != wantCompression || length != int64(len(plaintext)) {
			t.Fatalf("%s: compression %s length %d", name, compression, length)
		}
		opened, err := Open(c, testAuditID, compression, length, enc)
		if err != nil || !bytes.Equal(opened, plaintext) {
			t.Fatalf("%s: open %v", name, err)
		}
		other := map[string]string{"none": "gzip", "gzip": "none"}[compression]
		tampered := bytes.Clone(enc)
		tampered[len(tampered)-1] ^= 1
		rejections := map[string]func() ([]byte, error){
			"other audit":         func() ([]byte, error) { return Open(c, "aud_other", compression, length, enc) },
			"other compression":   func() ([]byte, error) { return Open(c, testAuditID, other, length, enc) },
			"unknown compression": func() ([]byte, error) { return Open(c, testAuditID, "zstd", length, enc) },
			"shorter length":      func() ([]byte, error) { return Open(c, testAuditID, compression, length-1, enc) },
			"longer length":       func() ([]byte, error) { return Open(c, testAuditID, compression, length+1, enc) },
			"negative length":     func() ([]byte, error) { return Open(c, testAuditID, compression, -1, enc) },
			"length over limit":   func() ([]byte, error) { return Open(c, testAuditID, compression, MaxPlaintextLength+1, enc) },
			"tampered":            func() ([]byte, error) { return Open(c, testAuditID, compression, length, tampered) },
			"empty ciphertext":    func() ([]byte, error) { return Open(c, testAuditID, compression, length, nil) },
		}
		for reason, open := range rejections {
			if _, err := open(); !errors.Is(err, ErrIntegrity) {
				t.Errorf("%s/%s: got %v", name, reason, err)
			}
		}
	}
}

func TestUserAgentKeepsAbsenceEmptinessAndOrder(t *testing.T) {
	c := testCipher(t)
	if EncodeUserAgent(nil) != nil || EncodeUserAgent([]string{}) != nil {
		t.Fatal("no value must encode to nil (NULL)")
	}
	enc, err := SealUserAgent(c, testAuditID, nil)
	if err != nil || enc != nil {
		t.Fatalf("absent user agent sealed to %x, %v", enc, err)
	}
	if got, err := OpenUserAgent(c, testAuditID, nil); err != nil || got != nil {
		t.Fatalf("NULL opened to %q, %v", got, err)
	}
	for _, want := range [][]string{{""}, {"agent/1.0"}, {"first", "", "\xff second"}} {
		enc, err := SealUserAgent(c, testAuditID, want)
		if err != nil || enc == nil {
			t.Fatalf("seal %q: %v", want, err)
		}
		got, err := OpenUserAgent(c, testAuditID, enc)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("open = %q, %v; want %q", got, err, want)
		}
		if _, err := OpenUserAgent(c, "aud_other", enc); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("user agent opened under another audit: %v", err)
		}
	}
	for name, plaintext := range map[string][]byte{
		"empty":             nil,
		"version only":      {0x01},
		"wrong version":     {0x02, 0, 0, 0, 0},
		"truncated length":  {0x01, 0, 0},
		"length beyond end": {0x01, 0, 0, 0, 5, 'a'},
		"trailing byte":     {0x01, 0, 0, 0, 1, 'a', 0},
	} {
		if _, err := DecodeUserAgent(plaintext); !errors.Is(err, ErrIntegrity) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestUserAgentValuesSelection(t *testing.T) {
	fields := Snapshot(http.Header{
		"Accept":     {"x"},
		"User-Agent": {"one", "two"},
		"user-agent": {"ignored"}, // reads the canonical values, as legacy rows do
	})
	if got := UserAgentValues(fields); !reflect.DeepEqual(got, []string{"one", "two", "one", "two"}) {
		t.Fatalf("UserAgentValues = %q", got)
	}
	if got := UserAgentValues(Snapshot(http.Header{"Accept": {"x"}})); got != nil {
		t.Fatalf("absent user agent = %q", got)
	}
	if got := UserAgentValues(Snapshot(http.Header{"User-Agent": {""}})); !reflect.DeepEqual(got, []string{""}) {
		t.Fatalf("empty user agent = %q", got)
	}
}

// legacyRows writes per-value rows exactly as Session.addHeadersLocked does.
func legacyRows(t testing.TB, c security.Cipher, stage, kind string, headers http.Header) []storage.HeaderEvidence {
	t.Helper()
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	var rows []storage.HeaderEvidence
	for _, name := range names {
		for index, value := range headers.Values(name) {
			aad, err := security.AAD(testAuditID, "header", stage, kind, name, strconv.Itoa(index))
			if err != nil {
				t.Fatal(err)
			}
			enc, err := c.Encrypt(aad, []byte(value))
			if err != nil {
				t.Fatal(err)
			}
			rows = append(rows, storage.HeaderEvidence{Stage: stage, Kind: kind, Name: name, ValueIndex: index, ValueLength: len(value), ValueEnc: enc})
		}
	}
	return rows
}

type capturedStage struct {
	name     string
	headers  http.Header
	trailers http.Header
}

// bothVersions builds the version 1 and version 2 sources for the same
// captured stages.
func bothVersions(t testing.TB, c security.Cipher, captured []capturedStage, shuffle *rand.Rand) (storage.HeaderSource, storage.HeaderSource) {
	t.Helper()
	v1 := storage.HeaderSource{CaptureVersion: storage.CaptureVersion1}
	v2 := storage.HeaderSource{CaptureVersion: storage.CaptureVersion2}
	var stages []Stage
	for _, stage := range captured {
		v1.Rows = append(v1.Rows, legacyRows(t, c, stage.name, storage.HeaderKindHeader, stage.headers)...)
		v1.Rows = append(v1.Rows, legacyRows(t, c, stage.name, storage.HeaderKindTrailer, stage.trailers)...)
		v1.StageSet = append(v1.StageSet, stage.name)
		stages = append(stages, Stage{Name: stage.name, Headers: Snapshot(stage.headers), Trailers: Snapshot(stage.trailers)})
	}
	if shuffle != nil {
		shuffle.Shuffle(len(v1.Rows), func(i, j int) { v1.Rows[i], v1.Rows[j] = v1.Rows[j], v1.Rows[i] })
	}
	sealed, err := SealBlock(c, testAuditID, stages)
	if err != nil {
		t.Fatal(err)
	}
	v2.Block = &storage.HeaderBlockEvidence{Compression: sealed.Compression, PlaintextLength: sealed.PlaintextLength, DataEnc: sealed.DataEnc}
	v2.StageSet = slices.Clone(v1.StageSet)
	return v1, v2
}

func TestExpandGivesTheSameListForBothVersions(t *testing.T) {
	c := testCipher(t)
	captured := []capturedStage{
		{name: storage.StageRequestReceived,
			headers: http.Header{
				"Content-Type": {"application/json"},
				"Accept":       {"a", "", "c"},
				"X-Binary":     {"\xff\x00\xfe"},
				"X-Dup":        {"canonical"},
				"x-dup":        {"shadowed"},
				"x-gone":       {"lost"},
				"User-Agent":   {""},
			},
			trailers: http.Header{"X-Request-Trailer": {"t1", "t2"}}},
		// request_sent was reached but had no Header at all
		{name: storage.StageRequestSent},
		// response_received was never reached
		{name: storage.StageResponseSent,
			headers:  http.Header{"Content-Type": {"text/event-stream"}, "Vary": {"Origin", "Accept-Encoding"}},
			trailers: http.Header{"X-Response-Trailer": {""}}},
	}
	v1, v2 := bothVersions(t, c, captured, rand.New(rand.NewPCG(1, 2)))
	got1, err := Expand(c, testAuditID, v1)
	if err != nil {
		t.Fatal(err)
	}
	got2, err := Expand(c, testAuditID, v2)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got1, got2) {
		t.Fatalf("version 1 expands to\n%+v\nversion 2 to\n%+v", got1, got2)
	}
	rq, rs := storage.StageRequestReceived, storage.StageResponseSent
	h, tr := storage.HeaderKindHeader, storage.HeaderKindTrailer
	want := []Value{
		{rq, h, "Accept", 0, []byte("a")}, {rq, h, "Accept", 1, []byte("")}, {rq, h, "Accept", 2, []byte("c")},
		{rq, h, "Content-Type", 0, []byte("application/json")},
		{rq, h, "User-Agent", 0, []byte("")},
		{rq, h, "X-Binary", 0, []byte("\xff\x00\xfe")},
		{rq, h, "X-Dup", 0, []byte("canonical")},
		{rq, h, "x-dup", 0, []byte("canonical")},
		{rq, tr, "X-Request-Trailer", 0, []byte("t1")}, {rq, tr, "X-Request-Trailer", 1, []byte("t2")},
		{rs, h, "Content-Type", 0, []byte("text/event-stream")},
		{rs, h, "Vary", 0, []byte("Origin")}, {rs, h, "Vary", 1, []byte("Accept-Encoding")},
		{rs, tr, "X-Response-Trailer", 0, []byte("")},
	}
	if !reflect.DeepEqual(got2, want) {
		t.Fatalf("flat list =\n%+v\nwant\n%+v", got2, want)
	}
}

func TestExpandEquivalenceOnRandomHeaders(t *testing.T) {
	c := testCipher(t)
	random := rand.New(rand.NewPCG(59, 59))
	for round := 0; round < 200; round++ {
		var captured []capturedStage
		for _, name := range stageNames {
			if random.IntN(4) == 0 {
				continue
			}
			stage := capturedStage{name: name, headers: randomHeader(random), trailers: randomHeader(random)}
			captured = append(captured, stage)
		}
		v1, v2 := bothVersions(t, c, captured, random)
		got1, err1 := Expand(c, testAuditID, v1)
		got2, err2 := Expand(c, testAuditID, v2)
		if err1 != nil || err2 != nil || !reflect.DeepEqual(got1, got2) {
			t.Fatalf("round %d: %v %v; lists differ", round, err1, err2)
		}
	}
}

func randomHeader(random *rand.Rand) http.Header {
	pool := []string{"Accept", "accept", "Content-Type", "content-type", "X-A", "x-a", "X-Long-Name", "Authorization", "\xffraw"}
	headers := http.Header{}
	for range random.IntN(6) {
		name := pool[random.IntN(len(pool))]
		var vals []string
		for range random.IntN(3) {
			vals = append(vals, randomBytes(random, random.IntN(10)))
		}
		headers[name] = vals
	}
	return headers
}

func TestExpandRejectsInconsistentSources(t *testing.T) {
	c := testCipher(t)
	captured := []capturedStage{{name: storage.StageRequestReceived, headers: http.Header{"A": {"1"}}}}
	v1, v2 := bothVersions(t, c, captured, nil)

	tamperedRow := slices.Clone(v1.Rows)
	tamperedRow[0].ValueLength++
	movedRow := slices.Clone(v1.Rows)
	movedRow[0].Stage = storage.StageRequestSent
	unknownStage := slices.Clone(v1.Rows)
	unknownStage[0].Stage = "elsewhere"
	cases := map[string]storage.HeaderSource{
		"unknown version":         {CaptureVersion: 3},
		"zero version":            {CaptureVersion: 0},
		"v1 with block":           {CaptureVersion: 1, Rows: v1.Rows, Block: v2.Block},
		"v1 wrong length":         {CaptureVersion: 1, Rows: tamperedRow},
		"v1 row of another stage": {CaptureVersion: 1, Rows: movedRow},
		"v1 unknown stage":        {CaptureVersion: 1, Rows: unknownStage},
		"v2 with rows":            {CaptureVersion: 2, Rows: v1.Rows, Block: v2.Block, StageSet: v2.StageSet},
		"v2 missing stage row":    {CaptureVersion: 2, Block: v2.Block},
		"v2 extra stage row":      {CaptureVersion: 2, Block: v2.Block, StageSet: []string{storage.StageRequestReceived, storage.StageRequestSent}},
		"v2 repeated stage row":   {CaptureVersion: 2, Block: v2.Block, StageSet: []string{storage.StageRequestReceived, storage.StageRequestReceived}},
		"v2 no block, stage rows": {CaptureVersion: 2, StageSet: []string{storage.StageRequestReceived}},
		"v2 block of other audit": {CaptureVersion: 2, Block: v2.Block, StageSet: v2.StageSet},
	}
	for name, source := range cases {
		auditID := testAuditID
		if name == "v2 block of other audit" {
			auditID = "aud_other"
		}
		if _, err := Expand(c, auditID, source); !errors.Is(err, ErrIntegrity) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if got, err := Expand(c, testAuditID, storage.HeaderSource{CaptureVersion: 2}); err != nil || len(got) != 0 {
		t.Fatalf("v2 without block and stages: %v %v", got, err)
	}
	if got, err := Expand(c, testAuditID, storage.HeaderSource{CaptureVersion: 1}); err != nil || len(got) != 0 {
		t.Fatalf("v1 without rows: %v %v", got, err)
	}
}

// TestIncompleteBlockMatchesTheStagesWrittenSoFar follows one audit through
// the blocks of C.8: each write holds only the stages written so far, and
// reads check the block against the stage rows of that moment.
func TestIncompleteBlockMatchesTheStagesWrittenSoFar(t *testing.T) {
	c := testCipher(t)
	request := Stage{Name: storage.StageRequestReceived, Headers: []Field{{Name: "A", Values: values("1")}}}
	sent := Stage{Name: storage.StageRequestSent, Headers: []Field{{Name: "A", Values: values("1")}}, Trailers: []Field{{Name: "T", Values: values("t")}}}
	response := Stage{Name: storage.StageResponseReceived, Headers: []Field{{Name: "Content-Type", Values: values("text/event-stream")}}}
	writes := []struct {
		name   string
		stages []Stage
	}{
		{"begin audit", []Stage{request}},
		{"checkpoint 1", []Stage{request, sent}},
		{"checkpoint 2", []Stage{request, sent, response}},
	}
	for _, write := range writes {
		sealed, err := SealBlock(c, testAuditID, write.stages)
		if err != nil {
			t.Fatal(err)
		}
		evidence := &storage.HeaderBlockEvidence{Compression: sealed.Compression, PlaintextLength: sealed.PlaintextLength, DataEnc: sealed.DataEnc}
		stageSet := StageNames(write.stages)
		got, err := Expand(c, testAuditID, storage.HeaderSource{CaptureVersion: 2, Block: evidence, StageSet: stageSet})
		if err != nil || !reflect.DeepEqual(got, Flatten(write.stages)) {
			t.Fatalf("%s: %v", write.name, err)
		}
		stages, err := OpenBlock(c, testAuditID, *evidence)
		if err != nil {
			t.Fatal(err)
		}
		if err := CheckStageSet(stages, append(slices.Clone(stageSet), storage.StageResponseSent)); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("%s: a stage row without a section passed: %v", write.name, err)
		}
		if len(stageSet) > 1 {
			if err := CheckStageSet(stages, stageSet[:len(stageSet)-1]); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("%s: a section without a stage row passed: %v", write.name, err)
			}
		}
		reversed := slices.Clone(stageSet)
		slices.Reverse(reversed)
		if err := CheckStageSet(stages, reversed); err != nil {
			t.Fatalf("%s: stage set order must not matter: %v", write.name, err)
		}
	}
}

func TestContentHeadersSelection(t *testing.T) {
	str := func(value string) *string { return &value }
	cases := []struct {
		name         string
		headers      http.Header
		wantType     *string
		wantEncoding *string
	}{
		{"none", http.Header{"Accept": {"x"}}, nil, nil},
		{"simple", http.Header{"Content-Type": {"application/json"}, "Content-Encoding": {"gzip"}}, str("application/json"), str("gzip")},
		{"first non-empty", http.Header{"Content-Type": {"", "text/plain", "text/html"}}, str("text/plain"), nil},
		{"only empty", http.Header{"Content-Encoding": {""}}, nil, nil},
		{"case variants", http.Header{"Content-Type": {"", "b"}, "content-type": {"ignored"}}, str("b"), nil},
	}
	for _, testCase := range cases {
		gotType, gotEncoding := ContentHeaders(Snapshot(testCase.headers))
		if !reflect.DeepEqual(gotType, testCase.wantType) || !reflect.DeepEqual(gotEncoding, testCase.wantEncoding) {
			t.Errorf("%s: got %v %v", testCase.name, gotType, gotEncoding)
		}
	}
}
