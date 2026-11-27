package headerblock

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// The vectors in testdata/vectors.json pin the header block plaintext (C.3),
// the AAD and stored triple of a sealed block (C.4) and the user_agent_enc
// encoding (C.5), so a second implementation can be checked against them.
// Sealed values use a random GCM nonce and toolchain-dependent gzip output, so
// they are checked by opening them with the synthetic key, never by sealing
// again. Regenerate with: go test ./internal/headerblock -run Vectors -update
var updateVectors = flag.Bool("update", false, "rewrite testdata/vectors.json")

const vectorAuditID = "aud_vector_0001"

type vectorFile struct {
	Description      string            `json:"description"`
	KeyHex           string            `json:"key_hex"`
	Blocks           []blockVector     `json:"blocks"`
	InvalidBlocks    []invalidVector   `json:"invalid_blocks"`
	BlockAADs        []aadVector       `json:"block_aads"`
	SealedBlocks     []sealedVector    `json:"sealed_blocks"`
	UserAgents       []userAgentVector `json:"user_agents"`
	UserAgentAADs    []aadVector       `json:"user_agent_aads"`
	SealedUserAgents []sealedUserAgent `json:"sealed_user_agents"`
}

type fieldVector struct {
	Name      string   `json:"name"`
	ValuesHex []string `json:"values_hex"`
}

type stageVector struct {
	Stage     string        `json:"stage"`
	StageCode int           `json:"stage_code"`
	Headers   []fieldVector `json:"headers"`
	Trailers  []fieldVector `json:"trailers"`
}

type blockVector struct {
	Name         string        `json:"name"`
	Description  string        `json:"description"`
	Stages       []stageVector `json:"stages"`
	PlaintextHex string        `json:"plaintext_hex"`
}

type invalidVector struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	PlaintextHex string `json:"plaintext_hex"`
}

type aadVector struct {
	AuditID     string `json:"audit_id"`
	Compression string `json:"compression,omitempty"`
	AADHex      string `json:"aad_hex"`
}

type sealedVector struct {
	Name            string `json:"name"`
	Description     string `json:"description"`
	AuditID         string `json:"audit_id"`
	Compression     string `json:"compression"`
	PlaintextLength int64  `json:"plaintext_length"`
	BlockEncHex     string `json:"block_enc_hex"`
	PlaintextHex    string `json:"plaintext_hex"`
}

type userAgentVector struct {
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Absent       bool     `json:"absent"`
	ValuesHex    []string `json:"values_hex"`
	PlaintextHex string   `json:"plaintext_hex"`
}

type sealedUserAgent struct {
	Name      string   `json:"name"`
	AuditID   string   `json:"audit_id"`
	EncHex    string   `json:"enc_hex"`
	ValuesHex []string `json:"values_hex"`
}

func fieldsOf(t *testing.T, vectors []fieldVector) []Field {
	var fields []Field
	for _, vector := range vectors {
		field := Field{Name: vector.Name}
		for _, valueHex := range vector.ValuesHex {
			field.Values = append(field.Values, mustHex(t, valueHex))
		}
		fields = append(fields, field)
	}
	return fields
}

func vectorFields(fields []Field) []fieldVector {
	out := []fieldVector{}
	for _, field := range fields {
		vector := fieldVector{Name: field.Name, ValuesHex: []string{}}
		for _, value := range field.Values {
			vector.ValuesHex = append(vector.ValuesHex, hex.EncodeToString(value))
		}
		out = append(out, vector)
	}
	return out
}

func stagesOf(t *testing.T, vectors []stageVector) []Stage {
	var stages []Stage
	for _, vector := range vectors {
		code, ok := StageCode(vector.Stage)
		if !ok || int(code) != vector.StageCode {
			t.Fatalf("vector stage %q has code %d", vector.Stage, vector.StageCode)
		}
		stages = append(stages, Stage{Name: vector.Stage, Headers: fieldsOf(t, vector.Headers), Trailers: fieldsOf(t, vector.Trailers)})
	}
	return stages
}

func mustHex(t *testing.T, text string) []byte {
	t.Helper()
	value, err := hex.DecodeString(text)
	if err != nil {
		t.Fatalf("bad hex %q: %v", text, err)
	}
	return value
}

// vectorBlocks are the inputs of the block vectors.
func vectorBlocks() []struct {
	name, description string
	stages            []Stage
} {
	rq, rs, pr, ps := storage.StageRequestReceived, storage.StageRequestSent, storage.StageResponseReceived, storage.StageResponseSent
	return []struct {
		name, description string
		stages            []Stage
	}{
		{"empty", "No stage reached: magic and version only.", nil},
		{"single_value", "One request_received Header A: b and no Trailer.", []Stage{{Name: rq, Headers: []Field{{Name: "A", Values: values("b")}}}}},
		{"empty_stage", "request_sent reached without any Header or Trailer: both name counts are zero.", []Stage{{Name: rs}}},
		{"values_in_order", "Several values of one name keep value_index order, including an empty value and non-UTF-8 bytes.",
			[]Stage{{Name: rq, Headers: []Field{{Name: "Accept", Values: values("a", "", "\xff\xfe")}}}}},
		{"case_variants", "Two map keys differing only in case are distinct names in byte order (upper case first); legacy reads the canonical key's values for both.",
			[]Stage{{Name: rq, Headers: []Field{{Name: "X-Dup", Values: values("v")}, {Name: "x-dup", Values: values("v")}}}}},
		{"trailers", "A response_sent Trailer after its Headers.",
			[]Stage{{Name: ps, Headers: []Field{{Name: "Content-Type", Values: values("text/event-stream")}}, Trailers: []Field{{Name: "X-Trailer", Values: values("done")}}}}},
		{"skipped_stage", "request_received and response_received reached, the stages between not: codes 1 and 3 only.",
			[]Stage{{Name: rq, Headers: []Field{{Name: "A", Values: values("1")}}}, {Name: pr, Headers: []Field{{Name: "B", Values: values("2")}}}}},
		{"all_stages", "All four stages with Headers, one Trailer on request_received.", []Stage{
			{Name: rq, Headers: []Field{{Name: "Content-Type", Values: values("application/json")}, {Name: "User-Agent", Values: values("example/1.0")}}, Trailers: []Field{{Name: "X-T", Values: values("t")}}},
			{Name: rs, Headers: []Field{{Name: "Content-Type", Values: values("application/json")}}},
			{Name: pr, Headers: []Field{{Name: "Content-Type", Values: values("text/event-stream")}}},
			{Name: ps, Headers: []Field{{Name: "Content-Type", Values: values("text/event-stream")}}},
		}},
	}
}

func vectorInvalidBlocks() []invalidVector {
	raw := func(name, description string, data []byte) invalidVector {
		return invalidVector{Name: name, Description: description, PlaintextHex: hex.EncodeToString(data)}
	}
	return []invalidVector{
		raw("wrong_magic", "Magic is not LLHB.", []byte("LLHC\x01")),
		raw("wrong_version", "Version byte 0x02.", []byte("LLHB\x02")),
		raw("stage_code_zero", "Stage code 0 is not defined.", newBlock().raw(0).u32(0).u32(0).data),
		raw("stage_code_five", "Stage code 5 is not defined.", newBlock().raw(5).u32(0).u32(0).data),
		raw("stages_out_of_order", "Stage code 2 before 1.", newBlock().raw(2).u32(0).u32(0).raw(1).u32(0).u32(0).data),
		raw("stage_repeated", "Stage code 1 twice.", newBlock().raw(1).u32(0).u32(0).raw(1).u32(0).u32(0).data),
		raw("missing_trailer_section", "A stage with only its header section.", newBlock().raw(1).u32(0).data),
		raw("names_not_increasing", "Names b then a within one kind.", newBlock().raw(1).u32(2).name("b", "1").name("a", "1").u32(0).data),
		raw("name_repeated", "The same name twice within one kind.", newBlock().raw(1).u32(2).name("a", "1").name("a", "2").u32(0).data),
		raw("name_without_values", "value_count 0.", newBlock().raw(1).u32(1).str("a").u32(0).u32(0).data),
		raw("value_beyond_end", "A value length larger than what remains.", newBlock().raw(1).u32(1).str("a").u32(1).u32(50).raw('x').u32(0).data),
		raw("trailing_bytes", "One byte after the last stage section.", newBlock().raw(1).u32(0).u32(0).raw(0).data),
	}
}

func vectorUserAgents() []struct {
	name, description string
	values            []string
} {
	return []struct {
		name, description string
		values            []string
	}{
		{"absent", "No User-Agent Header: no plaintext, the column is NULL.", nil},
		{"empty_value", "A User-Agent Header with one empty value.", []string{""}},
		{"single", "One value.", []string{"example-cli/1.0"}},
		{"several", "Several values in order, one of them non-UTF-8.", []string{"first", "", "\xffsecond"}},
	}
}

func buildVectors(t *testing.T) vectorFile {
	c := testCipher(t)
	file := vectorFile{
		Description: "Test vectors for internal/headerblock: the header block plaintext (design C.3), the sealed block AAD and stored triple (C.4) and the user_agent_enc encoding and AAD (C.5). All hex is lower case. The key is synthetic (bytes 0x00 to 0x1f) and only for these vectors. Sealed values carry a random AES-GCM nonce (12 bytes, prefixed) and a 16-byte tag; check them by opening, not by sealing again.",
		KeyHex:      hex.EncodeToString(testKey()),
	}
	for _, input := range vectorBlocks() {
		plaintext, err := Encode(input.stages)
		if err != nil {
			t.Fatalf("%s: %v", input.name, err)
		}
		vector := blockVector{Name: input.name, Description: input.description, Stages: []stageVector{}, PlaintextHex: hex.EncodeToString(plaintext)}
		for _, stage := range input.stages {
			code, _ := StageCode(stage.Name)
			vector.Stages = append(vector.Stages, stageVector{Stage: stage.Name, StageCode: int(code), Headers: vectorFields(stage.Headers), Trailers: vectorFields(stage.Trailers)})
		}
		file.Blocks = append(file.Blocks, vector)
	}
	file.InvalidBlocks = vectorInvalidBlocks()
	for _, compression := range []string{"none", "gzip"} {
		aad, err := BlockAAD(vectorAuditID, compression)
		if err != nil {
			t.Fatal(err)
		}
		file.BlockAADs = append(file.BlockAADs, aadVector{AuditID: vectorAuditID, Compression: compression, AADHex: hex.EncodeToString(aad)})
	}
	small, _ := Encode(vectorBlocks()[1].stages)
	large, _ := Encode(realisticStages())
	for _, input := range []struct {
		name, description string
		plaintext         []byte
	}{
		{"sealed_none", "The single_value block, shorter than 128 bytes, stored without compression.", small},
		{"sealed_gzip", "A block of realistic Headers for four stages, stored gzip-compressed.", large},
	} {
		compression, length, enc, err := Seal(c, vectorAuditID, input.plaintext)
		if err != nil {
			t.Fatal(err)
		}
		file.SealedBlocks = append(file.SealedBlocks, sealedVector{
			Name: input.name, Description: input.description, AuditID: vectorAuditID, Compression: compression,
			PlaintextLength: length, BlockEncHex: hex.EncodeToString(enc), PlaintextHex: hex.EncodeToString(input.plaintext),
		})
	}
	for _, input := range vectorUserAgents() {
		vector := userAgentVector{Name: input.name, Description: input.description, Absent: input.values == nil, ValuesHex: []string{}}
		for _, value := range input.values {
			vector.ValuesHex = append(vector.ValuesHex, hex.EncodeToString([]byte(value)))
		}
		vector.PlaintextHex = hex.EncodeToString(EncodeUserAgent(input.values))
		file.UserAgents = append(file.UserAgents, vector)
		if input.values != nil {
			enc, err := SealUserAgent(c, vectorAuditID, input.values)
			if err != nil {
				t.Fatal(err)
			}
			file.SealedUserAgents = append(file.SealedUserAgents, sealedUserAgent{Name: input.name, AuditID: vectorAuditID, EncHex: hex.EncodeToString(enc), ValuesHex: vector.ValuesHex})
		}
	}
	aad, err := UserAgentAAD(vectorAuditID)
	if err != nil {
		t.Fatal(err)
	}
	file.UserAgentAADs = []aadVector{{AuditID: vectorAuditID, AADHex: hex.EncodeToString(aad)}}
	return file
}

func TestVectors(t *testing.T) {
	path := filepath.Join("testdata", "vectors.json")
	if *updateVectors {
		data, err := json.MarshalIndent(buildVectors(t), "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file vectorFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	c, err := security.NewAESGCM(mustHex(t, file.KeyHex))
	if err != nil {
		t.Fatal(err)
	}

	// The vectors must match the inputs in this file, so a format change
	// cannot pass by regenerating the data alone.
	inputs := vectorBlocks()
	if len(file.Blocks) != len(inputs) {
		t.Fatalf("%d block vectors, want %d", len(file.Blocks), len(inputs))
	}
	for index, vector := range file.Blocks {
		stages := stagesOf(t, vector.Stages)
		if !reflect.DeepEqual(Flatten(stages), Flatten(inputs[index].stages)) {
			t.Fatalf("%s: vector stages differ from the inputs", vector.Name)
		}
		plaintext := mustHex(t, vector.PlaintextHex)
		encoded, err := Encode(stages)
		if err != nil || !bytes.Equal(encoded, plaintext) {
			t.Fatalf("%s: Encode = %x, %v; vector %s", vector.Name, encoded, err, vector.PlaintextHex)
		}
		decoded, err := Decode(plaintext)
		if err != nil || !reflect.DeepEqual(Flatten(decoded), Flatten(stages)) {
			t.Fatalf("%s: Decode differs: %v", vector.Name, err)
		}
	}
	// Two plaintexts written out by hand from the grammar, independent of
	// Encode.
	handWritten := map[string]string{
		"empty":        "4c4c484201",
		"single_value": "4c4c4842" + "01" + "01" + "00000001" + "00000001" + "41" + "00000001" + "00000001" + "62" + "00000000",
	}
	for _, vector := range file.Blocks {
		if want, ok := handWritten[vector.Name]; ok && vector.PlaintextHex != want {
			t.Fatalf("%s: vector %s, grammar gives %s", vector.Name, vector.PlaintextHex, want)
		}
	}

	if !reflect.DeepEqual(file.InvalidBlocks, vectorInvalidBlocks()) {
		t.Fatal("invalid block vectors differ from the inputs")
	}
	userAgentInputs := vectorUserAgents()
	if len(file.UserAgents) != len(userAgentInputs) || len(file.SealedUserAgents) != len(userAgentInputs)-1 ||
		len(file.BlockAADs) != 2 || len(file.UserAgentAADs) != 1 {
		t.Fatal("vector lists are incomplete")
	}
	for index, vector := range file.UserAgents {
		if vector.Name != userAgentInputs[index].name {
			t.Fatalf("user agent vector %d is %s, want %s", index, vector.Name, userAgentInputs[index].name)
		}
	}
	handWrittenUserAgents := map[string]string{
		"absent":      "",
		"empty_value": "01" + "00000000",
		"single":      "01" + "0000000f" + "6578616d706c652d636c692f312e30",
		"several":     "01" + "00000005" + "6669727374" + "00000000" + "00000007" + "ff7365636f6e64",
	}
	for _, vector := range file.UserAgents {
		if want := handWrittenUserAgents[vector.Name]; vector.PlaintextHex != want {
			t.Fatalf("user agent %s: vector %s, grammar gives %s", vector.Name, vector.PlaintextHex, want)
		}
	}
	for _, vector := range file.InvalidBlocks {
		if _, err := Decode(mustHex(t, vector.PlaintextHex)); !errors.Is(err, ErrIntegrity) {
			t.Errorf("invalid vector %s decoded: %v", vector.Name, err)
		}
	}
	for _, vector := range file.BlockAADs {
		aad, err := BlockAAD(vector.AuditID, vector.Compression)
		want := []byte(vector.AuditID + "\x00header_block_v1\x00" + vector.Compression)
		if err != nil || hex.EncodeToString(aad) != vector.AADHex || !bytes.Equal(aad, want) {
			t.Fatalf("block AAD %s: %x", vector.Compression, aad)
		}
	}
	for _, vector := range file.SealedBlocks {
		plaintext := mustHex(t, vector.PlaintextHex)
		if vector.PlaintextLength != int64(len(plaintext)) {
			t.Fatalf("%s: plaintext_length %d", vector.Name, vector.PlaintextLength)
		}
		opened, err := Open(c, vector.AuditID, vector.Compression, vector.PlaintextLength, mustHex(t, vector.BlockEncHex))
		if err != nil || !bytes.Equal(opened, plaintext) {
			t.Fatalf("%s: Open %v", vector.Name, err)
		}
		if _, err := Decode(opened); err != nil {
			t.Fatalf("%s: sealed plaintext does not decode: %v", vector.Name, err)
		}
	}
	if len(file.SealedBlocks) != 2 || file.SealedBlocks[0].Compression != "none" || file.SealedBlocks[1].Compression != "gzip" {
		t.Fatal("want one sealed vector without and one with compression")
	}
	for _, vector := range file.UserAgents {
		var want []string
		for _, valueHex := range vector.ValuesHex {
			want = append(want, string(mustHex(t, valueHex)))
		}
		if vector.Absent != (want == nil) {
			t.Fatalf("%s: absent flag disagrees with values", vector.Name)
		}
		plaintext := EncodeUserAgent(want)
		if hex.EncodeToString(plaintext) != vector.PlaintextHex {
			t.Fatalf("%s: EncodeUserAgent = %x", vector.Name, plaintext)
		}
		if vector.Absent {
			continue
		}
		got, err := DecodeUserAgent(plaintext)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: DecodeUserAgent = %q, %v", vector.Name, got, err)
		}
	}
	for _, vector := range file.UserAgentAADs {
		aad, err := UserAgentAAD(vector.AuditID)
		if err != nil || hex.EncodeToString(aad) != vector.AADHex || string(aad) != vector.AuditID+"\x00user_agent_v1" {
			t.Fatalf("user agent AAD: %x", aad)
		}
	}
	for _, vector := range file.SealedUserAgents {
		var want []string
		for _, valueHex := range vector.ValuesHex {
			want = append(want, string(mustHex(t, valueHex)))
		}
		got, err := OpenUserAgent(c, vector.AuditID, mustHex(t, vector.EncHex))
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: OpenUserAgent = %q, %v", vector.Name, got, err)
		}
	}
}
