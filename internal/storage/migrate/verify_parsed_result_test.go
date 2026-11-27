package migrate

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/security"
)

// The importer verifies every encrypted source row before copying it. A
// parsed result must pass in either stored form and fail when a compressed
// payload is damaged, even though its ciphertext still authenticates.
func TestVerifyEncryptedParsedResultFormats(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x19}, security.KeySize)
	cipher, err := security.NewAESGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	var spec tableSpec
	for _, candidate := range tables {
		if candidate.name == "parsed_results" {
			spec = candidate
		}
	}
	if spec.name == "" {
		t.Fatal("parsed_results table spec not found")
	}
	auditID, parserName := "audit-import-parsed", "openai.chat_completions"
	row := func(sealed []byte) []any {
		values := make([]any, len(spec.columns))
		for index, column := range spec.columns {
			switch column {
			case "audit_id":
				values[index] = auditID
			case "parser_name":
				values[index] = parserName
			case "parsed_json_enc":
				if sealed != nil {
					values[index] = sealed
				}
			}
		}
		return values
	}
	plaintext := []byte(`{"conversation":{"schema_version":1,"messages":[{"index":0,"role":"user","phase":"request","direction":"client_to_upstream","content":[{"index":0,"type":"text","text":"` + strings.Repeat("import example ", 2000) + `"}]}]}}`)
	aad, err := security.AAD(auditID, "parsed_json", parserName)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := cipher.Encrypt(aad, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	compressed, err := auditmodel.SealParsedResult(cipher, auditID, parserName, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	var stream bytes.Buffer
	writer := gzip.NewWriter(&stream)
	_, _ = writer.Write(plaintext)
	_ = writer.Close()
	truncated, err := cipher.Encrypt(aad, stream.Bytes()[:stream.Len()-8])
	if err != nil {
		t.Fatal(err)
	}

	for name, sealed := range map[string][]byte{"legacy": legacy, "compressed": compressed, "absent": nil} {
		if err := verifyEncrypted(spec, row(sealed), key); err != nil {
			t.Fatalf("%s parsed result rejected: %v", name, err)
		}
	}
	if err := verifyEncrypted(spec, row(truncated), key); err == nil {
		t.Fatal("truncated compressed parsed result accepted")
	}
}
