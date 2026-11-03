package insights

import (
	"bytes"
	"encoding/json"
	"llmapi-logger/internal/security"
	"reflect"
	"testing"
)

func TestDetailCodecLegacyAndVersioned(t *testing.T) {
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	codec := CipherDetailCodec{Cipher: cipher}
	want := Detail{Items: []Item{{Index: 0, Category: CategoryUser, Summary: "private summary"}}, ItemFPRs: []string{"keyed fingerprint"}}
	plain, _ := json.Marshal(want)
	aad, _ := detailAAD("audit", 3)
	legacy, _ := cipher.Encrypt(aad, plain)
	got, err := codec.OpenDetail("audit", 3, legacy)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("legacy roundtrip: %v", err)
	}
	sealed, err := codec.SealDetail("audit", want)
	if err != nil {
		t.Fatal(err)
	}
	got, err = codec.OpenDetail("audit", AnalysisVersion, sealed)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("new roundtrip: %v", err)
	}
	if _, err := codec.OpenDetail("other", AnalysisVersion, sealed); err == nil {
		t.Fatal("cross-audit AAD accepted")
	}
	if _, err := codec.OpenDetail("audit", AnalysisVersion+1, sealed); err == nil {
		t.Fatal("wrong version accepted")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := codec.OpenDetail("audit", AnalysisVersion, sealed); err == nil {
		t.Fatal("corruption accepted")
	}
}
func TestDetailPayloadBoundedCodec(t *testing.T) {
	plain := bytes.Repeat([]byte("repeated summary"), 1000)
	encoded, err := encodeDetailPayload(plain)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) >= len(plain) {
		t.Fatal("expected compression")
	}
	got, err := decodeDetailPayload(encoded)
	if err != nil || !bytes.Equal(plain, got) {
		t.Fatalf("roundtrip: %v", err)
	}
	for _, bad := range [][]byte{[]byte("AID"), []byte("AID\x02bogus"), []byte("AID\x01\x01\xff\xff\xff\xff"), []byte("AID\x01\x03\x00\x00\x00\x00"), encoded[:len(encoded)-1]} {
		if _, err := decodeDetailPayload(bad); err == nil {
			t.Fatal("bad envelope accepted")
		}
	}
}
