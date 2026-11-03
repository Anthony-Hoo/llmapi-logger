package migrate

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strconv"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/bodycodec"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/postgres"
)

func verifyEncrypted(t tableSpec, v []any, key []byte) error {
	m := make(map[string]any, len(v))
	for i, c := range t.columns {
		m[c] = v[i]
	}
	str := func(c string) string { s, _ := m[c].(string); return s }
	num := func(c string) int64 { n, _ := m[c].(int64); return n }
	blob := func(c string) []byte { b, _ := m[c].([]byte); return b }
	cipher, _ := security.NewAESGCM(key)
	open := func(col string, parts ...string) ([]byte, error) {
		if m[col] == nil {
			return nil, nil
		}
		aad, err := security.AAD(parts...)
		if err != nil {
			return nil, err
		}
		return cipher.Decrypt(aad, blob(col))
	}
	var plain []byte
	var err error
	switch t.name {
	case "audit_records":
		plain, err = open("request_uri_enc", str("audit_id"), "request_uri")
	case "http_headers":
		plain, err = open("value_enc", str("audit_id"), "header", str("stage"), str("kind"), str("name"), strconv.FormatInt(num("value_index"), 10))
		if err == nil && int64(len(plain)) != num("value_length") {
			err = fmt.Errorf("length")
		}
	case "body_chunks":
		plain, err = open("data_enc", str("audit_id"), "body_chunk_v2", str("stage"), strconv.FormatInt(num("seq"), 10), str("compression"))
		if err != nil && str("compression") == "none" {
			plain, err = open("data_enc", str("audit_id"), "body_chunk", str("stage"), strconv.FormatInt(num("seq"), 10))
		}
		if err == nil {
			if int64(len(plain)) != num("encoded_length") {
				err = fmt.Errorf("length")
			} else {
				decoded, e := bodycodec.Decode(plain, str("compression"), int(num("plaintext_length")))
				clear(decoded)
				err = e
			}
		}
	case "parsed_results":
		plain, err = open("parsed_json_enc", str("audit_id"), "parsed_json", str("parser_name"))
	case "stream_timelines":
		plain, err = open("timeline_enc", str("audit_id"), "stream_timeline_v1", str("stage"), str("compression"))
		if err == nil && m["timeline_enc"] != nil {
			decoded, e := bodycodec.Decode(plain, str("compression"), int(num("plaintext_length")))
			clear(decoded)
			err = e
		}
	case "audit_analysis":
		plain, err = open("detail_enc", str("audit_id"), "analysis_detail", strconv.FormatInt(num("analysis_version"), 10))
	case "content_external_refs":
		plain, err = open("value_enc", "external_ref", hex.EncodeToString(blob("object_hash")), str("json_pointer"), str("ref_kind"))
		if err == nil {
			h := auditmodel.ExternalValueHash(str("ref_kind"), string(plain))
			if !bytes.Equal(h, blob("value_hash")) {
				err = fmt.Errorf("hash")
			}
		}
	case "content_objects":
		var decoded auditmodel.DecodedObject
		decoded, err = auditmodel.OpenObject(cipher, auditmodel.StoredContent{Hash: blob("object_hash"), SemanticHash: blob("semantic_hash"), Kind: str("kind"), Compression: str("compression"), PlaintextLength: num("plaintext_length"), EncodedLength: num("encoded_length"), DataEnc: blob("data_enc")})
		if err == nil {
			h, e := auditmodel.SemanticHash(decoded.Kind, decoded.Value)
			if decoded.Kind == "request_envelope" || decoded.Kind == "response_envelope" {
				h = blob("object_hash")
				e = nil
			}
			if e != nil || !bytes.Equal(h, blob("semantic_hash")) {
				err = fmt.Errorf("semantic hash")
			}
		}
	case "binary_objects":
		plain, err = auditmodel.OpenBinary(cipher, auditmodel.StoredBinary{Hash: blob("binary_hash"), MediaType: str("media_type"), Compression: str("compression"), PlaintextLength: num("plaintext_length"), EncodedLength: num("encoded_length"), DataEnc: blob("data_enc")})
	}
	clear(plain)
	return err
}

func verifyGraphs(ctx context.Context, tx *sql.Tx, key []byte) error {
	// Read IDs first: database/sql cannot keep a pgx rows stream open while
	// querying graph nodes on the same transactional connection.
	rows, err := tx.QueryContext(ctx, `SELECT audit_id FROM turns ORDER BY turn_id`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	cipher, _ := security.NewAESGCM(key)
	for _, id := range ids {
		graph, err := postgres.ReadImportTurnGraph(ctx, tx, id)
		if err != nil || graph == nil {
			return Error("graph_integrity_failed")
		}
		// Failed reconstructions are retained evidence, not claims of verified JSON.
		if graph.ReconstructionStatus != "verified" {
			continue
		}
		objects := map[string]auditmodel.StoredContent{}
		for _, o := range graph.Objects {
			objects[hex.EncodeToString(o.Hash)] = o
		}
		assemble := func(refs []auditmodel.ObjectRef, envelopeHash []byte, layout string, want []byte) error {
			items := make([]auditmodel.Item, 0, len(refs))
			for _, ref := range refs {
				o, ok := objects[hex.EncodeToString(ref.ObjectHash)]
				if !ok || !bytes.Equal(o.SemanticHash, ref.SemanticHash) {
					return Error("graph_integrity_failed")
				}
				d, e := auditmodel.OpenObject(cipher, o)
				if e != nil {
					return e
				}
				items = append(items, auditmodel.Item{Slot: ref.Slot, Kind: d.Kind, Value: d.Value})
			}
			o, ok := objects[hex.EncodeToString(envelopeHash)]
			if !ok {
				return Error("graph_integrity_failed")
			}
			envelope, e := auditmodel.OpenObject(cipher, o)
			if e != nil {
				return e
			}
			value, e := auditmodel.Assemble(layout, envelope.Value, items)
			if e != nil {
				return e
			}
			canonical, e := auditmodel.CanonicalJSON(value)
			defer clear(canonical)
			if e != nil || !bytes.Equal(auditmodel.ReconstructionHash(canonical), want) {
				return Error("graph_integrity_failed")
			}
			return nil
		}
		if err = assemble(graph.RequestRefs, graph.RequestEnvelopeHash, graph.RequestLayout, graph.RequestReconstructionHash); err != nil {
			return err
		}
		if err = assemble(graph.ResponseRefs, graph.ResponseEnvelopeHash, graph.ResponseLayout, graph.ResponseReconstructionHash); err != nil {
			return err
		}
	}
	return nil
}
