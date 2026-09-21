package sqlite

import "testing"

func TestParsedSaveFailureDoesNotRollBackRetention(t *testing.T) {
	t.Parallel()
	for _, parserFirst := range []bool{false, true} {
		name := "retention first"
		if parserFirst {
			name = "parser first"
		}
		t.Run(name, func(t *testing.T) {
			store, _ := openTestStore(t)
			cipher := graphTestCipher(t)
			request, response := graphObjectFixture()
			saveGraphTestTurn(t, store, cipher, "retained-turn", "", "response-existing", 100, request, response)
			parsed := buildGraphTestTurn(t, store, cipher, "failing-turn", "", "response-failing", 200, request, response)
			insertRetentionAudit(t, store, "expired-audit", 1, int64Pointer(2), ParseOK, true)
			if _, err := store.writerDB.Exec("UPDATE binary_objects SET plaintext_length = plaintext_length + 1"); err != nil {
				t.Fatal(err)
			}
			cleanup := &retentionRequest{CutoffNS: 10, AuditLimit: 1}
			batch := []writeRequest{
				{kind: writeDeleteExpired, data: cleanup},
				{kind: writeSaveParsedAudit, data: parsed},
			}
			parserIndex := 1
			if parserFirst {
				batch[0], batch[1] = batch[1], batch[0]
				parserIndex = 0
			}
			results, wrote, err := store.commitBatch(batch)
			if err != nil || !wrote {
				t.Fatalf("parser failure rolled back retention: wrote=%v err=%v", wrote, err)
			}
			if results[parserIndex] == nil || results[1-parserIndex] != nil || cleanup.Result.DeletedAudits != 1 {
				t.Fatalf("independent operation results = %v, retention = %+v", results, cleanup.Result)
			}
			var remaining int
			if err := store.readerDB.QueryRow("SELECT count(*) FROM audit_records WHERE audit_id = 'expired-audit'").Scan(&remaining); err != nil || remaining != 0 {
				t.Fatalf("expired audit was not removed: rows=%d err=%v", remaining, err)
			}
			assertTableCount(t, store.readerDB, "body_chunks", 0)
		})
	}
}
