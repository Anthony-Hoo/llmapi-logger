package postgres

import (
	"bytes"
	"fmt"

	"llmapi-logger/internal/archive"
)

// reverifyArchiveEvents re-verifies the original integrity events of one
// audit before it is exported (design H.3) and returns their copies for the
// record. It requires a capture_finalized event, and a semantic_compacted
// event when the audit has a turn. For every event it re-derives the payload
// digest from the rows of this snapshot with integrityPayloadDigestFor, the
// function the background payload verification uses, and checks the event's
// MAC with the integrity signer. The chain linkage is not checked here:
// EnableIntegrity verified the whole chain at start-up.
//
// The digests bind the ciphertext this same snapshot then decrypts, so the
// plaintext the archive holds is the one the events signed.
func (snapshot *ArchiveSnapshot) reverifyArchiveEvents(auditID string, hasTurn bool) ([]archive.IntegrityEvent, error) {
	rows, err := snapshot.tx.QueryContext(snapshot.ctx, `
SELECT sequence, event_type, previous_mac, payload_digest, event_mac, created_at_ns
FROM integrity_events
WHERE audit_id = $1
ORDER BY sequence`, auditID)
	if err != nil {
		return nil, fmt.Errorf("postgres archive: read integrity events: %w", err)
	}
	var events []archive.IntegrityEvent
	for rows.Next() {
		var event archive.IntegrityEvent
		if err := rows.Scan(&event.Sequence, &event.EventType, &event.PreviousMAC, &event.PayloadDigest, &event.EventMAC, &event.CreatedAtNS); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("postgres archive: scan integrity event: %w", err)
		}
		event.PreviousMAC = cloneBytes(event.PreviousMAC)
		event.PayloadDigest = cloneBytes(event.PayloadDigest)
		event.EventMAC = cloneBytes(event.EventMAC)
		events = append(events, event)
	}
	if err := closeRows(rows); err != nil {
		return nil, fmt.Errorf("postgres archive: integrity events: %w", err)
	}
	present := make(map[string]bool, len(events))
	for _, event := range events {
		present[event.EventType] = true
	}
	if !present[integrityCaptureFinalized] || hasTurn && !present[integritySemanticCompacted] {
		return nil, snapshot.memberFailure(auditID, ArchiveReasonEventMissing, nil)
	}
	for _, event := range events {
		current, err := integrityPayloadDigestFor(snapshot.ctx, snapshot.tx, snapshot.cache, auditID, event.EventType, schemaLive)
		if err != nil {
			return nil, snapshot.memberFailure(auditID, ArchiveReasonEventPayload, err)
		}
		if !bytes.Equal(current, event.PayloadDigest) {
			return nil, snapshot.memberFailure(auditID, ArchiveReasonEventPayload, nil)
		}
		if !snapshot.signer.Verify(event.PreviousMAC, auditID, event.EventType, event.PayloadDigest, event.EventMAC, event.CreatedAtNS) {
			return nil, snapshot.memberFailure(auditID, ArchiveReasonEventMAC, nil)
		}
	}
	return events, nil
}
