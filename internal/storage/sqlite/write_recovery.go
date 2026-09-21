package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"
)

const (
	captureRecoveryInterval = 5 * time.Second
	captureRecoveryLimit    = 1024
	captureRecoveryBatch    = 16
)

// A failed transaction cannot persist its own failure marker. Keep only the
// identities and observation bounds needed to mark retained evidence honestly.
// No Header values, raw bytes, ciphertext or timeline payloads are retained.
type captureRecovery struct {
	version uint64
	marked  bool
	stages  [4]captureStageLoss
	finish  *AuditFinish
	barrier uint64
}

type captureStageLoss struct {
	affected bool
	headers  bool
	chunk    bool
	observed int64
}

var captureStageNames = [...]string{StageRequestReceived, StageRequestSent, StageResponseReceived, StageResponseSent}

func (store *Store) rememberFailedWrite(request writeRequest, barrier uint64) {
	store.recoveryMu.Lock()
	defer store.recoveryMu.Unlock()
	if store.recoveries == nil {
		store.recoveries = make(map[string]captureRecovery)
	}
	remember := func(id, stage string, headers, chunk bool, observed int64, finish *AuditFinish) {
		entry, exists := store.recoveries[id]
		if !exists && len(store.recoveries) >= captureRecoveryLimit {
			// Never evict an unknown capture fault and later claim complete.
			// Startup recovery reconciles all open audits after a restart.
			store.recoveryOverflow.Store(true)
			return
		}
		entry.version++
		entry.marked = false
		for index, name := range captureStageNames {
			if stage != name {
				continue
			}
			loss := &entry.stages[index]
			loss.affected = true
			loss.headers = loss.headers || headers
			loss.chunk = loss.chunk || chunk
			loss.observed = max(loss.observed, observed)
		}
		if finish != nil {
			owned := cloneAuditFinish(*finish)
			entry.finish = &owned
			entry.barrier = max(entry.barrier, barrier)
		}
		store.recoveries[id] = entry
	}
	switch request.kind {
	case writeStartStage:
		v := request.data.(HTTPStage)
		remember(v.AuditID, v.Stage, false, false, 0, nil)
	case writeStartBody:
		v := request.data.(BodyStream)
		remember(v.AuditID, v.Stage, false, false, v.ObservedLength, nil)
	case writeAddHeaders:
		for _, v := range request.data.([]HTTPHeader) {
			remember(v.AuditID, v.Stage, true, false, 0, nil)
		}
	case writeAddChunk:
		v := request.data.(BodyChunk)
		remember(v.AuditID, v.Stage, false, true, v.Offset+int64(v.PlaintextLength), nil)
	case writeFinishStage:
		v := request.data.(StageFinish)
		var observed int64
		if v.Body != nil {
			observed = v.Body.ObservedLength
		}
		remember(v.AuditID, v.Stage, false, false, observed, nil)
	case writeFinishAudit:
		v := request.data.(*AuditFinish)
		remember(v.AuditID, "", false, false, 0, v)
	}
	store.recoveryPending.Store(int32(len(store.recoveries)))
	// Queue-full finalization is not seen by the writer until it is woken.
	if request.kind == writeFinishAudit && request.sequence > barrier {
		select {
		case store.recoveryWake <- struct{}{}:
		default:
		}
	}
}

// Called only by the single writer, including when no new traffic arrives.
// Each entry has its own savepoint; one irreparable audit cannot undo recovery
// of another audit. Deferred finalizations never pass their queue barrier.
func (store *Store) recoverCaptureWrites() {
	if store.recoveryPending.Load() == 0 {
		return
	}
	store.recoveryMu.Lock()
	entries := make(map[string]captureRecovery, len(store.recoveries))
	ids := make([]string, 0, len(store.recoveries))
	for id, entry := range store.recoveries {
		if entry.marked && (entry.finish == nil || entry.barrier > store.processedSequence) {
			continue
		}
		entries[id] = entry
		ids = append(ids, id)
	}
	store.recoveryMu.Unlock()
	if len(ids) == 0 {
		return
	}
	sort.Strings(ids)
	// Rotate past irreparable entries instead of starving later recoveries.
	start := sort.SearchStrings(ids, store.recoveryCursor)
	for start < len(ids) && ids[start] <= store.recoveryCursor {
		start++
	}
	selected := make([]string, 0, min(len(ids), captureRecoveryBatch))
	for i := 0; i < min(len(ids), captureRecoveryBatch); i++ {
		selected = append(selected, ids[(start+i)%len(ids)])
	}
	ids = selected
	store.recoveryCursor = ids[len(ids)-1]
	// Bound transaction size rather than repeatedly timing out a large audit
	// before it can ever finish. SQLite's existing busy timeout still applies.
	tx, err := store.writerDB.BeginTx(context.Background(), nil)
	if err != nil {
		store.recoveryFailed(err)
		return
	}
	defer tx.Rollback()
	done := make(map[string]bool)
	wrote := false
	for _, id := range ids {
		if _, err := tx.Exec("SAVEPOINT capture_recovery"); err != nil {
			store.recoveryFailed(err)
			return
		}
		entry := entries[id]
		var before int64
		if err := tx.QueryRow("SELECT total_changes()").Scan(&before); err != nil {
			store.recoveryFailed(err)
			return
		}
		finished, err := store.recoverCaptureEntry(tx, id, entry)
		if err != nil {
			store.recoveryFailed(err)
			if !canIsolateWriteError(err) {
				return
			}
			if _, err := tx.Exec("ROLLBACK TO capture_recovery"); err != nil {
				store.recoveryFailed(err)
				return
			}
		} else {
			done[id] = finished
			var after int64
			if err := tx.QueryRow("SELECT total_changes()").Scan(&after); err != nil {
				store.recoveryFailed(err)
				return
			}
			wrote = wrote || after > before
		}
		if _, err := tx.Exec("RELEASE capture_recovery"); err != nil {
			store.recoveryFailed(err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		store.recoveryFailed(err)
		return
	}
	store.recoveryMu.Lock()
	completed := 0
	for id, finished := range done {
		entry, exists := store.recoveries[id]
		if !exists || entry.version != entries[id].version {
			continue
		}
		if finished {
			delete(store.recoveries, id)
			completed++
		} else {
			entry.marked = true
			store.recoveries[id] = entry
		}
	}
	store.recoveryPending.Store(int32(len(store.recoveries)))
	store.recoveryMu.Unlock()
	if wrote {
		store.healthy.Store(true)
	}
	if completed > 0 && store.logger != nil {
		store.logger.Info("audit capture recovery completed", "recovered_entries", completed)
	}
}

func (store *Store) forgetFinishedRecovery(id string) {
	store.recoveryMu.Lock()
	defer store.recoveryMu.Unlock()
	delete(store.recoveries, id)
	store.recoveryPending.Store(int32(len(store.recoveries)))
}

func (store *Store) recoveryFailed(err error) {
	store.healthy.Store(false)
	if store.logger != nil {
		store.logger.Warn("audit capture recovery failed", "error_category", "capture_recovery_failed",
			"storage_error", ErrorClass(err), "pending_recoveries", store.recoveryPending.Load())
	}
}

func (store *Store) recoverCaptureEntry(tx *sql.Tx, id string, entry captureRecovery) (bool, error) {
	var ended sql.NullInt64
	if err := tx.QueryRow("SELECT ended_at_ns FROM audit_records WHERE audit_id=?", id).Scan(&ended); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return true, nil
		}
		return false, err
	}
	// An uncertain acknowledgement may accompany a committed outcome. Never
	// modify signed evidence, parse results or caller state a second time.
	if ended.Valid {
		return true, nil
	}
	if !entry.marked {
		if _, err := tx.Exec(`UPDATE audit_records SET capture_status='failed', error_code='capture_write_failed'
WHERE audit_id=? AND ended_at_ns IS NULL`, id); err != nil {
			return false, err
		}
		for index, loss := range entry.stages {
			if !loss.affected {
				continue
			}
			code := "capture_storage_failed"
			if loss.headers {
				code = "capture_headers_failed"
			}
			if _, err := tx.Exec(`UPDATE http_stages SET state='partial',
error_code=CASE WHEN error_code='capture_headers_failed' THEN error_code ELSE ? END
WHERE audit_id=? AND stage=?`, code, id, captureStageNames[index]); err != nil {
				return false, err
			}
			if _, err := tx.Exec(`UPDATE body_streams SET observed_length=MAX(observed_length, ?),
error_code=CASE WHEN ? THEN 'capture_chunk_missing' ELSE error_code END
WHERE audit_id=? AND stage=?`, loss.observed, loss.chunk, id, captureStageNames[index]); err != nil {
				return false, err
			}
		}
	}
	if entry.finish == nil {
		return true, nil
	}
	if entry.barrier > store.processedSequence {
		return false, nil
	}
	finish := cloneAuditFinish(*entry.finish)
	if err := finishAudit(tx, &finish, store.integrity.Load()); err != nil {
		return false, fmt.Errorf("sqlite: recover finalization: %w", err)
	}
	return true, nil
}
