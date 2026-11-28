package audit

import (
	"llmapi-logger/internal/audit/staging"
	"llmapi-logger/internal/storage"
)

// Body capture has two layers (design H.1). The observation layer is
// observeBodyLocked and its callers: hash, length, first and last
// observation time, the SSE timeline, the terminal-event probe and the fault
// flags. The retention layer below decides what happens to the observed
// bytes: it keeps the plaintext in memory segments, lets a duplicate stage
// borrow its source's bytes instead of copying them, and seals chunks only
// when a checkpoint or the commit writes them (design B.5, F.2). Chunk
// boundaries follow the rule the legacy write path used: a chunk closes when
// it holds bodyChunkSize bytes or when the body ends (force), so the chunk
// rows are the ones it wrote. Plaintext the budgets cannot hold is sealed and
// handed to the stager (F.3); only under global budget pressure is a chunk
// closed early, shorter than 1 MiB.
// heldChunk is one chunk of a stage's own chunk grid. data holds the bytes
// the stage owns; a duplicate stage that borrows from its source owns only
// the tail from where it diverged, or nothing.
type heldChunk struct {
	offset  int64
	length  int64
	at      int64
	data    []byte
	closed  bool
	written bool
	// staged is the index entry of the sealed chunk the stager took; data is
	// then released.
	staged *staging.Ref
}

// unifiedBody is the retention state of one stage body.
type unifiedBody struct {
	chunks []*heldChunk
	open   *heldChunk
	// retained is the length of the retained prefix, borrowed bytes included.
	retained int64
	// source is the stage this duplicate compares with and borrows from;
	// borrowing is true while every byte so far equals the source's, and
	// borrowEnd is where it stopped.
	source    *bodyCapture
	borrowing bool
	borrowEnd int64
	// duplicate is the stage that borrows from this source.
	duplicate *bodyCapture
	ownBytes  int64
	exhausted bool
}

// borrowedPrefix is the length of the prefix this duplicate takes from its
// source.
func (held *unifiedBody) borrowedPrefix() int64 {
	if held.borrowing {
		return held.retained
	}
	return held.borrowEnd
}

// duplicateUse says what the duplicate of this source still needs from one
// chunk: pending, the duplicate has not compared the chunk's bytes yet;
// needed, the chunk overlaps the prefix the duplicate borrows, so its
// plaintext must stay in memory or be staged, never dropped (B.5).
func (held *unifiedBody) duplicateUse(chunk *heldChunk) (pending, needed bool) {
	if held.duplicate == nil || held.duplicate.unified == nil {
		return false, false
	}
	duplicate := held.duplicate.unified
	if duplicate.borrowing && !duplicate.exhausted && !held.duplicate.closed {
		return chunk.offset+chunk.length > duplicate.retained, true
	}
	return false, chunk.offset < duplicate.borrowedPrefix()
}

// retainLocked is called with every observed piece of a body, after the
// observation layer has accounted for it, under the session lock.
func (session *Session) retainLocked(stage *stageCapture, body *bodyCapture, data []byte, observedAtNS int64) {
	held := body.unified
	if held == nil || held.exhausted || len(data) == 0 {
		return
	}
	position := body.observedLength - int64(len(data))
	if position != held.retained {
		return
	}
	if held.borrowing {
		same := held.source.unified.matching(position, data)
		session.appendRetainedLocked(stage, body, data[:same], observedAtNS, false)
		if same == len(data) || held.exhausted {
			return
		}
		// The first byte that cannot be compared with the source starts the
		// bytes this stage owns; the prefix stays borrowed.
		held.borrowing = false
		held.borrowEnd = position + int64(same)
		data = data[same:]
	}
	session.appendRetainedLocked(stage, body, data, observedAtNS, true)
}

// flushRetainedLocked ends the open chunk when it is full, or always with
// force.
func (session *Session) flushRetainedLocked(body *bodyCapture, force bool) {
	held := body.unified
	if held == nil || held.open == nil {
		return
	}
	if held.open.length == bodyChunkSize || force && held.open.length > 0 {
		held.closeOpen(body)
	} else if force {
		held.chunks = held.chunks[:len(held.chunks)-1]
		held.open = nil
	}
}

// matching returns how many leading bytes of data equal this body's retained
// bytes at position. Staged bytes are not compared. Once the duplicate
// exists a source stages a chunk only after the duplicate compared it; a
// source read to its end before the duplicate started (a body interceptor's
// pre-read, which the application always has) may already have staged
// chunks, and the duplicate then owns its bytes from the first of them.
func (held *unifiedBody) matching(position int64, data []byte) int {
	if held == nil {
		return 0
	}
	available := held.retained - position
	if available <= 0 {
		return 0
	}
	limit := int(min(available, int64(len(data))))
	compared := 0
	for _, chunk := range held.chunks {
		if compared == limit {
			break
		}
		start := position + int64(compared)
		end := chunk.offset + chunk.length
		if end <= start || chunk.offset > start {
			continue
		}
		own := chunk.data
		ownStart := end - int64(len(own))
		if chunk.staged != nil || start < ownStart {
			break
		}
		piece := own[start-ownStart:]
		piece = piece[:min(len(piece), limit-compared)]
		for index := range piece {
			if piece[index] != data[compared+index] {
				return compared + index
			}
		}
		compared += len(piece)
	}
	return compared
}

// read appends the retained bytes [from, to) of a body that owns them. Bytes
// that were staged are read back from the stager and opened.
func (held *unifiedBody) read(destination []byte, from, to int64) ([]byte, bool) {
	for _, chunk := range held.chunks {
		if from >= to {
			break
		}
		end := chunk.offset + chunk.length
		if end <= from || chunk.offset >= to {
			continue
		}
		upto := min(end, to)
		if chunk.staged != nil {
			plaintext, err := chunk.staged.Plaintext()
			if err != nil || int64(len(plaintext)) != chunk.length {
				return destination, false
			}
			destination = append(destination, plaintext[from-chunk.offset:upto-chunk.offset]...)
			clear(plaintext)
			from = upto
			continue
		}
		ownStart := end - int64(len(chunk.data))
		if from < ownStart {
			return destination, false
		}
		destination = append(destination, chunk.data[from-ownStart:upto-ownStart]...)
		from = upto
	}
	return destination, from >= to
}

func (held *unifiedBody) closeOpen(body *bodyCapture) {
	held.open.closed = true
	body.storedLength += held.open.length
	body.chunkCount++
	held.open = nil
}

// appendRetainedLocked extends the chunk grid by data. With own the bytes are
// copied into the stage's memory, within the stage and global budgets;
// otherwise they are borrowed from the source.
func (session *Session) appendRetainedLocked(stage *stageCapture, body *bodyCapture, data []byte, observedAtNS int64, own bool) {
	held := body.unified
	for len(data) > 0 && !held.exhausted {
		room := int64(bodyChunkSize)
		if held.open != nil {
			room -= held.open.length
		}
		count := int(min(int64(len(data)), room))
		if own {
			// Reserving may stage chunks of this stage, and may close the
			// open chunk early, so the open chunk is taken afterwards.
			reserved, failure := session.reserveRetainedLocked(stage, body, count)
			if reserved == 0 {
				session.exhaustRetentionLocked(stage, body, failure)
				return
			}
			count = reserved
		}
		if held.open == nil {
			held.open = &heldChunk{offset: held.retained, at: observedAtNS}
			held.chunks = append(held.chunks, held.open)
		}
		chunk := held.open
		if own {
			if needed := len(chunk.data) + count; needed > cap(chunk.data) {
				next := make([]byte, len(chunk.data), min(bodyChunkSize, max(needed, 2*cap(chunk.data))))
				copy(next, chunk.data)
				chunk.data = next
			}
			chunk.data = append(chunk.data, data[:count]...)
		}
		chunk.length += int64(count)
		held.retained += int64(count)
		data = data[count:]
		if chunk.length == bodyChunkSize {
			held.closeOpen(body)
		}
	}
}

// reserveRetainedLocked returns how many of count bytes the budgets admit,
// staging chunks of this stage while the stage or the global budget is
// full. When nothing is admitted it also returns the error code of the
// stage's exhaustion.
//
// A source whose duplicate has not yet compared its oldest bytes cannot stage
// them; the duplicate lags by at most one read (B.5), so the bytes of that
// read are admitted over the budgets instead of ending retention.
func (session *Session) reserveRetainedLocked(stage *stageCapture, body *bodyCapture, count int) (int, string) {
	held := body.unified
	manager := session.manager
	wanted := int64(count)
	overshoot := false
	for !overshoot && min(wanted, manager.stageBytes-held.ownBytes) <= 0 {
		failure, pending := session.stageOneChunkLocked(stage, body)
		switch {
		case pending:
			overshoot = true
		case failure != "":
			return 0, failure
		}
	}
	if !overshoot {
		count = int(min(wanted, manager.stageBytes-held.ownBytes))
	}
	for !manager.budget.reserve(int64(count)) {
		failure, pending := session.stageOneChunkLocked(stage, body)
		if pending {
			queueBudget{budget: manager.budget}.Add(int64(count))
			break
		}
		if failure != "" {
			return 0, failure
		}
	}
	held.ownBytes += int64(count)
	session.memoryHeld += int64(count)
	return count, ""
}

// stageOneChunkLocked releases memory of one stage: the plaintext of a chunk
// a checkpoint already wrote, which is only a cache unless the stage's
// duplicate borrows it; otherwise, in seq order, the first chunk not yet
// staged is sealed and handed to the stager. The open chunk is closed early
// when it is all there is (F.2). Staging follows seq order so that what a
// file holds for a stage continues what the database holds. It returns the
// error code that ends retention when nothing could be released, or "";
// pending reports that the next chunk to stage waits for the duplicate.
func (session *Session) stageOneChunkLocked(stage *stageCapture, body *bodyCapture) (failure string, pending bool) {
	held := body.unified
	if session.committing {
		// A late read after the commit was built: nothing more is staged,
		// since the session releases its staging file right after.
		return "capture_budget_exhausted", false
	}
	for _, chunk := range held.chunks {
		if chunk.closed && chunk.written && chunk.staged == nil && len(chunk.data) > 0 {
			if _, needed := held.duplicateUse(chunk); !needed {
				session.releaseHeldLocked(held, chunk)
				return "", false
			}
		}
	}
	for index := 0; index < len(held.chunks); index++ {
		chunk := held.chunks[index]
		if chunk.staged != nil || chunk.written && len(chunk.data) == 0 {
			continue
		}
		if waiting, _ := held.duplicateUse(chunk); waiting {
			return "", true
		}
		if !chunk.closed {
			if chunk != held.open || chunk.length == 0 {
				return "capture_budget_exhausted", false
			}
			held.closeOpen(body)
		}
		plaintext, ok := chunkPlaintext(body, chunk)
		if !ok {
			return "capture_budget_exhausted", false
		}
		sealed, failure := session.sealChunkLocked(stage, int64(index), chunk.offset, plaintext, chunk.at)
		if int64(len(chunk.data)) != chunk.length {
			// A copy that includes borrowed bytes.
			clear(plaintext)
		}
		if failure != "" {
			return failure, false
		}
		ref, err := session.manager.stager.Stage(sealed)
		if err != nil {
			return stagingFailureCode(err), false
		}
		chunk.staged = ref
		session.stagedChunks = true
		freed := len(chunk.data) > 0
		if freed {
			session.releaseHeldLocked(held, chunk)
		}
		if !stage.spillWritten {
			session.spillCheckpointLocked(stage)
		}
		if freed {
			return "", false
		}
	}
	return "capture_budget_exhausted", false
}

func (session *Session) releaseHeldLocked(held *unifiedBody, chunk *heldChunk) {
	size := int64(len(chunk.data))
	clear(chunk.data)
	chunk.data = nil
	held.ownBytes -= size
	session.memoryHeld -= size
	session.manager.budget.release(size)
}

// exhaustRetentionLocked is design F.6: the stage keeps observing but stops
// retaining; what it holds is still written, the body is partial and raw is
// kept in full. errorCode is capture_budget_exhausted, or
// staging_write_failed when the staging file could not be written.
func (session *Session) exhaustRetentionLocked(stage *stageCapture, body *bodyCapture, errorCode string) {
	held := body.unified
	held.exhausted = true
	if held.open != nil {
		if held.open.length > 0 {
			held.closeOpen(body)
		} else {
			held.chunks = held.chunks[:len(held.chunks)-1]
			held.open = nil
		}
	}
	if errorCode == "" {
		errorCode = "capture_budget_exhausted"
	}
	body.faulted = true
	body.errorCode = errorCode
	session.markStageFaultLocked(stage, body.errorCode)
	session.recordGapReasonLocked(storage.GapReasonQueueFull)
}

// chunkPlaintext returns the plaintext of one chunk of the stage's grid: the
// borrowed prefix from the source followed by the bytes the stage owns.
func chunkPlaintext(body *bodyCapture, chunk *heldChunk) ([]byte, bool) {
	own := int64(len(chunk.data))
	if own == chunk.length {
		return chunk.data, true
	}
	source := body.unified.source
	if source == nil || source.unified == nil {
		return nil, false
	}
	plaintext := make([]byte, 0, chunk.length)
	plaintext, ok := source.unified.read(plaintext, chunk.offset, chunk.offset+chunk.length-own)
	if !ok {
		return nil, false
	}
	return append(plaintext, chunk.data...), true
}

// sealUnwrittenLocked seals the closed chunks of a stage no write has taken
// yet; a staged chunk is taken by its index entry. A chunk that cannot be
// sealed is lost, as a chunk whose flush failed was on the legacy path: the
// body is faulted and the chunk leaves the stored length. The returned chunks are handed to
// the store, which may keep them.
func (session *Session) sealUnwrittenLocked(stage *stageCapture) chunkSet {
	body := stage.body
	if body == nil || body.unified == nil {
		return nil
	}
	held := body.unified
	var sealed chunkSet
	for index, chunk := range held.chunks {
		if !chunk.closed || chunk.written {
			continue
		}
		if chunk.staged != nil {
			sealed = append(sealed, chunkItem{ref: chunk.staged})
			continue
		}
		failure := "body_encryption_failed"
		plaintext, ok := chunkPlaintext(body, chunk)
		if ok {
			var value storage.BodyChunk
			value, failure = session.sealChunkLocked(stage, int64(index), chunk.offset, plaintext, chunk.at)
			if failure == "" {
				sealed = append(sealed, chunkItem{chunk: value})
				continue
			}
		}
		chunk.written = true
		body.storedLength -= chunk.length
		body.chunkCount--
		body.faulted = true
		body.errorCode = failure
		session.markStageFaultLocked(stage, failure)
	}
	return sealed
}

// markSealedWritten records that a write took the chunks sealUnwrittenLocked
// returned.
func markSealedWritten(stage *stageCapture) {
	if stage.body == nil || stage.body.unified == nil {
		return
	}
	for _, chunk := range stage.body.unified.chunks {
		if chunk.closed {
			chunk.written = true
		}
	}
}

// releaseRetainedLocked drops every plaintext the session holds and its
// index of staged chunks.
func (session *Session) releaseRetainedLocked() {
	for _, stage := range session.stages {
		if stage.body == nil || stage.body.unified == nil {
			continue
		}
		for _, chunk := range stage.body.unified.chunks {
			clear(chunk.data)
			chunk.data = nil
			chunk.staged = nil
		}
		stage.body.unified.ownBytes = 0
		// A late Read or Close after Finish must not retain again.
		stage.body.unified.exhausted = true
		stage.body.unified.open = nil
	}
	if session.manager != nil {
		session.manager.budget.release(session.memoryHeld)
	}
	session.memoryHeld = 0
}
