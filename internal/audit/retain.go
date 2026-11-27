package audit

import "llmapi-logger/internal/storage"

// Body capture has two layers (design H.1). The observation layer, shared by
// both write paths, is observeBodyLocked and its callers: hash, length,
// first and last observation time, the SSE timeline, the terminal-event probe
// and the fault flags. The retention layer decides what happens to the
// observed bytes and is a bodyRetainer:
//
//   - legacyRetainer stages at most one 1 MiB chunk in bodyCapture.pending and
//     hands every full chunk, and the tail at the end of the body, to
//     AddChunk;
//   - unifiedRetainer keeps the plaintext in memory segments, lets a
//     duplicate stage borrow its source's bytes instead of copying them, and
//     seals chunks at the same boundaries only when a checkpoint or the commit
//     writes them.
type bodyRetainer interface {
	// retain is called with every observed piece of a body, after the
	// observation layer has accounted for it, under the session lock.
	retain(session *Session, stage *stageCapture, body *bodyCapture, data []byte, observedAtNS int64)
	// flush ends the open chunk when it is full, or always with force.
	flush(session *Session, stage *stageCapture, body *bodyCapture, force bool)
}

// legacyRetainer is today's retention; its state lives in bodyCapture
// (pending, pendingAtNS, nextSeq, storedLength, chunkCount).
type legacyRetainer struct{}

// retention returns the session's retainer. A Session without one, including
// the zero value, uses the legacy retainer.
func (session *Session) retention() bodyRetainer {
	if session.retainer != nil {
		return session.retainer
	}
	return legacyRetainer{}
}

// unifiedRetainer keeps body plaintext in memory until a checkpoint or the
// commit writes it (design B.5, F.2). Chunk boundaries follow the legacy
// rule: a chunk closes when it holds bodyChunkSize bytes or when the body
// ends (force), so the chunk rows are the ones legacy writes.
type unifiedRetainer struct{}

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
	// staged is the sealed chunk a ChunkStager took; data is then released.
	staged *storage.BodyChunk
}

// unifiedBody is the retention state of one stage body on the unified path.
type unifiedBody struct {
	chunks []*heldChunk
	open   *heldChunk
	// retained is the length of the retained prefix, borrowed bytes included.
	retained int64
	// source is the stage this duplicate compares with and borrows from;
	// borrowing is true while every byte so far equals the source's.
	source    *bodyCapture
	borrowing bool
	// borrowed marks a source a duplicate borrows from: its plaintext must
	// stay in memory until Finish.
	borrowed  bool
	ownBytes  int64
	exhausted bool
}

func (unifiedRetainer) retain(session *Session, stage *stageCapture, body *bodyCapture, data []byte, observedAtNS int64) {
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
		if same == len(data) {
			return
		}
		// The first byte that cannot be compared with the source starts the
		// bytes this stage owns; the prefix stays borrowed.
		held.borrowing = false
		data = data[same:]
	}
	session.appendRetainedLocked(stage, body, data, observedAtNS, true)
}

func (unifiedRetainer) flush(session *Session, stage *stageCapture, body *bodyCapture, force bool) {
	held := body.unified
	if held == nil || held.open == nil {
		return
	}
	if held.open.length == bodyChunkSize || force && held.open.length > 0 {
		held.closeOpen(body)
	} else if force {
		held.open = nil
	}
}

// matching returns how many leading bytes of data equal this body's retained
// bytes at position.
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

// read appends the retained bytes [from, to) of a body that owns them.
func (held *unifiedBody) read(destination []byte, from, to int64) ([]byte, bool) {
	for _, chunk := range held.chunks {
		if from >= to {
			break
		}
		end := chunk.offset + chunk.length
		if end <= from || chunk.offset >= to {
			continue
		}
		ownStart := end - int64(len(chunk.data))
		if chunk.staged != nil || from < ownStart {
			return destination, false
		}
		upto := min(end, to)
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
		if held.open == nil {
			held.open = &heldChunk{offset: held.retained, at: observedAtNS}
			held.chunks = append(held.chunks, held.open)
		}
		chunk := held.open
		count := int(min(int64(len(data)), bodyChunkSize-chunk.length))
		if own {
			count = session.reserveRetainedLocked(stage, body, count)
			if count == 0 {
				session.exhaustRetentionLocked(stage, body)
				return
			}
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
// handing chunks to the stager when the global budget is full.
func (session *Session) reserveRetainedLocked(stage *stageCapture, body *bodyCapture, count int) int {
	held := body.unified
	manager := session.manager
	wanted := int64(count)
	for min(wanted, manager.stageBytes-held.ownBytes) <= 0 {
		if !session.stageOneChunkLocked(stage, body) {
			return 0
		}
	}
	count = int(min(wanted, manager.stageBytes-held.ownBytes))
	for !manager.budget.reserve(int64(count)) {
		if !session.stageOneChunkLocked(stage, body) {
			return 0
		}
	}
	held.ownBytes += int64(count)
	session.memoryHeld += int64(count)
	return count
}

// stageOneChunkLocked hands the oldest closed chunk the stage owns in full to
// the stager and releases its plaintext. A source a duplicate borrows from
// keeps its plaintext. It reports whether memory was released.
func (session *Session) stageOneChunkLocked(stage *stageCapture, body *bodyCapture) bool {
	held := body.unified
	if held.borrowed {
		return false
	}
	// A chunk a checkpoint already wrote needs no staging: its plaintext is
	// only a cache once no duplicate borrows from it.
	for _, chunk := range held.chunks {
		if chunk.closed && chunk.written && len(chunk.data) > 0 {
			session.releaseHeldLocked(held, chunk)
			return true
		}
	}
	for _, chunk := range held.chunks {
		if !chunk.closed || chunk.staged != nil || chunk.written || int64(len(chunk.data)) != chunk.length {
			continue
		}
		sealed, failure := session.sealChunkLocked(stage, int64(chunkIndex(held, chunk)), chunk.offset, chunk.data, chunk.at)
		if failure != "" {
			return false
		}
		if err := session.manager.stager.StageChunk(sealed); err != nil {
			return false
		}
		chunk.staged = &sealed
		session.releaseHeldLocked(held, chunk)
		return true
	}
	return false
}

func chunkIndex(held *unifiedBody, target *heldChunk) int {
	for index, chunk := range held.chunks {
		if chunk == target {
			return index
		}
	}
	return -1
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
// kept in full.
func (session *Session) exhaustRetentionLocked(stage *stageCapture, body *bodyCapture) {
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
	body.faulted = true
	body.errorCode = "capture_budget_exhausted"
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
// yet. A chunk that cannot be sealed is lost, like a legacy chunk whose
// flush failed: the body is faulted and the chunk leaves the stored length.
// The returned slice is handed to the store, which may keep it.
func (session *Session) sealUnwrittenLocked(stage *stageCapture) []storage.BodyChunk {
	body := stage.body
	if body == nil || body.unified == nil {
		return nil
	}
	held := body.unified
	var sealed []storage.BodyChunk
	for index, chunk := range held.chunks {
		if !chunk.closed || chunk.written {
			continue
		}
		if chunk.staged != nil {
			sealed = append(sealed, *chunk.staged)
			continue
		}
		failure := "body_encryption_failed"
		plaintext, ok := chunkPlaintext(body, chunk)
		if ok {
			var value storage.BodyChunk
			value, failure = session.sealChunkLocked(stage, int64(index), chunk.offset, plaintext, chunk.at)
			if failure == "" {
				sealed = append(sealed, value)
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

// releaseRetainedLocked drops every plaintext the session holds.
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
