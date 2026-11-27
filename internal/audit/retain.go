package audit

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
