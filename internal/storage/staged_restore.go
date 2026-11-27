package storage

// Start-up import of local staging (doc/design/issue-59-stage3-write-path.md
// F.7). A staging file holds sealed chunks of one audit whose plaintext did
// not fit the memory budget; the import puts the ones the database does not
// have yet back into body_chunks before RecoverInterruptedAudits finalizes
// the audit. Both stores apply the same rules through StagedRestorePlan.

// Outcomes of RestoreStagedChunks.
const (
	// StagedRestoreImported: the audit is open; every chunk was inserted,
	// already present, or reported in the result.
	StagedRestoreImported = "imported"
	// StagedRestoreFinalized: the audit is finalized (the process stopped
	// after its commit and before the file was removed); nothing is written.
	StagedRestoreFinalized = "finalized"
	// StagedRestoreNoAudit: there is no audit row for the file.
	StagedRestoreNoAudit = "no_audit"
)

// StagedChunkRestore is the input of RestoreStagedChunks: the verified chunks
// of one staging file, in file order.
type StagedChunkRestore struct {
	AuditID string
	Chunks  ChunkSource
}

// StagedChunkRestoreResult says what RestoreStagedChunks did with the chunks.
type StagedChunkRestoreResult struct {
	Outcome string
	// Inserted chunks were missing and are now stored; Present ones were
	// already stored by a checkpoint or the commit.
	Inserted int
	Present  int
	// Borrowed counts chunks of a duplicate stage whose body row points at
	// its source (merged at checkpoint 1): the source's chunks are the
	// evidence, so these are not inserted.
	Borrowed int
	// NoBody lists stages with chunks but without a body row: the checkpoint
	// that should have written the row was lost.
	NoBody []string
	// Discontinuous lists stages where a chunk did not continue the stored
	// chunks (seq and offset); that chunk and the rest of the stage are not
	// inserted.
	Discontinuous []string
}

// StoredChunkRun is what a body already has in body_chunks: the next seq
// and the end offset of the stored chunks, which are contiguous from 0.
type StoredChunkRun struct {
	Next int64
	End  int64
}

// StagedRestorePlan decides, chunk by chunk, what an import inserts. bodies
// maps each stage with a body row to its source_stage; stored maps stages to
// their stored chunks.
type StagedRestorePlan struct {
	bodies map[string]string
	stored map[string]StoredChunkRun
	result StagedChunkRestoreResult
	run    map[string]StoredChunkRun
	broken map[string]bool
	noBody map[string]bool
}

func NewStagedRestorePlan(bodies map[string]string, stored map[string]StoredChunkRun) *StagedRestorePlan {
	return &StagedRestorePlan{bodies: bodies, stored: stored}
}

// Filter returns a source over the chunks of source the plan inserts. Each
// pass starts the decisions afresh, so the result describes the last pass.
func (plan *StagedRestorePlan) Filter(source ChunkSource) ChunkSource {
	return stagedRestoreFilter{plan: plan, source: source}
}

// Result returns the decisions of the last pass. Its outcome is imported.
func (plan *StagedRestorePlan) Result() StagedChunkRestoreResult {
	result := plan.result
	result.Outcome = StagedRestoreImported
	for _, stage := range stageNames {
		if plan.noBody[stage] {
			result.NoBody = append(result.NoBody, stage)
		}
		if plan.broken[stage] {
			result.Discontinuous = append(result.Discontinuous, stage)
		}
	}
	return result
}

var stageNames = [...]string{StageRequestReceived, StageRequestSent, StageResponseReceived, StageResponseSent}

type stagedRestoreFilter struct {
	plan   *StagedRestorePlan
	source ChunkSource
}

func (filter stagedRestoreFilter) Each(visit func(BodyChunk) error) error {
	plan := filter.plan
	plan.result = StagedChunkRestoreResult{}
	plan.run = make(map[string]StoredChunkRun, len(plan.stored))
	for stage, run := range plan.stored {
		plan.run[stage] = run
	}
	plan.broken = map[string]bool{}
	plan.noBody = map[string]bool{}
	if filter.source == nil {
		return nil
	}
	return filter.source.Each(func(chunk BodyChunk) error {
		source, ok := plan.bodies[chunk.Stage]
		switch {
		case !ok:
			plan.noBody[chunk.Stage] = true
			return nil
		case source != chunk.Stage:
			plan.result.Borrowed++
			return nil
		case plan.broken[chunk.Stage]:
			return nil
		}
		run := plan.run[chunk.Stage]
		switch {
		case chunk.Seq < run.Next:
			plan.result.Present++
			return nil
		case chunk.Seq != run.Next || chunk.Offset != run.End:
			plan.broken[chunk.Stage] = true
			return nil
		}
		if err := visit(chunk); err != nil {
			return err
		}
		plan.result.Inserted++
		plan.run[chunk.Stage] = StoredChunkRun{Next: run.Next + 1, End: run.End + int64(chunk.PlaintextLength)}
		return nil
	})
}
