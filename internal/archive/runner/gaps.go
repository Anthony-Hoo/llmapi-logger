package runner

import "llmapi-logger/internal/archive/bundle"

// gaps exports the audit_gaps rows that ended before the cutoff and are in
// no segment yet (C.6, H.2) into gap bundles of at most gapBundleLimit gaps,
// each registered, published, re-read and sealed like a segment. Nothing is
// deleted: removing exported gaps from the hot store is the removal phase.
func (current *run) gaps() error {
	options := current.options()
	snapshot, err := options.Store.OpenSnapshot(current.ctx)
	if err != nil {
		return current.snapshotFailure(err)
	}
	defer snapshot.Close()
	var after int64
	for {
		if err := current.ctx.Err(); err != nil {
			return err
		}
		gaps, err := snapshot.DueGaps(current.cutoffNS, after, gapBundleLimit)
		if err != nil {
			return current.snapshotFailure(err)
		}
		if len(gaps) == 0 {
			return nil
		}
		writerOptions, release := current.writerOptions()
		writer, err := bundle.NewGapSegment(writerOptions)
		release()
		if err != nil {
			return current.writeFailure(err)
		}
		ids := make([]int64, 0, len(gaps))
		for _, gap := range gaps {
			if err := writer.Add(gap); err != nil {
				return current.writeFailure(err)
			}
			ids = append(ids, gap.ID)
		}
		sealed, err := writer.Seal()
		if err != nil {
			return current.writeFailure(err)
		}
		if _, err := current.commit(false, sealed, nil, ids); err != nil {
			return err
		}
		current.result.ExportedGaps += int64(len(ids))
		after = gaps[len(gaps)-1].ID
		if len(gaps) < gapBundleLimit {
			return nil
		}
	}
}
