package audit

import (
	"llmapi-logger/internal/audit/staging"
	"llmapi-logger/internal/storage"
)

// chunkItem is one chunk a checkpoint or the commit writes: ciphertext in
// memory, or the index entry of a staged chunk.
type chunkItem struct {
	chunk storage.BodyChunk
	ref   *staging.Ref
}

// chunkSet is the chunks of one write, in the order they were sealed.
type chunkSet []chunkItem

// source returns the set as the store's chunk source: a plain ChunkList when
// nothing is staged, so the common case is unchanged.
func (set chunkSet) source() storage.ChunkSource {
	if len(set) == 0 {
		return nil
	}
	list := make(storage.ChunkList, 0, len(set))
	for _, item := range set {
		if item.ref != nil {
			return stagedChunkSource(set)
		}
		list = append(list, item.chunk)
	}
	return list
}

// commitSource is source for a commit: when some chunks are staged it also
// hands the store what it needs if the commit fails for good
// (storage.StagedChunkHolder): the staged chunks alone, read from the
// staging file, and release, which removes that file once the store has
// written them.
func (set chunkSet) commitSource(release func()) storage.ChunkSource {
	source := set.source()
	if staged, ok := source.(stagedChunkSource); ok {
		return commitChunkSource{stagedChunkSource: staged, release: release}
	}
	return source
}

// payloadBytes sizes the ciphertext of the set; a staged chunk counts with
// its record size.
func (set chunkSet) payloadBytes() int64 {
	var total int64
	for _, item := range set {
		if item.ref != nil {
			total += item.ref.Size()
		} else {
			total += int64(len(item.chunk.DataEnc))
		}
	}
	return total
}

// stagedChunkSource is a chunk source of which some chunks are staged. It is
// an immutable snapshot taken under the session lock and can be iterated
// more than once. Each reads a staged chunk from the stager's memory or file
// without taking the session lock or waiting for the staging writer, so it
// is safe inside the store's writer and under the store's own locks; a read
// failure is returned unchanged, and the store treats it as a local error of
// that write (F.4).
type stagedChunkSource []chunkItem

func (source stagedChunkSource) Each(visit func(storage.BodyChunk) error) error {
	for _, item := range source {
		chunk := item.chunk
		if item.ref != nil {
			read, err := item.ref.Chunk()
			if err != nil {
				return err
			}
			chunk = read
		}
		if err := visit(chunk); err != nil {
			return err
		}
	}
	return nil
}

// EachMetadata yields the chunks without their staged ciphertext. The stores
// use it where only seq, offset and length matter (failure bookkeeping),
// which may run under their locks.
func (source stagedChunkSource) EachMetadata(visit func(storage.BodyChunk) error) error {
	for _, item := range source {
		chunk := item.chunk
		if item.ref != nil {
			chunk = item.ref.Metadata()
		}
		if err := visit(chunk); err != nil {
			return err
		}
	}
	return nil
}

// commitChunkSource is the chunk source of a commit with staged chunks.
type commitChunkSource struct {
	stagedChunkSource
	release func()
}

// StagedChunks returns the staged chunks of the commit only. A chunk that
// can no longer be read is skipped; the store then stops that stage at the
// gap.
func (source commitChunkSource) StagedChunks() storage.ChunkSource {
	return stagedOnlySource(source.stagedChunkSource)
}

// ReleaseStaged removes the staging file after the store committed the
// staged chunks with the failed audit's finalization.
func (source commitChunkSource) ReleaseStaged() { source.release() }

type stagedOnlySource []chunkItem

func (source stagedOnlySource) Each(visit func(storage.BodyChunk) error) error {
	for _, item := range source {
		if item.ref == nil {
			continue
		}
		chunk, err := item.ref.Chunk()
		if err != nil {
			continue
		}
		if err := visit(chunk); err != nil {
			return err
		}
	}
	return nil
}

func (source stagedOnlySource) EachMetadata(visit func(storage.BodyChunk) error) error {
	for _, item := range source {
		if item.ref == nil {
			continue
		}
		if err := visit(item.ref.Metadata()); err != nil {
			return err
		}
	}
	return nil
}
