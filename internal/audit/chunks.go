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
