package bundle

import (
	"errors"
	"path/filepath"

	"llmapi-logger/internal/archive"
)

// GapWriter writes one gap bundle: gaps/gaps-<first_id>-<last_id> with a
// lines file of audit_gaps rows (C.6) and a manifest whose members are empty
// and whose gaps field holds the id range (F.1). Gaps are added in strictly
// increasing id order. Errors are final, as for SegmentWriter.
type GapWriter struct {
	options     Options
	key         []byte
	faults      faults
	segmentID   string
	tempDir     string
	lines       *encodedFile
	firstID     int64
	lastID      int64
	count       int64
	first, last int64
	done        bool
}

// NewGapSegment starts a gap bundle: it creates gaps/ under the root and
// the temporary lines file there.
func NewGapSegment(options Options) (*GapWriter, error) {
	key, err := options.validate()
	if err != nil {
		return nil, err
	}
	writer := &GapWriter{options: options, key: key, faults: options.Fault, tempDir: filepath.Join(options.Root, GapsDir)}
	if writer.segmentID, err = randomHex(16); err != nil {
		clear(key)
		return nil, err
	}
	if err := makeDirs(writer.faults, options.Root, writer.tempDir); err != nil {
		clear(key)
		return nil, err
	}
	if writer.lines, err = newEncodedFile(writer.faults, writer.tempDir, writer.segmentID, roleLines, key); err != nil {
		clear(key)
		return nil, err
	}
	return writer, nil
}

// Add writes one gap.
func (writer *GapWriter) Add(gap archive.Gap) error {
	if writer.done {
		return fail(ReasonClosed, nil)
	}
	if writer.count > 0 && gap.ID <= writer.lastID {
		writer.Abort()
		return fail(ReasonOrder, errors.New("gap ids not strictly increasing"))
	}
	if err := writer.lines.writeEntry(archive.EncodeGap(gap)); err != nil {
		writer.Abort()
		return err
	}
	if writer.count == 0 {
		writer.firstID, writer.first, writer.last = gap.ID, gap.StartedAtNS, gap.EndedAtNS
	}
	writer.first, writer.last = min(writer.first, gap.StartedAtNS), max(writer.last, gap.EndedAtNS)
	writer.lastID = gap.ID
	writer.count++
	return nil
}

// Abort removes the temporary files of an unsealed gap bundle.
func (writer *GapWriter) Abort() {
	if writer.done {
		return
	}
	writer.done = true
	writer.lines.discard()
	clear(writer.key)
}

// Seal finishes the gaps file and writes the signed manifest as a temporary
// file, as SegmentWriter.Seal does.
func (writer *GapWriter) Seal() (*Sealed, error) {
	if writer.done {
		return nil, fail(ReasonClosed, nil)
	}
	sealed, err := writer.seal()
	if err != nil {
		writer.Abort()
		return nil, err
	}
	writer.done = true
	clear(writer.key)
	return sealed, nil
}

func (writer *GapWriter) seal() (*Sealed, error) {
	if writer.count == 0 {
		return nil, fail(ReasonEmptySegment, nil)
	}
	if err := writer.lines.close(); err != nil {
		return nil, err
	}
	base := gapBase(writer.firstID, writer.lastID)
	manifest := &archive.Manifest{
		Format: archive.FormatName, FormatVersion: archive.FormatVersion, SourceSchemaVersion: writer.options.SourceSchemaVersion,
		SegmentID: writer.segmentID, RunID: writer.options.RunID, BundleKind: archive.BundleGaps,
		Conversations: []string{}, FirstStartedAtNS: writer.first, LastEndedAtNS: writer.last, CreatedAtNS: writer.options.now(),
		Encrypted: writer.options.Encrypt, Tables: archive.ManifestTables(),
		Files: []archive.ManifestFile{{Role: archive.FileLines, Name: linesName(base, writer.options.Encrypt),
			Bytes: writer.lines.out.size, SHA256: writer.lines.out.sum()}},
		LineCount: writer.count, Members: []archive.ManifestMember{},
		Gaps: &archive.ManifestGaps{FirstID: writer.firstID, LastID: writer.lastID, Count: writer.count},
	}
	return sealSegment(writer.faults, writer.options, manifest, writer.tempDir, writer.tempDir, base, []*outFile{writer.lines.out})
}
