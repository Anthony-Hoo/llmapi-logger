// Package staging is the encrypted local staging of the unified write path
// (doc/design/issue-59-stage3-write-path.md F.3 to F.7). A body stage whose
// plaintext does not fit the memory budget hands its sealed chunks here; they
// are written to one file per audit and read back when a checkpoint or the
// commit inserts them into body_chunks. A file left behind by a process that
// stopped is imported at the next start, before interrupted audits are
// recovered.
//
// The chunks are stored in exactly the ciphertext format of body_chunks
// (bodycodec, then AES-GCM with the AAD (audit_id, "body_chunk_v2", stage,
// seq, compression)), so a staged chunk is inserted unchanged. The file adds
// no secret of its own: it holds ciphertext and the chunk metadata the
// database stores beside it.
package staging

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"

	"llmapi-logger/internal/bodycodec"
	"llmapi-logger/internal/storage"
)

// File format (F.4):
//
//	file   = header record*
//	header = "LLSTG\x00\x02\x00" u32be(len(audit_id)) audit_id
//	record = u32be(body_len) u32be(crc32c(body)) body
//	body   = stage_code(1) seq(u64be) offset(u64be) plaintext_length(u32be)
//	         encoded_length(u32be) observed_at_ns(u64be) compression(1) data_enc
//
// stage_code is 1 request_received, 2 request_sent, 3 response_received,
// 4 response_sent (as in the header block); compression is 0 none, 1 gzip.
// The CRC only finds a record the process did not finish writing; the AEAD
// is what authenticates a chunk.
const (
	magic = "LLSTG\x00\x02\x00"
	// recordPrefix is body_len and the CRC.
	recordPrefix = 8
	// recordMeta is the fixed part of a body before data_enc.
	recordMeta = 1 + 8 + 8 + 4 + 4 + 8 + 1
	// maxAuditID bounds the id in a header read from disk.
	maxAuditID = 256
	// maxRecordBody bounds a body read from disk: a chunk holds at most 1 MiB
	// of plaintext, and neither codec nor AEAD can grow it this far.
	maxRecordBody = 4 << 20
	// Suffix is the name suffix of a staging file: <audit_id>.stg.
	Suffix = ".stg"
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

func crc32Of(data []byte) uint32 { return crc32.Checksum(data, castagnoli) }

var stageCodes = [...]string{1: storage.StageRequestReceived, 2: storage.StageRequestSent, 3: storage.StageResponseReceived, 4: storage.StageResponseSent}

func stageCode(stage string) (byte, bool) {
	for code, name := range stageCodes {
		if code > 0 && name == stage {
			return byte(code), true
		}
	}
	return 0, false
}

func compressionCode(compression string) (byte, bool) {
	switch compression {
	case bodycodec.CompressionNone:
		return 0, true
	case bodycodec.CompressionGZIP:
		return 1, true
	default:
		return 0, false
	}
}

func compressionName(code byte) (string, bool) {
	switch code {
	case 0:
		return bodycodec.CompressionNone, true
	case 1:
		return bodycodec.CompressionGZIP, true
	default:
		return "", false
	}
}

// encodeHeader returns the file header for one audit.
func encodeHeader(auditID string) []byte {
	header := make([]byte, 0, len(magic)+4+len(auditID))
	header = append(header, magic...)
	header = binary.BigEndian.AppendUint32(header, uint32(len(auditID)))
	return append(header, auditID...)
}

// encodeRecordHead returns the length prefix, CRC and fixed metadata of a
// record; data_enc follows it unchanged, so it is never copied.
func encodeRecordHead(chunk storage.BodyChunk) ([]byte, error) {
	stage, ok := stageCode(chunk.Stage)
	if !ok {
		return nil, fmt.Errorf("staging: unknown stage %q", chunk.Stage)
	}
	compression, ok := compressionCode(chunk.Compression)
	if !ok {
		return nil, fmt.Errorf("staging: unknown compression %q", chunk.Compression)
	}
	if chunk.Seq < 0 || chunk.Offset < 0 || chunk.PlaintextLength < 0 || chunk.EncodedLength < 0 ||
		uint64(chunk.PlaintextLength) > 1<<32-1 || uint64(chunk.EncodedLength) > 1<<32-1 || len(chunk.DataEnc) == 0 {
		return nil, errors.New("staging: chunk metadata out of range")
	}
	bodyLength := recordMeta + len(chunk.DataEnc)
	if bodyLength > maxRecordBody {
		return nil, errors.New("staging: chunk too large")
	}
	head := make([]byte, recordPrefix, recordPrefix+recordMeta)
	head = append(head, stage)
	head = binary.BigEndian.AppendUint64(head, uint64(chunk.Seq))
	head = binary.BigEndian.AppendUint64(head, uint64(chunk.Offset))
	head = binary.BigEndian.AppendUint32(head, uint32(chunk.PlaintextLength))
	head = binary.BigEndian.AppendUint32(head, uint32(chunk.EncodedLength))
	head = binary.BigEndian.AppendUint64(head, uint64(chunk.ObservedAtNS))
	head = append(head, compression)
	crc := crc32.Update(crc32.Checksum(head[recordPrefix:], castagnoli), castagnoli, chunk.DataEnc)
	binary.BigEndian.PutUint32(head[0:4], uint32(bodyLength))
	binary.BigEndian.PutUint32(head[4:8], crc)
	return head, nil
}

// decodeRecordBody parses a record body whose CRC has been checked.
func decodeRecordBody(auditID string, body []byte) (storage.BodyChunk, error) {
	if len(body) <= recordMeta {
		return storage.BodyChunk{}, errors.New("staging: record body too short")
	}
	stageValue := body[0]
	if int(stageValue) >= len(stageCodes) || stageValue == 0 {
		return storage.BodyChunk{}, fmt.Errorf("staging: unknown stage code %d", stageValue)
	}
	compression, ok := compressionName(body[33])
	if !ok {
		return storage.BodyChunk{}, fmt.Errorf("staging: unknown compression code %d", body[33])
	}
	seq := binary.BigEndian.Uint64(body[1:9])
	offset := binary.BigEndian.Uint64(body[9:17])
	observed := binary.BigEndian.Uint64(body[25:33])
	if seq > 1<<62 || offset > 1<<62 || observed > 1<<63-1 {
		return storage.BodyChunk{}, errors.New("staging: record metadata out of range")
	}
	return storage.BodyChunk{
		AuditID:         auditID,
		Stage:           stageCodes[stageValue],
		Seq:             int64(seq),
		Offset:          int64(offset),
		PlaintextLength: int(binary.BigEndian.Uint32(body[17:21])),
		EncodedLength:   int(binary.BigEndian.Uint32(body[21:25])),
		ObservedAtNS:    int64(observed),
		Compression:     compression,
		DataEnc:         body[recordMeta:],
	}, nil
}

// parseHeader reads the audit id of a file header. It returns the header
// length, or an error when data does not start with a whole header.
func parseHeader(data []byte) (string, int, error) {
	if len(data) < len(magic)+4 {
		return "", 0, errTruncated
	}
	if string(data[:len(magic)]) != magic {
		return "", 0, errors.New("staging: not a staging file")
	}
	length := binary.BigEndian.Uint32(data[len(magic):])
	if length == 0 || length > maxAuditID {
		return "", 0, errors.New("staging: audit id length out of range")
	}
	end := len(magic) + 4 + int(length)
	if len(data) < end {
		return "", 0, errTruncated
	}
	return string(data[len(magic)+4 : end]), end, nil
}

var errTruncated = errors.New("staging: truncated")
