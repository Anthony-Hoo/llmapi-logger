// Package bodycodec adaptively compresses large transient/raw evidence chunks
// before authenticated encryption and restores them for parser/query readers.
package bodycodec

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"mime"
	"strings"
	"time"
)

const (
	CompressionNone = "none"
	CompressionGZIP = "gzip"
)

func Encode(plaintext []byte, contentType string) (string, []byte, error) {
	if len(plaintext) < 128 || !compressible(contentType, plaintext) {
		return CompressionNone, append([]byte(nil), plaintext...), nil
	}
	var output bytes.Buffer
	writer, err := gzip.NewWriterLevel(&output, gzip.BestSpeed)
	if err != nil {
		return "", nil, err
	}
	writer.Header.ModTime = time.Unix(0, 0)
	writer.Header.OS = 255
	if _, err := writer.Write(plaintext); err != nil {
		_ = writer.Close()
		return "", nil, err
	}
	if err := writer.Close(); err != nil {
		return "", nil, err
	}
	compressed := output.Bytes()
	if len(compressed)+32 >= len(plaintext) {
		return CompressionNone, append([]byte(nil), plaintext...), nil
	}
	return CompressionGZIP, compressed, nil
}

func Decode(encoded []byte, compression string, expectedLength int) ([]byte, error) {
	if expectedLength < 0 {
		return nil, errors.New("bodycodec: negative expected length")
	}
	switch compression {
	case CompressionNone:
		if len(encoded) != expectedLength {
			return nil, errors.New("bodycodec: uncompressed length mismatch")
		}
		return append([]byte(nil), encoded...), nil
	case CompressionGZIP:
		reader, err := gzip.NewReader(bytes.NewReader(encoded))
		if err != nil {
			return nil, fmt.Errorf("bodycodec: open gzip: %w", err)
		}
		plaintext, readErr := io.ReadAll(io.LimitReader(reader, int64(expectedLength)+1))
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil {
			return nil, errors.Join(readErr, closeErr)
		}
		if len(plaintext) != expectedLength {
			return nil, errors.New("bodycodec: gzip length mismatch")
		}
		return plaintext, nil
	default:
		return nil, fmt.Errorf("bodycodec: unsupported compression %q", compression)
	}
}

func compressible(contentType string, data []byte) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err == nil {
		mediaType = strings.ToLower(mediaType)
		if strings.HasPrefix(mediaType, "text/") || strings.Contains(mediaType, "json") || strings.Contains(mediaType, "xml") || strings.Contains(mediaType, "svg") {
			return true
		}
		if strings.HasPrefix(mediaType, "image/") || strings.HasPrefix(mediaType, "audio/") || strings.HasPrefix(mediaType, "video/") {
			return false
		}
		switch mediaType {
		case "application/zip", "application/gzip", "application/x-gzip", "application/x-7z-compressed", "application/x-rar-compressed", "application/pdf":
			return false
		}
	}
	return !compressedMagic(data)
}

func compressedMagic(data []byte) bool {
	return bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")) ||
		bytes.HasPrefix(data, []byte("\xff\xd8\xff")) ||
		bytes.HasPrefix(data, []byte("GIF87a")) ||
		bytes.HasPrefix(data, []byte("GIF89a")) ||
		bytes.HasPrefix(data, []byte("PK\x03\x04")) ||
		bytes.HasPrefix(data, []byte("\x1f\x8b")) ||
		bytes.HasPrefix(data, []byte("%PDF-")) ||
		len(data) >= 12 && string(data[:4]) == "RIFF" && string(data[8:12]) == "WEBP"
}
