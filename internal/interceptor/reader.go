package interceptor

import (
	"bytes"
	"io"
)

// readerOnly deliberately narrows bytes.Reader to io.Reader, preventing an
// interceptor from reaching its backing bytes through a concrete return type.
type readerOnly struct {
	reader *bytes.Reader
}

func (r readerOnly) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}

func newReadOnlyBytesReader(data []byte) io.Reader {
	return readerOnly{reader: bytes.NewReader(data)}
}
