package web

import (
	"bytes"
	"io"
	"net/http"
)

const delayedWriteLimit = 128 << 10

// delayedWriter holds the first storage chunk so an authentication failure in
// that chunk can still become a normal JSON error response. Memory stays
// bounded because capture chunks are much smaller than delayedWriteLimit.
type delayedWriter struct {
	response  http.ResponseWriter
	buffer    bytes.Buffer
	committed bool
}

func newDelayedWriter(response http.ResponseWriter) *delayedWriter {
	return &delayedWriter{response: response}
}

func (writer *delayedWriter) Write(data []byte) (int, error) {
	if writer.committed {
		return writer.response.Write(data)
	}
	if writer.buffer.Len() == 0 && len(data) <= delayedWriteLimit {
		return writer.buffer.Write(data)
	}
	if err := writer.Commit(); err != nil {
		return 0, err
	}
	return writer.response.Write(data)
}

func (writer *delayedWriter) Commit() error {
	if writer.committed {
		return nil
	}
	writer.committed = true
	writer.response.WriteHeader(http.StatusOK)
	if writer.buffer.Len() == 0 {
		return nil
	}
	_, err := io.Copy(writer.response, &writer.buffer)
	return err
}

func (writer *delayedWriter) Committed() bool {
	return writer.committed
}
