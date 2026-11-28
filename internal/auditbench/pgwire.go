package auditbench

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
)

// wireCounter relays the application's PostgreSQL connections and counts,
// per connection, what the protocol shows: completed statements, writer
// operations, commits and ended transactions. It is the only way to tell the
// writer's transactions from the reader pool's statements without changing
// the store, because PostgreSQL keeps transaction counters per database, not
// per backend.
//
// Bytes are relayed unchanged; the counter only reads message headers, the
// SQL text of Parse and Query messages and the tags of CommandComplete. It
// refuses TLS and GSS encryption to the application (answering 'N') and
// talks plain TCP to the server, so it works only where the server accepts a
// plain connection, as local test databases do.
type wireCounter struct {
	listener net.Listener
	target   string

	mu     sync.Mutex
	conns  []*wireConn
	closed bool
	wait   sync.WaitGroup
}

// wireConn holds the counters of one relayed connection.
type wireConn struct {
	pid      atomic.Int32
	readOnly atomic.Bool
	cancel   atomic.Bool

	statements atomic.Int64
	operations atomic.Int64
	commits    atomic.Int64
	ended      atomic.Int64
	bytesIn    atomic.Int64
	bytesOut   atomic.Int64
}

// WireCounts are the relayed protocol counters of one class of connections.
type WireCounts struct {
	Connections int64 `json:"connections"`
	// Statements counts CommandComplete messages: every statement that
	// finished, including BEGIN, SAVEPOINT, RELEASE and COMMIT.
	Statements int64 `json:"statements"`
	// Operations counts executions of SAVEPOINT writer_operation: one per
	// writer operation (postgres commitBatch wraps each in it).
	Operations int64 `json:"writer_operations"`
	// Commits counts COMMIT that committed (tag COMMIT); Transactions counts
	// explicit transactions that ended, committed or rolled back.
	Commits      int64 `json:"commits"`
	Transactions int64 `json:"transactions_ended"`
	// BytesToServer and BytesFromServer are protocol bytes.
	BytesToServer   int64 `json:"bytes_to_server"`
	BytesFromServer int64 `json:"bytes_from_server"`
}

func (counts WireCounts) minus(other WireCounts) WireCounts {
	return WireCounts{
		Connections: counts.Connections - other.Connections, Statements: counts.Statements - other.Statements,
		Operations: counts.Operations - other.Operations, Commits: counts.Commits - other.Commits,
		Transactions:  counts.Transactions - other.Transactions,
		BytesToServer: counts.BytesToServer - other.BytesToServer, BytesFromServer: counts.BytesFromServer - other.BytesFromServer,
	}
}

// WireStats split the relayed counters by connection: the writer (the
// backend that holds the writer lock), the read-only reader pool (sessions
// started with default_transaction_read_only=on) and any other.
type WireStats struct {
	Available bool       `json:"available"`
	Writer    WireCounts `json:"writer"`
	Readers   WireCounts `json:"readers"`
	Other     WireCounts `json:"other"`
}

func (stats WireStats) minus(other WireStats) WireStats {
	return WireStats{Available: stats.Available && other.Available, Writer: stats.Writer.minus(other.Writer),
		Readers: stats.Readers.minus(other.Readers), Other: stats.Other.minus(other.Other)}
}

func newWireCounter(target string) (*wireCounter, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	counter := &wireCounter{listener: listener, target: target}
	counter.wait.Add(1)
	go counter.accept()
	return counter, nil
}

func (counter *wireCounter) address() string { return counter.listener.Addr().String() }

func (counter *wireCounter) accept() {
	defer counter.wait.Done()
	for {
		client, err := counter.listener.Accept()
		if err != nil {
			return
		}
		connection := &wireConn{}
		counter.mu.Lock()
		if counter.closed {
			counter.mu.Unlock()
			_ = client.Close()
			return
		}
		counter.conns = append(counter.conns, connection)
		counter.wait.Add(1)
		counter.mu.Unlock()
		go func() {
			defer counter.wait.Done()
			connection.relay(client, counter.target)
		}()
	}
}

// close stops accepting. Relayed connections end when the application closes
// them.
func (counter *wireCounter) close() {
	counter.mu.Lock()
	counter.closed = true
	counter.mu.Unlock()
	_ = counter.listener.Close()
}

// stats adds up the counters by class. writerPID identifies the writer.
func (counter *wireCounter) stats(writerPID int32) WireStats {
	counter.mu.Lock()
	conns := append([]*wireConn(nil), counter.conns...)
	counter.mu.Unlock()
	result := WireStats{Available: true}
	for _, connection := range conns {
		if connection.cancel.Load() {
			continue
		}
		target := &result.Other
		switch {
		case writerPID != 0 && connection.pid.Load() == writerPID:
			target = &result.Writer
		case connection.readOnly.Load():
			target = &result.Readers
		}
		target.Connections++
		target.Statements += connection.statements.Load()
		target.Operations += connection.operations.Load()
		target.Commits += connection.commits.Load()
		target.Transactions += connection.ended.Load()
		target.BytesToServer += connection.bytesIn.Load()
		target.BytesFromServer += connection.bytesOut.Load()
	}
	return result
}

const (
	sslRequestCode    = 80877103
	gssRequestCode    = 80877104
	cancelRequestCode = 80877102
	maxStartupLength  = 10000
)

func (connection *wireConn) relay(client net.Conn, target string) {
	defer client.Close()
	clientReader := bufio.NewReaderSize(client, 64<<10)
	startup, err := connection.readStartup(clientReader, client)
	if err != nil {
		return
	}
	server, err := net.Dial("tcp", target)
	if err != nil {
		return
	}
	defer server.Close()
	if _, err := server.Write(startup); err != nil {
		return
	}
	connection.bytesIn.Add(int64(len(startup)))
	if connection.cancel.Load() {
		_, _ = io.Copy(io.Discard, server)
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection.fromServer(bufio.NewReaderSize(server, 64<<10), bufio.NewWriterSize(client, 64<<10))
		_ = client.Close()
	}()
	connection.fromClient(clientReader, bufio.NewWriterSize(server, 64<<10))
	_ = server.Close()
	<-done
}

// readStartup answers SSL and GSS encryption requests with 'N' and returns
// the startup or cancel packet to forward.
func (connection *wireConn) readStartup(reader *bufio.Reader, client net.Conn) ([]byte, error) {
	for {
		header := make([]byte, 8)
		if _, err := io.ReadFull(reader, header); err != nil {
			return nil, err
		}
		length := int(binary.BigEndian.Uint32(header[:4]))
		code := binary.BigEndian.Uint32(header[4:8])
		if length < 8 || length > maxStartupLength {
			return nil, errors.New("bad startup length")
		}
		packet := make([]byte, length)
		copy(packet, header)
		if _, err := io.ReadFull(reader, packet[8:]); err != nil {
			return nil, err
		}
		switch code {
		case sslRequestCode, gssRequestCode:
			if _, err := client.Write([]byte{'N'}); err != nil {
				return nil, err
			}
			continue
		case cancelRequestCode:
			connection.cancel.Store(true)
			return packet, nil
		}
		// StartupMessage: name/value pairs after the protocol version.
		fields := bytes.Split(packet[8:], []byte{0})
		for index := 0; index+1 < len(fields); index += 2 {
			if string(fields[index]) == "default_transaction_read_only" && strings.EqualFold(string(fields[index+1]), "on") {
				connection.readOnly.Store(true)
			}
		}
		return packet, nil
	}
}

// writerOperationSQL is what postgres commitBatch runs before each writer
// operation (internal/storage/postgres/writer.go).
const writerOperationSQL = "savepoint writer_operation"

func isWriterOperation(query string) bool {
	return strings.EqualFold(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(query), ";")), writerOperationSQL)
}

// fromClient relays frontend messages and follows the extended protocol:
// Parse names a statement's SQL, Bind binds a portal to a statement, and
// Execute runs a portal; a simple Query carries its SQL.
func (connection *wireConn) fromClient(reader *bufio.Reader, writer *bufio.Writer) {
	statements := map[string]bool{}
	portals := map[string]bool{}
	header := make([]byte, 5)
	for {
		if reader.Buffered() == 0 {
			if writer.Flush() != nil {
				return
			}
		}
		if _, err := io.ReadFull(reader, header); err != nil {
			_ = writer.Flush()
			return
		}
		kind := header[0]
		length := int64(binary.BigEndian.Uint32(header[1:5])) - 4
		if length < 0 {
			return
		}
		if _, err := writer.Write(header); err != nil {
			return
		}
		connection.bytesIn.Add(5 + length)
		var err error
		switch kind {
		case 'Q', 'P', 'B', 'E':
			var names []string
			names, err = copyNames(reader, writer, length, map[byte]int{'Q': 1, 'P': 2, 'B': 2, 'E': 1}[kind])
			if err != nil {
				return
			}
			switch kind {
			case 'Q':
				if len(names) == 1 && isWriterOperation(names[0]) {
					connection.operations.Add(1)
				}
			case 'P':
				if len(names) == 2 {
					statements[names[0]] = isWriterOperation(names[1])
				}
			case 'B':
				if len(names) == 2 {
					portals[names[0]] = statements[names[1]]
				}
			case 'E':
				if len(names) == 1 && portals[names[0]] {
					connection.operations.Add(1)
				}
			}
		default:
			_, err = io.CopyN(writer, reader, length)
		}
		if err != nil {
			return
		}
	}
}

// copyNames copies a message body of length bytes, reading its first count
// NUL-terminated strings, and returns them.
func copyNames(reader *bufio.Reader, writer *bufio.Writer, length int64, count int) ([]string, error) {
	names := make([]string, 0, count)
	for range count {
		if length <= 0 {
			break
		}
		value, used, err := readCString(reader, writer, length)
		if err != nil {
			return nil, err
		}
		length -= used
		names = append(names, value)
	}
	if length > 0 {
		if _, err := io.CopyN(writer, reader, length); err != nil {
			return nil, err
		}
	}
	return names, nil
}

// readCString copies one NUL-terminated string of at most limit bytes and
// returns its first 256 bytes, which is all the counter compares.
func readCString(reader *bufio.Reader, writer *bufio.Writer, limit int64) (string, int64, error) {
	var kept []byte
	var used int64
	for used < limit {
		value, err := reader.ReadByte()
		if err != nil {
			return "", used, err
		}
		used++
		if err := writer.WriteByte(value); err != nil {
			return "", used, err
		}
		if value == 0 {
			return string(kept), used, nil
		}
		if len(kept) < 256 {
			kept = append(kept, value)
		}
	}
	return string(kept), used, nil
}

// fromServer relays backend messages and reads BackendKeyData (the backend
// pid), CommandComplete (statement tags) and ReadyForQuery (transaction
// status).
func (connection *wireConn) fromServer(reader *bufio.Reader, writer *bufio.Writer) {
	header := make([]byte, 5)
	status := byte('I')
	for {
		if reader.Buffered() == 0 {
			if writer.Flush() != nil {
				return
			}
		}
		if _, err := io.ReadFull(reader, header); err != nil {
			_ = writer.Flush()
			return
		}
		kind := header[0]
		length := int64(binary.BigEndian.Uint32(header[1:5])) - 4
		if length < 0 {
			return
		}
		if _, err := writer.Write(header); err != nil {
			return
		}
		connection.bytesOut.Add(5 + length)
		var err error
		switch {
		case kind == 'K' && length >= 4, kind == 'Z' && length == 1, kind == 'C' && length <= 256:
			body := make([]byte, length)
			if _, err = io.ReadFull(reader, body); err != nil {
				return
			}
			_, err = writer.Write(body)
			switch kind {
			case 'K':
				connection.pid.Store(int32(binary.BigEndian.Uint32(body[:4])))
			case 'Z':
				if status != 'I' && body[0] == 'I' {
					connection.ended.Add(1)
				}
				status = body[0]
			case 'C':
				connection.statements.Add(1)
				if string(bytes.TrimRight(body, "\x00")) == "COMMIT" {
					connection.commits.Add(1)
				}
			}
		default:
			if kind == 'C' {
				connection.statements.Add(1)
			}
			_, err = io.CopyN(writer, reader, length)
		}
		if err != nil {
			return
		}
	}
}
