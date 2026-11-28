package auditbench

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func message(kind byte, parts ...[]byte) []byte {
	body := bytes.Join(parts, nil)
	encoded := []byte{kind, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(encoded[1:], uint32(len(body)+4))
	return append(encoded, body...)
}

func cstring(value string) []byte { return append([]byte(value), 0) }

func startupPacket(params ...string) []byte {
	body := []byte{0, 3, 0, 0}
	for _, param := range params {
		body = append(body, cstring(param)...)
	}
	body = append(body, 0)
	packet := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint32(packet, uint32(len(body)+4))
	return append(packet, body...)
}

func complete(tag string) []byte    { return message('C', cstring(tag)) }
func ready(status byte) []byte      { return message('Z', []byte{status}) }
func joined(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// fakeBackend accepts one connection, answers the startup with
// BackendKeyData carrying pid, then writes reply(kind) after each frontend
// message.
func fakeBackend(t *testing.T, pid int32, reply func(kind byte) []byte) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		length := make([]byte, 4)
		if _, err := io.ReadFull(reader, length); err != nil {
			return
		}
		if _, err := io.CopyN(io.Discard, reader, int64(binary.BigEndian.Uint32(length))-4); err != nil {
			return
		}
		key := make([]byte, 8)
		binary.BigEndian.PutUint32(key, uint32(pid))
		_, _ = connection.Write(joined(message('R', make([]byte, 4)), message('K', key), ready('I')))
		header := make([]byte, 5)
		for {
			if _, err := io.ReadFull(reader, header); err != nil {
				return
			}
			if _, err := io.CopyN(io.Discard, reader, int64(binary.BigEndian.Uint32(header[1:]))-4); err != nil {
				return
			}
			if answer := reply(header[0]); len(answer) > 0 {
				_, _ = connection.Write(answer)
			}
		}
	}()
	return listener.Addr().String()
}

func readUntilReady(t *testing.T, reader *bufio.Reader) {
	t.Helper()
	header := make([]byte, 5)
	for {
		if _, err := io.ReadFull(reader, header); err != nil {
			t.Fatal(err)
		}
		if _, err := io.CopyN(io.Discard, reader, int64(binary.BigEndian.Uint32(header[1:]))-4); err != nil {
			t.Fatal(err)
		}
		if header[0] == 'Z' {
			return
		}
	}
}

func dialRelay(t *testing.T, target string) (*wireCounter, net.Conn, *bufio.Reader) {
	t.Helper()
	counter, err := newWireCounter(target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(counter.close)
	client, err := net.Dial("tcp", counter.address())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return counter, client, bufio.NewReader(client)
}

func send(t *testing.T, client net.Conn, data ...[]byte) {
	t.Helper()
	if _, err := client.Write(joined(data...)); err != nil {
		t.Fatal(err)
	}
}

func TestWireCounterCountsWriterOperations(t *testing.T) {
	t.Parallel()
	target := fakeBackend(t, 4242, func(kind byte) []byte {
		switch kind {
		case 'E':
			return complete("SAVEPOINT")
		case 'Q':
			return joined(complete("SAVEPOINT"), ready('T'))
		case 'S':
			return ready('T')
		}
		return nil
	})
	counter, client, reader := dialRelay(t, target)
	// The relay refuses TLS itself, so the session stays readable.
	ssl := make([]byte, 8)
	binary.BigEndian.PutUint32(ssl, 8)
	binary.BigEndian.PutUint32(ssl[4:], sslRequestCode)
	send(t, client, ssl)
	answer := make([]byte, 1)
	if _, err := io.ReadFull(reader, answer); err != nil || answer[0] != 'N' {
		t.Fatalf("TLS answer %q, %v", answer, err)
	}
	send(t, client, startupPacket("user", "bench", "application_name", "llmapi-logger"))
	readUntilReady(t, reader)
	// A cached statement executed twice through the extended protocol, an
	// unrelated one, and one simple query.
	send(t, client,
		message('P', cstring("s1"), cstring("SAVEPOINT writer_operation"), []byte{0, 0}),
		message('P', cstring("s2"), cstring("SAVEPOINT begin_inbound"), []byte{0, 0}),
		message('B', cstring(""), cstring("s1"), make([]byte, 6)), message('E', cstring(""), make([]byte, 4)),
		message('B', cstring("p"), cstring("s2"), make([]byte, 6)), message('E', cstring("p"), make([]byte, 4)),
		message('B', cstring(""), cstring("s1"), make([]byte, 6)), message('E', cstring(""), make([]byte, 4)),
		message('S'))
	readUntilReady(t, reader)
	send(t, client, message('Q', cstring("savepoint writer_operation")))
	readUntilReady(t, reader)
	stats := counter.stats(4242)
	if stats.Writer.Connections != 1 || stats.Writer.Operations != 3 || stats.Writer.Statements != 4 || stats.Readers.Connections != 0 {
		t.Fatalf("stats = %+v", stats)
	}
	if other := counter.stats(1); other.Writer.Connections != 0 || other.Other.Operations != 3 {
		t.Fatalf("with another writer pid: %+v", other)
	}
}

func TestWireCounterCountsCommitsAndReaders(t *testing.T) {
	t.Parallel()
	replies := [][]byte{
		joined(complete("BEGIN"), ready('T')), joined(complete("INSERT 0 1"), ready('T')), joined(complete("COMMIT"), ready('I')),
		joined(complete("BEGIN"), ready('T')), joined(complete("ROLLBACK"), ready('I')), joined(complete("SELECT 1"), ready('I')),
	}
	next := 0
	target := fakeBackend(t, 7, func(kind byte) []byte {
		if kind != 'Q' || next >= len(replies) {
			return nil
		}
		next++
		return replies[next-1]
	})
	counter, client, reader := dialRelay(t, target)
	send(t, client, startupPacket("user", "bench", "default_transaction_read_only", "on"))
	readUntilReady(t, reader)
	before := counter.stats(0)
	for _, query := range []string{"begin", "insert", "commit", "begin", "rollback", "select 1"} {
		send(t, client, message('Q', cstring(query)))
		readUntilReady(t, reader)
	}
	stats := counter.stats(0).minus(before)
	if stats.Readers.Statements != 6 || stats.Readers.Commits != 1 || stats.Readers.Transactions != 2 || stats.Writer.Statements != 0 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestRelayDSN(t *testing.T) {
	t.Parallel()
	got, err := relayDSN("postgres://user:secret@db.example.com:5433/logger?sslmode=disable&search_path=s1", "127.0.0.1:6000")
	if err != nil {
		t.Fatal(err)
	}
	config, err := pgx.ParseConfig(got)
	if err != nil || config.Host != "127.0.0.1" || config.Port != 6000 || config.Database != "logger" || config.User != "user" ||
		config.RuntimeParams["search_path"] != "s1" {
		t.Fatalf("url form: %+v, %v", config, err)
	}
	got, err = relayDSN("host=db.example.com port=5433 user=user dbname=logger sslmode=disable", "127.0.0.1:6001")
	if err != nil {
		t.Fatal(err)
	}
	if config, err = pgx.ParseConfig(got); err != nil || config.Host != "127.0.0.1" || config.Port != 6001 {
		t.Fatalf("keyword form: %+v, %v", config, err)
	}
	for _, dsn := range []string{"postgres://user@db.example.com/logger?sslmode=require", "host=/var/run/postgresql dbname=logger"} {
		config, err := pgx.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := relayTarget(config); err == nil {
			t.Errorf("relayTarget(%q) accepted", dsn)
		}
	}
	config, _ = pgx.ParseConfig("postgres://user@db.example.com:5433/logger?sslmode=prefer")
	if target, err := relayTarget(config); err != nil || target != "db.example.com:5433" {
		t.Fatalf("prefer: %q, %v", target, err)
	}
}

func TestCompareWarnsAboutWritePathLabels(t *testing.T) {
	t.Parallel()
	base := Result{FormatVersion: FormatVersion, WritePath: WritePathInfo{Requested: "legacy", Effective: "legacy", CountStatements: true}}
	unified := base
	unified.WritePath = WritePathInfo{Requested: "unified", Effective: "unified", CountStatements: true}
	if warnings := strings.Join(writePathWarnings(base, unified), "\n"); !strings.Contains(warnings, "both runs relayed") || strings.Count(warnings, "\n") != 0 {
		t.Fatalf("relayed A/B: %s", warnings)
	}
	unrelayedA, unrelayedB := base, unified
	unrelayedA.WritePath.CountStatements, unrelayedB.WritePath.CountStatements = false, false
	if warnings := writePathWarnings(unrelayedA, unrelayedB); len(warnings) != 0 {
		t.Fatalf("clean A/B warned: %v", warnings)
	}
	label := base
	label.WritePath.Requested = "unified"
	if warnings := strings.Join(writePathWarnings(base, label), "\n"); !strings.Contains(warnings, "only by label") || !strings.Contains(warnings, "requested the unified") {
		t.Fatalf("label-only A/B: %s", warnings)
	}
	backlog := unified
	backlog.Client.ParseBacklog.Max = BacklogLimit + 1
	if warnings := strings.Join(writePathWarnings(base, backlog), "\n"); !strings.Contains(warnings, "backlog reached 101") {
		t.Fatalf("backlog: %s", warnings)
	}
	old := Result{FormatVersion: 1}
	var output strings.Builder
	compareResults(old, unified, "old.json", "new.json", &output)
	if text := output.String(); !strings.Contains(text, "does not record the write path") || !strings.Contains(text, "| writer commits per audit | count | n/a |") {
		t.Fatalf("format 1 comparison:\n%s", text)
	}
}

// The legacy write path is gone: --write-path names only unified, and a
// request for legacy says which binary still has it.
func TestRunRefusesTheRemovedLegacyWritePath(t *testing.T) {
	for value, want := range map[string]string{"legacy": "b807047", "fast": "must be unified"} {
		var stdout, stderr strings.Builder
		if code := Main(context.Background(), []string{"run", "--write-path", value}, func(string) string { return "" }, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), want) {
			t.Fatalf("--write-path %s: exit %d, stderr %q", value, code, stderr.String())
		}
	}
}
