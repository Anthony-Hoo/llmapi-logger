package agentcli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"

	"llmapi-logger/internal/agentapi"
)

// runRead is every plain read command: GET the route, check the envelope
// and print it, or write data to --out.
func runRead(inv *invocation) (*result, error) {
	route, err := inv.route()
	if err != nil {
		return nil, err
	}
	path, err := inv.path(route)
	if err != nil {
		return nil, err
	}
	// An unusable --out fails before the server is asked, so a failed command
	// neither logs a sensitive view nor uses quota.
	target := ""
	if inv.has("out") {
		if target, err = outPath(inv); err != nil {
			return nil, err
		}
	}
	c, err := inv.client()
	if err != nil {
		return nil, err
	}
	ctx, cancel := inv.context()
	defer cancel()
	envelope, err := c.call(ctx, inv, route, path, inv.query(), nil)
	if err != nil {
		return nil, err
	}
	if target != "" {
		return inv.writeOut(envelope, c.server, target)
	}
	return &result{envelope: envelope, server: c.server}, nil
}

// compactData is data exactly as it is printed on stdout without --out.
func compactData(raw json.RawMessage) ([]byte, error) {
	var buffer bytes.Buffer
	if err := json.Compact(&buffer, raw); err != nil {
		return nil, &cliError{Code: agentapi.CodeInvalidResponse, Message: "the response data is not valid JSON"}
	}
	return buffer.Bytes(), nil
}

// outSummary is what replaces data on stdout when --out is given.
type outSummary struct {
	Path          string `json:"path"`
	Bytes         int64  `json:"bytes"`
	SHA256        string `json:"sha256"`
	Complete      *bool  `json:"complete,omitempty"`
	MissingChunks *bool  `json:"missing_chunks,omitempty"`
}

// outPath resolves --out and checks, before anything is sent, that the file
// can be written there: the directory exists and takes a new file (the
// temporary file the atomic replace uses), the target is not a directory,
// its name can be created there (a missing target is created exclusively
// and removed), and on Windows an existing file is not read-only (it is
// opened for writing and not truncated).
func outPath(inv *invocation) (string, error) {
	target, err := filepath.Abs(inv.value("out"))
	if err != nil {
		return "", localFileError("the --out path is not usable", map[string]any{"field": "--out"})
	}
	details := map[string]any{"field": "--out", "path": target}
	if info, err := os.Stat(target); err == nil && info.IsDir() {
		return "", localFileError("--out names a directory; give a file name", details)
	}
	if info, err := os.Stat(filepath.Dir(target)); err != nil || !info.IsDir() {
		return "", localFileError("the directory of --out does not exist", details)
	}
	probe, probePath, err := createTemp(filepath.Dir(target), false)
	if err != nil {
		return "", localFileError("the directory of --out does not accept a new file", details)
	}
	_ = probe.Close()
	_ = os.Remove(probePath)
	// The longest name the write uses is the target's own (the temporary
	// file's name is short and fixed). A name the file system cannot hold
	// (too long in bytes on Linux, in UTF-16 units on NTFS, or not allowed
	// there) fails only when the file is created, so a target that does not
	// exist is created exclusively and removed again: that proves the name
	// and leaves nothing behind. An existing target already proves it and
	// is not touched.
	switch _, err := os.Lstat(target); {
	case errors.Is(err, fs.ErrNotExist):
		created, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return "", localFileError("the --out file cannot be created in its directory: the name is too long or not allowed there", details)
		}
		_ = created.Close()
		if err := os.Remove(target); err != nil {
			return "", localFileError("the --out file cannot be created in its directory", details)
		}
	case err != nil:
		return "", localFileError("the --out file name is not usable: it is too long or not allowed there", details)
	}
	// Windows cannot rename over a read-only file; POSIX can.
	if info, err := os.Lstat(target); err == nil && info.Mode().IsRegular() && runtime.GOOS == "windows" {
		existing, err := os.OpenFile(target, os.O_WRONLY, 0)
		if err != nil {
			return "", localFileError("the existing --out file cannot be replaced", details)
		}
		_ = existing.Close()
	}
	return target, nil
}

// writeOut writes {"meta": …, "data": …} to --out and replaces data on
// stdout with the file summary; meta and the explanatory fields stay as the
// server sent them. The file carries meta so that a file read later still
// says whether its data is complete; its data is byte for byte what stdout
// would carry without --out.
func (inv *invocation) writeOut(envelope *serverEnvelope, server, target string) (*result, error) {
	data, err := compactData(envelope.Data)
	if err != nil {
		return nil, err
	}
	meta := []byte("null")
	if len(envelope.Meta) > 0 {
		if meta, err = compactData(envelope.Meta); err != nil {
			return nil, err
		}
	}
	content := make([]byte, 0, len(meta)+len(data)+20)
	content = append(append(append(append(content, `{"meta":`...), meta...), `,"data":`...), data...)
	content = append(content, '}')
	size, sum, err := writeAtomic(target, false, func(writer io.Writer) error {
		_, err := writer.Write(content)
		return err
	})
	if err != nil {
		return nil, localFileError("cannot write the --out file", map[string]any{"field": "--out", "path": target})
	}
	summary, _ := json.Marshal(outSummary{Path: target, Bytes: size, SHA256: sum})
	replaced := *envelope
	replaced.Data = summary
	return &result{envelope: &replaced, server: server}, nil
}

// runExport streams an export to --out. The body is the content itself, not
// an envelope; failures are still envelopes.
func runExport(inv *invocation) (*result, error) {
	route, err := inv.route()
	if err != nil {
		return nil, err
	}
	path, err := inv.path(route)
	if err != nil {
		return nil, err
	}
	target, err := outPath(inv)
	if err != nil {
		return nil, err
	}
	c, err := inv.client()
	if err != nil {
		return nil, err
	}
	if err := inv.checkDeclared(route, nil, nil); err != nil {
		return nil, err
	}
	ctx, cancel := inv.context()
	defer cancel()
	response, err := c.send(ctx, route.Method, path, nil, nil)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		data, err := readLimited(ctx, response.Body)
		if err != nil {
			return nil, err
		}
		_, err = decodeEnvelope(response, data, false)
		if err == nil {
			err = invalidResponse(response.StatusCode, "the export failed without a failure envelope")
		}
		return nil, err
	}
	var copyErr error
	size, sum, err := writeAtomic(target, false, func(writer io.Writer) error {
		_, copyErr = io.Copy(writer, response.Body)
		return copyErr
	})
	if copyErr != nil {
		return nil, transportError(ctx, copyErr)
	}
	if err != nil {
		return nil, localFileError("cannot write the --out file", map[string]any{"field": "--out", "path": target})
	}
	summary := outSummary{Path: target, Bytes: size, SHA256: sum}
	complete, reason := exportCompleteness(response.Header)
	summary.Complete = &complete
	if value := response.Header.Get("X-Audit-Missing-Chunks"); value != "" {
		missing, parseErr := strconv.ParseBool(value)
		if parseErr == nil {
			summary.MissingChunks = &missing
		}
	}
	data, _ := json.Marshal(summary)
	meta, _ := json.Marshal(agentapi.Meta{State: "exported", Complete: complete, IncompleteReason: reason})
	ok := true
	return &result{envelope: &serverEnvelope{OK: &ok, Data: data, Meta: meta}, server: c.server}, nil
}

// exportCompleteness reads the completeness headers of an export. Only an
// explicit X-Audit-Complete: true is complete; a missing header means the
// server did not say, so the export is not called complete (contract
// section 0.1 items 49(e) and 96). The reason is the server's
// X-Audit-Incomplete-Reason when it is a plain reason word, otherwise
// capture_incomplete for an explicit "false" and completeness_unknown for a
// missing header.
func exportCompleteness(header http.Header) (bool, string) {
	value := header.Get("X-Audit-Complete")
	if value == "true" {
		return true, ""
	}
	if reason := header.Get("X-Audit-Incomplete-Reason"); reasonPattern.MatchString(reason) {
		return false, reason
	}
	if value == "" {
		return false, "completeness_unknown"
	}
	return false, "capture_incomplete"
}

var reasonPattern = regexp.MustCompile(`^[a-z][a-z_]{0,63}$`)

// runVersion reports the client version and, when it can reach the server,
// the two version headers. Failing to reach the server is not an error.
func runVersion(inv *invocation) (*result, error) {
	type serverVersions struct {
		Latest          string `json:"api_latest"`
		Minimum         string `json:"api_min"`
		Compatible      bool   `json:"compatible"`
		UpdateAvailable bool   `json:"update_available"`
	}
	data := struct {
		Client string          `json:"cli_version"`
		Server *serverVersions `json:"server"`
	}{Client: Version}
	meta := agentapi.Meta{State: "ok", Complete: true}
	// version only reads the credentials to reach the server: it checks the
	// credential store like every other command but never changes it.
	c, err := inv.clientWith(false)
	var cliErr *cliError
	switch {
	case errors.As(err, &cliErr) && cliErr.Code == agentapi.CodeNotLoggedIn:
		meta = agentapi.Meta{State: "ok", IncompleteReason: "not_logged_in"}
	case err != nil:
		return nil, err
	default:
		ctx, cancel := inv.context()
		defer cancel()
		route := &inv.spec.Routes[0]
		response, sendErr := c.send(ctx, route.Method, route.Path, nil, nil)
		if sendErr != nil {
			if errors.As(sendErr, &cliErr) && cliErr.Code == agentapi.CodeClientTooOld {
				minimum, _ := cliErr.Details["min_version"].(string)
				data.Server = &serverVersions{Minimum: minimum}
				break
			}
			meta = agentapi.Meta{State: "ok", IncompleteReason: "server_unreachable"}
			break
		}
		header := response.Header
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		response.Body.Close()
		versions := &serverVersions{Latest: header.Get(agentapi.HeaderLatest), Minimum: header.Get(agentapi.HeaderMin)}
		own, _ := agentapi.ParseVersion(Version)
		minimum, minOK := agentapi.ParseVersion(versions.Minimum)
		latest, latestOK := agentapi.ParseVersion(versions.Latest)
		versions.Compatible = !minOK || agentapi.CompareVersions(own, minimum) >= 0
		versions.UpdateAvailable = latestOK && agentapi.CompareVersions(own, latest) < 0
		if versions.Latest == "" && versions.Minimum == "" {
			meta = agentapi.Meta{State: "ok", IncompleteReason: "server_versions_missing"}
		}
		data.Server = versions
	}
	encodedData, _ := json.Marshal(data)
	encodedMeta, _ := json.Marshal(meta)
	ok := true
	envelope := &serverEnvelope{OK: &ok, Data: encodedData, Meta: encodedMeta}
	if data.Server != nil && !data.Server.Compatible {
		envelope.NextActions = []string{"This llmaudit is older than the server accepts: ask the user to reinstall the llmapi-audit skill from the Agent access page."}
	} else if data.Server != nil && data.Server.UpdateAvailable {
		envelope.NextActions = []string{"A newer llmaudit exists: the user can reinstall the llmapi-audit skill from the Agent access page."}
	}
	return &result{envelope: envelope}, nil
}

// runLogout revokes the token and removes the local credentials. When the
// server says the token is already invalid, the local credentials go too.
func runLogout(inv *invocation) (*result, error) {
	c, err := inv.client()
	if err != nil {
		return nil, err
	}
	ctx, cancel := inv.context()
	defer cancel()
	route := &inv.spec.Routes[0]
	envelope, err := c.call(ctx, inv, route, route.Path, nil, nil)
	if err != nil {
		var cliErr *cliError
		if errors.As(err, &cliErr) && (cliErr.Code == agentapi.CodeUnauthenticated || cliErr.Code == agentapi.CodeTokenExpired || cliErr.Code == agentapi.CodeTokenRevoked) {
			if removeErr := removeCredentials(inv.env); removeErr != nil {
				return nil, removeErr
			}
			data, _ := json.Marshal(map[string]any{"revoked": false, "token_already_invalid": string(cliErr.Code), "local_credentials_removed": true})
			ok := true
			return &result{envelope: &serverEnvelope{OK: &ok, Data: data}}, nil
		}
		return nil, err
	}
	if err := removeCredentials(inv.env); err != nil {
		return nil, err
	}
	var data map[string]any
	if json.Unmarshal(envelope.Data, &data) != nil || data == nil {
		data = map[string]any{}
	}
	data["local_credentials_removed"] = true
	envelope.Data, _ = json.Marshal(data)
	return &result{envelope: envelope}, nil
}
