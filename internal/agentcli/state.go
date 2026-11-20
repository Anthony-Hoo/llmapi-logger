package agentcli

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"llmapi-logger/internal/agentapi"
)

const (
	credentialsFile = "credentials.json"
	configFile      = "config.json"
	// tempPrefix is the short fixed prefix of every temporary file.
	tempPrefix = ".llmaudit-"
)

// credentials is credentials.json: readable only by the current user.
type credentials struct {
	Server    string `json:"server"`
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	Role      string `json:"role,omitempty"`
	Tier      string `json:"tier,omitempty"`
}

// localConfig is the optional config.json.
type localConfig struct {
	CAFile string `json:"ca_file,omitempty"`
}

func localFileError(message string, details map[string]any) *cliError {
	return &cliError{Code: agentapi.CodeLocalFileError, Message: message, Details: details}
}

// loadCredentials reads credentials.json after checking the credential
// store (securePrivateState); fix says whether a loose mode of the user's own
// store may be tightened (every command that uses the token) or only
// reported (version, which changes nothing). Nothing is checked or changed
// when nothing is saved.
func loadCredentials(env *Env, fix bool) (*credentials, error) {
	dir, err := env.stateDir()
	if err != nil {
		return nil, err
	}
	if exists, problem := inspectPrivate(dir, true, 0o700, false); !exists {
		return nil, &cliError{Code: agentapi.CodeNotLoggedIn}
	} else if problem == problemSymlink || problem == problemNotDir {
		return nil, storeError(dir, problem, 0o700)
	}
	if exists, _ := inspectPrivate(filepath.Join(dir, credentialsFile), false, 0o600, false); !exists {
		return nil, &cliError{Code: agentapi.CodeNotLoggedIn}
	}
	if err := securePrivateState(dir, fix); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(dir, credentialsFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, &cliError{Code: agentapi.CodeNotLoggedIn}
	}
	if err != nil {
		return nil, localFileError("cannot read the local credentials", nil)
	}
	var creds credentials
	if err := json.Unmarshal(data, &creds); err != nil || creds.Server == "" || creds.Token == "" {
		return nil, &cliError{Code: agentapi.CodeNotLoggedIn, Message: "the local credentials are unreadable"}
	}
	return &creds, nil
}

func saveCredentials(env *Env, creds *credentials) error {
	dir, err := env.stateDir()
	if err != nil {
		return err
	}
	if err := ensurePrivateDir(dir); err != nil {
		return err
	}
	if err := securePrivateState(dir, true); err != nil {
		return err
	}
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return internalError("cannot encode the credentials")
	}
	if _, _, err := writeAtomic(filepath.Join(dir, credentialsFile), true, func(writer io.Writer) error {
		_, err := writer.Write(append(data, '\n'))
		return err
	}); err != nil {
		return localFileError("cannot write the local credentials", nil)
	}
	return nil
}

func removeCredentials(env *Env) error {
	dir, err := env.stateDir()
	if err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dir, credentialsFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return localFileError("cannot remove the local credentials", nil)
	}
	return nil
}

func loadConfig(env *Env) (localConfig, error) {
	var config localConfig
	dir, err := env.stateDir()
	if err != nil {
		return config, err
	}
	data, err := os.ReadFile(filepath.Join(dir, configFile))
	if errors.Is(err, fs.ErrNotExist) {
		return config, nil
	}
	if err != nil {
		return config, localFileError("cannot read config.json", nil)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return config, localFileError("config.json is not valid: it accepts only {\"ca_file\": \"<path>\"}", nil)
	}
	return config, nil
}

// What can be wrong with an entry of the credential store (details.reason
// of the LOCAL_FILE_ERROR).
const (
	problemSymlink    = "symlink"
	problemNotDir     = "not_a_directory"
	problemNotFile    = "not_a_regular_file"
	problemNotOwned   = "not_owned"
	problemShared     = "shared_directory"
	problemMode       = "accessible_to_others"
	problemUnreadable = "unreadable"
)

// entryKindProblem refuses a link and an entry of the wrong type.
func entryKindProblem(info fs.FileInfo, dir bool) string {
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		return problemSymlink
	case dir && !info.IsDir():
		return problemNotDir
	case !dir && !info.Mode().IsRegular():
		return problemNotFile
	}
	return ""
}

// storeError is the LOCAL_FILE_ERROR for an entry of the credential store;
// details.required_mode is the mode the entry needs, whatever is wrong.
func storeError(path, problem string, mode os.FileMode) *cliError {
	details := map[string]any{"path": path, "reason": problem, "required_mode": fmt.Sprintf("%04o", mode)}
	switch problem {
	case problemSymlink, problemNotDir, problemNotFile:
		return &cliError{Code: agentapi.CodeLocalFileError, Message: "the local credential store is a link or not of the expected type, so it is not used",
			Hint:    "Point LLMAUDIT_HOME at a real directory owned by you (or unset it to use ~/.llmaudit); credentials.json there must be a regular file, not a link. Ask the user to fix it.",
			Details: details}
	case problemNotOwned, problemShared:
		return &cliError{Code: agentapi.CodeLocalFileError, Message: "the local credential store is not owned by you or is a shared directory, so it is neither used nor changed",
			Hint:    "Point LLMAUDIT_HOME at a directory of your own that others cannot write to, such as the default ~/.llmaudit (unset LLMAUDIT_HOME). Ask the user to fix it.",
			Details: details}
	}
	return &cliError{Code: agentapi.CodeLocalFileError, Message: "the local credential store is accessible to other users and could not be made private",
		Hint:    "Make it private and run the command again: the state directory needs mode 0700 and credentials.json mode 0600 (chmod 700 <dir>; chmod 600 <dir>/credentials.json), both owned by you.",
		Details: details}
}

// securePrivateState checks the state directory and credentials.json before
// the credentials are read or replaced: neither may be a link, of the wrong
// type or owned by another user, and the directory may not be sticky (a
// shared directory such as /tmp itself); those are refused with
// LOCAL_FILE_ERROR and never changed. When fix is true an entry the user
// owns that group or others can access is made private (on POSIX 0700 and
// 0600); when fix is false, or that fails, the command stops with
// LOCAL_FILE_ERROR naming the path and the required modes. The file's
// content is never read here or printed, and nothing outside the state
// directory and the file is touched.
func securePrivateState(dir string, fix bool) error {
	file := filepath.Join(dir, credentialsFile)
	for _, item := range []struct {
		path string
		dir  bool
		mode os.FileMode
	}{{dir, true, 0o700}, {file, false, 0o600}} {
		if _, problem := inspectPrivate(item.path, item.dir, item.mode, fix); problem != "" {
			return storeError(item.path, problem, item.mode)
		}
	}
	return nil
}

// checkStoreBeforeLogin refuses, before a login starts, a credential store
// saveCredentials would refuse after the user approved, so no token is
// issued that cannot be saved. It changes nothing: a loose mode of the
// user's own store is left for saveCredentials to tighten.
func checkStoreBeforeLogin(env *Env) error {
	dir, err := env.stateDir()
	if err != nil {
		return err
	}
	exists, problem := inspectPrivate(dir, true, 0o700, false)
	if !exists {
		if info, err := os.Stat(filepath.Dir(dir)); err != nil || !info.IsDir() {
			return localFileError("the directory that should hold the state directory does not exist; it is not created",
				map[string]any{"path": dir, "reason": "parent_missing"})
		}
		return nil
	}
	if problem != "" && problem != problemMode {
		return storeError(dir, problem, 0o700)
	}
	file := filepath.Join(dir, credentialsFile)
	if _, problem := inspectPrivate(file, false, 0o600, false); problem != "" && problem != problemMode {
		return storeError(file, problem, 0o600)
	}
	return nil
}

// ensurePrivateDir creates the state directory with owner-only access when
// it does not exist. Its parent must exist: it is never created or changed.
func ensurePrivateDir(dir string) error {
	exists, problem := inspectPrivate(dir, true, 0o700, false)
	if exists {
		if problem == problemSymlink || problem == problemNotDir {
			return storeError(dir, problem, 0o700)
		}
		return nil
	}
	if info, err := os.Stat(filepath.Dir(dir)); err != nil || !info.IsDir() {
		return localFileError("the directory that should hold the state directory does not exist; it is not created",
			map[string]any{"path": dir, "reason": "parent_missing"})
	}
	if err := createPrivateDir(dir); err != nil {
		return localFileError("cannot create the state directory", map[string]any{"path": dir})
	}
	return nil
}

// writeAtomic writes target through a temporary file in the same directory
// and renames it over target. private makes the file readable by the current
// user only. It returns the size and SHA-256 of what was written.
func writeAtomic(target string, private bool, write func(io.Writer) error) (int64, string, error) {
	dir := filepath.Dir(target)
	file, tempPath, err := createTemp(dir, private)
	if err != nil {
		return 0, "", err
	}
	committed := false
	defer func() {
		if !committed {
			_ = file.Close()
			_ = os.Remove(tempPath)
		}
	}()
	hash := sha256.New()
	counter := &countingWriter{}
	if err := write(io.MultiWriter(file, hash, counter)); err != nil {
		return 0, "", err
	}
	if err := file.Sync(); err != nil {
		return 0, "", err
	}
	if err := file.Close(); err != nil {
		return 0, "", err
	}
	if err := os.Rename(tempPath, target); err != nil {
		_ = os.Remove(tempPath)
		committed = true
		return 0, "", err
	}
	committed = true
	return counter.count, hex.EncodeToString(hash.Sum(nil)), nil
}

func createTemp(dir string, private bool) (*os.File, string, error) {
	if !private {
		file, err := os.CreateTemp(dir, tempPrefix+"*")
		if err != nil {
			return nil, "", err
		}
		return file, file.Name(), nil
	}
	for attempt := 0; attempt < 10; attempt++ {
		var random [6]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", err
		}
		path := filepath.Join(dir, tempPrefix+hex.EncodeToString(random[:]))
		file, err := createPrivateFile(path)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		return file, path, nil
	}
	return nil, "", errors.New("cannot create a temporary file")
}

type countingWriter struct{ count int64 }

func (writer *countingWriter) Write(data []byte) (int, error) {
	writer.count += int64(len(data))
	return len(data), nil
}
