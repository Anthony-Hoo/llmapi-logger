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
	"runtime"
	"strings"
	"unicode/utf16"

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
	// caData holds the CA file when it lies in the state directory: the bytes
	// read through the handle that was checked (checkCAFileInState), which
	// newHTTPClient uses instead of opening the file again.
	caData    []byte
	caInState bool
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
	path := filepath.Join(dir, credentialsFile)
	file, exists, problem := openStateFile(path)
	if !exists {
		return nil, &cliError{Code: agentapi.CodeNotLoggedIn}
	}
	if file != nil {
		defer file.Close()
	}
	// The directory is checked (and tightened) before the file, so its
	// problem is the one reported when both have one.
	if _, dirProblem := inspectPrivate(dir, true, 0o700, fix); dirProblem != "" {
		return nil, storeError(dir, dirProblem, 0o700)
	}
	data, problem := readStateFile(file, problem, 0o600, fix)
	if problem == problemUnreadable {
		return nil, localFileError("cannot read the local credentials", nil)
	}
	if problem != "" {
		return nil, storeError(path, problem, 0o600)
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

// loadConfig reads config.json. It names the CA the client trusts with the
// token, so it is checked like credentials.json before it is read (contract
// section 0.1 items 164 and 169). First the state directory itself must pass
// the store's rules (not a link, not of the wrong type, owned by the user,
// not sticky); a loose mode of the user's own directory is tightened when
// fix is true and refused otherwise, so no other user can replace a file in
// it from here on. config.json is then opened once without following links
// (openStateFile), checked on that handle (a regular file owned by the user;
// a loose mode is tightened through it when fix is true, refused otherwise)
// and read from that handle; a link, an entry that is not a regular file, or
// a file owned by another user is refused with LOCAL_FILE_ERROR and never
// read. Besides credentials.json, these are the only files the client reads
// from the state directory: config.json and, when it lies there, the CA file
// it names (checkCAFileInState).
func loadConfig(env *Env, fix bool) (localConfig, error) {
	var config localConfig
	dir, err := env.stateDir()
	if err != nil {
		return config, err
	}
	if exists, problem := inspectPrivate(dir, true, 0o700, fix); !exists {
		return config, nil
	} else if problem != "" {
		return config, storeError(dir, problem, 0o700)
	}
	path := filepath.Join(dir, configFile)
	file, exists, problem := openStateFile(path)
	if !exists {
		return config, nil
	}
	if file != nil {
		defer file.Close()
	}
	data, problem := readStateFile(file, problem, 0o600, fix)
	if problem == problemUnreadable {
		return config, localFileError("cannot read config.json", nil)
	}
	if problem != "" {
		return config, configFileError(path, problem)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return config, localFileError("config.json is not valid: it accepts only {\"ca_file\": \"<path>\"}", nil)
	}
	if config.caData, config.caInState, err = checkCAFileInState(dir, config.CAFile, fix); err != nil {
		return config, err
	}
	return config, nil
}

// checkCAFileInState applies the same checks to the CA file config.json
// names when it lies inside the state directory, and to every directory
// between: a CA file planted there would decide which server gets the token
// just as config.json does. The directories are checked (and tightened) by
// path, and they lie in the state directory loadConfig has just made
// private; the file itself is opened once without following links, checked
// on that handle and read from it, and those bytes are what the TLS
// configuration trusts (inState true). A CA file elsewhere is the user's
// choice and is read by newHTTPClient as it is (inState false).
func checkCAFileInState(dir, caFile string, fix bool) ([]byte, bool, error) {
	if caFile == "" {
		return nil, false, nil
	}
	path, err := filepath.Abs(caFile)
	if err != nil {
		return nil, false, nil // newHTTPClient reports the unreadable file
	}
	relative, err := filepath.Rel(dir, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return nil, false, nil
	}
	refused := func(at, problem string, mode os.FileMode) error {
		return &cliError{Code: agentapi.CodeLocalFileError,
			Message: "the CA file config.json names lies in the state directory and is a link, of the wrong type, owned by another user, or accessible to others, so it is not read",
			Hint:    "Ask the user to check it: a CA file in the state directory must be a regular file owned by them with mode 0600, or config.json must name one elsewhere.",
			Details: map[string]any{"path": at, "reason": problem, "required_mode": fmt.Sprintf("%04o", mode)}}
	}
	unreadable := localFileError("cannot read the CA file named in config.json", nil)
	parts := strings.Split(relative, string(filepath.Separator))
	at := dir
	for _, part := range parts[:len(parts)-1] {
		at = filepath.Join(at, part)
		exists, problem := inspectPrivate(at, true, 0o700, fix)
		if !exists {
			return nil, true, unreadable
		}
		if problem != "" {
			return nil, true, refused(at, problem, 0o700)
		}
	}
	at = filepath.Join(at, parts[len(parts)-1])
	file, exists, problem := openStateFile(at)
	if !exists {
		return nil, true, unreadable
	}
	if file != nil {
		defer file.Close()
	}
	data, problem := readStateFile(file, problem, 0o600, fix)
	if problem == problemUnreadable {
		return nil, true, unreadable
	}
	if problem != "" {
		return nil, true, refused(at, problem, 0o600)
	}
	return data, true, nil
}

// readStateFile checks a file openStateFile opened (checkStateFile, on that
// handle) and reads it from the same handle; problem is openStateFile's, and
// when it or the check names one nothing is read.
func readStateFile(file *os.File, problem string, mode os.FileMode, fix bool) ([]byte, string) {
	if problem != "" {
		return nil, problem
	}
	if problem := checkStateFile(file, mode, fix); problem != "" {
		return nil, problem
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, problemUnreadable
	}
	return data, ""
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

// configFileError is the LOCAL_FILE_ERROR for a config.json that is not
// read.
func configFileError(path, problem string) *cliError {
	return &cliError{Code: agentapi.CodeLocalFileError,
		Message: "config.json in the state directory is a link, not a regular file, owned by another user, or accessible to others, so it is not read",
		Hint: "config.json names the CA the client trusts with the token. Ask the user to check it: it must be a regular file owned by them with mode 0600 " +
			"(chmod 600 <dir>/config.json), or be removed.",
		Details: map[string]any{"path": path, "reason": problem, "required_mode": "0600"}}
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
// user's own state directory is tightened by loadConfig, before config.json
// is read and before any request, and that of credentials.json by
// saveCredentials.
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

// tempFileWriter is what writeAtomic writes the temporary file through. It
// is the file itself; tests replace it to make a write fail part way, as a
// full disk would.
var tempFileWriter = func(file *os.File) io.Writer { return file }

// writeAtomic writes target through a temporary file in the same directory
// and renames it over target. private makes the file readable by the current
// user only; any other temporary file has a random name as long as the
// target's, the name outPath proved can be created. It returns the size and
// SHA-256 of what was written.
func writeAtomic(target string, private bool, write func(io.Writer) error) (int64, string, error) {
	return writeAtomicChecked(target, private, write, nil)
}

// writeAtomicChecked is writeAtomic with a check of what was written, run
// before the temporary file replaces target: when check returns an error the
// temporary file is removed and target is left as it was.
func writeAtomicChecked(target string, private bool, write func(io.Writer) error, check func(size int64, sum string) error) (int64, string, error) {
	dir := filepath.Dir(target)
	var file *os.File
	var tempPath string
	var err error
	if private {
		file, tempPath, err = createPrivateTemp(dir)
	} else {
		file, tempPath, err = createSameLength(dir, filepath.Base(target))
	}
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
	if err := write(io.MultiWriter(tempFileWriter(file), hash, counter)); err != nil {
		return 0, "", err
	}
	sum := hex.EncodeToString(hash.Sum(nil))
	if check != nil {
		if err := check(counter.count, sum); err != nil {
			return 0, "", err
		}
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
	return counter.count, sum, nil
}

// createPrivateTemp creates a private temporary file with a short fixed
// prefix in dir.
func createPrivateTemp(dir string) (*os.File, string, error) {
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

// nameLength is the length of a file name in the unit the file system limits
// it in: UTF-16 code units on Windows (NTFS), bytes elsewhere.
func nameLength(name string) int {
	if runtime.GOOS == "windows" {
		return len(utf16.Encode([]rune(name)))
	}
	return len(name)
}

// sameLengthName is a fresh random name of nameLength(name), made of ASCII
// letters and digits (so bytes and UTF-16 units agree), starting with
// tempPrefix when it is long enough to leave eight random characters.
func sameLengthName(name string) (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	length := nameLength(name)
	prefix := ""
	switch {
	case length >= len(tempPrefix)+8:
		prefix = tempPrefix
	case length >= 2:
		prefix = "."
	case length < 1:
		length = 1
	}
	random := make([]byte, length-len(prefix))
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	for index, value := range random {
		random[index] = alphabet[int(value)%len(alphabet)]
	}
	return prefix + string(random), nil
}

// createSameLength creates, exclusively, a file in dir with a fresh random
// name as long as name (sameLengthName). It never creates or opens anything
// at name itself: a random name equal to it, also without regard to case
// (Windows and macOS compare names so), is skipped.
func createSameLength(dir, name string) (*os.File, string, error) {
	for attempt := 0; attempt < 10; attempt++ {
		random, err := sameLengthName(name)
		if err != nil {
			return nil, "", err
		}
		if strings.EqualFold(random, name) {
			continue
		}
		path := filepath.Join(dir, random)
		file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
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
