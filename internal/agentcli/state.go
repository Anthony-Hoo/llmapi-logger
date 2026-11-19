package agentcli

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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

func loadCredentials(env *Env) (*credentials, error) {
	dir, err := env.stateDir()
	if err != nil {
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
		return localFileError("cannot create the state directory", nil)
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

func ensurePrivateDir(dir string) error {
	info, err := os.Stat(dir)
	if err == nil {
		if !info.IsDir() {
			return errors.New("not a directory")
		}
		return nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return err
	}
	return createPrivateDir(dir)
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
