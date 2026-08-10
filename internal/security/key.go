package security

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const KeySize = 32

// LoadOrCreateKey loads a raw 32-byte AES-256 key. When allowCreate is true
// and the file does not exist, it publishes a fully written temporary file via
// an atomic hard link. Concurrent creators therefore all observe the same key
// and an existing key is never overwritten.
func LoadOrCreateKey(path string, allowCreate bool) ([]byte, error) {
	if path == "" {
		return nil, errors.New("security: key path is empty")
	}

	key, err := loadKey(path)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if !allowCreate {
		return nil, err
	}
	return createKey(path)
}

func loadKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("security: read key file: %w", err)
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("security: key file must contain exactly %d bytes, got %d", KeySize, len(key))
	}
	return key, nil
}

func createKey(path string) ([]byte, error) {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("security: create key directory: %w", err)
	}

	// Another process may have created the key while the directory was being
	// prepared. Reading it here avoids unnecessary temporary files in that case.
	if key, err := loadKey(path); err == nil {
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("security: generate key: %w", err)
	}

	temporary, err := os.CreateTemp(directory, ".audit-key-*")
	if err != nil {
		return nil, fmt.Errorf("security: create temporary key file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()

	if err := temporary.Chmod(0o600); err != nil {
		return nil, fmt.Errorf("security: restrict temporary key permissions: %w", err)
	}
	if err := writeAll(temporary, key); err != nil {
		return nil, fmt.Errorf("security: write temporary key file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return nil, fmt.Errorf("security: sync temporary key file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return nil, fmt.Errorf("security: close temporary key file: %w", err)
	}

	if err := os.Link(temporaryPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return loadKey(path)
		}
		return nil, fmt.Errorf("security: publish key file atomically: %w", err)
	}
	return key, nil
}

func writeAll(file *os.File, data []byte) error {
	for len(data) > 0 {
		written, err := file.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}
