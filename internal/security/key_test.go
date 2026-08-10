package security

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
)

func TestLoadOrCreateKeyCreatesAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "audit.key")
	created, err := LoadOrCreateKey(path, true)
	if err != nil {
		t.Fatalf("LoadOrCreateKey(create) error = %v", err)
	}
	if len(created) != KeySize {
		t.Fatalf("created key length = %d, want %d", len(created), KeySize)
	}

	loaded, err := LoadOrCreateKey(path, false)
	if err != nil {
		t.Fatalf("LoadOrCreateKey(load) error = %v", err)
	}
	if !bytes.Equal(loaded, created) {
		t.Fatal("reloaded key differs from created key")
	}

	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !bytes.Equal(stored, created) {
		t.Fatal("stored key differs from returned key")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat() error = %v", err)
		}
		if permissions := info.Mode().Perm(); permissions != 0o600 {
			t.Fatalf("key permissions = %#o, want 0600", permissions)
		}
	}
}

func TestLoadOrCreateKeyDoesNotCreateWhenForbidden(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.key")
	_, err := LoadOrCreateKey(path, false)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("LoadOrCreateKey() error = %v, want os.ErrNotExist", err)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("Stat() error = %v, want os.ErrNotExist", statErr)
	}
}

func TestLoadOrCreateKeyRejectsWrongLength(t *testing.T) {
	for _, size := range []int{0, KeySize - 1, KeySize + 1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.key")
			if err := os.WriteFile(path, bytes.Repeat([]byte{0x42}, size), 0o600); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}
			if _, err := LoadOrCreateKey(path, true); err == nil {
				t.Fatalf("LoadOrCreateKey() accepted %d-byte key", size)
			}
		})
	}
}

func TestLoadOrCreateKeyConcurrentCreatorsShareOneKey(t *testing.T) {
	const workers = 32
	path := filepath.Join(t.TempDir(), "nested", "audit.key")
	start := make(chan struct{})
	keys := make([][]byte, workers)
	errorsFound := make([]error, workers)

	var group sync.WaitGroup
	group.Add(workers)
	for index := 0; index < workers; index++ {
		go func(index int) {
			defer group.Done()
			<-start
			keys[index], errorsFound[index] = LoadOrCreateKey(path, true)
		}(index)
	}
	close(start)
	group.Wait()

	for index, err := range errorsFound {
		if err != nil {
			t.Fatalf("worker %d error = %v", index, err)
		}
		if !bytes.Equal(keys[index], keys[0]) {
			t.Fatalf("worker %d returned a different key", index)
		}
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !bytes.Equal(stored, keys[0]) {
		t.Fatal("stored key differs from concurrently returned key")
	}
}

func TestLoadOrCreateKeyRejectsEmptyPath(t *testing.T) {
	if _, err := LoadOrCreateKey("", true); err == nil {
		t.Fatal("LoadOrCreateKey() error = nil")
	}
}
