// Package state persists agent identity and source cursors with atomic file replacement.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Identity is the enrolled agent identity. The credential is a secret: the file is 0600.
type Identity struct {
	AgentID             string `json:"agent_id"`
	TenantID            string `json:"tenant_id"`
	Credential          string `json:"credential"`
	CredentialExpiresAt string `json:"credential_expires_at"`
}

// Cursor is a resumable position in one source.
type Cursor struct {
	FileID string `json:"file_id,omitempty"` // device/inode or equivalent identity
	Offset int64  `json:"offset"`
	// RecordID is used by record-based sources (Windows event log).
	RecordID uint64 `json:"record_id,omitempty"`
	Resets   int    `json:"resets"`
}

// WriteJSONAtomic writes v to path via a temp file + rename (crash-safe on the same volume).
func WriteJSONAtomic(path string, v any, perm os.FileMode) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := func() { _ = os.Remove(name) }
	if err := tmp.Chmod(perm); err != nil && !errors.Is(err, os.ErrInvalid) {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(name, path); err != nil {
		cleanup()
		return err
	}
	return nil
}

// LoadIdentity reads the identity file.
func LoadIdentity(dir string) (*Identity, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "identity.json"))
	if err != nil {
		return nil, fmt.Errorf("agent is not enrolled (run `aegis-agent enroll`): %w", err)
	}
	var id Identity
	if err := json.Unmarshal(raw, &id); err != nil {
		return nil, fmt.Errorf("corrupt identity file: %w", err)
	}
	if id.AgentID == "" || id.Credential == "" {
		return nil, errors.New("identity file is incomplete")
	}
	return &id, nil
}

// SaveIdentity writes the identity with owner-only permissions.
func SaveIdentity(dir string, id *Identity) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return WriteJSONAtomic(filepath.Join(dir, "identity.json"), id, 0o600)
}

// Cursors is a concurrency-safe cursor store persisted as one JSON file.
type Cursors struct {
	mu   sync.Mutex
	path string
	data map[string]Cursor
}

// OpenCursors loads cursors.json (missing file = empty store).
func OpenCursors(dir string) (*Cursors, error) {
	c := &Cursors{path: filepath.Join(dir, "cursors.json"), data: map[string]Cursor{}}
	raw, err := os.ReadFile(c.path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &c.data); err != nil {
		return nil, fmt.Errorf("corrupt cursors file: %w", err)
	}
	return c, nil
}

// Get returns the cursor for a source.
func (c *Cursors) Get(name string) (Cursor, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.data[name]
	return v, ok
}

// Set updates and persists a cursor.
func (c *Cursors) Set(name string, cur Cursor) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[name] = cur
	return WriteJSONAtomic(c.path, c.data, 0o600)
}
