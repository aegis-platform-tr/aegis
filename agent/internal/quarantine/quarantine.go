// Package quarantine keeps malformed or rejected input for operator review, bounded in size.
package quarantine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// MaxSampleBytes bounds how much of a bad line is retained.
const MaxSampleBytes = 2048

// Store appends JSON lines to quarantine.jsonl and rotates once at maxBytes (keeping one old file).
type Store struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	count    int64
}

// Entry is one quarantined item.
type Entry struct {
	At      time.Time `json:"at"`
	Source  string    `json:"source"`
	Parser  string    `json:"parser"`
	Reason  string    `json:"reason"`
	Locator string    `json:"locator"`
	Sample  string    `json:"sample"`
}

// Open creates the store in dir.
func Open(dir string, maxBytes int64) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{path: filepath.Join(dir, "quarantine.jsonl"), maxBytes: maxBytes}, nil
}

// Add records an entry. Errors are returned so callers can surface them; they never panic.
func (s *Store) Add(e Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(e.Sample) > MaxSampleBytes {
		e.Sample = e.Sample[:MaxSampleBytes]
	}
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if info, err := os.Stat(s.path); err == nil && info.Size()+int64(len(line)) > s.maxBytes/2 {
		if err := os.Rename(s.path, s.path+".1"); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	s.count++
	return nil
}

// Count returns entries added since start.
func (s *Store) Count() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}
