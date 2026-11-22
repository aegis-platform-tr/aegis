// Package spool is a bounded, crash-safe, on-disk FIFO of event batches.
//
// Each batch is one file named by a monotonically increasing sequence number. A batch is
// written atomically (temp + rename) before the corresponding source cursor advances, and
// deleted only after the server durably acknowledged it. When the byte limit is reached,
// Append returns ErrFull and collectors pause (back-pressure) instead of dropping events.
package spool

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"aegis/agent/internal/state"
)

// ErrFull means the spool reached its byte limit.
var ErrFull = errors.New("spool is full")

// Batch is a group of normalized events.
type Batch struct {
	Seq    uint64            `json:"seq"`
	Events []json.RawMessage `json:"events"`
}

// Spool is safe for concurrent use.
type Spool struct {
	mu       sync.Mutex
	dir      string
	maxBytes int64
	bytes    int64
	nextSeq  uint64
	files    []uint64
	events   int
}

// Open scans dir and restores state from existing batch files.
func Open(dir string, maxBytes int64) (*Spool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Spool{dir: dir, maxBytes: maxBytes, nextSeq: 1}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".tmp-") {
			_ = os.Remove(filepath.Join(dir, name)) // interrupted write
			continue
		}
		if !strings.HasSuffix(name, ".batch") {
			continue
		}
		seq, err := strconv.ParseUint(strings.TrimSuffix(name, ".batch"), 10, 64)
		if err != nil {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return nil, err
		}
		b, err := s.read(seq)
		if err != nil {
			return nil, fmt.Errorf("spool batch %d unreadable: %w", seq, err)
		}
		s.files = append(s.files, seq)
		s.bytes += info.Size()
		s.events += len(b.Events)
		if seq >= s.nextSeq {
			s.nextSeq = seq + 1
		}
	}
	sort.Slice(s.files, func(i, j int) bool { return s.files[i] < s.files[j] })
	return s, nil
}

func (s *Spool) path(seq uint64) string {
	return filepath.Join(s.dir, fmt.Sprintf("%020d.batch", seq))
}

func (s *Spool) read(seq uint64) (*Batch, error) {
	raw, err := os.ReadFile(s.path(seq))
	if err != nil {
		return nil, err
	}
	var b Batch
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// Append durably stores a batch, or returns ErrFull without writing anything.
func (s *Spool) Append(events []json.RawMessage) error {
	if len(events) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := Batch{Seq: s.nextSeq, Events: events}
	data, err := json.Marshal(b)
	if err != nil {
		return err
	}
	if s.bytes+int64(len(data)) > s.maxBytes {
		return ErrFull
	}
	if err := state.WriteJSONAtomic(s.path(b.Seq), b, 0o600); err != nil {
		return err
	}
	info, err := os.Stat(s.path(b.Seq))
	if err != nil {
		return err
	}
	s.files = append(s.files, b.Seq)
	s.bytes += info.Size()
	s.events += len(events)
	s.nextSeq++
	return nil
}

// Peek returns the oldest batch, or nil when empty.
func (s *Spool) Peek() (*Batch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.files) == 0 {
		return nil, nil
	}
	return s.read(s.files[0])
}

// Ack removes the oldest batch after successful delivery.
func (s *Spool) Ack(seq uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.files) == 0 || s.files[0] != seq {
		return fmt.Errorf("ack out of order: %d", seq)
	}
	p := s.path(seq)
	info, statErr := os.Stat(p)
	b, readErr := s.read(seq)
	if err := os.Remove(p); err != nil {
		return err
	}
	if statErr == nil {
		s.bytes -= info.Size()
	}
	if readErr == nil {
		s.events -= len(b.Events)
	}
	s.files = s.files[1:]
	return nil
}

// Stats reports queue depth (events), batches and bytes.
func (s *Spool) Stats() (events, batches int, bytes int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.events, len(s.files), s.bytes
}

// Full reports whether the next append of minBytes would fail.
func (s *Spool) Full(minBytes int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bytes+minBytes > s.maxBytes
}
