package spool

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func ev(s string) []json.RawMessage { return []json.RawMessage{json.RawMessage(`{"x":"` + s + `"}`)} }

func TestFIFOAndPersistence(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"a", "b", "c"} {
		if err := s.Append(ev(v)); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := s.Peek()
	if err := s.Ack(b.Seq); err != nil {
		t.Fatal(err)
	}
	// Simulate an interrupted write and a restart.
	_ = os.WriteFile(filepath.Join(dir, ".tmp-123"), []byte("partial"), 0o600)
	s2, err := Open(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	events, batches, _ := s2.Stats()
	if events != 2 || batches != 2 {
		t.Fatalf("after restart: %d events %d batches", events, batches)
	}
	b, _ = s2.Peek()
	if string(b.Events[0]) != `{"x":"b"}` {
		t.Fatalf("order: %s", b.Events[0])
	}
	if _, err := os.Stat(filepath.Join(dir, ".tmp-123")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("temp file not cleaned")
	}
	if err := s2.Ack(b.Seq + 5); err == nil {
		t.Fatal("out-of-order ack accepted")
	}
}

func TestBoundedNoPartialWrite(t *testing.T) {
	s, _ := Open(t.TempDir(), 200)
	if err := s.Append(ev("small")); err != nil {
		t.Fatal(err)
	}
	big := []json.RawMessage{json.RawMessage(`{"x":"` + string(make([]byte, 300)) + `"}`)}
	big[0] = json.RawMessage(`{"x":"` + string(bytesOf('a', 300)) + `"}`)
	if err := s.Append(big); !errors.Is(err, ErrFull) {
		t.Fatalf("expected ErrFull, got %v", err)
	}
	if events, _, _ := s.Stats(); events != 1 {
		t.Fatalf("partial write: %d", events)
	}
}

func bytesOf(c byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return b
}
