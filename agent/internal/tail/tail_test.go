package tail

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aegis/agent/internal/state"
)

func TestPartialLinesRotationAndTruncation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "app.log")
	_ = os.WriteFile(p, []byte("one\ntwo\nthr"), 0o600)
	r, err := Read(p, state.Cursor{}, 100)
	if err != nil || len(r.Lines) != 2 || string(r.Lines[1].Text) != "two" || r.Lines[1].Offset != 4 {
		t.Fatalf("first read %+v %v", r, err)
	}
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.WriteString("ee\nfour\n")
	f.Close()
	r2, _ := Read(p, r.Cursor, 100)
	if len(r2.Lines) != 2 || string(r2.Lines[0].Text) != "three" {
		t.Fatalf("resume %+v", r2)
	}
	// Rotation: rename and recreate.
	_ = os.Rename(p, p+".1")
	_ = os.WriteFile(p, []byte("new-1\n"), 0o600)
	r3, _ := Read(p, r2.Cursor, 100)
	if !r3.Reset || len(r3.Lines) != 1 || r3.Cursor.Resets != 1 {
		t.Fatalf("rotation %+v", r3)
	}
	// Truncation in place.
	_ = os.WriteFile(p, []byte(""), 0o600)
	r4, _ := Read(p, r3.Cursor, 100)
	if !r4.Reset {
		t.Fatalf("truncation not detected %+v", r4)
	}
}

func TestOversizeLineFlagged(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big.log")
	_ = os.WriteFile(p, []byte(strings.Repeat("x", MaxLineBytes+10)+"\nok\n"), 0o600)
	r, _ := Read(p, state.Cursor{}, 10)
	if len(r.Lines) != 2 || !r.Lines[0].Oversize || len(r.Lines[0].Text) > MaxLineBytes || string(r.Lines[1].Text) != "ok" {
		t.Fatalf("oversize handling: %d lines", len(r.Lines))
	}
}

func TestMissingFile(t *testing.T) {
	r, err := Read("/nonexistent/x.log", state.Cursor{Offset: 5}, 10)
	if err != nil || !r.Missing || r.Cursor.Offset != 5 {
		t.Fatalf("%+v %v", r, err)
	}
}
