// Package tail reads complete lines from a growing log file starting at a persisted cursor.
package tail

import (
	"bufio"
	"errors"
	"io"
	"os"

	"aegis/agent/internal/state"
)

// MaxLineBytes is the longest line accepted; longer lines are returned with Oversize=true.
const MaxLineBytes = 64 * 1024

// Line is one complete line and the byte offset where it starts.
type Line struct {
	Offset   int64
	Text     []byte
	Oversize bool
}

// Result of one read pass.
type Result struct {
	Lines   []Line
	Cursor  state.Cursor
	Missing bool
	Reset   bool // file rotated or truncated; reading restarted at 0
}

// Read returns up to maxLines complete lines after cur. A trailing partial line is left
// unread so it is picked up whole on the next pass. It never advances past unread data.
func Read(path string, cur state.Cursor, maxLines int) (Result, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return Result{Cursor: cur, Missing: true}, nil
	}
	if err != nil {
		return Result{Cursor: cur}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return Result{Cursor: cur}, err
	}
	res := Result{Cursor: cur}
	id := fileID(info)
	if (cur.FileID != "" && id != "" && cur.FileID != id) || info.Size() < cur.Offset {
		res.Reset = true
		res.Cursor = state.Cursor{FileID: id, Offset: 0, Resets: cur.Resets + 1}
	}
	res.Cursor.FileID = id
	if _, err := f.Seek(res.Cursor.Offset, io.SeekStart); err != nil {
		return res, err
	}
	r := bufio.NewReaderSize(f, 64*1024)
	offset := res.Cursor.Offset
	for len(res.Lines) < maxLines {
		start := offset
		var buf []byte
		oversize := false
		complete := false
		for {
			chunk, err := r.ReadSlice('\n')
			offset += int64(len(chunk))
			if len(buf)+len(chunk) <= MaxLineBytes {
				buf = append(buf, chunk...)
			} else {
				oversize = true
			}
			if err == nil {
				complete = true
				break
			}
			if errors.Is(err, bufio.ErrBufferFull) {
				continue
			}
			if errors.Is(err, io.EOF) {
				break
			}
			return res, err
		}
		if !complete {
			break // partial line: leave for next pass
		}
		text := trimEOL(buf)
		res.Lines = append(res.Lines, Line{Offset: start, Text: text, Oversize: oversize})
		res.Cursor.Offset = offset
	}
	return res, nil
}

func trimEOL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// Size returns the current file size, or -1 if missing (used to compute backlog).
func Size(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return -1
	}
	return info.Size()
}
