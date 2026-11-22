//go:build windows

package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"aegis/agent/internal/config"
	"aegis/agent/internal/parsers"
	"aegis/agent/internal/state"
)

// pollWindows queries the Security channel through wevtutil with a FIXED argument list built
// from the persisted EventRecordID cursor. No configuration value reaches the command line
// except the validated channel name ("Security"). Requires membership in "Event Log Readers"
// (or Administrators) for the service account.
//
// Verification status: parser verified on XML fixtures; live collection NOT runtime-verified
// in the M2 build environment (Linux only).
func (r *Runner) pollWindows(ctx context.Context, src config.Source, p parsers.Parser) bool {
	cur, _ := r.cursors.Get(src.Name)
	query := fmt.Sprintf("*[System[(EventID=4624 or EventID=4625 or EventID=4740) and (EventRecordID>%d)]]", cur.RecordID)
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "wevtutil.exe", "qe", "Security", "/q:"+query, "/f:xml", "/rd:false",
		fmt.Sprintf("/c:%d", r.cfg.BatchSize))
	out, err := cmd.Output()
	if err != nil {
		r.setStatus(src.Name, func(s *SourceStatus) {
			s.Status, s.Error = "error", "wevtutil query failed (check Event Log Readers membership)"
		})
		return false
	}
	var batch []json.RawMessage
	maxID := cur.RecordID
	for _, chunk := range bytes.SplitAfter(out, []byte("</Event>")) {
		chunk = bytes.TrimSpace(chunk)
		if len(chunk) == 0 {
			continue
		}
		id, err := parsers.RecordID(chunk)
		if err != nil {
			r.quarantine(src, p, "unreadable record", "", chunk)
			continue
		}
		if id > maxID {
			maxID = id
		}
		raw, _, ok := r.normalize(src, p, chunk, fmt.Sprintf("%s:record:%d", src.Name, id), false)
		if ok {
			batch = append(batch, raw)
		}
	}
	if err := r.spool.Append(batch); err != nil {
		r.spoolFull.Store(true)
		r.setStatus(src.Name, func(s *SourceStatus) { s.Status, s.Error = "paused", "spool full: back-pressure" })
		return false
	}
	if maxID != cur.RecordID {
		if err := r.cursors.Set(src.Name, state.Cursor{RecordID: maxID, Resets: cur.Resets}); err != nil {
			r.log.Error("persist cursor failed", "source", src.Name, "err", err)
		}
		r.signal()
	}
	now := r.now().UTC()
	r.setStatus(src.Name, func(s *SourceStatus) { s.Status, s.Error, s.LastReadAt = "ok", "", &now })
	return len(batch) == r.cfg.BatchSize
}
