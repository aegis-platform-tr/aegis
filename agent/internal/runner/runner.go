// Package runner wires sources, spool, uploader and heartbeats together.
package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/rand/v2"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"aegis/agent/internal/config"
	"aegis/agent/internal/parsers"
	"aegis/agent/internal/quarantine"
	"aegis/agent/internal/spool"
	"aegis/agent/internal/state"
	"aegis/agent/internal/tail"
	"aegis/agent/internal/uploader"
)

// Version is set at build time (-ldflags "-X aegis/agent/internal/runner.Version=...").
var Version = "0.2.0"

// Retry delays (variables so tests can shorten them).
var (
	InitialBackoff = time.Second
	MaxBackoff     = 60 * time.Second
)

// SourceStatus mirrors the heartbeat source status contract.
type SourceStatus struct {
	Name         string     `json:"name"`
	Type         string     `json:"type"`
	Status       string     `json:"status"`
	LagSeconds   *float64   `json:"lag_seconds,omitempty"`
	LastReadAt   *time.Time `json:"last_read_at,omitempty"`
	CursorResets int        `json:"cursor_resets"`
	Error        string     `json:"error,omitempty"`
}

// Runner is one agent instance.
type Runner struct {
	cfg     *config.Config
	id      *state.Identity
	client  *uploader.Client
	spool   *spool.Spool
	quar    *quarantine.Store
	cursors *state.Cursors
	log     *slog.Logger
	now     func() time.Time

	mu        sync.Mutex
	statuses  map[string]*SourceStatus
	spoolFull atomic.Bool
	sent      atomic.Int64
	dropped   atomic.Int64
	revoked   atomic.Bool
	wake      chan struct{}
}

// New opens state for cfg.
func New(cfg *config.Config, id *state.Identity, log *slog.Logger) (*Runner, error) {
	sp, err := spool.Open(filepath.Join(cfg.StateDir, "spool"), cfg.SpoolMaxBytes)
	if err != nil {
		return nil, fmt.Errorf("open spool: %w", err)
	}
	q, err := quarantine.Open(filepath.Join(cfg.StateDir, "quarantine"), cfg.QuarantineMaxBytes)
	if err != nil {
		return nil, fmt.Errorf("open quarantine: %w", err)
	}
	cur, err := state.OpenCursors(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	r := &Runner{
		cfg: cfg, id: id, client: uploader.New(cfg.ServerURL, id.Credential), spool: sp,
		quar: q, cursors: cur, log: log, now: time.Now, statuses: map[string]*SourceStatus{},
		wake: make(chan struct{}, 1),
	}
	for _, s := range cfg.Sources {
		r.statuses[s.Name] = &SourceStatus{Name: s.Name, Type: s.Type, Status: "waiting"}
	}
	return r, nil
}

// Client exposes the uploader (tests).
func (r *Runner) Client() *uploader.Client { return r.client }

// Run blocks until ctx is cancelled or the credential is revoked.
func (r *Runner) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	for _, src := range r.cfg.Sources {
		src := src
		wg.Add(1)
		go func() { defer wg.Done(); r.collect(ctx, src) }()
	}
	wg.Add(2)
	go func() { defer wg.Done(); r.uploadLoop(ctx, cancel) }()
	go func() { defer wg.Done(); r.heartbeatLoop(ctx, cancel) }()
	wg.Wait()
	if r.revoked.Load() {
		return uploader.ErrRevoked
	}
	return nil
}

func (r *Runner) setStatus(name string, f func(s *SourceStatus)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f(r.statuses[name])
}

// ---- Collection ---------------------------------------------------------------------------

func parserFor(src config.Source) (parsers.Parser, error) {
	switch src.Type {
	case config.SourceLinuxAuth:
		return parsers.LinuxAuth{}, nil
	case config.SourceSuricataEVE:
		return parsers.SuricataEVE{}, nil
	case config.SourceZeekJSON:
		return parsers.ZeekJSON{FileName: src.Path}, nil
	case config.SourceWindowsXMLFile, config.SourceWindowsLive:
		return parsers.WindowsSecurity{}, nil
	}
	return nil, fmt.Errorf("no parser for %s", src.Type)
}

func (r *Runner) collect(ctx context.Context, src config.Source) {
	p, err := parserFor(src)
	if err != nil {
		r.setStatus(src.Name, func(s *SourceStatus) { s.Status, s.Error = "error", err.Error() })
		return
	}
	ticker := time.NewTicker(r.cfg.Flush())
	defer ticker.Stop()
	for {
		var more bool
		if src.Type == config.SourceWindowsLive {
			more = r.pollWindows(ctx, src, p)
		} else {
			more = r.pollFile(src, p)
		}
		if more {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// pollFile reads one chunk; returns true if more data is probably waiting.
func (r *Runner) pollFile(src config.Source, p parsers.Parser) bool {
	cur, known := r.cursors.Get(src.Name)
	if !known {
		startAtEnd := src.StartAtEnd == nil || *src.StartAtEnd
		if startAtEnd {
			if size := tail.Size(src.Path); size >= 0 {
				cur = state.Cursor{Offset: size}
				res, err := tail.Read(src.Path, cur, 0) // establish file identity
				if err == nil {
					cur = res.Cursor
				}
			}
		}
	}
	if r.spool.Full(4096) {
		r.spoolFull.Store(true)
		r.setStatus(src.Name, func(s *SourceStatus) { s.Status = "paused"; s.Error = "spool full: back-pressure" })
		return false
	}
	res, err := tail.Read(src.Path, cur, r.cfg.BatchSize)
	if err != nil {
		st := "error"
		if errors.Is(err, fs.ErrPermission) {
			st = "permission_denied"
		}
		r.setStatus(src.Name, func(s *SourceStatus) { s.Status, s.Error = st, sanitize(err) })
		return false
	}
	if res.Missing {
		r.setStatus(src.Name, func(s *SourceStatus) { s.Status, s.Error = "waiting", "file not found" })
		return false
	}
	locator := res.Cursor.FileID
	if locator == "" {
		locator = fmt.Sprintf("r%d", res.Cursor.Resets)
	}
	var batch []json.RawMessage
	var newest time.Time
	for _, ln := range res.Lines {
		nativeID := fmt.Sprintf("%s:%s:%d", src.Name, locator, ln.Offset)
		raw, ts, ok := r.normalize(src, p, ln.Text, nativeID, ln.Oversize)
		if ok {
			batch = append(batch, raw)
			if ts.After(newest) {
				newest = ts
			}
		}
	}
	if err := r.spool.Append(batch); err != nil {
		if errors.Is(err, spool.ErrFull) {
			r.spoolFull.Store(true)
			r.setStatus(src.Name, func(s *SourceStatus) { s.Status = "paused"; s.Error = "spool full: back-pressure" })
			return false // cursor not advanced: nothing is lost
		}
		r.setStatus(src.Name, func(s *SourceStatus) { s.Status, s.Error = "error", sanitize(err) })
		return false
	}
	r.spoolFull.Store(false)
	if len(batch) > 0 {
		r.signal()
	}
	if res.Cursor != cur {
		if err := r.cursors.Set(src.Name, res.Cursor); err != nil {
			r.log.Error("persist cursor failed", "source", src.Name, "err", err)
		}
	}
	now := r.now().UTC()
	r.setStatus(src.Name, func(s *SourceStatus) {
		s.Status, s.Error, s.CursorResets = "ok", "", res.Cursor.Resets
		s.LastReadAt = &now
		if !newest.IsZero() {
			lag := now.Sub(newest).Seconds()
			if lag < 0 {
				lag = 0
			}
			s.LagSeconds = &lag
		}
	})
	return len(res.Lines) == r.cfg.BatchSize
}

func (r *Runner) normalize(src config.Source, p parsers.Parser, line []byte, nativeID string, oversize bool) (json.RawMessage, time.Time, bool) {
	if oversize {
		r.quarantine(src, p, "line exceeds maximum length", nativeID, line)
		return nil, time.Time{}, false
	}
	if len(line) == 0 {
		return nil, time.Time{}, false
	}
	ev, err := p.Parse(line)
	if errors.Is(err, parsers.ErrSkip) {
		return nil, time.Time{}, false
	}
	var mErr *parsers.MalformedError
	if errors.As(err, &mErr) {
		r.quarantine(src, p, mErr.Reason, nativeID, line)
		return nil, time.Time{}, false
	}
	if err != nil {
		r.quarantine(src, p, "parser error", nativeID, line)
		return nil, time.Time{}, false
	}
	ev.Source.NativeID = nativeID
	ev.AssetID = src.AssetID
	ev.ObservedAt = r.now().UTC()
	raw, err := json.Marshal(ev)
	if err != nil {
		r.quarantine(src, p, "encode error", nativeID, line)
		return nil, time.Time{}, false
	}
	ts := ev.ObservedAt
	if ev.OccurredAt != nil {
		ts = *ev.OccurredAt
	}
	return raw, ts, true
}

func (r *Runner) quarantine(src config.Source, p parsers.Parser, reason, locator string, sample []byte) {
	if err := r.quar.Add(quarantine.Entry{
		Source: src.Name, Parser: p.Adapter() + "/" + p.Version(), Reason: reason,
		Locator: locator, Sample: string(sample),
	}); err != nil {
		r.log.Error("quarantine write failed", "source", src.Name, "err", err)
	}
}

func (r *Runner) signal() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// ---- Delivery -----------------------------------------------------------------------------

func (r *Runner) uploadLoop(ctx context.Context, stop context.CancelFunc) {
	backoff := InitialBackoff
	ticker := time.NewTicker(r.cfg.Flush())
	defer ticker.Stop()
	for {
		b, err := r.spool.Peek()
		if err != nil {
			r.log.Error("spool read failed", "err", err)
		}
		if b == nil || err != nil {
			select {
			case <-ctx.Done():
				return
			case <-r.wake:
			case <-ticker.C:
			}
			continue
		}
		ok, revoked := r.deliver(ctx, b.Events)
		if revoked {
			r.revoked.Store(true)
			r.log.Error("credential rejected by server; stopping. Spooled data is kept for re-enrollment.")
			stop()
			return
		}
		if ok {
			if err := r.spool.Ack(b.Seq); err != nil {
				r.log.Error("spool ack failed", "err", err)
			}
			backoff = InitialBackoff
			continue
		}
		delay := backoff/2 + time.Duration(rand.Int64N(int64(backoff)))
		r.log.Warn("delivery failed; retrying", "delay", delay.String())
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		backoff = min(backoff*2, MaxBackoff)
	}
}

// deliver sends events, splitting on 413. Returns (done, revoked).
func (r *Runner) deliver(ctx context.Context, events []json.RawMessage) (bool, bool) {
	res, err := r.client.SendEvents(ctx, events)
	switch res.Outcome {
	case uploader.Delivered:
		r.sent.Add(int64(res.Accepted + res.Duplicate))
		for _, it := range res.Rejected {
			reason := "rejected by server"
			if len(it.Errors) > 0 {
				reason = fmt.Sprintf("rejected: %s %s", it.Errors[0].Field, it.Errors[0].Code)
			}
			if it.Index >= 0 && it.Index < len(events) {
				r.quarantineRaw("server", reason, events[it.Index])
			}
		}
		return true, false
	case uploader.TooLarge:
		if len(events) == 1 {
			r.quarantineRaw("server", "single event too large", events[0])
			return true, false
		}
		mid := len(events) / 2
		for _, part := range [][]json.RawMessage{events[:mid], events[mid:]} {
			done, revoked := r.deliver(ctx, part)
			if revoked || !done {
				return done, revoked
			}
		}
		return true, false
	case uploader.Revoked:
		return false, true
	case uploader.Poison:
		r.log.Error("server refused batch permanently; quarantining", "err", err)
		for _, ev := range events {
			r.quarantineRaw("server", "batch refused: "+sanitize(err), ev)
		}
		return true, false
	default:
		if err != nil {
			r.log.Warn("send failed", "err", sanitize(err))
		}
		return false, false
	}
}

func (r *Runner) quarantineRaw(source, reason string, raw json.RawMessage) {
	if err := r.quar.Add(quarantine.Entry{Source: source, Parser: "delivery", Reason: reason,
		Sample: string(raw)}); err != nil {
		r.log.Error("quarantine write failed", "err", err)
	}
}

// ---- Heartbeat ----------------------------------------------------------------------------

// HeartbeatPayload builds the current status report.
func (r *Runner) HeartbeatPayload() map[string]any {
	events, _, bytes := r.spool.Stats()
	r.mu.Lock()
	sources := make([]SourceStatus, 0, len(r.statuses))
	for _, s := range r.cfg.Sources {
		sources = append(sources, *r.statuses[s.Name])
	}
	r.mu.Unlock()
	return map[string]any{
		"agent_version": Version, "config_version": r.cfg.ConfigVersion,
		"agent_time": r.now().UTC(), "queue_depth": events, "spool_bytes": bytes,
		"spool_full": r.spoolFull.Load(), "dropped_events": r.dropped.Load(),
		"quarantined_lines": r.quar.Count(), "sent_events": r.sent.Load(), "sources": sources,
	}
}

func (r *Runner) heartbeatLoop(ctx context.Context, stop context.CancelFunc) {
	ticker := time.NewTicker(r.cfg.Heartbeat())
	defer ticker.Stop()
	for {
		hb, err := r.client.Heartbeat(ctx, r.HeartbeatPayload())
		switch {
		case errors.Is(err, uploader.ErrRevoked):
			r.revoked.Store(true)
			r.log.Error("heartbeat: credential rejected; stopping")
			stop()
			return
		case err != nil:
			r.log.Warn("heartbeat failed", "err", sanitize(err))
		default:
			if !hb.AgentVersionSupported {
				r.log.Warn("server reports this agent version as unsupported; upgrade required")
			}
			if hb.ClockSkewMS > 30_000 || hb.ClockSkewMS < -30_000 {
				r.log.Warn("clock skew exceeds 30s", "skew_ms", hb.ClockSkewMS)
			}
			if hb.RotateCredential {
				r.rotate(ctx)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (r *Runner) rotate(ctx context.Context) {
	cred, exp, err := r.client.Rotate(ctx)
	if err != nil {
		r.log.Warn("credential rotation failed", "err", sanitize(err))
		return
	}
	next := *r.id
	next.Credential, next.CredentialExpiresAt = cred, exp
	if err := state.SaveIdentity(r.cfg.StateDir, &next); err != nil {
		r.log.Error("could not persist rotated credential; keeping old identity file", "err", err)
		return
	}
	r.id = &next
	r.client.SetCredential(cred)
	r.log.Info("credential rotated")
}

// sanitize drops anything after the first line and never includes credentials.
func sanitize(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	for i, c := range s {
		if c == '\n' {
			s = s[:i]
			break
		}
	}
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}
