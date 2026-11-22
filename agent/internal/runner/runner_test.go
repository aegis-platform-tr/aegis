package runner

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"aegis/agent/internal/config"
	"aegis/agent/internal/state"
	"aegis/agent/internal/uploader"
)

// fakeServer emulates the AEGIS agent API with switchable failure modes.
type fakeServer struct {
	mu        sync.Mutex
	mode      string // ok | down | revoked | reject_all | too_large_over
	limit     int
	seen      map[string]int // native_id -> deliveries
	accepted  int
	heartbeat int
	srv       *httptest.Server
}

func newFake(t *testing.T) *fakeServer {
	f := &fakeServer{mode: "ok", seen: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeServer) set(mode string) { f.mu.Lock(); f.mode = mode; f.mu.Unlock() }

func (f *fakeServer) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer aegis_agt_") {
		w.WriteHeader(401)
		return
	}
	switch f.mode {
	case "down":
		w.WriteHeader(503)
		return
	case "revoked":
		w.WriteHeader(401)
		_, _ = io.WriteString(w, `{"error":{"code":"invalid_agent_credential"}}`)
		return
	}
	switch r.URL.Path {
	case "/api/v1/agent/heartbeat":
		f.heartbeat++
		_, _ = io.WriteString(w, `{"server_time":"2026-01-01T00:00:00Z","clock_skew_ms":0,"accepted_schema_versions":["1.0"],"agent_version_supported":true,"rotate_credential":false}`)
	case "/api/v1/agent/events":
		var body struct{ Events []map[string]any }
		_ = json.NewDecoder(r.Body).Decode(&body)
		if f.mode == "too_large_over" && len(body.Events) > f.limit {
			w.WriteHeader(413)
			return
		}
		type item struct {
			Index  int              `json:"index"`
			Status string           `json:"status"`
			Errors []map[string]any `json:"errors"`
		}
		var res []item
		acc, dup, rej := 0, 0, 0
		for i, e := range body.Events {
			if f.mode == "reject_all" {
				res = append(res, item{i, "rejected", []map[string]any{{"field": "schema_version", "code": "value_error"}}})
				rej++
				continue
			}
			id := e["source"].(map[string]any)["native_id"].(string)
			f.seen[id]++
			if f.seen[id] > 1 {
				res = append(res, item{Index: i, Status: "duplicate"})
				dup++
			} else {
				res = append(res, item{Index: i, Status: "accepted"})
				acc++
				f.accepted++
			}
		}
		code := 200
		if rej > 0 {
			code = 422
		}
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]any{"accepted": acc, "duplicate": dup, "rejected": rej, "results": res})
	default:
		w.WriteHeader(404)
	}
}

func (f *fakeServer) stats() (accepted, unique int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.accepted, len(f.seen)
}

func setup(t *testing.T, f *fakeServer, spoolMax int64) (*config.Config, string) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "auth.log")
	src, _ := os.ReadFile("../../testdata/auth.log")
	if err := os.WriteFile(logPath, src, 0o600); err != nil {
		t.Fatal(err)
	}
	no := false
	cfg := &config.Config{
		SchemaVersion: 1, ConfigVersion: 1, ServerURL: f.srv.URL, StateDir: filepath.Join(dir, "state"),
		HeartbeatSeconds: 5, FlushSeconds: 1, BatchSize: 3, SpoolMaxBytes: spoolMax,
		QuarantineMaxBytes: 1 << 20, AllowInsecureLocal: true,
		Sources: []config.Source{{Name: "auth", Type: "linux_auth", Path: logPath, AssetID: "web01", StartAtEnd: &no}},
	}
	if err := state.SaveIdentity(cfg.StateDir, &state.Identity{AgentID: "agt_test", TenantID: "t", Credential: "aegis_agt_test"}); err != nil {
		t.Fatal(err)
	}
	InitialBackoff, MaxBackoff = 20*time.Millisecond, 100*time.Millisecond
	return cfg, logPath
}

func start(t *testing.T, cfg *config.Config) (*Runner, context.CancelFunc, chan error) {
	id, err := state.LoadIdentity(cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	r, err := New(cfg, id, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	return r, cancel, done
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

const expectedEvents = 7 // testdata/auth.log: 7 sshd auth events, 1 skipped, 1 malformed

func TestRetryAfterDisconnectDeliversEverythingOnce(t *testing.T) {
	f := newFake(t)
	f.set("down")
	cfg, _ := setup(t, f, 1<<20)
	r, cancel, done := start(t, cfg)
	defer cancel()
	waitFor(t, "spooling while server is down", func() bool { e, _, _ := r.spool.Stats(); return e == expectedEvents })
	f.set("ok")
	waitFor(t, "delivery after reconnect", func() bool { a, _ := f.stats(); return a == expectedEvents })
	waitFor(t, "spool drained", func() bool { e, _, _ := r.spool.Stats(); return e == 0 })
	cancel()
	<-done
	if r.quar.Count() != 1 {
		t.Fatalf("expected 1 quarantined malformed line, got %d", r.quar.Count())
	}
}

func TestRestartResumesFromCursorWithoutRereading(t *testing.T) {
	f := newFake(t)
	cfg, logPath := setup(t, f, 1<<20)
	_, cancel, done := start(t, cfg)
	waitFor(t, "first delivery", func() bool { a, _ := f.stats(); return a == expectedEvents })
	cancel()
	<-done
	fh, _ := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0)
	_, _ = fh.WriteString("2026-01-01T10:00:00+00:00 web01 sshd[9]: Failed password for root from 192.0.2.99 port 1 ssh2\n")
	fh.Close()
	_, cancel2, done2 := start(t, cfg)
	defer cancel2()
	waitFor(t, "new line delivered", func() bool { a, _ := f.stats(); return a == expectedEvents+1 })
	time.Sleep(200 * time.Millisecond)
	cancel2()
	<-done2
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, n := range f.seen {
		if n != 1 {
			t.Fatalf("%s delivered %d times after restart", id, n)
		}
	}
}

func TestRevocationStopsAgentAndKeepsSpool(t *testing.T) {
	f := newFake(t)
	f.set("revoked")
	cfg, _ := setup(t, f, 1<<20)
	r, cancel, done := start(t, cfg)
	defer cancel()
	select {
	case err := <-done:
		if !errors.Is(err, uploader.ErrRevoked) {
			t.Fatalf("expected ErrRevoked, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("agent did not stop on revocation")
	}
	if a, _ := f.stats(); a != 0 {
		t.Fatal("events accepted with revoked credential")
	}
	if events, _, _ := r.spool.Stats(); events == 0 {
		t.Fatalf("spool must be retained for re-enrollment, has %d events", events)
	}
}

func TestVersionSkewRejectionsAreQuarantinedNotRetriedForever(t *testing.T) {
	f := newFake(t)
	f.set("reject_all")
	cfg, _ := setup(t, f, 1<<20)
	r, cancel, done := start(t, cfg)
	defer cancel()
	waitFor(t, "all rejected items quarantined", func() bool { return r.quar.Count() == expectedEvents+1 })
	waitFor(t, "spool drained", func() bool { e, _, _ := r.spool.Stats(); return e == 0 })
	cancel()
	<-done
	raw, _ := os.ReadFile(filepath.Join(cfg.StateDir, "quarantine", "quarantine.jsonl"))
	if !strings.Contains(string(raw), "schema_version") {
		t.Fatal("rejection reason not recorded")
	}
}

func TestTooLargeBatchesAreSplit(t *testing.T) {
	f := newFake(t)
	f.mu.Lock()
	f.mode, f.limit = "too_large_over", 1
	f.mu.Unlock()
	cfg, _ := setup(t, f, 1<<20)
	_, cancel, done := start(t, cfg)
	defer cancel()
	waitFor(t, "split delivery", func() bool { a, _ := f.stats(); return a == expectedEvents })
	cancel()
	<-done
}

func TestBackPressureWhenSpoolFullLosesNothing(t *testing.T) {
	f := newFake(t)
	f.set("down")
	cfg, _ := setup(t, f, 1<<16) // minimum allowed spool
	// Inflate the log so it cannot all fit in the spool.
	fh, _ := os.OpenFile(cfg.Sources[0].Path, os.O_APPEND|os.O_WRONLY, 0)
	for i := 0; i < 400; i++ {
		_, _ = fh.WriteString("2026-01-01T11:00:00+00:00 web01 sshd[9]: Failed password for root from 192.0.2.50 port " +
			strconv.Itoa(1000+i) + " ssh2\n")
	}
	fh.Close()
	r, cancel, done := start(t, cfg)
	defer cancel()
	waitFor(t, "source paused by back-pressure", func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.statuses["auth"].Status == "paused"
	})
	if hb := r.HeartbeatPayload(); hb["spool_full"] != true {
		t.Fatal("spool_full not reported")
	}
	f.set("ok")
	waitFor(t, "everything delivered", func() bool { a, _ := f.stats(); return a == expectedEvents+400 })
	cancel()
	<-done
	if r.dropped.Load() != 0 {
		t.Fatal("events dropped")
	}
}
