package parsers

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func lines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

type tally struct{ events, skipped, malformed int }

func run(t *testing.T, p Parser, path string) ([]*Event, tally) {
	var evs []*Event
	var c tally
	for _, l := range lines(t, path) {
		ev, err := p.Parse([]byte(l))
		var m *MalformedError
		switch {
		case err == nil:
			evs = append(evs, ev)
			c.events++
		case errors.Is(err, ErrSkip):
			c.skipped++
		case errors.As(err, &m):
			c.malformed++
		default:
			t.Fatalf("unexpected error %v", err)
		}
	}
	return evs, c
}

func TestLinuxAuth(t *testing.T) {
	p := LinuxAuth{Now: func() time.Time { return time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC) }, Location: time.UTC}
	evs, c := run(t, p, "../../testdata/auth.log")
	if c != (tally{events: 7, skipped: 1, malformed: 1}) {
		t.Fatalf("tally %+v", c)
	}
	first := evs[0]
	if first.EventType != "login_failure" || first.SourceIP != "192.0.2.42" || first.Principal != "admin" ||
		*first.SourcePort != 51122 || first.Attributes["invalid_user"] != true {
		t.Fatalf("bad first event %+v", first)
	}
	if !first.OccurredAt.Equal(time.Date(2026, 1, 1, 9, 12, 10, 0, time.UTC)) {
		t.Fatalf("time %v", first.OccurredAt)
	}
	// +0000 (journald short-iso) form parses.
	if !evs[5].OccurredAt.Equal(time.Date(2026, 1, 1, 9, 13, 29, 0, time.UTC)) {
		t.Fatalf("short-iso time %v", evs[5].OccurredAt)
	}
	last := evs[6]
	if last.EventType != "login_success" || last.Attributes["time_assumptions"] == nil {
		t.Fatalf("legacy line %+v", last)
	}
}

func TestLinuxAuthLegacyYearRollover(t *testing.T) {
	p := LinuxAuth{Now: func() time.Time { return time.Date(2026, 1, 1, 0, 5, 0, 0, time.UTC) }, Location: time.UTC}
	ev, err := p.Parse([]byte("Dec 31 23:59:00 h sshd[1]: Failed password for x from 192.0.2.1 port 1 ssh2"))
	if err != nil || ev.OccurredAt.Year() != 2025 {
		t.Fatalf("rollover: %v %v", ev, err)
	}
}

func TestSuricataEVE(t *testing.T) {
	evs, c := run(t, SuricataEVE{}, "../../testdata/eve.json")
	if c != (tally{events: 4, skipped: 1, malformed: 2}) {
		t.Fatalf("tally %+v", c)
	}
	alert := evs[0]
	if alert.EventType != "ids_alert" || alert.Severity != "medium" || alert.Attributes["signature_id"] != int64(2100498) {
		t.Fatalf("alert %+v", alert)
	}
	if alert.Protocol != "tcp" || *alert.DestinationPort != 80 {
		t.Fatalf("endpoints %+v", alert)
	}
	http := evs[2]
	raw, _ := json.Marshal(http)
	if strings.Contains(string(raw), "SECRET-CANARY") {
		t.Fatal("query string leaked into event")
	}
	if http.Attributes["path"] != "/login" {
		t.Fatalf("path %v", http.Attributes["path"])
	}
}

func TestZeekJSON(t *testing.T) {
	evs, c := run(t, ZeekJSON{FileName: "/var/log/zeek/current/conn.log"}, "../../testdata/conn.log")
	if c != (tally{events: 2, skipped: 1, malformed: 1}) {
		t.Fatalf("tally %+v", c)
	}
	if evs[0].EventType != "flow" || evs[0].Attributes["bytes_toclient"] != float64(9000) || *evs[0].DestinationPort != 443 {
		t.Fatalf("conn %+v", evs[0])
	}
	if evs[1].EventType != "dns_query" || evs[1].Attributes["query"] != "updates.example.org" {
		t.Fatalf("dns %+v", evs[1])
	}
	if evs[0].OccurredAt.Unix() != 1767259200 {
		t.Fatalf("ts %v", evs[0].OccurredAt)
	}
}

func TestWindowsSecurity(t *testing.T) {
	evs, c := run(t, WindowsSecurity{}, "../../testdata/security.xml")
	if c != (tally{events: 2, skipped: 1, malformed: 1}) {
		t.Fatalf("tally %+v", c)
	}
	f := evs[0]
	if f.EventType != "login_failure" || f.SourceIP != "192.0.2.77" || f.Principal != "administrator" || f.Attributes["logon_type"] != "3" {
		t.Fatalf("4625 %+v", f)
	}
	if _, ok := f.Attributes["TargetSid"]; ok {
		t.Fatal("non-allowlisted field collected")
	}
	if evs[1].SourceIP != "" {
		t.Fatal("'-' address must map to empty")
	}
	if id, _ := RecordID([]byte(lines(t, "../../testdata/security.xml")[0])); id != 9001 {
		t.Fatalf("record id %d", id)
	}
}
