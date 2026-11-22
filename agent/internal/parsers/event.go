// Package parsers converts raw source records into AEGIS event envelope v1.0.
//
// Each parser is an independently versioned contract (Adapter/AdapterVersion). Unknown
// fields in source records are ignored; records missing required fields are reported as
// malformed so the runner can quarantine them. Records that are valid but irrelevant
// (for example Suricata "stats") are skipped and counted.
package parsers

import (
	"errors"
	"time"
)

// SchemaVersion is the event envelope version produced by this agent.
const SchemaVersion = "1.0"

// ErrSkip marks a well-formed record that this adapter intentionally does not forward.
var ErrSkip = errors.New("record skipped")

// MalformedError marks input that violates the source contract.
type MalformedError struct{ Reason string }

func (e *MalformedError) Error() string { return "malformed: " + e.Reason }

func malformed(reason string) error { return &MalformedError{Reason: reason} }

// Source identifies the adapter inside an event.
type Source struct {
	Adapter        string `json:"adapter"`
	AdapterVersion string `json:"adapter_version"`
	NativeID       string `json:"native_id"`
}

// Event mirrors contracts/events/event-envelope.v1.schema.json (public ingest shape).
type Event struct {
	SchemaVersion   string         `json:"schema_version"`
	EventCategory   string         `json:"event_category"`
	EventType       string         `json:"event_type"`
	Severity        string         `json:"severity,omitempty"`
	OccurredAt      *time.Time     `json:"occurred_at"`
	ObservedAt      time.Time      `json:"observed_at"`
	Source          Source         `json:"source"`
	AssetID         string         `json:"asset_id,omitempty"`
	SourceIP        string         `json:"source_ip,omitempty"`
	DestinationIP   string         `json:"destination_ip,omitempty"`
	SourcePort      *int           `json:"source_port,omitempty"`
	DestinationPort *int           `json:"destination_port,omitempty"`
	Protocol        string         `json:"protocol,omitempty"`
	Principal       string         `json:"principal,omitempty"`
	Attributes      map[string]any `json:"attributes"`
	Origin          string         `json:"origin"`
}

// Parser turns one raw record into an event (without native_id, asset or observed time,
// which the runner assigns).
type Parser interface {
	Adapter() string
	Version() string
	Parse(raw []byte) (*Event, error)
}

func newEvent(p Parser, category, typ string) *Event {
	return &Event{
		SchemaVersion: SchemaVersion,
		EventCategory: category,
		EventType:     typ,
		Source:        Source{Adapter: p.Adapter(), AdapterVersion: p.Version()},
		Attributes:    map[string]any{},
		Origin:        "observed",
	}
}

func intPtr(v int) *int {
	if v < 0 || v > 65535 {
		return nil
	}
	return &v
}

func timePtr(t time.Time) *time.Time {
	u := t.UTC()
	return &u
}

// truncate keeps strings within the contract's bounds.
func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
