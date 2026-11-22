// Package config loads and validates the agent configuration.
//
// Configuration is data only: source types come from a fixed allowlist and no field can carry
// a command, script or executable. Unknown fields are rejected so typos fail loudly.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// SchemaVersion is the only configuration schema this build understands.
const SchemaVersion = 1

// SourceType values are the complete allowlist of collectors.
const (
	SourceLinuxAuth      = "linux_auth"
	SourceSuricataEVE    = "suricata_eve"
	SourceZeekJSON       = "zeek_json"
	SourceWindowsXMLFile = "windows_event_xml"
	SourceWindowsLive    = "windows_eventlog"
)

var allowedSources = map[string]bool{
	SourceLinuxAuth: true, SourceSuricataEVE: true, SourceZeekJSON: true,
	SourceWindowsXMLFile: true, SourceWindowsLive: true,
}

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_\-]{0,62}$`)
var assetRe = regexp.MustCompile(`^[A-Za-z0-9._:\-/@]{1,120}$`)

// Source is one collection input.
type Source struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Path    string `json:"path,omitempty"`
	Channel string `json:"channel,omitempty"` // windows_eventlog only: Security
	AssetID string `json:"asset_id"`
	// StartAtEnd skips existing content on first run (default true for live logs).
	StartAtEnd *bool `json:"start_at_end,omitempty"`
}

// Config is the full agent configuration.
type Config struct {
	SchemaVersion      int      `json:"schema_version"`
	ConfigVersion      int      `json:"config_version"`
	ServerURL          string   `json:"server_url"`
	StateDir           string   `json:"state_dir"`
	HeartbeatSeconds   int      `json:"heartbeat_seconds"`
	FlushSeconds       int      `json:"flush_seconds"`
	BatchSize          int      `json:"batch_size"`
	SpoolMaxBytes      int64    `json:"spool_max_bytes"`
	QuarantineMaxBytes int64    `json:"quarantine_max_bytes"`
	AllowInsecureLocal bool     `json:"allow_insecure_localhost"`
	Sources            []Source `json:"sources"`
}

// Defaults applied before validation.
func (c *Config) applyDefaults() {
	if c.HeartbeatSeconds == 0 {
		c.HeartbeatSeconds = 30
	}
	if c.FlushSeconds == 0 {
		c.FlushSeconds = 2
	}
	if c.BatchSize == 0 {
		c.BatchSize = 200
	}
	if c.SpoolMaxBytes == 0 {
		c.SpoolMaxBytes = 64 << 20
	}
	if c.QuarantineMaxBytes == 0 {
		c.QuarantineMaxBytes = 8 << 20
	}
}

// Load reads, decodes strictly and validates a configuration file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(raw)
}

// Parse decodes and validates configuration bytes.
func Parse(raw []byte) (*Config, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate checks every field; it never mutates the configuration.
func (c *Config) Validate() error {
	var errs []error
	if c.SchemaVersion != SchemaVersion {
		errs = append(errs, fmt.Errorf("schema_version must be %d", SchemaVersion))
	}
	if c.ConfigVersion < 1 {
		errs = append(errs, errors.New("config_version must be >= 1"))
	}
	u, err := url.Parse(c.ServerURL)
	switch {
	case err != nil || u.Host == "":
		errs = append(errs, errors.New("server_url must be an absolute URL"))
	case u.Scheme == "https":
	case u.Scheme == "http" && c.AllowInsecureLocal && isLoopback(u.Hostname()):
	default:
		errs = append(errs, errors.New("server_url must use https (http allowed only for localhost with allow_insecure_localhost)"))
	}
	if !filepath.IsAbs(c.StateDir) {
		errs = append(errs, errors.New("state_dir must be an absolute path"))
	}
	if c.HeartbeatSeconds < 5 || c.HeartbeatSeconds > 3600 {
		errs = append(errs, errors.New("heartbeat_seconds must be 5..3600"))
	}
	if c.FlushSeconds < 1 || c.FlushSeconds > 300 {
		errs = append(errs, errors.New("flush_seconds must be 1..300"))
	}
	if c.BatchSize < 1 || c.BatchSize > 500 {
		errs = append(errs, errors.New("batch_size must be 1..500"))
	}
	if c.SpoolMaxBytes < 1<<16 || c.SpoolMaxBytes > 4<<30 {
		errs = append(errs, errors.New("spool_max_bytes must be 64KiB..4GiB"))
	}
	if c.QuarantineMaxBytes < 1<<12 || c.QuarantineMaxBytes > 1<<30 {
		errs = append(errs, errors.New("quarantine_max_bytes must be 4KiB..1GiB"))
	}
	if len(c.Sources) == 0 || len(c.Sources) > 50 {
		errs = append(errs, errors.New("sources must contain 1..50 entries"))
	}
	seen := map[string]bool{}
	for i, s := range c.Sources {
		p := fmt.Sprintf("sources[%d]", i)
		if !nameRe.MatchString(s.Name) {
			errs = append(errs, fmt.Errorf("%s.name invalid", p))
		}
		if seen[s.Name] {
			errs = append(errs, fmt.Errorf("%s.name duplicated", p))
		}
		seen[s.Name] = true
		if !allowedSources[s.Type] {
			errs = append(errs, fmt.Errorf("%s.type %q is not an allowed source type", p, s.Type))
		}
		if !assetRe.MatchString(s.AssetID) {
			errs = append(errs, fmt.Errorf("%s.asset_id invalid", p))
		}
		if s.Type == SourceWindowsLive {
			if s.Channel != "Security" {
				errs = append(errs, fmt.Errorf("%s.channel must be Security", p))
			}
			if s.Path != "" {
				errs = append(errs, fmt.Errorf("%s.path not allowed for windows_eventlog", p))
			}
		} else if !filepath.IsAbs(s.Path) {
			errs = append(errs, fmt.Errorf("%s.path must be absolute", p))
		}
	}
	return errors.Join(errs...)
}

// Heartbeat returns the heartbeat interval.
func (c *Config) Heartbeat() time.Duration { return time.Duration(c.HeartbeatSeconds) * time.Second }

// Flush returns the flush interval.
func (c *Config) Flush() time.Duration { return time.Duration(c.FlushSeconds) * time.Second }

func isLoopback(host string) bool {
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}
