package config

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// build makes a config with OS-appropriate absolute paths (tests run on Linux and Windows).
func build(logPath string) string {
	base, _ := filepath.Abs("testroot")
	state, _ := json.Marshal(filepath.Join(base, "state"))
	if logPath == "" {
		logPath = filepath.Join(base, "auth.log")
	}
	logf, _ := json.Marshal(logPath)
	return `{"schema_version":1,"config_version":3,"server_url":"https://aegis.example","state_dir":` +
		string(state) + `,"sources":[{"name":"auth","type":"linux_auth","path":` + string(logf) +
		`,"asset_id":"web01"}]}`
}

var good = build("")

func TestValidConfig(t *testing.T) {
	c, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if c.BatchSize != 200 || c.HeartbeatSeconds != 30 {
		t.Fatalf("defaults not applied: %+v", c)
	}
}

func TestRejectsUnsafeOrInvalid(t *testing.T) {
	cases := map[string]string{
		"unknown field (e.g. command)": strings.Replace(good, `"asset_id":"web01"`, `"asset_id":"web01","command":"rm -rf /"`, 1),
		"unknown source type":          strings.Replace(good, "linux_auth", "shell_exec", 1),
		"plain http remote":            strings.Replace(good, "https://aegis.example", "http://aegis.example", 1),
		"relative path":                build("auth.log"),
		"wrong schema":                 strings.Replace(good, `"schema_version":1`, `"schema_version":2`, 1),
		"bad asset":                    strings.Replace(good, `"web01"`, `"web 01; ls"`, 1),
	}
	for name, raw := range cases {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

func TestLocalhostHTTPNeedsOptIn(t *testing.T) {
	raw := strings.Replace(good, "https://aegis.example", "http://127.0.0.1:8000", 1)
	if _, err := Parse([]byte(raw)); err == nil {
		t.Fatal("http localhost without opt-in accepted")
	}
	raw = strings.Replace(raw, `"config_version":3`, `"config_version":3,"allow_insecure_localhost":true`, 1)
	if _, err := Parse([]byte(raw)); err != nil {
		t.Fatal(err)
	}
}
