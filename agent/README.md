# aegis-agent (M2)

A single static Go binary (standard library only) that collects security telemetry, normalizes
it to event envelope v1.0, spools it on disk and delivers it to the AEGIS agent API.

```bash
go build -o aegis-agent ./cmd/aegis-agent          # GOOS=windows for aegis-agent.exe
aegis-agent validate-config -config agent.json
aegis-agent enroll -config agent.json -token-file /root/aegis-token   # then delete the file
aegis-agent run -config agent.json                 # exit code 3 = credential revoked/expired
```

Enrollment tokens are minted by a tenant admin (`POST /api/v1/agents/enrollment-tokens`), are
single-use, tenant-bound and expire (default 1 h, max 24 h). Enrollment returns a per-agent
credential (30 days) stored in `state_dir/identity.json` with mode 0600. The server asks the
agent to rotate it during the last 7 days; revocation stops the agent with exit code 3 and the
spool is kept so nothing is lost after re-enrollment.

## Sources and required permissions

| Type | Input | Parser contract | Permission needed | Status |
|---|---|---|---|---|
| `linux_auth` | `/var/log/auth.log`, `/var/log/secure`, or a file written by `journalctl -o short-iso -f -u ssh` | `linux-auth` v1 (OpenSSH accepted/failed) | read on the file (`adm` group on Debian/Ubuntu) | verified on Linux |
| `suricata_eve` | `eve.json` | `suricata-eve` v1 (alert, flow, dns, http, tls) | read on the log | verified on fixtures and live file tailing |
| `zeek_json` | Zeek logs with `LogAscii::use_json=T` | `zeek-json` v1 (conn, dns, http, ssl) | read on the log | verified on fixtures and live file tailing |
| `windows_event_xml` | file with one Security event XML per line | `windows-security` v1 (4624, 4625, 4740) | read on the file | verified on fixtures (Linux) |
| `windows_eventlog` | live Security channel via `wevtutil qe` (fixed argument list) | `windows-security` v1 | member of **Event Log Readers** | **compiles; not runtime-verified** (no Windows host in the build environment) |

journald is read via `journalctl -o short-iso` output, not the journal API, to keep the binary
dependency-free; native journal reading is a follow-up.

Only allowlisted fields are collected. HTTP query strings are dropped (they often carry
tokens). Windows events keep only the listed EventData fields.

## Delivery guarantees and failure behavior

- **At-least-once, deduplicated server-side.** Every event has a stable `native_id`
  (`<source>:<file identity>:<byte offset>` or `<source>:record:<EventRecordID>`). A batch is
  written to the spool *before* the cursor advances and deleted only after the server answers.
  Crashes cause re-sends that the server reports as `duplicate`.
- **Disconnect:** exponential backoff with jitter (1 s → 60 s), same batch retried.
- **Restart:** cursors and spool survive; reading resumes at the persisted offset.
- **Rotation/truncation:** a new file identity or a file shorter than the cursor restarts at
  offset 0 and increments `cursor_resets` (reported in heartbeats). Lines written to the old
  file after rotation and before the next poll can be missed (documented gap).
- **Disk bound:** when `spool_max_bytes` is reached sources pause (`status: paused`,
  `spool_full: true`); cursors do not advance, so events are delayed, not dropped. If the
  source log itself rotates away while paused, that data is lost and shows as `cursor_resets`.
- **Malformed input / oversize lines (>64 KiB):** written to `state_dir/quarantine/` (bounded,
  samples truncated to 2 KiB) and counted in heartbeats.
- **Server rejects items (e.g. schema version skew):** rejected items are quarantined with the
  server's field/code; they are not retried forever. `413` splits the batch; other permanent
  `4xx` quarantine the batch.
- **Version skew:** heartbeats return `agent_version_supported` and
  `accepted_schema_versions`; the agent logs a warning when unsupported.

Configuration is strict JSON (unknown fields rejected), versioned (`config_version`) and has
no field that can carry a command or executable. `http://` is accepted only for localhost with
`allow_insecure_localhost: true`.
