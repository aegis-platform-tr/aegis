package parsers

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// LinuxAuth parses OpenSSH authentication messages from syslog-formatted auth logs
// (/var/log/auth.log, /var/log/secure, or `journalctl -o short-iso` output).
type LinuxAuth struct {
	// Now and Location support legacy timestamps without year/zone (injectable for tests).
	Now      func() time.Time
	Location *time.Location
}

func (LinuxAuth) Adapter() string { return "linux-auth" }
func (LinuxAuth) Version() string { return "1" }

var (
	isoPrefix    = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\s+(\S+)\s+(.*)$`)
	legacyPrefix = regexp.MustCompile(`^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$`)
	sshdTag      = regexp.MustCompile(`^sshd(?:-session)?\[\d+\]:\s+(.*)$`)
	failedRe     = regexp.MustCompile(`^Failed (password|publickey|keyboard-interactive/pam) for (invalid user )?(\S+) from (\S+) port (\d+)`)
	acceptedRe   = regexp.MustCompile(`^Accepted (password|publickey|keyboard-interactive/pam|gssapi-with-mic) for (\S+) from (\S+) port (\d+)`)
)

// Parse implements Parser.
func (p LinuxAuth) Parse(raw []byte) (*Event, error) {
	line := string(raw)
	var ts time.Time
	var host, rest string
	attrs := map[string]any{}
	if m := isoPrefix.FindStringSubmatch(line); m != nil {
		t, err := parseISO(m[1])
		if err != nil {
			return nil, malformed("bad timestamp")
		}
		ts, host, rest = t, m[2], m[3]
	} else if m := legacyPrefix.FindStringSubmatch(line); m != nil {
		t, err := p.legacyTime(m[1], m[2], m[3])
		if err != nil {
			return nil, malformed("bad legacy timestamp")
		}
		ts, host, rest = t, m[4], m[5]
		attrs["time_assumptions"] = "year and timezone inferred by collector"
	} else {
		return nil, malformed("unrecognized syslog prefix")
	}
	tag := sshdTag.FindStringSubmatch(rest)
	if tag == nil {
		return nil, ErrSkip
	}
	msg := tag[1]
	attrs["hostname"] = truncate(host, 200)
	if m := failedRe.FindStringSubmatch(msg); m != nil {
		ev := newEvent(p, "authentication", "login_failure")
		ev.Severity = "low"
		attrs["auth_method"] = m[1]
		attrs["invalid_user"] = m[2] != ""
		return finishSSH(ev, ts, m[3], m[4], m[5], attrs)
	}
	if m := acceptedRe.FindStringSubmatch(msg); m != nil {
		ev := newEvent(p, "authentication", "login_success")
		ev.Severity = "info"
		attrs["auth_method"] = m[1]
		return finishSSH(ev, ts, m[2], m[3], m[4], attrs)
	}
	return nil, ErrSkip
}

func finishSSH(ev *Event, ts time.Time, user, ip, port string, attrs map[string]any) (*Event, error) {
	if net.ParseIP(ip) == nil {
		return nil, malformed("invalid source address")
	}
	pn, err := strconv.Atoi(port)
	if err != nil {
		return nil, malformed("invalid port")
	}
	ev.OccurredAt = timePtr(ts)
	ev.SourceIP = ip
	ev.SourcePort = intPtr(pn)
	ev.DestinationPort = intPtr(22)
	ev.Protocol = "tcp"
	ev.Principal = truncate(user, 200)
	attrs["service"] = "sshd"
	ev.Attributes = attrs
	return ev, nil
}

func parseISO(s string) (time.Time, error) {
	// journalctl short-iso uses +0300 (no colon); RFC3339 needs +03:00.
	if n := len(s); n >= 5 && (s[n-5] == '+' || s[n-5] == '-') && !strings.Contains(s[n-5:], ":") {
		s = s[:n-2] + ":" + s[n-2:]
	}
	return time.Parse(time.RFC3339Nano, s)
}

func (p LinuxAuth) legacyTime(mon, day, clock string) (time.Time, error) {
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	loc := p.Location
	if loc == nil {
		loc = time.Local
	}
	n := now().In(loc)
	t, err := time.ParseInLocation("2006 Jan 2 15:04:05", strconv.Itoa(n.Year())+" "+mon+" "+day+" "+clock, loc)
	if err != nil {
		return t, err
	}
	// A December line read in January belongs to the previous year.
	if t.After(n.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t, nil
}
