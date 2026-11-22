package parsers

import (
	"encoding/xml"
	"net"
	"strconv"
	"strings"
	"time"
)

// WindowsSecurity maps Windows Security log events rendered as XML (wevtutil /f:xml or
// Get-WinEvent ... .ToXml()). Only allowlisted event IDs and EventData fields are kept.
type WindowsSecurity struct{}

func (WindowsSecurity) Adapter() string { return "windows-security" }
func (WindowsSecurity) Version() string { return "1" }

// AllowedEventIDs maps Security event IDs to AEGIS event types.
var AllowedEventIDs = map[int]string{
	4624: "login_success",
	4625: "login_failure",
	4740: "account_lockout",
}

var allowedDataFields = map[string]string{
	"TargetUserName":            "target_user",
	"TargetDomainName":          "target_domain",
	"LogonType":                 "logon_type",
	"Status":                    "status",
	"SubStatus":                 "sub_status",
	"WorkstationName":           "workstation",
	"AuthenticationPackageName": "auth_package",
}

type winEvent struct {
	System struct {
		EventID     string `xml:"EventID"`
		Computer    string `xml:"Computer"`
		RecordID    string `xml:"EventRecordID"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Channel string `xml:"Channel"`
	} `xml:"System"`
	Data []struct {
		Name  string `xml:"Name,attr"`
		Value string `xml:",chardata"`
	} `xml:"EventData>Data"`
}

// RecordID extracts EventRecordID without full mapping (used for cursors).
func RecordID(raw []byte) (uint64, error) {
	var e winEvent
	if err := xml.Unmarshal(raw, &e); err != nil {
		return 0, malformed("invalid XML")
	}
	return strconv.ParseUint(strings.TrimSpace(e.System.RecordID), 10, 64)
}

// Parse implements Parser.
func (p WindowsSecurity) Parse(raw []byte) (*Event, error) {
	var e winEvent
	dec := xml.NewDecoder(strings.NewReader(string(raw)))
	dec.Strict = true
	// Defense in depth: the decoder never resolves external entities; also refuse DTDs.
	if strings.Contains(string(raw), "<!DOCTYPE") {
		return nil, malformed("DTD not allowed")
	}
	if err := dec.Decode(&e); err != nil {
		return nil, malformed("invalid XML")
	}
	id, err := strconv.Atoi(strings.TrimSpace(e.System.EventID))
	if err != nil {
		return nil, malformed("missing EventID")
	}
	typ, ok := AllowedEventIDs[id]
	if !ok {
		return nil, ErrSkip
	}
	ts, err := time.Parse(time.RFC3339Nano, e.System.TimeCreated.SystemTime)
	if err != nil {
		return nil, malformed("bad SystemTime")
	}
	ev := newEvent(p, "authentication", typ)
	ev.Severity = map[string]string{"login_failure": "low", "login_success": "info", "account_lockout": "medium"}[typ]
	ev.OccurredAt = timePtr(ts)
	ev.Attributes["event_id"] = id
	ev.Attributes["record_id"] = strings.TrimSpace(e.System.RecordID)
	ev.Attributes["computer"] = truncate(e.System.Computer, 200)
	var ip, port string
	for _, d := range e.Data {
		v := strings.TrimSpace(d.Value)
		switch d.Name {
		case "IpAddress":
			ip = v
		case "IpPort":
			port = v
		default:
			if key, ok := allowedDataFields[d.Name]; ok && v != "" && v != "-" {
				ev.Attributes[key] = truncate(v, 200)
			}
		}
	}
	if u, ok := ev.Attributes["target_user"].(string); ok {
		ev.Principal = u
	}
	if ip != "" && ip != "-" && ip != "::1" && ip != "127.0.0.1" {
		if net.ParseIP(ip) == nil {
			return nil, malformed("invalid IpAddress")
		}
		ev.SourceIP = ip
	}
	if n, err := strconv.Atoi(port); err == nil && n > 0 {
		ev.SourcePort = intPtr(n)
	}
	return ev, nil
}
