package parsers

import (
	"encoding/json"
	"math"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

// ---- Suricata EVE JSON (contract: suricata-eve v1) -------------------------------------

// SuricataEVE maps alert, flow, dns, http and tls records. Other event types are skipped.
type SuricataEVE struct{}

func (SuricataEVE) Adapter() string { return "suricata-eve" }
func (SuricataEVE) Version() string { return "1" }

type eveRecord struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	FlowID    *int64 `json:"flow_id"`
	SrcIP     string `json:"src_ip"`
	SrcPort   *int   `json:"src_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  *int   `json:"dest_port"`
	Proto     string `json:"proto"`
	AppProto  string `json:"app_proto"`
	Alert     *struct {
		Action      string `json:"action"`
		SignatureID int64  `json:"signature_id"`
		Rev         int64  `json:"rev"`
		Signature   string `json:"signature"`
		Category    string `json:"category"`
		Severity    int    `json:"severity"`
	} `json:"alert"`
	DNS *struct {
		Type   string `json:"type"`
		RRName string `json:"rrname"`
		RRType string `json:"rrtype"`
		RCode  string `json:"rcode"`
	} `json:"dns"`
	Flow *struct {
		PktsToServer  int64  `json:"pkts_toserver"`
		PktsToClient  int64  `json:"pkts_toclient"`
		BytesToServer int64  `json:"bytes_toserver"`
		BytesToClient int64  `json:"bytes_toclient"`
		State         string `json:"state"`
		Reason        string `json:"reason"`
	} `json:"flow"`
	HTTP *struct {
		Hostname string `json:"hostname"`
		URL      string `json:"url"`
		Method   string `json:"http_method"`
		Status   int    `json:"status"`
	} `json:"http"`
	TLS *struct {
		SNI     string `json:"sni"`
		Version string `json:"version"`
	} `json:"tls"`
}

// Parse implements Parser.
func (p SuricataEVE) Parse(raw []byte) (*Event, error) {
	var r eveRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, malformed("invalid JSON")
	}
	if r.Timestamp == "" || r.EventType == "" {
		return nil, malformed("missing timestamp or event_type")
	}
	ts, err := parseISO(r.Timestamp)
	if err != nil {
		return nil, malformed("bad timestamp")
	}
	var ev *Event
	switch r.EventType {
	case "alert":
		if r.Alert == nil {
			return nil, malformed("alert record without alert object")
		}
		ev = newEvent(p, "ids", "ids_alert")
		ev.Severity = map[int]string{1: "high", 2: "medium", 3: "low"}[r.Alert.Severity]
		if ev.Severity == "" {
			ev.Severity = "info"
		}
		ev.Attributes["signature_id"] = r.Alert.SignatureID
		ev.Attributes["signature_rev"] = r.Alert.Rev
		ev.Attributes["signature"] = truncate(r.Alert.Signature, 300)
		ev.Attributes["category"] = truncate(r.Alert.Category, 200)
		ev.Attributes["sensor_action"] = r.Alert.Action
	case "flow":
		if r.Flow == nil {
			return nil, malformed("flow record without flow object")
		}
		ev = newEvent(p, "network", "flow")
		ev.Attributes["bytes_toserver"] = r.Flow.BytesToServer
		ev.Attributes["bytes_toclient"] = r.Flow.BytesToClient
		ev.Attributes["pkts_toserver"] = r.Flow.PktsToServer
		ev.Attributes["pkts_toclient"] = r.Flow.PktsToClient
		ev.Attributes["state"] = r.Flow.State
		ev.Attributes["end_reason"] = r.Flow.Reason
	case "dns":
		if r.DNS == nil {
			return nil, malformed("dns record without dns object")
		}
		typ := "dns_query"
		if r.DNS.Type == "answer" {
			typ = "dns_answer"
		}
		ev = newEvent(p, "network", typ)
		ev.Attributes["query"] = truncate(r.DNS.RRName, 255)
		ev.Attributes["qtype"] = r.DNS.RRType
		if r.DNS.RCode != "" {
			ev.Attributes["rcode"] = r.DNS.RCode
		}
	case "http":
		if r.HTTP == nil {
			return nil, malformed("http record without http object")
		}
		ev = newEvent(p, "network", "http_request")
		ev.Attributes["host"] = truncate(r.HTTP.Hostname, 255)
		ev.Attributes["path"] = pathOnly(r.HTTP.URL) // query strings may carry secrets
		ev.Attributes["method"] = r.HTTP.Method
		ev.Attributes["status"] = r.HTTP.Status
	case "tls":
		if r.TLS == nil {
			return nil, malformed("tls record without tls object")
		}
		ev = newEvent(p, "network", "tls_handshake")
		ev.Attributes["sni"] = truncate(r.TLS.SNI, 255)
		ev.Attributes["tls_version"] = r.TLS.Version
		ev.Attributes["visibility"] = "metadata only; payload encrypted"
	default:
		return nil, ErrSkip
	}
	if r.FlowID != nil {
		ev.Attributes["flow_id"] = *r.FlowID
	}
	if r.AppProto != "" {
		ev.Attributes["app_proto"] = r.AppProto
	}
	ev.OccurredAt = timePtr(ts)
	if err := setEndpoints(ev, r.SrcIP, r.DestIP, r.SrcPort, r.DestPort, r.Proto); err != nil {
		return nil, err
	}
	return ev, nil
}

// ---- Zeek JSON logs (contract: zeek-json v1) --------------------------------------------

// ZeekJSON maps conn, dns, http and ssl logs written with LogAscii::use_json=T.
// The log kind comes from the `_path` field, or else from the file name.
type ZeekJSON struct {
	FileName string
}

func (ZeekJSON) Adapter() string { return "zeek-json" }
func (ZeekJSON) Version() string { return "1" }

// Parse implements Parser.
func (p ZeekJSON) Parse(raw []byte) (*Event, error) {
	var r map[string]any
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, malformed("invalid JSON")
	}
	kind, _ := r["_path"].(string)
	if kind == "" {
		kind = strings.SplitN(filepath.Base(p.FileName), ".", 2)[0]
	}
	ts, err := zeekTime(r["ts"])
	if err != nil {
		return nil, malformed("missing or bad ts")
	}
	var ev *Event
	switch kind {
	case "conn":
		ev = newEvent(p, "network", "flow")
		copyKeys(ev.Attributes, r, map[string]string{
			"service": "service", "duration": "duration", "orig_bytes": "bytes_toserver",
			"resp_bytes": "bytes_toclient", "conn_state": "state", "orig_pkts": "pkts_toserver",
			"resp_pkts": "pkts_toclient",
		})
	case "dns":
		ev = newEvent(p, "network", "dns_query")
		copyKeys(ev.Attributes, r, map[string]string{"query": "query", "qtype_name": "qtype", "rcode_name": "rcode"})
	case "http":
		ev = newEvent(p, "network", "http_request")
		copyKeys(ev.Attributes, r, map[string]string{"host": "host", "method": "method", "status_code": "status"})
		if uri, ok := r["uri"].(string); ok {
			ev.Attributes["path"] = pathOnly(uri)
		}
	case "ssl":
		ev = newEvent(p, "network", "tls_handshake")
		copyKeys(ev.Attributes, r, map[string]string{"server_name": "sni", "version": "tls_version"})
		ev.Attributes["visibility"] = "metadata only; payload encrypted"
	default:
		return nil, ErrSkip
	}
	if uid, ok := r["uid"].(string); ok {
		ev.Attributes["zeek_uid"] = truncate(uid, 64)
	}
	ev.OccurredAt = timePtr(ts)
	src, _ := r["id.orig_h"].(string)
	dst, _ := r["id.resp_h"].(string)
	proto, _ := r["proto"].(string)
	if err := setEndpoints(ev, src, dst, numPtr(r["id.orig_p"]), numPtr(r["id.resp_p"]), proto); err != nil {
		return nil, err
	}
	return ev, nil
}

func zeekTime(v any) (time.Time, error) {
	switch t := v.(type) {
	case float64:
		sec, frac := math.Modf(t)
		return time.Unix(int64(sec), int64(frac*1e9)).UTC(), nil
	case string:
		return parseISO(t)
	}
	return time.Time{}, malformed("ts")
}

func numPtr(v any) *int {
	if f, ok := v.(float64); ok && f == math.Trunc(f) {
		return intPtr(int(f))
	}
	return nil
}

func copyKeys(dst, src map[string]any, mapping map[string]string) {
	for from, to := range mapping {
		if v, ok := src[from]; ok && v != nil {
			if s, isStr := v.(string); isStr {
				v = truncate(s, 255)
			}
			dst[to] = v
		}
	}
}

func setEndpoints(ev *Event, src, dst string, sp, dp *int, proto string) error {
	if src != "" {
		if net.ParseIP(src) == nil {
			return malformed("invalid source address")
		}
		ev.SourceIP = src
	}
	if dst != "" {
		if net.ParseIP(dst) == nil {
			return malformed("invalid destination address")
		}
		ev.DestinationIP = dst
	}
	if sp != nil {
		ev.SourcePort = intPtr(*sp)
	}
	if dp != nil {
		ev.DestinationPort = intPtr(*dp)
	}
	if proto != "" {
		ev.Protocol = strings.ToLower(truncate(proto, 32))
	}
	return nil
}

func pathOnly(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return truncate(u.EscapedPath(), 255)
}
