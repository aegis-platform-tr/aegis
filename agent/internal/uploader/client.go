// Package uploader talks to the AEGIS agent API.
package uploader

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// UserAgent identifies the agent build.
var UserAgent = "aegis-agent"

// MaxResponseBytes bounds how much of a server response is read.
const MaxResponseBytes = 4 << 20

// ErrRevoked means the server rejected the agent credential (revoked, expired or unknown).
var ErrRevoked = errors.New("agent credential rejected by server")

// Client is safe for concurrent use.
type Client struct {
	BaseURL string
	HTTP    *http.Client
	mu      sync.RWMutex
	cred    string
}

// New creates a client with sane timeouts. TLS verification is always on.
func New(baseURL, credential string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP:    &http.Client{Timeout: 30 * time.Second},
		cred:    credential,
	}
}

// SetCredential swaps the credential after rotation.
func (c *Client) SetCredential(cred string) {
	c.mu.Lock()
	c.cred = cred
	c.mu.Unlock()
}

func (c *Client) credential() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cred
}

// StatusError is a non-2xx response.
type StatusError struct {
	Status int
	Code   string
}

func (e *StatusError) Error() string { return fmt.Sprintf("server returned %d (%s)", e.Status, e.Code) }

func (c *Client) do(ctx context.Context, path string, body any, auth bool) (int, []byte, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(data))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	if auth {
		req.Header.Set("Authorization", "Bearer "+c.credential())
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes))
	return resp.StatusCode, out, err
}

func errorCode(body []byte) string {
	var e struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &e)
	return e.Error.Code
}

// EnrollResult is returned by Enroll.
type EnrollResult struct {
	AgentID             string `json:"agent_id"`
	TenantID            string `json:"tenant_id"`
	Credential          string `json:"credential"`
	CredentialExpiresAt string `json:"credential_expires_at"`
}

// Enroll exchanges a single-use enrollment token for an agent identity.
func (c *Client) Enroll(ctx context.Context, token, hostname, platform, version string) (*EnrollResult, error) {
	status, body, err := c.do(ctx, "/api/v1/agent/enroll", map[string]string{
		"enrollment_token": token, "hostname": hostname, "platform": platform, "agent_version": version,
	}, false)
	if err != nil {
		return nil, err
	}
	if status != http.StatusCreated {
		return nil, &StatusError{status, errorCode(body)}
	}
	var r EnrollResult
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// HeartbeatResponse carries server directives.
type HeartbeatResponse struct {
	ServerTime             time.Time `json:"server_time"`
	ClockSkewMS            int64     `json:"clock_skew_ms"`
	AcceptedSchemaVersions []string  `json:"accepted_schema_versions"`
	AgentVersionSupported  bool      `json:"agent_version_supported"`
	RotateCredential       bool      `json:"rotate_credential"`
}

// Heartbeat reports agent status.
func (c *Client) Heartbeat(ctx context.Context, payload any) (*HeartbeatResponse, error) {
	status, body, err := c.do(ctx, "/api/v1/agent/heartbeat", payload, true)
	if err != nil {
		return nil, err
	}
	if status == http.StatusUnauthorized {
		return nil, ErrRevoked
	}
	if status != http.StatusOK {
		return nil, &StatusError{status, errorCode(body)}
	}
	var r HeartbeatResponse
	return &r, json.Unmarshal(body, &r)
}

// Rotate obtains a new credential; the old one stops working immediately.
func (c *Client) Rotate(ctx context.Context) (cred, expires string, err error) {
	status, body, err := c.do(ctx, "/api/v1/agent/rotate", map[string]string{}, true)
	if err != nil {
		return "", "", err
	}
	if status == http.StatusUnauthorized {
		return "", "", ErrRevoked
	}
	if status != http.StatusOK {
		return "", "", &StatusError{status, errorCode(body)}
	}
	var r struct {
		Credential string `json:"credential"`
		Expires    string `json:"credential_expires_at"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return "", "", err
	}
	return r.Credential, r.Expires, nil
}

// ItemResult mirrors the API per-item result.
type ItemResult struct {
	Index   int    `json:"index"`
	Status  string `json:"status"`
	EventID string `json:"event_id"`
	Errors  []struct {
		Field   string `json:"field"`
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
}

// Outcome classifies a batch delivery attempt.
type Outcome int

const (
	// Delivered means every item was accepted, duplicate or permanently rejected.
	Delivered Outcome = iota
	// Retry means a transient failure; resend the same batch later.
	Retry
	// TooLarge means the batch must be split.
	TooLarge
	// Revoked means stop sending; the credential is no longer valid.
	Revoked
	// Poison means the server refused the whole request permanently (e.g. 400).
	Poison
)

// SendResult is the outcome of SendEvents.
type SendResult struct {
	Outcome   Outcome
	Status    int
	Rejected  []ItemResult
	Accepted  int
	Duplicate int
}

// SendEvents posts a batch and classifies the response.
func (c *Client) SendEvents(ctx context.Context, events []json.RawMessage) (SendResult, error) {
	status, body, err := c.do(ctx, "/api/v1/agent/events", map[string]any{"events": events}, true)
	if err != nil {
		return SendResult{Outcome: Retry}, err
	}
	res := SendResult{Status: status}
	switch {
	case status == http.StatusOK || status == http.StatusMultiStatus ||
		(status == http.StatusUnprocessableEntity && strings.Contains(string(body), `"results"`)):
		var r struct {
			Accepted  int          `json:"accepted"`
			Duplicate int          `json:"duplicate"`
			Results   []ItemResult `json:"results"`
		}
		if err := json.Unmarshal(body, &r); err != nil {
			return SendResult{Outcome: Retry, Status: status}, err
		}
		res.Outcome, res.Accepted, res.Duplicate = Delivered, r.Accepted, r.Duplicate
		for _, it := range r.Results {
			if it.Status == "rejected" {
				res.Rejected = append(res.Rejected, it)
			}
		}
		return res, nil
	case status == http.StatusUnauthorized:
		res.Outcome = Revoked
	case status == http.StatusRequestEntityTooLarge:
		res.Outcome = TooLarge
	case status == http.StatusTooManyRequests || status >= 500:
		res.Outcome = Retry
	default:
		res.Outcome = Poison
	}
	return res, &StatusError{status, errorCode(body)}
}
