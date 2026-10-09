// Package routeros is a small client for the RouterOS v7 REST API
// (https://help.mikrotik.com/docs/display/ROS/REST+API). It implements
// model.RouterAPI and exposes a generic Get for ad-hoc queries.
package routeros

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Marteva/routeros-guardian/internal/model"
)

// Config configures a Client.
type Config struct {
	BaseURL     string // e.g. "http://172.17.0.1" or "https://192.168.88.1"; a trailing "/rest" is accepted
	User        string
	Password    string
	InsecureTLS bool          // skip certificate verification (self-signed www-ssl)
	Timeout     time.Duration // per request; 0 = 10s
}

// Client talks to the RouterOS REST API. It is safe for concurrent use.
type Client struct {
	base       string // scheme://host[:port][/prefix], no trailing slash
	user, pass string
	hc         *http.Client

	connHint atomic.Int64 // size of the last connection table, used to pre-size slices
}

var _ model.RouterAPI = (*Client)(nil)

// New validates cfg and builds a Client. It does not contact the router.
func New(cfg Config) (*Client, error) {
	raw := strings.TrimSpace(cfg.BaseURL)
	if raw == "" {
		return nil, errors.New("routeros: empty BaseURL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("routeros: bad BaseURL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("routeros: BaseURL scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("routeros: BaseURL %q has no host", raw)
	}
	path := strings.TrimRight(u.Path, "/")
	path = strings.TrimSuffix(path, "/rest")
	base := u.Scheme + "://" + u.Host + path

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil                                                                                      // the router is always reached directly
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: cfg.InsecureTLS, MinVersion: tls.VersionTLS12} //nolint:gosec // opt-in for self-signed router certs
	tr.MaxIdleConnsPerHost = 2
	tr.IdleConnTimeout = 90 * time.Second
	// Compression would cost router CPU for no gain on a local link.
	tr.DisableCompression = true

	return &Client{
		base: base,
		user: cfg.User,
		pass: cfg.Password,
		hc:   &http.Client{Transport: tr, Timeout: timeout},
	}, nil
}

// APIError is a non-2xx response from RouterOS. The body is usually
// {"error":400,"message":"Bad Request","detail":"failure: already have such entry"}.
type APIError struct {
	Method  string
	Path    string
	Status  int
	Message string
	Detail  string
}

func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	if e.Detail != "" {
		return fmt.Sprintf("routeros: %s %s: %d %s: %s", e.Method, e.Path, e.Status, msg, e.Detail)
	}
	return fmt.Sprintf("routeros: %s %s: %d %s", e.Method, e.Path, e.Status, msg)
}

// Get performs GET /rest/<path>?<query> and JSON-decodes the response into out
// (nil out discards the body). Remember that RouterOS encodes all values as strings.
func (c *Client) Get(ctx context.Context, path string, query url.Values, out any) error {
	resp, err := c.do(ctx, http.MethodGet, path, query, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("routeros: decode %s: %w", path, err)
	}
	return nil
}

// endpoint builds the request URL. The URL is assembled as a string so that
// RouterOS ids like "*1A" keep their literal '*' (url.URL would escape it).
func (c *Client) endpoint(path string, query url.Values) string {
	var b strings.Builder
	b.WriteString(c.base)
	b.WriteString("/rest/")
	b.WriteString(strings.TrimLeft(path, "/"))
	if len(query) > 0 {
		b.WriteByte('?')
		// Commas are legal in a query; keep .proplist readable for RouterOS.
		b.WriteString(strings.ReplaceAll(query.Encode(), "%2C", ","))
	}
	return b.String()
}

// do sends a request and returns the response for 2xx statuses. Any other
// status is converted to *APIError and the body is closed.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body any) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("routeros: encode body: %w", err)
		}
		rd = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint(path, query), rd)
	if err != nil {
		return nil, fmt.Errorf("routeros: %w", err)
	}
	req.SetBasicAuth(c.user, c.pass)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("routeros: %s %s: %w", method, path, err)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp, nil
	}
	defer resp.Body.Close()
	return nil, readAPIError(resp, method, path)
}

func readAPIError(resp *http.Response, method, path string) *APIError {
	e := &APIError{Method: method, Path: path, Status: resp.StatusCode}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var body struct {
		Message str `json:"message"`
		Detail  str `json:"detail"`
	}
	if json.Unmarshal(data, &body) == nil && (body.Message != "" || body.Detail != "") {
		e.Message, e.Detail = string(body.Message), string(body.Detail)
		return e
	}
	text := strings.TrimSpace(string(data))
	if len(text) > 256 {
		text = text[:256] + "..."
	}
	e.Detail = text
	return e
}

// countingReader counts bytes read from the response body.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// decodeArray stream-decodes a JSON array, calling fn for each element. The
// element is zeroed before each decode so missing keys never leak values.
func decodeArray[T any](r io.Reader, fn func(*T)) error {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return fmt.Errorf("expected JSON array, got %v", tok)
	}
	var v T
	for dec.More() {
		var zero T
		v = zero
		if err := dec.Decode(&v); err != nil {
			return err
		}
		fn(&v)
	}
	_, err = dec.Token() // closing ']'
	return err
}

// getArray GETs path and stream-decodes the array response.
func getArray[T any](ctx context.Context, c *Client, path string, query url.Values, fn func(*T)) (int64, error) {
	resp, err := c.do(ctx, http.MethodGet, path, query, nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	cr := &countingReader{r: resp.Body}
	if err := decodeArray(cr, fn); err != nil {
		return cr.n, fmt.Errorf("routeros: decode %s: %w", path, err)
	}
	return cr.n, nil
}
