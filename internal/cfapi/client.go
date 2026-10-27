package cfapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
)

const BaseURL = "https://api.cloudflare.com/client/v4"

// Client uses a fresh token for each request, including subsequent pages.
// BaseURL and HTTPClient may be replaced for tests.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	UserAgent  string
	Tokens     TokenSource
}

func New(tokens TokenSource, version string) *Client {
	return &Client{BaseURL: BaseURL, HTTPClient: &http.Client{Timeout: 45 * time.Second}, UserAgent: "meshscale/" + version, Tokens: tokens}
}

type APIMessage struct {
	Code       int          `json:"code,omitempty"`
	Message    string       `json:"message"`
	ErrorChain []APIMessage `json:"error_chain,omitempty"`
}

// Some endpoints put plain strings in messages rather than error objects.
func (m *APIMessage) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '"' {
		return json.Unmarshal(data, &m.Message)
	}
	type plain APIMessage
	return json.Unmarshal(data, (*plain)(m))
}

func (m APIMessage) String() string {
	s := printable(m.Message)
	if m.Code != 0 {
		s = fmt.Sprintf("%d: %s", m.Code, s)
	}
	for _, child := range m.ErrorChain {
		s += ": " + child.String()
	}
	return s
}

// printable escapes control and bidirectional-override characters, so API
// text that echoes account data cannot forge log lines or rewrite a terminal.
func printable(s string) string {
	unsafe := func(r rune) bool {
		return unicode.IsControl(r) || r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069
	}
	if !strings.ContainsFunc(s, unsafe) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if unsafe(r) {
			fmt.Fprintf(&b, "\\u%04x", r)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// APIError preserves Cloudflare's error codes for callers that need them.
type APIError struct {
	Method, Path string
	StatusCode   int
	Errors       []APIMessage
	Messages     []APIMessage
	retryAfter   time.Duration
}

func (e *APIError) Error() string {
	items := e.Errors
	if len(items) == 0 {
		items = e.Messages
	}
	parts := make([]string, 0, len(items))
	for _, m := range items {
		parts = append(parts, m.String())
	}
	detail := strings.Join(parts, "; ")
	if detail == "" {
		detail = "unsuccessful API response"
	}
	return fmt.Sprintf("cloudflare %s %s (HTTP %d): %s", e.Method, e.Path, e.StatusCode, detail)
}

type resultInfo struct {
	Page       int    `json:"page"`
	PerPage    int    `json:"per_page"`
	Count      int    `json:"count"`
	TotalCount *int   `json:"total_count"`
	TotalPages *int   `json:"total_pages"`
	Cursor     string `json:"cursor"`
}

type envelope struct {
	Success    bool            `json:"success"`
	Errors     []APIMessage    `json:"errors"`
	Messages   []APIMessage    `json:"messages"`
	Result     json.RawMessage `json:"result"`
	ResultInfo *resultInfo     `json:"result_info"`
}

// request retries only idempotent methods, with at most four total attempts.
func (c *Client) request(ctx context.Context, method, path string, query url.Values, body, out any) (*resultInfo, error) {
	// Bound the whole operation, including rate-limit waits and token refresh.
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	for attempt := 0; ; attempt++ {
		info, err := c.requestOnce(ctx, method, path, query, body, out)
		var api *APIError
		if attempt == 3 || (method != http.MethodGet && method != http.MethodPut && method != http.MethodDelete) || !errors.As(err, &api) || (api.StatusCode != 429 && (api.StatusCode < 500 || api.StatusCode >= 600)) {
			return info, err
		}
		delay := (100 * time.Millisecond << attempt) + time.Duration(rand.Int64N(int64(100*time.Millisecond<<attempt)))
		delay = max(delay, api.retryAfter)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, fmt.Errorf("%w (retry interrupted: %w)", err, ctx.Err())
		case <-timer.C:
		}
	}
}

func retryAfter(value string, now time.Time) time.Duration {
	if seconds, err := strconv.ParseInt(value, 10, 32); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second
	}
	if date, err := http.ParseTime(value); err == nil {
		return max(0, date.Sub(now))
	}
	return 0
}

func (c *Client) requestOnce(ctx context.Context, method, path string, query url.Values, body, out any) (*resultInfo, error) {
	if c.Tokens == nil {
		return nil, fmt.Errorf("cloudflare: no token source")
	}
	token, err := c.Tokens.Token(ctx)
	if err != nil {
		return nil, &safeError{message: "cloudflare token unavailable", cause: err}
	}
	var payload io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("cloudflare encode request: %w", err)
		}
		payload = bytes.NewReader(data)
	}
	base := c.BaseURL
	if base == "" {
		base = BaseURL
	}
	u := strings.TrimRight(base, "/") + path
	if len(query) != 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, payload)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := c.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 45 * time.Second}
	}
	// API operations never follow redirects, including same-host redirects that
	// would otherwise forward credentials or replay a mutation. Copy the client
	// so a caller-supplied transport/client can safely be shared.
	client := *hc
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	var written atomic.Bool
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		WroteHeaders: func() { written.Store(true) },
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err == nil {
				written.Store(true)
			}
		},
	}))
	resp, err := client.Do(req)
	if err != nil {
		err = &safeError{message: fmt.Sprintf("cloudflare %s %s: %s", method, path, redactToken(err.Error(), token)), cause: err}
		if written.Load() {
			err = &uncertainCreateError{err}
		}
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent && method == http.MethodDelete {
		return nil, nil
	}
	const responseLimit = 16 << 20
	data, err := io.ReadAll(io.LimitReader(resp.Body, responseLimit+1))
	if len(data) > responseLimit {
		err = fmt.Errorf("response exceeds 16 MiB limit")
	}
	var env envelope
	if err == nil {
		err = json.Unmarshal(data, &env)
	}
	if err != nil {
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			// Keep the status typed so callers can tell a 403 from an outage.
			return nil, &APIError{Method: method, Path: path, StatusCode: resp.StatusCode, retryAfter: retryAfter(resp.Header.Get("Retry-After"), time.Now()), Messages: []APIMessage{{Message: "non-JSON error response"}}}
		}
		return nil, &uncertainCreateError{fmt.Errorf("cloudflare %s %s (HTTP %d): decode response: %w", method, path, resp.StatusCode, err)}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !env.Success || len(env.Errors) > 0 {
		return nil, &APIError{Method: method, Path: path, StatusCode: resp.StatusCode, retryAfter: retryAfter(resp.Header.Get("Retry-After"), time.Now()), Errors: redactMessages(env.Errors, token), Messages: redactMessages(env.Messages, token)}
	}
	if out != nil {
		if len(env.Result) == 0 || bytes.Equal(bytes.TrimSpace(env.Result), []byte("null")) {
			return nil, &uncertainCreateError{fmt.Errorf("cloudflare %s %s: missing result", method, path)}
		}
		if err := json.Unmarshal(env.Result, out); err != nil {
			return nil, &uncertainCreateError{fmt.Errorf("cloudflare %s %s: decode result: %w", method, path, err)}
		}
	}
	return env.ResultInfo, nil
}

type pagination int

// maxListItems is far above any real account's devices, rules or records.
const maxListItems = 1_000_000

const (
	pages pagination = iota
	cursors
	unpaginated
)

func list[T any](ctx context.Context, c *Client, path string, mode pagination) ([]T, error) {
	return listPageSize[T](ctx, c, path, mode, 100)
}

func listPageSize[T any](ctx context.Context, c *Client, path string, mode pagination, perPage int) ([]T, error) {
	return listQuery[T](ctx, c, path, mode, perPage, url.Values{})
}

func listQuery[T any](ctx context.Context, c *Client, path string, mode pagination, perPage int, query url.Values) ([]T, error) {
	all := make([]T, 0)
	if mode != unpaginated {
		query.Set("per_page", strconv.Itoa(perPage))
	}
	seenCursors := map[string]bool{}
	for page := 1; ; page++ {
		if page > 10000 {
			return nil, fmt.Errorf("cloudflare %s: pagination limit exceeded", path)
		}
		if mode == pages {
			query.Set("page", strconv.Itoa(page))
		}
		var batch []T
		info, err := c.request(ctx, http.MethodGet, path, query, nil, &batch)
		if err != nil {
			return nil, err
		}
		// Some endpoints ignore per_page, so only a page larger than its own
		// reported size is malformed. maxListItems bounds the whole list.
		if info != nil && info.PerPage > 0 && len(batch) > info.PerPage {
			return nil, fmt.Errorf("cloudflare %s: page has %d items, more than its per_page %d", path, len(batch), info.PerPage)
		}
		if len(all)+len(batch) > maxListItems {
			return nil, fmt.Errorf("cloudflare %s: more than %d items", path, maxListItems)
		}
		all = append(all, batch...)
		if mode == unpaginated {
			return all, nil
		}
		if info == nil {
			if len(batch) >= perPage {
				return nil, fmt.Errorf("cloudflare %s: pagination metadata missing for full page", path)
			}
			return all, nil
		}
		if info.Page < 0 || info.PerPage < 0 || info.TotalCount != nil && *info.TotalCount < 0 || info.TotalPages != nil && *info.TotalPages < 0 {
			return nil, fmt.Errorf("cloudflare %s: invalid pagination metadata", path)
		}
		if mode == pages && info.Page > 0 && info.Page != page {
			return nil, fmt.Errorf("cloudflare %s: unexpected pagination page %d (wanted %d)", path, info.Page, page)
		}
		if len(batch) == 0 && (info.Cursor != "" || info.TotalCount != nil && len(all) < *info.TotalCount || info.TotalPages != nil && page < *info.TotalPages) {
			return nil, fmt.Errorf("cloudflare %s: incomplete pagination", path)
		}
		if mode == cursors {
			if info.Cursor == "" {
				return all, nil
			}
			if seenCursors[info.Cursor] {
				return nil, fmt.Errorf("cloudflare %s: repeated pagination cursor", path)
			}
			seenCursors[info.Cursor] = true
			query.Set("cursor", info.Cursor)
			continue
		}
		if info.TotalCount != nil {
			if len(all) >= *info.TotalCount {
				return all, nil
			}
		} else if info.TotalPages != nil {
			if page >= *info.TotalPages {
				return all, nil
			}
		} else {
			limit := info.PerPage
			if limit <= 0 {
				limit = perPage
			}
			if len(batch) < limit {
				return all, nil
			}
		}
	}
}

func accountPath(accountID, suffix string) string {
	return "/accounts/" + url.PathEscape(accountID) + suffix
}

func get[T any](ctx context.Context, c *Client, path string) (T, error) {
	return send[T](ctx, c, http.MethodGet, path, nil)
}

func send[T any](ctx context.Context, c *Client, method, path string, body any) (T, error) {
	var result T
	_, err := c.request(ctx, method, path, nil, body, &result)
	return result, err
}

// safeError retains errors.Is/As without exposing credentials in diagnostics.
type safeError struct {
	message string
	cause   error
}

func (e *safeError) Error() string { return e.message }
func (e *safeError) Unwrap() error { return e.cause }
func redactToken(message, token string) string {
	if token == "" {
		return message
	}
	return strings.ReplaceAll(message, token, "[redacted]")
}
func redactMessages(messages []APIMessage, token string) []APIMessage {
	for i := range messages {
		messages[i].Message = redactToken(messages[i].Message, token)
		messages[i].ErrorChain = redactMessages(messages[i].ErrorChain, token)
	}
	return messages
}
