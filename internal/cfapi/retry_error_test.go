package cfapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type rateLimitTransport struct{ cancel context.CancelFunc }

func (r rateLimitTransport) RoundTrip(*http.Request) (*http.Response, error) {
	r.cancel()
	return &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": []string{"60"}}, Body: io.NopCloser(strings.NewReader(`{"success":false,"errors":[{"code":1015,"message":"rate limited"}]}`))}, nil
}

func TestRetryCancellationRetainsRateLimitCause(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	client := New(StaticToken("test-token"), "test")
	client.HTTPClient = &http.Client{Transport: rateLimitTransport{cancel}}
	_, err := client.request(ctx, http.MethodGet, "/test", nil, nil, nil)
	var api *APIError
	if !errors.As(err, &api) || api.StatusCode != http.StatusTooManyRequests || !errors.Is(err, context.Canceled) {
		t.Fatalf("retry lost the API failure or cancellation: %v", err)
	}
}
