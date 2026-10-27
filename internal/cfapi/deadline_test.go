package cfapi

import (
	"context"
	"net/http"
	"testing"
	"time"
)

type deadlineTransport struct {
	t *testing.T
}

func (d deadlineTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	deadline, ok := req.Context().Deadline()
	if !ok || time.Until(deadline) > 25*time.Second {
		d.t.Error("API request can outlive the 30-second interactive operation budget")
	}
	return nil, context.DeadlineExceeded
}

func TestRequestHasInteractiveDeadlineWithoutCallerDeadline(t *testing.T) {
	c := New(StaticToken("test-token"), "test")
	c.HTTPClient = &http.Client{Transport: deadlineTransport{t}}
	if _, err := c.request(context.Background(), http.MethodGet, "/test", nil, nil, nil); err == nil {
		t.Fatal("stalled transport returned success")
	}
}
