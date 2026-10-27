package service

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestInventoryRetainsLastSuccessfulSnapshot(t *testing.T) {
	failure := errors.New("API unavailable")
	calls := 0
	cache := NewInventoryCache(func(context.Context) ([]Device, error) {
		calls++
		if calls > 1 {
			return nil, failure
		}
		return []Device{{ID: "registration-1", Name: "laptop", IPv4: "100.96.0.6"}}, nil
	})
	if !cache.View().UpdatedAt.IsZero() {
		t.Fatal("uninitialized cache has timestamp")
	}
	first, err := cache.Refresh(context.Background())
	if err != nil || len(first.Devices) != 1 {
		t.Fatal(first, err)
	}
	if _, err := cache.Refresh(context.Background()); !errors.Is(err, failure) {
		t.Fatalf("lost error cause: %v", err)
	}
	stale := cache.View()
	if stale.Devices[0].ID != first.Devices[0].ID || !stale.UpdatedAt.Equal(first.UpdatedAt) || stale.Error == "" {
		t.Fatalf("lost successful snapshot: %+v", stale)
	}
}

func TestInventoryReadersDoNotWaitForRefresh(t *testing.T) {
	started, finish := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	cache := NewInventoryCache(func(context.Context) ([]Device, error) {
		if calls.Add(1) > 1 {
			close(started)
			<-finish
		}
		return []Device{{ID: "registration"}}, nil
	})
	if _, err := cache.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := cache.Refresh(context.Background()); done <- err }()
	<-started
	ctrl := &Control{Inventory: cache}
	response := httptest.NewRecorder()
	ctrl.deviceInventory(response, httptest.NewRequest("GET", "/devices", nil))
	if response.Code != 200 || calls.Load() != 2 {
		t.Fatal(response.Code, calls.Load())
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cache.Refresh(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	close(finish)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestInventoryEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name, method string
		warm, fail   bool
		want         int
	}{
		{name: "warming", method: "GET", want: 503},
		{name: "cached", method: "GET", warm: true, want: 200},
		{name: "refresh", method: "POST", want: 200},
		{name: "refresh failed", method: "POST", warm: true, fail: true, want: 200},
		{name: "first refresh failed", method: "POST", fail: true, want: 502},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fail := false
			calls := 0
			cache := NewInventoryCache(func(context.Context) ([]Device, error) {
				calls++
				if fail {
					return nil, errors.New("offline")
				}
				return []Device{{ID: "registration"}}, nil
			})
			if tc.warm {
				if _, err := cache.Refresh(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			fail = tc.fail
			ctrl := &Control{Inventory: cache}
			ctrl.Update(func(s *Status) { s.LastSync = time.Now(); s.Secure.ExitState = "blocked" })
			response := httptest.NewRecorder()
			ctrl.deviceInventory(response, httptest.NewRequest(tc.method, "/devices", nil))
			if response.Code != tc.want {
				t.Fatalf("status %d: %s", response.Code, response.Body)
			}
			wantCalls := 0
			if tc.warm {
				wantCalls++
			}
			if tc.method == "POST" {
				wantCalls++
			}
			if calls != wantCalls {
				t.Fatalf("calls %d want %d", calls, wantCalls)
			}
			if tc.warm && tc.fail && !strings.Contains(response.Body.String(), `"error":"refresh device inventory: offline"`) {
				t.Fatalf("stale view hides the failure: %s", response.Body)
			}
		})
	}
}

func TestInventoryRefreshSurvivesCallerCancellation(t *testing.T) {
	started, finish := make(chan struct{}), make(chan struct{})
	var once sync.Once
	cache := NewInventoryCache(func(ctx context.Context) ([]Device, error) {
		once.Do(func() { close(started) })
		select {
		case <-finish:
			return []Device{{ID: "registration"}}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	first, cancel := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() { _, err := cache.Refresh(first); firstDone <- err }()
	<-started
	second := make(chan error, 1)
	go func() { _, err := cache.Refresh(context.Background()); second <- err }()
	time.Sleep(10 * time.Millisecond) // let the second caller join the load
	cancel()
	if err := <-firstDone; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	close(finish)
	if err := <-second; err != nil {
		t.Fatalf("joined refresh failed with the first caller: %v", err)
	}
}
