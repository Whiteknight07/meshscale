package exitnode

import (
	"context"
	"testing"
	"time"
)

func TestDebounceEventsCoalescesBurst(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	source := make(chan struct{}, 8)
	got := debounceEvents(ctx, source, 60*time.Millisecond)
	for range 4 {
		source <- struct{}{}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case <-got:
	case <-time.After(time.Second):
		t.Fatal("debounced event was not delivered")
	}
	select {
	case <-got:
		t.Fatal("burst produced more than one event")
	case <-time.After(100 * time.Millisecond):
	}
	source <- struct{}{}
	select {
	case <-got:
	case <-time.After(time.Second):
		t.Fatal("later event was not delivered")
	}
}

func TestDebounceEventsStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	source := make(chan struct{}, 1)
	got := debounceEvents(ctx, source, time.Second)
	source <- struct{}{}
	cancel()
	select {
	case _, ok := <-got:
		if ok {
			t.Fatal("delivered an event after cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("debouncer did not stop")
	}
}

func TestMergeEventsForwardsAndClosesWhenASourceDies(t *testing.T) {
	a, b := make(chan struct{}), make(chan struct{})
	got := mergeEvents(t.Context(), a, nil, b)
	b <- struct{}{}
	select {
	case <-got:
	case <-time.After(time.Second):
		t.Fatal("event was not forwarded")
	}
	close(a)
	select {
	case _, ok := <-got:
		if ok {
			t.Fatal("merged channel stayed open after a source died")
		}
	case <-time.After(time.Second):
		t.Fatal("merged channel did not close")
	}
}
