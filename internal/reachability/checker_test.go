package reachability

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type probeFunc func(context.Context, netip.Addr) error

func (f probeFunc) Probe(ctx context.Context, ip netip.Addr) error { return f(ctx, ip) }

func TestCacheAndExpiry(t *testing.T) {
	for _, online := range []bool{false, true} {
		t.Run(fmt.Sprint(online), func(t *testing.T) {
			calls := 0
			checker := New(probeFunc(func(ctx context.Context, _ netip.Addr) error {
				calls++
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > ProbeTimeout {
					t.Error("missing per-probe deadline")
				}
				if !online {
					return errors.New("unreachable")
				}
				return nil
			}))
			now := time.Now()
			checker.now = func() time.Time { return now }
			ip := netip.MustParseAddr("100.96.0.1")
			for range 2 {
				if got := checker.Check(context.Background(), []netip.Addr{ip})[ip.String()]; got != online {
					t.Fatal(got)
				}
			}
			if calls != 1 {
				t.Fatalf("cache missed: %d calls", calls)
			}
			now = now.Add(CacheTTL)
			checker.Check(context.Background(), []netip.Addr{ip})
			if calls != 2 {
				t.Fatalf("expired cache reused: %d calls", calls)
			}
		})
	}
}

func TestConcurrentRequestsCoalesce(t *testing.T) {
	var calls atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	checker := New(probeFunc(func(ctx context.Context, _ netip.Addr) error {
		if calls.Add(1) == 1 {
			close(entered)
		}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}))
	ip := netip.MustParseAddr("100.96.0.1")
	var group sync.WaitGroup
	for range 20 {
		group.Go(func() {
			if !checker.Check(context.Background(), []netip.Addr{ip})[ip.String()] {
				t.Error("missing positive result")
			}
		})
	}
	<-entered
	close(release)
	group.Wait()
	if calls.Load() != 1 {
		t.Fatalf("probe storm: %d calls", calls.Load())
	}
}

func TestWorkerAndBatchBounds(t *testing.T) {
	var active, peak atomic.Int32
	checker := New(probeFunc(func(ctx context.Context, _ netip.Addr) error {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		<-ctx.Done()
		return ctx.Err()
	}))
	ips := make([]netip.Addr, 1000)
	for i := range ips {
		ips[i] = netip.AddrFrom4([4]byte{100, 96, byte(i / 256), byte(i % 256)})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	start := time.Now()
	var requests sync.WaitGroup
	for i := range 4 {
		requests.Go(func() { checker.Check(ctx, ips[i*250:(i+1)*250]) })
	}
	requests.Wait()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("batch took %s", elapsed)
	}
	if peak.Load() <= 1 || peak.Load() > Workers {
		t.Fatalf("peak %d", peak.Load())
	}
	// Started probes finish within ProbeTimeout of the batch and are cached;
	// probes the batch never started are forgotten so the next one retries.
	deadline := time.Now().Add(2 * ProbeTimeout)
	for active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if active.Load() != 0 {
		t.Fatalf("probes still running: %d", active.Load())
	}
	checker.mu.Lock()
	defer checker.mu.Unlock()
	if len(checker.cache) == 0 || len(checker.cache) > 2*Workers {
		t.Fatalf("cache holds %d entries", len(checker.cache))
	}
	for ip, e := range checker.cache {
		if e.expires.IsZero() {
			t.Fatalf("unfinished probe cached for %s", ip)
		}
	}
}

func TestSlowProbeIsCachedAfterBatchTimeout(t *testing.T) {
	var calls atomic.Int32
	checker := New(probeFunc(func(ctx context.Context, _ netip.Addr) error {
		calls.Add(1)
		select {
		case <-time.After(50 * time.Millisecond):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}))
	ip := netip.MustParseAddr("100.96.0.1")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if checker.Check(ctx, []netip.Addr{ip})[ip.String()] {
		t.Fatal("answer arrived before the probe finished")
	}
	time.Sleep(100 * time.Millisecond)
	if !checker.Check(context.Background(), []netip.Addr{ip})[ip.String()] || calls.Load() != 1 {
		t.Fatalf("slow answer was abandoned: %d calls", calls.Load())
	}
}
