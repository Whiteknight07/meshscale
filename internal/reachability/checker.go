package reachability

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

const (
	Workers      = 16
	BatchTimeout = 800 * time.Millisecond
	CacheTTL     = 30 * time.Second
)

type entry struct {
	done    chan struct{}
	online  bool
	expires time.Time
}

// Checker bounds network concurrency across callers and coalesces simultaneous
// probes of an address. Both positive and negative results expire after 30s.
// Construct one per daemon, rather than one per status request.
type Checker struct {
	prober Prober
	slots  chan struct{}
	mu     sync.Mutex
	cache  map[netip.Addr]*entry
	now    func() time.Time
}

func New(prober Prober) *Checker {
	return &Checker{prober: prober, slots: make(chan struct{}, Workers), cache: make(map[netip.Addr]*entry), now: time.Now}
}

// probe waits for ip's shared probe, starting one if none is cached or in
// flight, until ctx ends.
func (c *Checker) probe(ctx context.Context, ip netip.Addr) bool {
	if ctx.Err() != nil {
		return false
	}
	c.mu.Lock()
	e := c.cache[ip]
	if e == nil || !e.expires.IsZero() && !c.now().Before(e.expires) {
		e = &entry{done: make(chan struct{})}
		c.cache[ip] = e
		go c.run(ctx, ip, e)
	}
	c.mu.Unlock()
	select {
	case <-e.done:
		return e.online
	case <-ctx.Done():
		return false
	}
}

// run performs one probe. Once started it completes even if the batch that
// asked for it times out, so a slow host's answer is cached for the next
// status request rather than being abandoned and reported offline each time.
func (c *Checker) run(ctx context.Context, ip netip.Addr, e *entry) {
	select {
	case c.slots <- struct{}{}:
	case <-ctx.Done():
		// Never started: forget it so the next batch probes again.
		c.mu.Lock()
		if c.cache[ip] == e {
			delete(c.cache, ip)
		}
		close(e.done)
		c.mu.Unlock()
		return
	}
	probeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ProbeTimeout)
	online := c.prober.Probe(probeCtx, ip) == nil
	cancel()
	<-c.slots
	c.mu.Lock()
	e.online, e.expires = online, c.now().Add(CacheTTL)
	// Don't grow the cache indefinitely if private clients submit many
	// distinct addresses.
	if len(c.cache) > 4096 && c.cache[ip] == e {
		delete(c.cache, ip)
	}
	close(e.done)
	c.mu.Unlock()
}

// Check returns completed results within a fixed total budget, even for very
// large accounts. Unscheduled or unanswered addresses remain offline.
func (c *Checker) Check(ctx context.Context, ips []netip.Addr) map[string]bool {
	ctx, cancel := context.WithTimeout(ctx, BatchTimeout)
	defer cancel()
	c.mu.Lock()
	for ip, e := range c.cache {
		if !e.expires.IsZero() && !c.now().Before(e.expires) {
			delete(c.cache, ip)
		}
	}
	c.mu.Unlock()
	jobs := make(chan netip.Addr)
	results := make(map[string]bool, len(ips))
	var mu sync.Mutex
	var workers sync.WaitGroup
	for range min(Workers, len(ips)) {
		workers.Go(func() {
			for ip := range jobs {
				online := c.probe(ctx, ip)
				mu.Lock()
				results[ip.String()] = online
				mu.Unlock()
			}
		})
	}
dispatch:
	for _, ip := range ips {
		select {
		case jobs <- ip:
		case <-ctx.Done():
			break dispatch
		}
	}
	close(jobs)
	workers.Wait()
	return results
}
