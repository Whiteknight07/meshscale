package exitnode

import (
	"context"
	"sync"
	"time"
)

const networkEventDebounce = 250 * time.Millisecond

// debounceEvents coalesces bursts into one notification after a quiet period.
func debounceEvents(ctx context.Context, source <-chan struct{}, delay time.Duration) <-chan struct{} {
	if delay <= 0 {
		delay = networkEventDebounce
	}
	out := make(chan struct{}, 1)
	go func() {
		defer close(out)
		timer := time.NewTimer(delay)
		timer.Stop()
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-source:
				if !ok {
					return
				}
				// Since Go 1.23, Reset discards any tick still pending from an earlier burst.
				timer.Reset(delay)
			case <-timer.C:
				select {
				case out <- struct{}{}:
				default:
				}
			}
		}
	}()
	return out
}

// mergeEvents fans sources into one channel. Nil sources are ignored. The
// result closes when ctx ends or any source closes, since a closed source means
// that subscription has died.
func mergeEvents(ctx context.Context, sources ...<-chan struct{}) <-chan struct{} {
	out := make(chan struct{}, 1)
	stop := make(chan struct{})
	var once sync.Once
	var wg sync.WaitGroup
	for _, source := range sources {
		if source == nil {
			continue
		}
		wg.Go(func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-stop:
					return
				case _, ok := <-source:
					if !ok {
						once.Do(func() { close(stop) })
						return
					}
					queueEvent(out)
				}
			}
		})
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

func queueEvent(events chan<- struct{}) {
	select {
	case events <- struct{}{}:
	default:
	}
}
