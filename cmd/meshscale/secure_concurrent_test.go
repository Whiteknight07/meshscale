package main

import (
	"context"
	"sync"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/secure"
)

func TestConcurrentSetPreservesSuccessfulIndependentChanges(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	dir, err := secureDir()
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 20; attempt++ {
		if err := (secure.Config{Enabled: true, Userspace: true}).Save(dir); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		errs := make(chan error, 2)
		var workers sync.WaitGroup
		for _, args := range [][]string{{"--exit-node-allow-lan-access=true"}, {"--secure-engine=go"}} {
			workers.Add(1)
			go func(args []string) {
				defer workers.Done()
				<-start
				errs <- runSet(context.Background(), args)
			}(args)
		}
		close(start)
		workers.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		after, err := secure.LoadConfig(dir)
		if err != nil || !after.AllowLAN || after.Engine != "go" {
			t.Fatalf("successful concurrent changes lost on attempt %d: LAN=%t engine=%q error=%v", attempt, after.AllowLAN, after.Engine, err)
		}
	}
}
