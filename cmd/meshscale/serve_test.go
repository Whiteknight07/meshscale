package main

import (
	"context"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/service"
)

func TestServeOffWhileDaemonStopped(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	options, err := config.LoadService()
	if err != nil {
		t.Fatal(err)
	}
	options.SSH = true
	options.Forwards = []service.Forward{{Port: 9000, MeshPort: 9001}}
	if err := options.Save(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := runServe(context.Background(), []string{"off"}); err != nil {
			t.Fatal(err)
		}
	}
	options, err = config.LoadService()
	if err != nil {
		t.Fatal(err)
	}
	if len(options.Forwards) != 0 || !options.SSH {
		t.Fatalf("configuration lost: %+v", options)
	}
}
