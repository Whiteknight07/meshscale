package main

import "testing"

func TestTuneArguments(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		fail bool
	}{
		{"help", []string{"--help"}, false},
		{"no implicit tuning", nil, true},
		{"undo needs explicit feature", []string{"--undo"}, true},
		{"negative PID", []string{"--warp-buffers", "--warp-pid=-1"}, true},
		{"undo uses recorded PID", []string{"--warp-buffers", "--undo", "--warp-pid=1"}, true},
		{"positional argument", []string{"--warp-buffers", "unexpected"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := runTune(t.Context(), tc.args); (err != nil) != tc.fail {
				t.Fatal(err)
			}
		})
	}
}
