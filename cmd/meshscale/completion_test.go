package main

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

func TestCompletionUsesCommandRegistry(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		var out bytes.Buffer
		if err := writeCompletion(&out, shell); err != nil {
			t.Fatal(err)
		}
		for name := range commands {
			if !strings.Contains(out.String(), name) {
				t.Fatalf("%s missing registered %s", shell, name)
			}
		}
		if _, err := exec.LookPath(shell); err == nil {
			cmd := exec.Command(shell, "-n")
			cmd.Stdin = bytes.NewReader(out.Bytes())
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s syntax: %s %v", shell, output, err)
			}
		}
	}
	if err := writeCompletion(&bytes.Buffer{}, "unsupported"); err == nil {
		t.Fatal("unknown shell accepted")
	}
}
