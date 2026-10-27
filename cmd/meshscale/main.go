// Command meshscale gives Cloudflare Mesh a Tailscale-style CLI.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/Whiteknight07/meshscale/internal/config"
)

var version = "0.0.0-dev"

// command is one CLI subcommand. Each command lives in its own file and
// registers itself from an init function, so files can be added independently.
type command struct {
	name  string
	short string // one-line help
	run   func(ctx context.Context, args []string) error
}

var commands = map[string]*command{}

func register(c *command) {
	if _, dup := commands[c.name]; dup {
		panic("duplicate command " + c.name)
	}
	commands[c.name] = c
}

func usage() string {
	var b strings.Builder
	b.WriteString("meshscale: a Tailscale-style CLI for Cloudflare Mesh\n\nUsage:\n  meshscale <command> [flags]\n\nCommands:\n")
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(&b, "  %-10s %s\n", n, commands[n].short)
	}
	return b.String()
}

func main() {
	config.SealCredentialEnvironment()
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage())
		os.Exit(2)
	}
	name := os.Args[1]
	switch name {
	case "help", "--help", "-h":
		fmt.Print(usage())
		return
	case "--version", "-v":
		name = "version"
	}
	c, ok := commands[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "meshscale: unknown command %q\n\n%s", name, usage())
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := c.run(ctx, os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "meshscale %s: %v\n", name, err)
		os.Exit(1)
	}
}

func init() {
	registerDoctorCommands()
	register(&command{name: "version", short: "print the meshscale version", run: func(context.Context, []string) error {
		fmt.Println(version)
		return nil
	}})
}
