package config

import "github.com/Whiteknight07/meshscale/internal/localstate"

// ChildEnvironment keeps meshscale's API credentials out of unrelated programs.
func ChildEnvironment() []string { return localstate.ChildEnvironment() }
