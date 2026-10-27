//go:build !linux

package main

import (
	"context"
	"fmt"
	"github.com/Whiteknight07/meshscale/internal/cloudflaressh"
)

type unsupportedSSHHost struct{}

func (unsupportedSSHHost) Enable(context.Context, *cloudflaressh.State, string) error {
	return fmt.Errorf("cloudflare SSH provisioning requires Linux")
}
func (unsupportedSSHHost) Disable(context.Context, *cloudflaressh.State, string) error {
	return fmt.Errorf("cloudflare SSH provisioning requires Linux")
}
func newCloudflareSSHHost(sshModeStore) cloudflaressh.Host { return unsupportedSSHHost{} }
