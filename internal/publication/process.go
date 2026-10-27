package publication

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Process isolates cloudflared supervision from resource provisioning.
type Process interface {
	Check() error
	Start(context.Context, string) error
	Stop()
	Status() (bool, string)
}
type Cloudflared struct {
	Output    io.Writer
	mu        sync.Mutex
	cancel    context.CancelFunc
	done      chan struct{}
	running   bool
	lastError string
}

func (p *Cloudflared) Check() error {
	if _, err := exec.LookPath("cloudflared"); err != nil {
		return fmt.Errorf("cloudflared is required: install from https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/ (macOS: brew install cloudflared), then restart the daemon: %w", err)
	}
	return nil
}
func (p *Cloudflared) Start(parent context.Context, token string) error {
	if err := p.Check(); err != nil {
		return err
	}
	if err := parent.Err(); err != nil {
		return fmt.Errorf("start cloudflared: %w", err)
	}
	p.Stop()
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	p.mu.Lock()
	p.cancel, p.done = cancel, done
	p.mu.Unlock()
	go func() {
		defer close(done)
		delay := time.Second
		for ctx.Err() == nil {
			cmd := exec.CommandContext(ctx, "cloudflared", "tunnel", "--no-autoupdate", "--config", os.DevNull, "run")
			// The token never appears in argv, saved state, logs or the status response.
			for _, entry := range os.Environ() {
				key, _, _ := strings.Cut(entry, "=")
				if !strings.HasPrefix(key, "CLOUDFLARE_") && !strings.HasPrefix(key, "CF_API_") && !strings.HasPrefix(key, "TUNNEL_TOKEN") {
					cmd.Env = append(cmd.Env, entry)
				}
			}
			cmd.Env = append(cmd.Env, "TUNNEL_TOKEN="+token)
			cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
			cmd.WaitDelay = 5 * time.Second
			cmd.Stdout, cmd.Stderr = p.Output, p.Output
			started := time.Now()
			err := cmd.Start()
			if err == nil {
				p.mu.Lock()
				p.running, p.lastError = true, ""
				p.mu.Unlock()
				err = cmd.Wait()
			}
			p.mu.Lock()
			p.running = false
			if ctx.Err() == nil {
				p.lastError = "cloudflared exited; restarting"
				if err != nil {
					p.lastError = fmt.Sprintf("cloudflared exited: %v; restarting", err)
				}
			}
			p.mu.Unlock()
			if ctx.Err() != nil {
				return
			}
			if time.Since(started) > time.Minute {
				delay = time.Second
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			delay = min(delay*2, time.Minute)
		}
	}()
	return nil
}
func (p *Cloudflared) Stop() {
	p.mu.Lock()
	cancel, done := p.cancel, p.done
	p.cancel, p.done = nil, nil
	p.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}
func (p *Cloudflared) Status() (bool, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.running, p.lastError
}
