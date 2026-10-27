// Package warpcli wraps the locally installed Cloudflare One client.
package warpcli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/Whiteknight07/meshscale/internal/backend"
	"github.com/Whiteknight07/meshscale/internal/linuxnetwork"
)

// ExecFunc must honor ctx and return stdout/stderr from one invocation.
type ExecFunc func(ctx context.Context, path string, args ...string) ([]byte, error)

// StreamOpen starts a long-running invocation and returns its stdout.
type StreamOpen func(ctx context.Context, path string, args ...string) (io.ReadCloser, error)

type Client struct {
	Path    string
	Exec    ExecFunc
	Stream  StreamOpen
	Network linuxnetwork.Manager
	// Set by enrollment and daemon startup before connecting.
	Organization       string
	RequireSafeProfile bool
}

func New(path string) *Client {
	if path == "" {
		path = DefaultPath()
	}
	c := &Client{Path: path, RequireSafeProfile: runtime.GOOS == "darwin", Exec: func(ctx context.Context, path string, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, path, args...).CombinedOutput()
	}}
	if runtime.GOOS == "linux" {
		c.Network = linuxnetwork.New()
	}
	return c
}

const DownloadURL = "https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/download/"

func DefaultPath() string {
	if path, err := exec.LookPath("warp-cli"); err == nil {
		return path
	}
	if runtime.GOOS == "darwin" {
		for _, path := range []string{"/Applications/Cloudflare WARP.app/Contents/Resources/warp-cli", "/Applications/Cloudflare One.app/Contents/Resources/warp-cli", "/usr/local/bin/warp-cli"} {
			if info, err := os.Stat(path); err == nil && !info.IsDir() && info.Mode()&0111 != 0 {
				return path
			}
		}
	}
	return "warp-cli"
}

func Installed() bool { _, err := exec.LookPath(DefaultPath()); return err == nil }

func (c *Client) run(ctx context.Context, secret string, args ...string) (string, error) {
	path := c.Path
	if path == "" {
		path = "warp-cli"
	}
	run := c.Exec
	if run == nil {
		run = New(path).Exec
	}
	output, err := run(ctx, path, append([]string{"--accept-tos"}, args...)...)
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		detail := strings.TrimSpace(string(output))
		message := fmt.Sprintf("warp-cli %s: %v", args[0], err)
		if detail != "" {
			message += ": " + detail
		}
		cause := err
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "[redacted]")
			if strings.Contains(err.Error(), secret) {
				cause = nil // unwrapping must not reveal it either
			}
		}
		return "", &commandError{message: message, err: cause}
	}
	return string(output), nil
}

// commandError keeps a failed command's cause for errors.Is and errors.As
// while its message carries warp-cli's output with any secret redacted.
type commandError struct {
	message string
	err     error
}

func (e *commandError) Error() string { return e.message }
func (e *commandError) Unwrap() error { return e.err }

type ConnectionStatus = backend.Status

func (c *Client) Status(ctx context.Context) (ConnectionStatus, error) {
	output, err := c.run(ctx, "", "status")
	if err != nil {
		return ConnectionStatus{}, err
	}
	return ParseStatus(output)
}

// WatchStatus streams `warp-cli --listen status`, which prints only on state
// changes, until ctx ends or the stream closes. Lines it cannot parse are
// skipped, so callers should keep a slow poll as a safety net.
func (c *Client) WatchStatus(ctx context.Context, updates chan<- backend.Status) error {
	path := c.Path
	if path == "" {
		path = DefaultPath()
	}
	open := c.Stream
	if open == nil {
		open = openStatusStream
	}
	// Cancelling kills warp-cli, so Close never waits on a child that is
	// blocked until its next write.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := open(ctx, path, "--accept-tos", "--listen", "status")
	if err != nil {
		return fmt.Errorf("start warp-cli status listener: %w", err)
	}
	defer func() { cancel(); stream.Close() }()
	scanner := bufio.NewScanner(stream)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if lower := strings.ToLower(line); !strings.HasPrefix(lower, "status update:") && !strings.HasPrefix(lower, "status:") {
			continue // the stream also carries DNS logs
		}
		status, err := ParseStatus(line)
		if err != nil {
			continue // an unfamiliar state; the caller's poll will catch up
		}
		select {
		case updates <- status:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.New("warp-cli status listener closed")
}

type waitReadCloser struct {
	io.ReadCloser
	wait func() error
}

func (r waitReadCloser) Close() error {
	err := r.ReadCloser.Close()
	if waitErr := r.wait(); err == nil {
		err = waitErr
	}
	return err
}

func openStatusStream(ctx context.Context, path string, args ...string) (io.ReadCloser, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stderr = io.Discard
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return waitReadCloser{ReadCloser: stdout, wait: cmd.Wait}, nil
}

func ParseStatus(output string) (ConnectionStatus, error) {
	var status ConnectionStatus
	for _, line := range lines(output) {
		line = strings.TrimSpace(line)
		key, value, ok := strings.Cut(line, ":")
		if ok {
			switch strings.ToLower(strings.TrimSpace(key)) {
			case "status update", "status":
				line = strings.TrimSpace(value)
			case "reason":
				status.Reason = strings.TrimSpace(value)
				continue
			}
		}
		state, reason, _ := strings.Cut(line, ".")
		state = strings.ToLower(strings.TrimSpace(state))
		switch state {
		case "connected", "disconnected", "connecting", "disconnecting", "unable", "disabled":
			status.State = state
			status.Connected = state == "connected"
			status.Reason = ""
			if reason = strings.TrimSpace(reason); reason != "" {
				if key, value, ok := strings.Cut(reason, ":"); ok && strings.EqualFold(strings.TrimSpace(key), "reason") {
					reason = strings.TrimSpace(value)
				}
				status.Reason = reason
			}
		}
	}
	if status.State == "" {
		return status, fmt.Errorf("warp-cli: unrecognized status output")
	}
	return status, nil
}

func (c *Client) Connect(ctx context.Context) error {
	if c.RequireSafeProfile {
		if err := c.CheckSafety(ctx); err != nil {
			return err
		}
	}
	_, err := c.run(ctx, "", "connect")
	return err
}

func (c *Client) Disconnect(ctx context.Context) error {
	_, err := c.run(ctx, "", "disconnect")
	return errors.Join(err, c.CleanupNetwork(ctx))
}

func (c *Client) ConnectorNew(ctx context.Context, token string) error {
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("warp-cli: connector token is empty")
	}
	// warp-cli only takes the token as an argument, so it is briefly visible
	// in the process list; errors never repeat it.
	_, err := c.run(ctx, token, "connector", "new", token)
	return err
}

// ID is the legacy ambiguous "ID" field; callers should compare it with both
// registration and physical device IDs. Explicit IDs take precedence.
type RegistrationInfo = backend.Registration

func (c *Client) Registration(ctx context.Context) (RegistrationInfo, error) {
	output, err := c.run(ctx, "", "registration", "show")
	if err != nil {
		return RegistrationInfo{}, err
	}
	return ParseRegistration(output)
}

func ParseRegistration(output string) (RegistrationInfo, error) {
	var info RegistrationInfo
	for _, line := range lines(output) {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "account type":
			info.AccountType = value
		case "organization":
			info.Organization = value
		case "id":
			info.ID = value
		case "registration id", "registration_id":
			info.RegistrationID = value
		case "device id", "device_id":
			info.DeviceID = value
		case "connector id", "connector_id", "tunnel id", "tunnel_id":
			info.ConnectorID = value
		}
	}
	if info.ID == "" && info.DeviceID == "" && info.RegistrationID == "" && info.ConnectorID == "" {
		return info, fmt.Errorf("warp-cli: registration output contains no device or registration ID")
	}
	return info, nil
}

// lines also splits on a bare CR, so no parsed value can carry one into a
// log line or terminal.
func lines(output string) []string {
	return strings.FieldsFunc(output, func(r rune) bool { return r == '\n' || r == '\r' })
}

// IsUnregistered recognizes the daemon's explicit no-registration response;
// transport, permission and parsing failures must never trigger re-enrollment.
func IsUnregistered(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "registration missing") || strings.Contains(s, "missing registration") || strings.Contains(s, "not registered")
}
