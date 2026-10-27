// Package warptune implements explicit, reversible tuning of existing WARP
// receive sockets. It never runs as part of daemon startup or writes sysctls.
package warptune

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Whiteknight07/meshscale/internal/localstate"
)

const BufferSize = 8 * 1024 * 1024 // Linux SO_RCVBUF readback, including bookkeeping.

type Socket struct {
	PID      int
	FD       int
	Inode    uint64
	Start    string // /proc start time protects against PID reuse.
	Previous int
}

type Backend interface {
	Discover(context.Context, int) ([]Socket, error)
	// Set ignores closed or replaced sockets and never adopts their replacements.
	Set(context.Context, Socket, int) error
}

type state struct {
	Version int
	Sockets []Socket
}

type Tuner struct {
	Dir     string
	Backend Backend
}

func (t Tuner) Apply(ctx context.Context, pid int) error {
	unlock, err := localstate.Lock(t.Dir)
	if err != nil {
		return fmt.Errorf("lock WARP tuning: %w", err)
	}
	defer unlock()
	path := filepath.Join(t.Dir, "warp-buffers.json")
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		if err != nil {
			return fmt.Errorf("inspect WARP tuning state: %w", err)
		}
		return fmt.Errorf("WARP tuning already recorded; run meshscale tune --warp-buffers --undo first")
	}
	sockets, err := t.Backend.Discover(ctx, pid)
	if err != nil {
		return fmt.Errorf("discover WARP receive sockets: %w", err)
	}
	if len(sockets) == 0 {
		return fmt.Errorf("no connected warp-svc UDP/443 sockets found")
	}
	saved := state{Version: 1, Sockets: sockets}
	// Write and fsync the original sizes before the first socket mutation.
	if err := localstate.Write(path, saved); err != nil {
		return fmt.Errorf("save WARP buffers: %w", err)
	}
	for _, socket := range sockets {
		if err := t.Backend.Set(ctx, socket, BufferSize); err != nil {
			// Cancellation must not suppress restoration. Keep state if undo fails.
			restoreErr := t.restore(context.WithoutCancel(ctx), path, saved)
			return errors.Join(fmt.Errorf("tune WARP PID %d FD %d: %w", socket.PID, socket.FD, err), restoreErr)
		}
	}
	return nil
}

func (t Tuner) Undo(ctx context.Context) error {
	unlock, err := localstate.Lock(t.Dir)
	if err != nil {
		return fmt.Errorf("lock WARP tuning: %w", err)
	}
	defer unlock()
	path := filepath.Join(t.Dir, "warp-buffers.json")
	var saved state
	if err := localstate.Read(path, &saved); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read WARP buffer state: %w", err)
	}
	if saved.Version != 1 || len(saved.Sockets) == 0 {
		return fmt.Errorf("invalid WARP buffer state version or sockets")
	}
	for _, s := range saved.Sockets {
		if s.PID <= 0 || s.FD < 0 || s.Inode == 0 || s.Start == "" || s.Previous < 256 || s.Previous > 1<<30 || s.Previous%2 != 0 {
			return fmt.Errorf("invalid saved WARP socket identity or buffer size")
		}
	}
	return t.restore(ctx, path, saved)
}

func (t Tuner) restore(ctx context.Context, path string, saved state) error {
	var errs []error
	for _, s := range saved.Sockets {
		if err := t.Backend.Set(ctx, s, s.Previous); err != nil {
			errs = append(errs, fmt.Errorf("restore WARP PID %d FD %d: %w", s.PID, s.FD, err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove WARP buffer state: %w", err)
	}
	return nil
}
