package warptune

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/localstate"
)

type fakeBackend struct {
	sockets             []Socket
	calls               []int
	failApply, failUndo bool
	discoverErr         error
	path                string
	t                   *testing.T
}

func (b *fakeBackend) Discover(context.Context, int) ([]Socket, error) {
	return b.sockets, b.discoverErr
}
func (b *fakeBackend) Set(_ context.Context, s Socket, n int) error {
	b.t.Helper()
	var saved state
	if err := localstate.Read(b.path, &saved); err != nil {
		b.t.Fatalf("changed socket before durable state: %v", err)
	}
	b.calls = append(b.calls, n)
	if n == BufferSize && b.failApply || n == s.Previous && b.failUndo {
		return os.ErrPermission
	}
	return nil
}
func TestTuningTransaction(t *testing.T) {
	for _, tc := range []struct {
		name                string
		applyFail, undoFail bool
	}{
		{name: "apply and undo"}, {name: "failed apply rolls back", applyFail: true}, {name: "failed restore retains state", applyFail: true, undoFail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "tuning")
			path := filepath.Join(dir, "warp-buffers.json")
			b := &fakeBackend{sockets: []Socket{{PID: 42, FD: 7, Inode: 19, Start: "123", Previous: 229376}}, path: path, t: t, failApply: tc.applyFail, failUndo: tc.undoFail}
			tuner := Tuner{Dir: dir, Backend: b}
			err := tuner.Apply(t.Context(), 0)
			if tc.applyFail != errors.Is(err, os.ErrPermission) {
				t.Fatalf("apply: %v", err)
			}
			if !tc.applyFail {
				if err := tuner.Apply(t.Context(), 0); err == nil {
					t.Fatal("overwrote original state")
				}
				if err := tuner.Undo(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			if !reflect.DeepEqual(b.calls, []int{BufferSize, 229376}) {
				t.Fatal(b.calls)
			}
			_, err = os.Lstat(path)
			if tc.undoFail {
				if err != nil {
					t.Fatal("lost recovery state", err)
				}
				b.failUndo = false
				if err := tuner.Undo(t.Context()); err != nil {
					t.Fatal(err)
				}
			} else if !os.IsNotExist(err) {
				t.Fatal("restore state not removed", err)
			}
			if err := tuner.Undo(t.Context()); err != nil {
				t.Fatal("undo is not idempotent", err)
			}
		})
	}
}
func TestDiscoverFailureDoesNotSaveState(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "no sockets", true: "discovery error"}[fail], func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "tuning")
			b := &fakeBackend{t: t}
			if fail {
				b.discoverErr = os.ErrPermission
			}
			err := (Tuner{Dir: dir, Backend: b}).Apply(t.Context(), 0)
			if err == nil || fail && !errors.Is(err, os.ErrPermission) {
				t.Fatal(err)
			}
			if _, err := os.Lstat(filepath.Join(dir, "warp-buffers.json")); !os.IsNotExist(err) {
				t.Fatal("saved incomplete discovery")
			}
		})
	}
}
func TestUndoRejectsInvalidState(t *testing.T) {
	for _, s := range []state{{Version: 2}, {Version: 1}, {Version: 1, Sockets: []Socket{{PID: 42, Inode: 1, Start: "123", Previous: -1}}}} {
		dir := filepath.Join(t.TempDir(), "tuning")
		if err := localstate.Write(filepath.Join(dir, "warp-buffers.json"), s); err != nil {
			t.Fatal(err)
		}
		b := &fakeBackend{t: t}
		if err := (Tuner{Dir: dir, Backend: b}).Undo(t.Context()); err == nil {
			t.Fatal("accepted invalid state")
		}
		if len(b.calls) > 0 {
			t.Fatal("mutated invalid socket")
		}
	}
}
