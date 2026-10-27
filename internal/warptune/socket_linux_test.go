//go:build linux

package warptune

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSocketClassification(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		domain, kind, protocol int
		port                   int
		connected              bool
		want                   bool
	}{
		{"connected UDP443", unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP, 443, true, true},
		{"other UDP port", unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP, 51821, true, false},
		{"unconnected UDP", unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP, 0, false, false},
		{"TCP", unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_TCP, 0, false, false},
		{"Unix datagram", unix.AF_UNIX, unix.SOCK_DGRAM, 0, 0, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fd, err := unix.Socket(tc.domain, tc.kind|unix.SOCK_CLOEXEC, tc.protocol)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fd)
			if tc.connected {
				if err := unix.Connect(fd, &unix.SockaddrInet4{Port: tc.port, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
					t.Fatal(err)
				}
			}
			size, err := receiveSize(fd)
			if err != nil {
				t.Fatal(err)
			}
			if (size > 0) != tc.want {
				t.Fatalf("size %d", size)
			}
		})
	}
}
func TestStaleSocketAndNonWarp(t *testing.T) {
	if err := (System{}).Set(t.Context(), Socket{PID: 1 << 30, FD: 3, Inode: 1, Start: "1"}, BufferSize); err != nil {
		t.Fatal(err)
	}
	if _, err := (System{}).Discover(t.Context(), os.Getpid()); err == nil {
		t.Fatal("accepted non-WARP process")
	}
	for _, err := range []error{unix.ESTALE, unix.ENOENT, unix.ESRCH, unix.EBADF} {
		if !stale(errors.Join(errors.New("wrapped"), err)) {
			t.Fatal(err)
		}
	}
	if stale(unix.EPERM) {
		t.Fatal("ignored permission failure")
	}
}
