//go:build linux

package warptune

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type System struct{}

func processStart(pid int) (string, error) {
	base := "/proc/" + strconv.Itoa(pid)
	comm, err := os.ReadFile(base + "/comm")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(string(comm)) != "warp-svc" {
		return "", fmt.Errorf("PID %d is not warp-svc: %w", pid, unix.ESTALE)
	}
	data, err := os.ReadFile(base + "/stat")
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(data)[strings.LastIndexByte(string(data), ')')+1:])
	if len(fields) <= 19 {
		return "", fmt.Errorf("invalid process start time for PID %d", pid)
	}
	return fields[19], nil
}

func warpPIDs(pid int) ([]int, error) {
	if pid < 0 {
		return nil, fmt.Errorf("invalid WARP PID")
	}
	if pid > 0 {
		return []int{pid}, nil
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, e := range entries {
		id, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		ns, err := os.Readlink("/proc/" + e.Name() + "/ns/net")
		if err != nil || ns != self {
			continue
		}
		comm, err := os.ReadFile("/proc/" + e.Name() + "/comm")
		if err == nil && strings.TrimSpace(string(comm)) == "warp-svc" {
			pids = append(pids, id)
		}
	}
	return pids, nil
}

func socketFD(s Socket) (int, error) {
	start, err := processStart(s.PID)
	if err != nil {
		return -1, err
	}
	if start != s.Start {
		return -1, unix.ENOENT
	}
	pidfd, err := unix.PidfdOpen(s.PID, 0)
	if err != nil {
		return -1, fmt.Errorf("pidfd_open: %w", err)
	}
	defer unix.Close(pidfd)
	fd, err := unix.PidfdGetfd(pidfd, s.FD, 0)
	if err != nil {
		return -1, fmt.Errorf("pidfd_getfd (requires CAP_SYS_PTRACE): %w", err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return -1, err
	}
	// Check both process start time and the duplicated inode, not just /proc/fd.
	after, err := processStart(s.PID)
	if err != nil || after != s.Start || st.Ino != s.Inode {
		unix.Close(fd)
		if err != nil {
			return -1, err
		}
		return -1, unix.ENOENT
	}
	return fd, nil
}

func receiveSize(fd int) (int, error) {
	kind, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || kind != unix.SOCK_DGRAM {
		return 0, err
	}
	proto, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PROTOCOL)
	if err != nil || proto != unix.IPPROTO_UDP {
		return 0, err
	}
	peer, err := unix.Getpeername(fd)
	if errors.Is(err, unix.ENOTCONN) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	port := 0
	switch addr := peer.(type) {
	case *unix.SockaddrInet4:
		port = addr.Port
	case *unix.SockaddrInet6:
		port = addr.Port
	}
	if port != 443 {
		return 0, nil
	}
	return unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
}

func (System) Discover(ctx context.Context, pid int) ([]Socket, error) {
	pids, err := warpPIDs(pid)
	if err != nil {
		return nil, err
	}
	var sockets []Socket
	for _, pid := range pids {
		start, err := processStart(pid)
		if err != nil {
			return nil, err
		}
		base := "/proc/" + strconv.Itoa(pid) + "/fd"
		entries, err := os.ReadDir(base)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			link, err := os.Readlink(filepath.Join(base, entry.Name()))
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]"), 10, 64)
			if err != nil {
				return nil, fmt.Errorf("parse socket inode: %w", err)
			}
			descriptor, err := strconv.Atoi(entry.Name())
			if err != nil {
				return nil, err
			}
			s := Socket{PID: pid, FD: descriptor, Inode: inode, Start: start}
			fd, err := socketFD(s)
			if stale(err) {
				continue
			}
			if err != nil {
				return nil, err
			}
			size, err := receiveSize(fd)
			unix.Close(fd)
			if err != nil {
				return nil, fmt.Errorf("inspect WARP socket: %w", err)
			}
			if size == 0 {
				continue
			}
			s.Previous = size
			sockets = append(sockets, s)
		}
	}
	return sockets, nil
}

func stale(err error) bool {
	return errors.Is(err, unix.ESTALE) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) || errors.Is(err, unix.EBADF)
}

func (System) Set(ctx context.Context, s Socket, size int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	fd, err := socketFD(s)
	if stale(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	current, err := receiveSize(fd)
	if err != nil {
		return err
	}
	if current == 0 {
		return fmt.Errorf("saved descriptor is no longer a connected WARP UDP/443 socket")
	}
	// Linux doubles SO_RCVBUF on readback. SO_RCVBUFFORCE needs CAP_NET_ADMIN
	// and bypasses the system maximum without modifying any global sysctl.
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, size/2); err != nil {
		return fmt.Errorf("SO_RCVBUFFORCE (requires CAP_NET_ADMIN): %w", err)
	}
	actual, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
	if err != nil {
		return err
	}
	if actual != size {
		return fmt.Errorf("WARP receive buffer readback %d, expected %d", actual, size)
	}
	return nil
}
