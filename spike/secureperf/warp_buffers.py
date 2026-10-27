#!/usr/bin/env python3
"""Opt-in diagnostic for existing WARP UDP receive buffers; no global sysctls.

Arm a four-minute rollback invoking `restore --state PATH` BEFORE `apply`.
Requires Linux pidfd_getfd, CAP_SYS_PTRACE and CAP_NET_ADMIN. A WARP restart
replaces sockets and discards this tuning. This is not meshscale daemon policy.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import platform
import socket
import sys


LIBC = ctypes.CDLL(None, use_errno=True)
SO_RCVBUFFORCE = 33


def duplicate(pid, fd):
    if platform.machine() not in {'aarch64', 'x86_64'}:
        raise RuntimeError('pidfd_getfd syscall number is verified only on ARM64/x86_64')
    pidfd = os.pidfd_open(pid)
    try:
        result = LIBC.syscall(438, pidfd, fd, 0)
    finally:
        os.close(pidfd)
    if result < 0:
        raise OSError(ctypes.get_errno(), 'pidfd_getfd')
    return result


def inspect(pids):
    records = []
    for pid in pids:
        if Path(f'/proc/{pid}/comm').read_text().strip() != 'warp-svc':
            raise RuntimeError(f'{pid}: expected warp-svc, refusing other processes')
        for path in Path(f'/proc/{pid}/fd').iterdir():
            inode = os.readlink(path)
            if not inode.startswith('socket:['):
                continue
            fd = duplicate(pid, int(path.name))
            if f'socket:[{os.fstat(fd).st_ino}]' != inode:
                os.close(fd)
                continue
            sock = None
            try:
                sock = socket.socket(fileno=fd)
                if sock.family not in {socket.AF_INET, socket.AF_INET6} or sock.type != socket.SOCK_DGRAM:
                    continue
                try:
                    peer = sock.getpeername()
                except OSError:
                    continue
                if peer[1] != 443:
                    continue
                records.append({'pid': pid, 'fd': int(path.name), 'inode': inode,
                                'peer': peer, 'old': sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)})
            finally:
                if sock is None:
                    os.close(fd)
                else:
                    sock.close()
    return records


def set_buffer(record, size):
    path = Path(f'/proc/{record["pid"]}/fd/{record["fd"]}')
    try:
        inode = os.readlink(path)
    except FileNotFoundError:
        return 'socket closed'
    if inode != record['inode']:
        return 'descriptor replaced; left unchanged'
    fd = duplicate(record['pid'], record['fd'])
    if f'socket:[{os.fstat(fd).st_ino}]' != record['inode']:
        os.close(fd)
        return 'descriptor replaced; left unchanged'
    with socket.socket(fileno=fd) as sock:
        # Linux doubles the requested buffer for bookkeeping. Store/read back
        # kernel sizes so restoring a default-sized socket is exact.
        sock.setsockopt(socket.SOL_SOCKET, SO_RCVBUFFORCE, size // 2)
        actual = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        if actual != size:
            raise RuntimeError(f'buffer readback {actual} != requested kernel size {size}')
        return actual


def restore(path):
    if path.is_symlink():
        raise RuntimeError('refusing symlink restore state')
    if not path.exists():
        return
    records = json.loads(path.read_text())
    failures = []
    for record in records:
        try:
            print(record['pid'], record['fd'], set_buffer(record, record['old']))
        except Exception as error:
            failures.append(str(error))
    if failures:
        raise RuntimeError('; '.join(failures))
    path.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['show', 'apply', 'restore'])
    parser.add_argument('--pid', type=int, action='append', default=[])
    parser.add_argument('--state', type=Path)
    parser.add_argument('--bytes', type=int, default=8 * 1024 * 1024,
                        help='kernel readback size (twice setsockopt request)')
    args = parser.parse_args()
    if args.action in {'apply', 'restore'} and (not args.state or not args.state.is_absolute()):
        parser.error('apply/restore require an absolute --state path')
    if args.action == 'restore':
        restore(args.state)
        return
    if not args.pid:
        parser.error('show/apply require at least one --pid')
    records = inspect(args.pid)
    if args.action == 'show':
        print(json.dumps(records, indent=2))
        return
    if not records:
        raise RuntimeError('no connected WARP UDP/443 sockets found')
    if not 4096 <= args.bytes <= 64 * 1024 * 1024 or args.bytes % 2:
        parser.error('--bytes must be an even integer between 4096 and 64 MiB')
    # Exclusive creation prevents adopting another experiment's restore state.
    fd = os.open(args.state, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump(records, output)
        output.flush()
        os.fsync(output.fileno())
    try:
        for record in records:
            print(record['pid'], record['fd'], set_buffer(record, args.bytes))
    except Exception:
        restore(args.state)
        raise


if __name__ == '__main__':
    main()
