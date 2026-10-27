"""Linux integration tests: real sockets, exact restoration, stale-fd isolation."""
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest

import warp_buffers


class BufferRestorationTest(unittest.TestCase):
    def setUp(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(self.sock.close)
        self.sock.connect(('127.0.0.1', 443))
        self.record = {'pid': os.getpid(), 'fd': self.sock.fileno(),
                       'inode': os.readlink(f'/proc/self/fd/{self.sock.fileno()}'),
                       'old': self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)}
        try:
            fd = warp_buffers.duplicate(os.getpid(), self.sock.fileno())
            os.close(fd)
        except OSError as error:
            self.skipTest(f'pidfd_getfd permission unavailable: {error}')

    def test_live_buffer_restores_exactly_and_restore_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'restore.json'
            state.write_text(json.dumps([self.record]))
            try:
                warp_buffers.set_buffer(self.record, 1024 * 1024)
            except PermissionError as error:
                self.skipTest(f'CAP_NET_ADMIN unavailable: {error}')
            self.assertEqual(self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF), 1024 * 1024)
            warp_buffers.restore(state)
            self.assertEqual(self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF), self.record['old'])
            self.assertFalse(state.exists())
            warp_buffers.restore(state)

    def test_reused_descriptor_cannot_change_unrelated_socket(self):
        # A restore record for an old socket must not apply to the new occupant
        # of the same descriptor, even when the PID and fd number still match.
        self.sock.close()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as replacement:
            self.assertEqual(replacement.fileno(), self.record['fd'])
            replacement.connect(('127.0.0.1', 443))
            before = replacement.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            warp_buffers.set_buffer(self.record, 1024 * 1024)
            self.assertEqual(replacement.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF), before)

    def test_closed_socket_restore_removes_completed_state(self):
        self.sock.close()
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'restore.json'
            state.write_text(json.dumps([self.record]))
            warp_buffers.restore(state)
            self.assertFalse(state.exists())


if __name__ == '__main__':
    unittest.main()
