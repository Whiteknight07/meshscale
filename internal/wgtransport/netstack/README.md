# Local WireGuard netstack adapter

`tun.go` is the MIT-licensed adapter from
`golang.zx2c4.com/wireguard` at `b3bc704ef0ee`
(`v0.0.0-20261024220952-b3bc704ef0ee`). The upstream copyright notice and license
are retained. TCP, UDP, ICMP and resolver behavior are kept together to preserve
the existing adapter API; WireGuard and gVisor themselves remain dependencies.

Local changes:

- Read packets directly from gVisor's synchronized channel endpoint queue instead
  of forwarding notifications to a second channel. gVisor invokes notifications
  outside its queue lock, so unregistering a notification does not prevent a late
  send to a channel closed by upstream `Close`. Application writes and TCP timers
  can trigger this even if TUN writes are serialized.
- Cancel blocked reads and close the endpoint queue before removing the NIC and
  closing the stack. Serialize inbound TUN writes with close, reject late writes,
  and make close idempotent.
- Release packet/view references after injection/read and close partially created
  stacks on initialization errors.

The regression tests in `../transport_test.go` exercise stack-originated UDP
output concurrently with shutdown and a blocked TUN reader. The nested WireGuard
integration in `internal/secure` covers TCP traffic through two userspace layers.
When updating WireGuard, compare this file with the upstream adapter and retire
this copy once upstream supplies equivalent shutdown and reference ownership.
