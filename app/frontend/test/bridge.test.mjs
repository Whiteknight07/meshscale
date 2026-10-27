import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readStatus } from '../src/bridge.ts'

const status = () => ({
  auth: 'signed-in', connection: { state: 'connected' },
  devices: [{ id: 'node', kind: 'node', name: 'server', online: true, this_machine: false }],
  sshDeviceIds: ['node'], updatedAt: new Date().toISOString(), preferences: { launchAtLogin: false },
})
test('accepts normal device snapshots and escaped display text', () => {
  const value = status()
  value.devices[0].name = '<img src=x onerror=alert(1)>'
  assert.equal(readStatus(value), value)
})
test('rejects injected enum attributes and malformed native messages before rendering', () => {
  const injected = status()
  injected.connection.state = '"><img src=x onerror=alert(1)>'
  const invalidDevices = status()
  invalidDevices.devices[0].name = { html: '<script>alert(1)</script>' }
  for (const value of [null, {}, injected, invalidDevices, { ...status(), devices: null }, { ...status(), error: { message: 'bad' } }]) {
    const safe = readStatus(value)
    assert.equal(safe.connection.state, 'error')
    assert.equal(safe.error.code, 'invalid-status')
    assert.deepEqual(safe.devices, [])
  }
})
