import type { AppStatus, MeshBridge, MeshDevice } from './bridge'

export const states = ['signed-out', 'signing-in', 'connected', 'disconnected', 'connecting', 'error', 'empty', 'device-detail', 'offline-detail', 'account', 'settings'] as const
export type ReviewState = typeof states[number]
const now = '2026-10-26T12:00:00Z'
const devices: MeshDevice[] = [
  { id: 'reg-mac', device_id: 'dev-mac', kind: 'device', name: 'macbook-air', dns_name: 'macbook-air.mesh', user: 'alex@example.com', ipv4: '100.96.0.2', os: 'mac', online: true, last_seen_at: now, this_machine: true },
  { id: 'node-homelab', registration_id: 'reg-homelab', kind: 'node', name: 'homelab', dns_name: 'homelab.mesh', user: 'Mesh node', ipv4: '100.96.0.10', os: 'linux', online: true, last_seen_at: now, this_machine: false, connection_state: 'healthy' },
  { id: 'reg-pixel', device_id: 'dev-pixel', kind: 'device', name: 'pixel-9', dns_name: 'pixel-9.mesh', user: 'alex@example.com', ipv4: '100.96.0.12', os: 'android', online: true, last_seen_at: now, this_machine: false },
  { id: 'node-nas', registration_id: 'reg-nas', kind: 'node', name: 'nas', dns_name: 'nas.mesh', user: 'Mesh node', ipv4: '100.96.0.20', os: 'linux', online: true, last_seen_at: now, this_machine: false, connection_state: 'healthy' },
  { id: 'reg-thinkpad', kind: 'device', name: 'old-thinkpad', dns_name: 'old-thinkpad.mesh', user: 'alex@example.com', ipv4: '100.96.0.31', os: 'linux', online: false, last_seen_at: '2026-10-23T12:00:00Z', this_machine: false },
]

export function fixture(state: ReviewState): AppStatus {
  const result: AppStatus = {
    auth: 'signed-in', account: { id: 'account-personal', name: 'Personal account', email: 'alex@example.com' },
    connection: { state: 'connected' }, devices: structuredClone(devices),
    sshDeviceIds: ['node-homelab', 'node-nas', 'reg-thinkpad'],
    updatedAt: now, preferences: { launchAtLogin: true },
  }
  if (state === 'signed-out' || state === 'signing-in') {
    result.auth = state
    delete result.account
    result.devices = []
    result.connection.state = 'disconnected'
  }
  if (state === 'disconnected' || state === 'connecting' || state === 'error') {
    result.connection.state = state
    result.devices[0].online = false
  }
  if (state === 'error') result.error = { code: 'cloudflare-unreachable', message: 'Cannot reach Cloudflare', recovery: 'Check your internet connection, then choose Connect to try again.' }
  if (state === 'empty') result.devices = result.devices.slice(0, 1)
  return result
}

export interface MockControls {
  setState(state: ReviewState): void
  completeSignIn(): void
  receipt: string
}

export function createMock(): MeshBridge & MockControls {
  let current = fixture('connected')
  let generation = 0
  const listeners = new Set<(value: AppStatus) => void>()
  const emit = () => listeners.forEach(fn => fn(structuredClone(current)))
  const mock: MeshBridge & MockControls = {
    receipt: '',
    getStatus: async () => structuredClone(current),
    onChange(fn) { listeners.add(fn); return () => { listeners.delete(fn) } },
    setState(state) { generation++; current = fixture(state); mock.receipt = ''; emit() },
    async connect() {
      const token = ++generation
      current.connection.state = 'connecting'
      delete current.error
      emit()
      await new Promise(resolve => setTimeout(resolve, 1200))
      if (token !== generation) return
      current.connection.state = 'connected'
      const local = current.devices.find(d => d.this_machine)
      if (local) local.online = true
      emit()
    },
    async disconnect() {
      generation++
      current.connection.state = 'disconnected'
      const local = current.devices.find(d => d.this_machine)
      if (local) local.online = false
      emit()
    },
    async signIn() { mock.setState('signing-in'); mock.receipt = 'Preview: browser sign-in requested.' },
    completeSignIn() { mock.setState('connected') },
    async cancelSignIn() { mock.setState('signed-out') },
    async signOut() { mock.setState('signed-out') },
    async copy(text) {
      if (!navigator.clipboard) throw new Error('Clipboard unavailable. Select and copy the value manually.')
      await navigator.clipboard.writeText(text)
    },
    async openSSH(device) {
      if (current.connection.state !== 'connected' || !device.online || device.this_machine || !current.sshDeviceIds.includes(device.id)) throw new Error('SSH is unavailable for this device.')
      mock.receipt = `Preview: SSH in Terminal requested for ${device.dns_name || device.ipv4 || device.ipv6 || device.name}.`
    },
    async quit() { mock.receipt = 'Preview: Quit requested. The native app would close.' },
    async setLaunchAtLogin(enabled) { current.preferences.launchAtLogin = enabled; emit() },
  }
  return mock
}
