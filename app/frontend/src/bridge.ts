/** Exact snake_case device shape emitted by `meshscale status --json`. */
export interface MeshDevice {
  id: string
  registration_id?: string
  device_id?: string
  kind: string
  name: string
  dns_name?: string
  user?: string
  ipv4?: string
  ipv6?: string
  os?: string
  online: boolean
  last_seen_at?: string
  this_machine: boolean
  connection_state?: string
}
export interface AppStatus {
  auth: 'signed-out' | 'signing-in' | 'signed-in'
  account?: { id: string; name: string; email?: string }
  connection: {
    state: 'connected' | 'connecting' | 'disconnected' | 'error'
    reason?: string
  }
  devices: MeshDevice[]
  sshDeviceIds: string[]
  updatedAt: string
  error?: { code: string; message: string; recovery: string }
  preferences: { launchAtLogin: boolean }
}
/** The single boundary for status, native actions, and status events. */
export interface MeshBridge {
  getStatus(): Promise<AppStatus>
  connect(): Promise<void>
  disconnect(): Promise<void>
  signIn(): Promise<void>
  cancelSignIn(): Promise<void>
  signOut(): Promise<void>
  copy(text: string): Promise<void>
  openSSH(device: MeshDevice): Promise<void>
  quit(): Promise<void>
  setLaunchAtLogin(enabled: boolean): Promise<void>
  onChange(callback: (status: AppStatus) => void): () => void
}

declare global {
  interface Window {
    meshscaleBridge?: MeshBridge
    __MESHSCALE_REVIEW__?: boolean
  }
}

export function unavailableBridge(): MeshBridge {
  const fail = async (): Promise<never> => { throw new Error('The meshscale service is unavailable. Quit and reopen meshscale.') }
  return {
    getStatus: async () => ({
      auth: 'signed-in', connection: { state: 'error' }, devices: [], sshDeviceIds: [],
      updatedAt: new Date().toISOString(), preferences: { launchAtLogin: false },
      error: { code: 'service-unavailable', message: 'Cannot reach meshscale', recovery: 'Quit and reopen meshscale to start the local service.' },
    }),
    connect: fail, disconnect: fail, signIn: fail, cancelSignIn: fail, signOut: fail,
    copy: fail, openSSH: fail, quit: fail, setLaunchAtLogin: fail,
    onChange: () => () => {},
  }
}

/** Validate bridge messages at runtime; TypeScript types do not protect the DOM. */
export function readStatus(value: unknown): AppStatus {
  const object = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v)
  const optionalText = (v: Record<string, unknown>, keys: string[]) => keys.every(key => v[key] === undefined || typeof v[key] === 'string')
  const device = (v: unknown) => object(v) && ['id', 'kind', 'name'].every(key => typeof v[key] === 'string') &&
    typeof v.online === 'boolean' && typeof v.this_machine === 'boolean' &&
    optionalText(v, ['registration_id', 'device_id', 'dns_name', 'user', 'ipv4', 'ipv6', 'os', 'last_seen_at', 'connection_state'])
  if (object(value) && typeof value.auth === 'string' && ['signed-out', 'signing-in', 'signed-in'].includes(value.auth) &&
    object(value.connection) && typeof value.connection.state === 'string' && ['connected', 'connecting', 'disconnected', 'error'].includes(value.connection.state) &&
    optionalText(value.connection, ['reason']) &&
    Array.isArray(value.devices) && value.devices.every(device) &&
    Array.isArray(value.sshDeviceIds) && value.sshDeviceIds.every(id => typeof id === 'string') &&
    typeof value.updatedAt === 'string' && object(value.preferences) && typeof value.preferences.launchAtLogin === 'boolean' &&
    (value.account === undefined || (object(value.account) && typeof value.account.id === 'string' && typeof value.account.name === 'string' && optionalText(value.account, ['email']))) &&
    (value.error === undefined || (object(value.error) && typeof value.error.code === 'string' && typeof value.error.message === 'string' && typeof value.error.recovery === 'string'))) {
    return value as unknown as AppStatus
  }
  return {
    auth: 'signed-in', connection: { state: 'error' }, devices: [], sshDeviceIds: [],
    updatedAt: new Date().toISOString(), preferences: { launchAtLogin: false },
    error: { code: 'invalid-status', message: 'Cannot read connection status', recovery: 'The local service sent invalid data. Quit and reopen meshscale.' },
  }
}
