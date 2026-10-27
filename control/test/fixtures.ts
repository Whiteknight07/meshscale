import { Schema } from 'effect';
import {
  Machine,
  Registration,
  PhysicalDevice,
  MeshNode,
  GatewayRule,
  Snapshot,
} from '../src/model.ts';
export const machine = (overrides: Partial<Machine> = {}): Machine => ({
  id: 'r1',
  deviceId: 'd1',
  registrationId: 'r1',
  kind: 'device',
  name: 'laptop',
  owner: 'owner@example.com',
  ownerEmail: 'owner@example.com',
  ipv4: '100.96.0.2',
  ipv6: '',
  os: 'mac',
  online: true,
  lastSeen: '2026-10-26T00:00:00Z',
  state: '',
  secure: false,
  offersExit: false,
  ssh: 'unknown',
  dns: 'laptop.mesh',
  ...overrides,
});
export const registration = (overrides: Record<string, unknown> = {}) =>
  Schema.decodeUnknownSync(Registration)({
    id: 'r1',
    device: { id: 'd1', name: 'laptop' },
    user: { email: 'owner@example.com' },
    virtual_ipv4: '100.96.0.2',
    last_seen_at: '2026-10-26T00:00:00Z',
    ...overrides,
  });
export const physical = (overrides: Record<string, unknown> = {}) =>
  Schema.decodeUnknownSync(PhysicalDevice)({
    id: 'd1',
    name: 'laptop',
    device_type: 'mac',
    ...overrides,
  });
export const node = (overrides: Record<string, unknown> = {}) =>
  Schema.decodeUnknownSync(MeshNode)({ id: 'n1', name: 'server', status: 'healthy', ...overrides });
export const rule = (overrides: Record<string, unknown> = {}) =>
  Schema.decodeUnknownSync(GatewayRule)({
    id: 'rule1',
    name: 'Customer rule',
    description: '',
    action: 'allow',
    enabled: true,
    filters: ['l4'],
    traffic: 'net.dst.port == 443',
    precedence: 2000,
    ...overrides,
  });
export const snapshot = (overrides: Partial<Snapshot> = {}): Snapshot => ({
  fetchedAt: 0,
  machines: [machine()],
  secureEndpoints: [],
  rules: [],
  warnings: [],
  nodeAssociationsError: null,
  secureDirectoryError: null,
  sshTargetsError: null,
  ...overrides,
});
