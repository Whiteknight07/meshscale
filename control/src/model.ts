import { Effect, Schema } from 'effect';
import { CloudflareError, StorageError, ValidationError } from './errors.ts';

const text = Schema.NullOr(Schema.String).pipe(Schema.withDecodingDefault(Effect.succeed('')));
const flag = Schema.Boolean.pipe(Schema.withDecodingDefault(Effect.succeed(false)));
export const IsoDateTime = Schema.String.check(
  Schema.isPattern(
    /^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/,
  ),
  Schema.makeFilter(
    (s) => {
      const date = s.slice(0, 10);
      const midnight = Date.parse(`${date}T00:00:00Z`);
      return (
        Number.isFinite(Date.parse(s)) &&
        Number.isFinite(midnight) &&
        new Date(midnight).toISOString().slice(0, 10) === date
      );
    },
    { message: 'Expected an ISO date-time' },
  ),
);
const date = Schema.NullOr(IsoDateTime).pipe(Schema.withDecodingDefault(Effect.succeed(null)));
export const User = Schema.Struct({ email: text, name: text });
export const Registration = Schema.Struct({
  id: Schema.String,
  device: Schema.Struct({ id: Schema.String, name: text }),
  user: Schema.NullOr(User).pipe(Schema.withDecodingDefault(Effect.succeed(null))),
  virtual_ipv4: text,
  virtual_ipv6: text,
  registration_type: text,
  last_seen_at: date,
  deleted_at: date,
  revoked_at: date,
});
export type Registration = typeof Registration.Type;
export const PhysicalDevice = Schema.Struct({
  id: Schema.String,
  name: text,
  device_type: text,
  last_seen_at: date,
  deleted_at: date,
  last_seen_user: Schema.NullOr(User).pipe(Schema.withDecodingDefault(Effect.succeed(null))),
});
export type PhysicalDevice = typeof PhysicalDevice.Type;
export const MeshNode = Schema.Struct({
  id: Schema.String,
  name: text,
  status: text,
  deleted_at: date,
  conns_inactive_at: date,
});
export type MeshNode = typeof MeshNode.Type;
export const Connector = Schema.Struct({ id: Schema.String });
export const GatewayList = Schema.Struct({
  id: Schema.String,
  name: Schema.String,
  type: Schema.String,
  description: text,
});
export type GatewayList = typeof GatewayList.Type;
export const SecureRecord = Schema.Struct({
  registration_id: Schema.String,
  public_key: Schema.String,
  enabled: Schema.Boolean,
  exit_version: Schema.Number.pipe(Schema.withDecodingDefault(Effect.succeed(0))),
  offers_exit_node: flag,
  ipv4: text,
});
export type SecureRecord = typeof SecureRecord.Type;
export const GatewayRule = Schema.Struct({
  id: Schema.String.pipe(Schema.withDecodingDefault(Effect.succeed(''))),
  name: Schema.String,
  description: text,
  action: Schema.String,
  enabled: flag,
  filters: Schema.Array(Schema.String),
  traffic: text,
  identity: text,
  device_posture: text,
  precedence: Schema.Number.pipe(Schema.withDecodingDefault(Effect.succeed(0))),
  read_only: flag,
  rule_settings: Schema.NullOr(
    Schema.Struct({
      override_ips: Schema.NullOr(Schema.Array(Schema.String)).pipe(
        Schema.withDecodingDefault(Effect.succeed(null)),
      ),
      override_host: text,
    }),
  ).pipe(Schema.withDecodingDefault(Effect.succeed(null))),
  schedule: Schema.optional(Schema.Unknown),
  expiration: Schema.optional(Schema.Unknown),
});
export type GatewayRule = typeof GatewayRule.Type;
export const Target = Schema.Struct({
  ip: Schema.Struct({
    ipv4: Schema.optional(Schema.NullOr(Schema.Struct({ ip_addr: Schema.String }))),
    ipv6: Schema.optional(Schema.NullOr(Schema.Struct({ ip_addr: Schema.String }))),
  }),
});
export const Machine = Schema.Struct({
  id: Schema.String,
  deviceId: Schema.String,
  registrationId: Schema.String,
  kind: Schema.Literals(['device', 'node']),
  name: Schema.String,
  owner: Schema.String,
  ownerEmail: Schema.String,
  ipv4: Schema.String,
  ipv6: Schema.String,
  os: Schema.String,
  online: Schema.Boolean,
  lastSeen: Schema.NullOr(IsoDateTime),
  state: Schema.String,
  secure: Schema.Boolean,
  offersExit: Schema.Boolean,
  ssh: Schema.Literals(['cloudflare', 'unknown']),
  dns: Schema.String,
});
export type Machine = typeof Machine.Type;
export const Snapshot = Schema.Struct({
  fetchedAt: Schema.Number,
  machines: Schema.Array(Machine),
  secureEndpoints: Schema.Array(Schema.String),
  rules: Schema.Array(GatewayRule),
  warnings: Schema.Array(Schema.String),
  nodeAssociationsError: Schema.NullOr(StorageError),
  secureDirectoryError: Schema.NullOr(ValidationError),
  sshTargetsError: Schema.NullOr(CloudflareError),
});
export type Snapshot = typeof Snapshot.Type;
export const Change = Schema.Struct({
  operation: Schema.Literals(['create', 'update', 'delete']),
  rule: GatewayRule,
});
export type Change = typeof Change.Type;
export const Action = Schema.Union([
  Schema.Struct({ type: Schema.Literal('rules'), policy: Schema.String }),
  Schema.Struct({ type: Schema.Literal('rename'), id: Schema.String, name: Schema.String }),
  Schema.Struct({ type: Schema.Literal('revoke'), id: Schema.String }),
]);
export type Action = typeof Action.Type;
export const Preview = Schema.Struct({
  fingerprint: Schema.String,
  changes: Schema.Array(Change),
  before: Schema.String,
  after: Schema.String,
  notice: Schema.String,
});
export type Preview = typeof Preview.Type;
export const Apply = Schema.Struct({
  action: Action,
  fingerprint: Schema.String,
  confirm: Schema.Literal(true),
});
export const Applied = Schema.Struct({ message: Schema.String });
export const StoredPolicy = Schema.Struct({
  version: Schema.Literal(1),
  json: Schema.String,
  updatedAt: Schema.Number,
});

export type StoredPolicy = typeof StoredPolicy.Type;
