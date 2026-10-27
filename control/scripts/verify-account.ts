import { ConfigProvider, Effect, Layer } from 'effect';
import { Cloudflare } from '../src/cloudflare.ts';
import { Settings } from '../src/config.ts';
import { Inventory } from '../src/inventory.ts';
import { Storage } from '../src/storage.ts';

const values = new Map<string, string>();
const kv = {
  get: (key: string) => Promise.resolve(values.get(key) ?? null),
  put: (key: string, value: string) => {
    values.set(key, value);
    return Promise.resolve();
  },
  delete: (key: string) => {
    values.delete(key);
    return Promise.resolve();
  },
};
const config = ConfigProvider.fromUnknown({
  ACCOUNT_ID: process.env.CLOUDFLARE_ACCOUNT_ID,
  API_TOKEN: process.env.MESHSCALE_CONSOLE_API_TOKEN,
  TEAM_DOMAIN: process.env.MESHSCALE_TEAM_DOMAIN,
  ACCESS_AUD: 'local-verification',
  OWNER_EMAIL: process.env.MESHSCALE_OWNER_EMAIL,
});
const base = Layer.mergeAll(
  Settings.layer.pipe(Layer.provide(ConfigProvider.layer(config))),
  Storage.layer(kv),
);
const inventory = Inventory.layer.pipe(
  Layer.provide(Cloudflare.layer.pipe(Layer.provideMerge(base))),
);
const program = Effect.gen(function* () {
  const service = yield* Inventory;
  const snapshot = yield* service.load(true);
  return snapshot.machines.map((machine) => ({
    kind: machine.kind,
    name: machine.name,
    ipv4: machine.ipv4,
    secure: machine.secure,
    offersExit: machine.offersExit,
  }));
}).pipe(Effect.provide(inventory));
const machines = await Effect.runPromise(program);
process.stdout.write(`${JSON.stringify(machines, null, 2)}\n`);
