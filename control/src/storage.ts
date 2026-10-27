import { Context, Effect, Layer, Schema } from 'effect';
import { StorageError } from './errors.ts';

export interface KeyValue {
  readonly get: (key: string) => Promise<string | null>;
  readonly put: (key: string, value: string, options?: { expirationTtl?: number }) => Promise<void>;
  readonly delete: (key: string) => Promise<void>;
}
export interface StorageService {
  readonly read: <S extends Schema.Constraint>(
    key: string,
    schema: S,
  ) => Effect.Effect<S['Type'] | null, StorageError, S['DecodingServices']>;
  readonly write: <S extends Schema.Constraint>(
    key: string,
    schema: S,
    value: S['Type'],
    ttl?: number,
  ) => Effect.Effect<void, StorageError, S['EncodingServices']>;
  readonly remove: (key: string) => Effect.Effect<void, StorageError>;
}
export class Storage extends Context.Service<Storage, StorageService>()('meshscale/Storage') {
  static layer = (kv: KeyValue) =>
    Layer.succeed(Storage)({
      read: (key, schema) =>
        Effect.gen(function* () {
          const value = yield* Effect.tryPromise({
            try: () => kv.get(key),
            catch: () =>
              new StorageError({ operation: 'read', message: 'Console storage unavailable' }),
          });
          if (value === null) return null;
          return yield* Schema.decodeUnknownEffect(Schema.fromJsonString(schema))(value).pipe(
            Effect.mapError(
              () =>
                new StorageError({ operation: 'read', message: `Invalid stored record: ${key}` }),
            ),
          );
        }),
      write: (key, schema, value, ttl) =>
        Schema.encodeEffect(Schema.fromJsonString(schema))(value).pipe(
          Effect.mapError(
            () => new StorageError({ operation: 'write', message: 'Cannot encode stored record' }),
          ),
          Effect.flatMap((json) =>
            Effect.tryPromise({
              try: () => kv.put(key, json, ttl === undefined ? undefined : { expirationTtl: ttl }),
              catch: () =>
                new StorageError({ operation: 'write', message: 'Cannot save console record' }),
            }),
          ),
        ),
      remove: (key) =>
        Effect.tryPromise({
          try: () => kv.delete(key),
          catch: () =>
            new StorageError({
              operation: 'invalidate',
              message: 'Cannot invalidate console cache',
            }),
        }),
    });
}
