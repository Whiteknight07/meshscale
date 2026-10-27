import { Schema } from 'effect';
import { HttpApi, HttpApiEndpoint, HttpApiGroup } from 'effect/http-api';
import { ApiError } from './errors.ts';
import { Action, Applied, Apply, Preview, Snapshot, StoredPolicy } from './model.ts';

export class ConsoleApi extends HttpApi.make('meshscale').add(
  HttpApiGroup.make('console')
    .add(HttpApiEndpoint.get('snapshot', '/api/snapshot', { success: Snapshot, error: ApiError }))
    .add(
      HttpApiEndpoint.get('policy', '/api/policy', {
        success: Schema.NullOr(StoredPolicy),
        error: ApiError,
      }),
    )
    .add(
      HttpApiEndpoint.post('preview', '/api/preview', {
        payload: Action,
        success: Preview,
        error: ApiError,
      }),
    )
    .add(
      HttpApiEndpoint.post('apply', '/api/apply', {
        payload: Apply,
        success: Applied,
        error: ApiError,
      }),
    ),
) {}
