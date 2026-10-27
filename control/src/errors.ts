import { Schema } from 'effect';

export class CloudflareError extends Schema.TaggedError<CloudflareError>()(
  'CloudflareError',
  { operation: Schema.String, status: Schema.Number, message: Schema.String },
  { httpApiStatus: 502 },
) {
  // Diagnostics stay server-side: neither field is part of the API schema.
  declare readonly retryAfterMs?: number;
  constructor(fields: {
    operation: string;
    status: number;
    message: string;
    cause?: unknown;
    retryAfterMs?: number;
  }) {
    super(fields);
    Object.defineProperty(this, 'cause', { value: fields.cause, enumerable: false });
    Object.defineProperty(this, 'retryAfterMs', { value: fields.retryAfterMs, enumerable: false });
  }
}
export class AssetError extends Schema.TaggedError<AssetError>()('AssetError', {
  message: Schema.String,
}) {}
export class StorageError extends Schema.TaggedError<StorageError>()(
  'StorageError',
  { operation: Schema.String, message: Schema.String },
  { httpApiStatus: 503 },
) {}
export class ValidationError extends Schema.TaggedError<ValidationError>()(
  'ValidationError',
  { message: Schema.String },
  { httpApiStatus: 400 },
) {}
export class Unauthorized extends Schema.TaggedError<Unauthorized>()(
  'Unauthorized',
  { message: Schema.String },
  { httpApiStatus: 403 },
) {}
export class Conflict extends Schema.TaggedError<Conflict>()(
  'Conflict',
  { message: Schema.String },
  { httpApiStatus: 409 },
) {}
// HttpApi needs separate schemas to retain each error's HTTP status annotation.
export const ApiError = [
  CloudflareError,
  StorageError,
  ValidationError,
  Unauthorized,
  Conflict,
] as const;
