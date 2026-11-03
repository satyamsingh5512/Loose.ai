/**
 * AppError — the single error type thrown by routes/services (spec §16.7).
 * Defaults (status, title, userMessage, retryable, recoverable, action) come
 * from the shared catalog; callers usually only add a devMessage.
 */
import {
  buildErrorEnvelope,
  getErrorDefinition,
  type ErrorAction,
  type ErrorCode,
  type ErrorEnvelope,
  type FieldErrors,
} from '@loose/shared';

export interface AppErrorOptions {
  /** Technical detail for logs / Pro Mode. Secrets are scrubbed on output. */
  devMessage?: string;
  fields?: FieldErrors;
  /** Override the catalog action; `null` removes it. */
  action?: ErrorAction | null;
  cause?: unknown;
  status?: number;
  title?: string;
  userMessage?: string;
  retryable?: boolean;
  recoverable?: boolean;
  /** Extra response headers (e.g. Retry-After). */
  headers?: Record<string, string>;
}

export class AppError extends Error {
  readonly code: ErrorCode;
  readonly status: number;
  readonly title: string;
  readonly userMessage: string;
  readonly devMessage: string | undefined;
  readonly retryable: boolean;
  readonly recoverable: boolean;
  readonly fields: FieldErrors | undefined;
  readonly action: ErrorAction | null | undefined;
  readonly headers: Record<string, string> | undefined;

  constructor(code: ErrorCode, opts: AppErrorOptions = {}) {
    const def = getErrorDefinition(code);
    super(
      opts.devMessage ?? def.title,
      opts.cause !== undefined ? { cause: opts.cause } : undefined,
    );
    this.name = 'AppError';
    this.code = code;
    this.status = opts.status ?? def.httpStatus;
    this.title = opts.title ?? def.title;
    this.userMessage = opts.userMessage ?? def.userMessage;
    this.devMessage = opts.devMessage;
    this.retryable = opts.retryable ?? def.retryable;
    this.recoverable = opts.recoverable ?? def.recoverable;
    this.fields = opts.fields;
    this.action = opts.action;
    this.headers = opts.headers;
  }

  toEnvelope(requestId: string, includeDevMessage = true): ErrorEnvelope {
    return buildErrorEnvelope(this.code, {
      requestId,
      ...(includeDevMessage && this.devMessage !== undefined
        ? { devMessage: this.devMessage }
        : {}),
      ...(this.fields ? { fields: this.fields } : {}),
      ...(this.action !== undefined ? { action: this.action } : {}),
      overrides: {
        status: this.status,
        title: this.title,
        userMessage: this.userMessage,
        retryable: this.retryable,
        recoverable: this.recoverable,
      },
    });
  }
}

export function isAppError(err: unknown): err is AppError {
  return err instanceof AppError;
}
