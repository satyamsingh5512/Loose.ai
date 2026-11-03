/**
 * Retry + circuit breaker for calls to e2b / GitHub (spec §16.4):
 * 3 jittered retries; the breaker opens after 5 failures within 60 s and then
 * fails fast with LSE-SYS-005 until a cool-down has passed (half-open probe).
 */
import { AppError } from './errors';

export const sleep = (ms: number) =>
  new Promise<void>((resolve) => {
    if (ms <= 0) return resolve();
    setTimeout(resolve, ms).unref?.();
  });

export interface RetryOptions {
  /** Additional attempts after the first (default 3). */
  retries?: number;
  baseMs?: number;
  maxMs?: number;
  /** Return false for errors that must not be retried (user errors, 4xx). */
  isRetryable?: (err: unknown) => boolean;
  /** Injected for tests. */
  sleepFn?: (ms: number) => Promise<void>;
  random?: () => number;
}

/** Exponential backoff with full jitter: delay ∈ [0, min(max, base·2^n)). */
export async function withRetry<T>(fn: (attempt: number) => Promise<T>, opts: RetryOptions = {}) {
  const retries = opts.retries ?? 3;
  const base = opts.baseMs ?? 500;
  const max = opts.maxMs ?? 30_000;
  const wait = opts.sleepFn ?? sleep;
  const random = opts.random ?? Math.random;
  let attempt = 0;
  for (;;) {
    try {
      return await fn(attempt);
    } catch (err) {
      if (attempt >= retries || (opts.isRetryable && !opts.isRetryable(err))) throw err;
      const cap = Math.min(max, base * 2 ** attempt);
      await wait(Math.floor(random() * cap));
      attempt += 1;
    }
  }
}

export interface CircuitBreakerOptions {
  failureThreshold?: number;
  windowMs?: number;
  /** How long the breaker stays open before letting one probe through. */
  openMs?: number;
  now?: () => number;
}

export class CircuitBreaker {
  readonly #threshold: number;
  readonly #windowMs: number;
  readonly #openMs: number;
  readonly #now: () => number;
  #failures: number[] = [];
  #openedAt: number | null = null;

  constructor(
    readonly name: string,
    opts: CircuitBreakerOptions = {},
  ) {
    this.#threshold = opts.failureThreshold ?? 5;
    this.#windowMs = opts.windowMs ?? 60_000;
    this.#openMs = opts.openMs ?? 30_000;
    this.#now = opts.now ?? Date.now;
  }

  get state(): 'closed' | 'open' | 'half_open' {
    if (this.#openedAt === null) return 'closed';
    return this.#now() - this.#openedAt >= this.#openMs ? 'half_open' : 'open';
  }

  /** Run `fn`; errors for which `isFailure` returns false don't count towards opening. */
  async exec<T>(
    fn: () => Promise<T>,
    isFailure: (err: unknown) => boolean = () => true,
  ): Promise<T> {
    if (this.state === 'open') {
      throw new AppError('LSE-SYS-005', {
        devMessage: `Circuit "${this.name}" is open after repeated failures`,
      });
    }
    try {
      const out = await fn();
      this.#failures = [];
      this.#openedAt = null;
      return out;
    } catch (err) {
      if (isFailure(err)) this.recordFailure();
      throw err;
    }
  }

  recordFailure(): void {
    const now = this.#now();
    if (this.state === 'half_open') {
      this.#openedAt = now; // probe failed → open again
      return;
    }
    this.#failures = this.#failures.filter((t) => now - t < this.#windowMs);
    this.#failures.push(now);
    if (this.#failures.length >= this.#threshold) this.#openedAt = now;
  }
}
