/** Sandbox provider selection + resilience wrapper (spec §13, §16.4). */
import type { Env } from '../../config/env';
import type { Logger } from '../logger';
import { CircuitBreaker, withRetry, type RetryOptions } from '../resilience';
import { E2bSandboxProvider, E2bTemplateBuilder } from './e2b';
import { FakeSandboxProvider, FakeTemplateBuilder } from './fake';
import { LocalSandboxProvider, LocalTemplateBuilder } from './local';
import {
  SandboxProviderError,
  isTransientSandboxError,
  type CreateSandboxOptions,
  type SandboxKind,
  type SandboxProvider,
  type TemplateBuilder,
} from './types';

export * from './types';
export { FakeSandboxProvider, FakeTemplateBuilder, FakeSandbox, FakeProcess } from './fake';
export { LocalSandboxProvider, LocalTemplateBuilder } from './local';
export { E2bSandboxProvider, E2bTemplateBuilder } from './e2b';

/** Retries transient provider failures and trips a breaker (→ LSE-SYS-005). */
export class ResilientSandboxProvider implements SandboxProvider {
  readonly breaker: CircuitBreaker;

  constructor(
    readonly inner: SandboxProvider,
    private readonly retry: RetryOptions = {},
    breaker?: CircuitBreaker,
  ) {
    this.breaker = breaker ?? new CircuitBreaker(`sandbox:${inner.kind}`);
  }

  get kind(): SandboxKind {
    return this.inner.kind;
  }

  #call<T>(fn: () => Promise<T>): Promise<T> {
    const infraFailure = (err: unknown) =>
      err instanceof SandboxProviderError
        ? err.kind === 'transient' || err.kind === 'capacity' || err.kind === 'timeout'
        : true;
    return withRetry(() => this.breaker.exec(fn, infraFailure), {
      ...this.retry,
      isRetryable: (err) => isTransientSandboxError(err),
    });
  }

  createFromTemplate(templateId: string, opts: CreateSandboxOptions) {
    return this.#call(() => this.inner.createFromTemplate(templateId, opts));
  }
  connect(sandboxId: string) {
    return this.#call(() => this.inner.connect(sandboxId));
  }
  kill(sandboxId: string) {
    return this.#call(() => this.inner.kill(sandboxId));
  }
  ping() {
    return this.inner.ping
      ? this.#call(() => this.inner.ping!())
      : this.#call(() => this.inner.list().then(() => undefined));
  }
  list() {
    return this.#call(() => this.inner.list());
  }
}

export interface SandboxServices {
  provider: SandboxProvider;
  templateBuilder: TemplateBuilder;
  /** The concrete provider kind actually in use (after any dev fallback). */
  kind: SandboxKind;
}

/**
 * Pick the provider from env. e2b without E2B_API_KEY: production fails at env
 * validation; development throws here unless LOCAL_SANDBOX_ALLOW_FALLBACK=true.
 */
export function createSandboxServices(env: Env, logger: Logger): SandboxServices {
  let kind: SandboxKind = env.SANDBOX_PROVIDER;
  if (kind === 'e2b' && !env.E2B_API_KEY) {
    if (env.NODE_ENV !== 'production' && env.LOCAL_SANDBOX_ALLOW_FALLBACK) {
      logger.warn(
        'SANDBOX_PROVIDER=e2b but E2B_API_KEY is missing; falling back to local (DEV ONLY)',
      );
      kind = 'local';
    } else {
      throw new SandboxProviderError(
        'start_failed',
        'SANDBOX_PROVIDER=e2b requires E2B_API_KEY (set LOCAL_SANDBOX_ALLOW_FALLBACK=true to use the local dev provider)',
      );
    }
  }
  if (env.NODE_ENV === 'production' && kind !== 'e2b') {
    throw new SandboxProviderError(
      'start_failed',
      `${kind} sandboxes are not allowed in production`,
    );
  }
  const retry: RetryOptions = { retries: 3, baseMs: env.SANDBOX_RETRY_BASE_MS };
  switch (kind) {
    case 'e2b': {
      const opts = {
        apiKey: env.E2B_API_KEY ?? '',
        ...(env.E2B_DOMAIN ? { domain: env.E2B_DOMAIN } : {}),
      };
      return {
        kind,
        provider: new ResilientSandboxProvider(new E2bSandboxProvider(opts), retry),
        templateBuilder: new E2bTemplateBuilder(opts),
      };
    }
    case 'local':
      return {
        kind,
        provider: new ResilientSandboxProvider(
          new LocalSandboxProvider({
            ...(env.LOCAL_SANDBOX_DIR ? { baseDir: env.LOCAL_SANDBOX_DIR } : {}),
            ...(env.LOCAL_RUNNER_ENTRY ? { runnerEntry: env.LOCAL_RUNNER_ENTRY } : {}),
            logger,
          }),
          retry,
        ),
        templateBuilder: new LocalTemplateBuilder(),
      };
    case 'fake':
      return {
        kind,
        provider: new ResilientSandboxProvider(new FakeSandboxProvider(), retry),
        templateBuilder: new FakeTemplateBuilder(),
      };
  }
}

/** Unwrap the resilience decorator (tests script the fake underneath). */
export function innerProvider<T extends SandboxProvider>(p: SandboxProvider): T {
  return (p instanceof ResilientSandboxProvider ? p.inner : p) as T;
}
