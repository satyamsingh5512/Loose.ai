/** Sandbox provider selection, resilience and pure helpers (no DB). */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Project } from '@prisma/client';
import { afterAll, describe, expect, it } from 'vitest';
import { EnvError } from '../src/config/env';
import { AppError } from '../src/lib/errors';
import { createLogger } from '../src/lib/logger';
import { CircuitBreaker, withRetry } from '../src/lib/resilience';
import {
  createSandboxServices,
  FakeSandboxProvider,
  innerProvider,
  ResilientSandboxProvider,
  TemplateBuildError,
} from '../src/lib/sandbox';
import { buildTemplateSpec, templateName } from '../src/lib/sandbox/templateSpec';
import { gitAuthEnv, shq } from '../src/services/gitAccess.service';
import {
  formatDotenv,
  healthProbeCommand,
  resolveSessionEnv,
} from '../src/services/workspace.service';
import { testEnv } from './helpers';

const logger = createLogger({ level: 'silent' });
const localDir = mkdtempSync(join(tmpdir(), 'loose-sbx-select-'));
afterAll(() => rmSync(localDir, { recursive: true, force: true }));

describe('sandbox provider selection', () => {
  it('defaults: fake in test, local in development, e2b in production', () => {
    expect(createSandboxServices(testEnv(), logger).kind).toBe('fake');
    const dev = createSandboxServices(
      testEnv({ NODE_ENV: 'development', LOCAL_SANDBOX_DIR: localDir }),
      logger,
    );
    expect(dev.kind).toBe('local');
    expect(dev.templateBuilder.kind).toBe('local');
    const prod = createSandboxServices(testEnv({ NODE_ENV: 'production' }), logger);
    expect(prod.kind).toBe('e2b');
    expect(prod.templateBuilder.kind).toBe('e2b');
    expect(prod.provider).toBeInstanceOf(ResilientSandboxProvider);
  });

  it('explicit SANDBOX_PROVIDER wins outside production', () => {
    expect(
      createSandboxServices(
        testEnv({ SANDBOX_PROVIDER: 'local', LOCAL_SANDBOX_DIR: localDir }),
        logger,
      ).kind,
    ).toBe('local');
    expect(
      createSandboxServices(testEnv({ NODE_ENV: 'development', SANDBOX_PROVIDER: 'fake' }), logger)
        .kind,
    ).toBe('fake');
  });

  it('production refuses local/fake sandboxes, a missing E2B key and the git remote override', () => {
    expect(() => testEnv({ NODE_ENV: 'production', SANDBOX_PROVIDER: 'local' })).toThrow(EnvError);
    expect(() => testEnv({ NODE_ENV: 'production', SANDBOX_PROVIDER: 'fake' })).toThrow(
      /SANDBOX_PROVIDER/,
    );
    expect(() => testEnv({ NODE_ENV: 'production', E2B_API_KEY: '' })).toThrow(/E2B_API_KEY/);
    expect(() =>
      testEnv({ NODE_ENV: 'production', DEV_GIT_REMOTE_OVERRIDE: '/tmp/{owner}/{repo}.git' }),
    ).toThrow(/DEV_GIT_REMOTE_OVERRIDE/);
  });

  it('development e2b without a key fails fast unless the local fallback is allowed', () => {
    const env = {
      NODE_ENV: 'development',
      SANDBOX_PROVIDER: 'e2b',
      E2B_API_KEY: '',
      LOCAL_SANDBOX_DIR: localDir,
    };
    expect(() => createSandboxServices(testEnv(env), logger)).toThrow(/E2B_API_KEY/);
    const fb = createSandboxServices(
      testEnv({ ...env, LOCAL_SANDBOX_ALLOW_FALLBACK: 'true' }),
      logger,
    );
    expect(fb.kind).toBe('local');
  });

  it('derived flags: RUNNER_MOCK off only for e2b, JOBS_INLINE off only in production', () => {
    expect(testEnv().RUNNER_MOCK).toBe(true);
    expect(testEnv().JOBS_INLINE).toBe(true);
    const prod = testEnv({ NODE_ENV: 'production' });
    expect(prod.RUNNER_MOCK).toBe(false);
    expect(prod.JOBS_INLINE).toBe(false);
    expect(testEnv({ RUNNER_MOCK: 'false' }).RUNNER_MOCK).toBe(false);
  });
});

describe('resilience', () => {
  it('retries transient create failures with jittered backoff', async () => {
    const fake = new FakeSandboxProvider().failNextCreate('transient', 2);
    const p = new ResilientSandboxProvider(fake, { retries: 3, baseMs: 0 });
    const sbx = await p.createFromTemplate('tpl', { timeoutMs: 1000 });
    expect(sbx.id).toMatch(/^fake-/);
    expect(fake.createCalls).toHaveLength(3);
  });

  it('does not retry non-transient failures', async () => {
    const fake = new FakeSandboxProvider().failNextCreate('start_failed', 3);
    const p = new ResilientSandboxProvider(fake, { retries: 3, baseMs: 0 });
    await expect(p.createFromTemplate('tpl', { timeoutMs: 1000 })).rejects.toMatchObject({
      kind: 'start_failed',
    });
    expect(fake.createCalls).toHaveLength(1);
  });

  it('opens the circuit after 5 infra failures in 60 s → LSE-SYS-005', async () => {
    const fake = new FakeSandboxProvider().failNextCreate('transient', 20);
    const p = new ResilientSandboxProvider(fake, { retries: 3, baseMs: 0 });
    await expect(p.createFromTemplate('tpl', { timeoutMs: 1 })).rejects.toMatchObject({
      kind: 'transient',
    });
    const err = await p.createFromTemplate('tpl', { timeoutMs: 1 }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AppError);
    expect((err as AppError).code).toBe('LSE-SYS-005');
    expect(fake.createCalls).toHaveLength(5); // fail fast while open
    expect(p.breaker.state).toBe('open');
  });

  it('half-opens after the cool-down and closes on success', async () => {
    let now = 0;
    const b = new CircuitBreaker('t', { failureThreshold: 2, openMs: 100, now: () => now });
    b.recordFailure();
    b.recordFailure();
    expect(b.state).toBe('open');
    now = 150;
    expect(b.state).toBe('half_open');
    await b.exec(async () => 'ok');
    expect(b.state).toBe('closed');
  });

  it('full jitter keeps every delay below the exponential cap', async () => {
    const delays: number[] = [];
    let n = 0;
    await withRetry(
      async () => {
        n += 1;
        if (n < 4) throw new Error('x');
        return n;
      },
      {
        retries: 3,
        baseMs: 100,
        maxMs: 250,
        sleepFn: async (ms) => void delays.push(ms),
        random: () => 0.999,
      },
    );
    expect(delays).toEqual([99, 199, 249]);
  });
});

describe('template spec', () => {
  it('adds service packages and the runner runtime; names are provider-safe', () => {
    const spec = buildTemplateSpec(
      { id: 'cAbC123', requiredServices: ['postgresql', 'redis'] },
      { version: 3 },
    );
    expect(spec.name).toBe('loose-cabc123-v3');
    expect(templateName('x_Y', 1)).toBe('loose-xy-v1');
    expect(spec.baseImage).toBe('node:22-bookworm');
    expect(spec.aptPackages).toEqual(
      expect.arrayContaining(['git', 'chromium', 'postgresql', 'redis-server']),
    );
    expect(spec.runCommands.join('\n')).toContain('@anthropic-ai/claude-agent-sdk@0.3.286');
    expect(spec.envs.CHROMIUM_PATH).toBe('/usr/bin/chromium');
  });

  it('rejects unsupported services', () => {
    expect(() =>
      buildTemplateSpec({ id: 'p', requiredServices: ['mongodb'] }, { version: 1 }),
    ).toThrow(TemplateBuildError);
  });
});

describe('workspace helpers', () => {
  it('formats .env values safely', () => {
    expect(formatDotenv({ B: 'x"y', A: 'line1\nline2', C: 'back\\slash' })).toBe(
      'A="line1\\nline2"\nB="x\\"y"\nC="back\\\\slash"\n',
    );
  });

  it('wires public sandbox URLs into configured env vars and CORS_ORIGIN', async () => {
    const fake = new FakeSandboxProvider();
    const sbx = await fake.createFromTemplate('t', { timeoutMs: 1 });
    const project = {
      portMap: [
        { name: 'web', port: 5173, public: true, envVar: 'APP_URL' },
        { name: 'api', port: 4000, public: false, envVar: 'VITE_API_URL' },
      ],
    } as unknown as Project;
    const env = resolveSessionEnv(project, sbx, {
      VITE_API_URL: 'http://localhost:4000',
      KEEP: '1',
    });
    expect(env).toEqual({
      KEEP: '1',
      APP_URL: `https://5173-${sbx.id}.fake.sandbox`,
      VITE_API_URL: `https://4000-${sbx.id}.fake.sandbox`,
      CORS_ORIGIN: `https://5173-${sbx.id}.fake.sandbox`,
    });
  });

  it('quotes shell arguments and never puts tokens in commands', () => {
    expect(shq("it's")).toBe(`'it'\\''s'`);
    expect(healthProbeCommand(3000, "/h'x")).toContain("http://127.0.0.1:3000/h'\\''x");
    const env = gitAuthEnv('ghs_token123');
    expect(env.GIT_CONFIG_KEY_0).toBe('http.https://github.com/.extraheader');
    expect(
      Buffer.from(
        env.GIT_CONFIG_VALUE_0!.replace('Authorization: Basic ', ''),
        'base64',
      ).toString(),
    ).toBe('x-access-token:ghs_token123');
    expect(gitAuthEnv(null)).toEqual({ GIT_TERMINAL_PROMPT: '0' });
  });

  it('innerProvider unwraps the resilience decorator', () => {
    const fake = new FakeSandboxProvider();
    expect(innerProvider(new ResilientSandboxProvider(fake))).toBe(fake);
  });
});
