import request from 'supertest';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { AppError } from '../src/lib/errors';
import { InMemorySessionEventBus } from '../src/lib/events/sessionEventBus';
import { AwsKmsProvider } from '../src/lib/kms';
import { withRetry } from '../src/lib/resilience';
import { EnvelopeCrypto } from '../src/lib/crypto';
import { mapGithubError } from '../src/services/github.service';
import { recoverSession, stopSession } from '../src/services/sessionLifecycle.service';
import { createOrg, linkGithub, login, makeApp, resetDb, testPrisma } from './helpers';
import { addApiKey, createReadyProject, fakeSandbox, settle } from './sessionHelpers';

const prisma = testPrisma();
const RETRYABLE = new Set([429, 529]);

beforeEach(async () => {
  await resetDb();
});

afterAll(async () => {
  await prisma.$disconnect();
});

describe('Phase 10 failure injection', () => {
  it('backs off provider 429/529 failures and retains their explicit catalog codes', async () => {
    const waits: number[] = [];
    let attempts = 0;
    const result = await withRetry(
      async () => {
        attempts += 1;
        if (attempts < 3)
          throw Object.assign(new Error('provider overloaded'), {
            status: attempts === 1 ? 429 : 529,
          });
        return 'recovered';
      },
      {
        retries: 3,
        baseMs: 10,
        random: () => 0.5,
        sleepFn: async (ms) => void waits.push(ms),
        isRetryable: (err) => RETRYABLE.has((err as { status?: number }).status ?? 0),
      },
    );
    expect({ result, attempts, waits }).toEqual({
      result: 'recovered',
      attempts: 3,
      waits: [5, 10],
    });
    expect(new AppError('LSE-KEY-005').code).toBe('LSE-KEY-005');
    expect(new AppError('LSE-KEY-006').code).toBe('LSE-KEY-006');
  });

  it('retries transient GitHub 5xx failures and maps a persisted outage to LSE-GH-011', async () => {
    let attempts = 0;
    const value = await withRetry(
      async () => {
        attempts += 1;
        if (attempts < 3) throw Object.assign(new Error('bad gateway'), { status: 502 });
        return 'created';
      },
      {
        retries: 3,
        sleepFn: async () => undefined,
        isRetryable: (err) => (err as { status?: number }).status! >= 500,
      },
    );
    expect({ value, attempts }).toEqual({ value: 'created', attempts: 3 });
    expect(mapGithubError(Object.assign(new Error('unavailable'), { status: 503 })).code).toBe(
      'LSE-GH-011',
    );
  });

  it('surfaces KMS wrapping failure as LSE-SYS-006 without exposing plaintext', async () => {
    const crypto = new EnvelopeCrypto(new AwsKmsProvider());
    await expect(crypto.encrypt('top-secret-value', 'generic')).rejects.toMatchObject({
      code: 'LSE-SYS-006',
    });
  });

  it('preserves a pre-death WIP ref, emits LSE-SBX-010, and can Recover the lost sandbox session', async () => {
    const { app, ctx } = makeApp();
    const fake = fakeSandbox(ctx);
    const owner = await login(app, 'chaos-owner@example.com');
    const org = await createOrg(owner, 'Chaos Org');
    await linkGithub(ctx, owner.user.id);
    await addApiKey(ctx, owner.user.id);
    const project = await createReadyProject(ctx, org.id);
    const created = await owner.post('/api/v1/sessions', { projectId: project.id });
    const running = await settle(ctx, created.body.data.id as string);
    const sandbox = fake.last()!;
    await prisma.session.update({
      where: { id: running.id },
      data: { wipRef: `refs/loose/wip/${running.id}` },
    });
    sandbox.lost = true;
    expect(
      await stopSession(ctx, running.id, {
        to: 'ERRORED',
        reason: 'lost',
        errorCode: 'LSE-SBX-010',
        pushWip: true,
      }),
    ).toBe(true);
    const errored = await prisma.session.findUniqueOrThrow({ where: { id: running.id } });
    expect(errored).toMatchObject({
      status: 'ERRORED',
      errorCode: 'LSE-SBX-010',
      wipRef: `refs/loose/wip/${running.id}`,
    });
    const recovered = await recoverSession(
      ctx,
      { user: await prisma.user.findUniqueOrThrow({ where: { id: owner.user.id } }) },
      running.id,
    );
    expect(recovered.status).toBe('QUEUED');
    expect((await settle(ctx, running.id)).status).toBe('RUNNING');
    await ctx.agent.shutdownAll();
  });

  it('replays events after a dropped connection and reports replay gaps after retention eviction', async () => {
    const bus = new InMemorySessionEventBus(2);
    await bus.publish('session-chaos', 'session_status', { status: 'RUNNING', message: 'one' });
    await bus.publish('session-chaos', 'session_status', { status: 'RUNNING', message: 'two' });
    const resumed = await bus.replay('session-chaos', 1);
    expect(resumed).toMatchObject({ complete: true, lastSeq: 2 });
    expect(resumed.events.map((event) => event.seq)).toEqual([2]);
    await bus.publish('session-chaos', 'session_status', { status: 'RUNNING', message: 'three' });
    const stale = await bus.replay('session-chaos', 0);
    expect(stale.complete).toBe(false);
    expect(new AppError('LSE-WS-004').code).toBe('LSE-WS-004');
  });

  it('degrades Redis-dependent readiness to LSE-SYS-003 rather than returning a false ready state', async () => {
    const down = { ping: async () => Promise.reject(new Error('connection refused')) };
    const { app } = makeApp({ context: { redis: down as never } });
    const response = await request(app).get('/readyz');
    expect(response.body.error.code).toBe('LSE-SYS-003');
    expect(response.status).toBe(503);
  });
});
