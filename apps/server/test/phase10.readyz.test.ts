import request from 'supertest';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { PrismaClient } from '@prisma/client';
import { createLogger } from '../src/lib/logger';
import { createRedis, type Redis } from '../src/lib/redis';
import { FakeSandboxProvider } from '../src/lib/sandbox';
import { expectError, makeApp, resetDb, testPrisma } from './helpers';

const prisma = testPrisma();
let redis: Redis | undefined;

beforeEach(async () => {
  await resetDb();
  redis ??= createRedis('redis://127.0.0.1:6379/15', createLogger({ level: 'silent' }));
});

afterAll(async () => {
  await redis?.quit();
  await prisma.$disconnect();
});

describe('Phase 10 observability endpoints', () => {
  it('keeps /metrics undiscoverable when unset and rejects missing/wrong bearer tokens when configured', async () => {
    const disabled = makeApp();
    expectError(await request(disabled.app).get('/metrics'), 'LSE-NF-001', 404);

    const token = 'metrics-token-abcdefghijklmnopqrstuvwxyz-123456';
    const { app } = makeApp({ env: { METRICS_TOKEN: token } });
    expectError(await request(app).get('/metrics'), 'LSE-AUTH-001', 401);
    expectError(
      await request(app).get('/metrics').set('authorization', 'Bearer not-the-metrics-token'),
      'LSE-AUTH-001',
      401,
    );
    const ok = await request(app).get('/metrics').set('authorization', `Bearer ${token}`);
    expect(ok.status).toBe(200);
    expect(ok.headers['content-type']).toContain('text/plain');
    expect(ok.text).toContain('loose_http_requests_total');
  });

  it('reports all readiness checks and surfaces Redis, database, and sandbox failures with their catalog codes', async () => {
    const sandbox = Object.assign(new FakeSandboxProvider(), { ping: async () => undefined });
    const healthy = makeApp({
      env: { READYZ_CHECK_E2B: 'true' },
      context: { redis: redis!, sandbox },
    });
    expect((await request(healthy.app).get('/readyz')).body).toEqual({
      data: { status: 'ok', checks: { db: 'ok', redis: 'ok', e2b: 'ok' } },
    });

    const downRedis = { ping: async () => Promise.reject(new Error('redis unavailable')) } as Redis;
    const redisFailure = makeApp({ context: { redis: downRedis } });
    expectError(await request(redisFailure.app).get('/readyz'), 'LSE-SYS-003', 503);

    const deadDb = new PrismaClient({
      datasources: { db: { url: 'postgresql://loose:loose@127.0.0.1:1/none?connect_timeout=1' } },
    });
    try {
      const dbFailure = makeApp({ context: { prisma: deadDb, redis: redis! } });
      expectError(await request(dbFailure.app).get('/readyz'), 'LSE-SYS-002', 503);
    } finally {
      await deadDb.$disconnect();
    }

    const brokenSandbox = Object.assign(new FakeSandboxProvider(), {
      ping: async () => Promise.reject(new Error('provider unavailable')),
    });
    const sandboxFailure = makeApp({
      env: { READYZ_CHECK_E2B: 'true' },
      context: { redis: redis!, sandbox: brokenSandbox },
    });
    expectError(await request(sandboxFailure.app).get('/readyz'), 'LSE-SYS-005', 504);
  });
});
