import { randomBytes } from 'node:crypto';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { IDEMPOTENCY_HEADER } from '@loose/shared';
import { PrismaClient } from '@prisma/client';
import { createLogger } from '../src/lib/logger';
import { createRedis, type Redis } from '../src/lib/redis';
import { createOrg, expectError, login, makeApp, resetDb, testPrisma } from './helpers';

const prisma = testPrisma();
let redis: Redis;

beforeAll(async () => {
  await resetDb();
  // Dedicated Redis DB index for tests.
  redis = createRedis('redis://127.0.0.1:6379/15', createLogger({ level: 'silent' }));
});
afterAll(async () => {
  await redis.quit();
  await prisma.$disconnect();
});

const randomIp = () => `10.${[1, 2, 3].map(() => randomBytes(1)[0]).join('.')}`;

describe('health', () => {
  it('GET /healthz → 200 ok', async () => {
    const { app } = makeApp();
    const res = await request(app).get('/healthz');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ data: { status: 'ok' } });
  });

  it('GET /readyz → 200 when DB and Redis are up', async () => {
    const { app } = makeApp({ context: { redis } });
    const res = await request(app).get('/readyz');
    expect(res.status).toBe(200);
    // The e2b probe is opt-in (READYZ_CHECK_E2B, covered in phase10.readyz.test.ts).
    expect(res.body).toEqual({
      data: { status: 'ok', checks: { db: 'ok', redis: 'ok', e2b: 'skipped' } },
    });
  });

  it('GET /readyz → 503 LSE-SYS-003 when Redis is down', async () => {
    const down = () => Promise.reject(new Error('ECONNREFUSED'));
    const broken = { ping: down, call: down } as unknown as Redis;
    const { app } = makeApp({ context: { redis: broken, kv: undefined } });
    expectError(await request(app).get('/readyz'), 'LSE-SYS-003', 503);
  });

  it('GET /readyz → 503 LSE-SYS-002 when the database is down', async () => {
    const deadDb = new PrismaClient({
      datasources: { db: { url: 'postgresql://loose:loose@127.0.0.1:1/none?connect_timeout=1' } },
    });
    const { app } = makeApp({ context: { prisma: deadDb, redis } });
    const res = await request(app).get('/readyz');
    expectError(res, 'LSE-SYS-002', 503);
    expect(res.body.error.retryable).toBe(true);
    await deadDb.$disconnect();
  });
});

describe('Redis-backed middleware', () => {
  it('general rate limit with the Redis store → LSE-RATE-001 + Retry-After', async () => {
    const { app } = makeApp({
      context: { redis },
      env: { RATE_LIMIT_GENERAL_MAX: '3', TRUST_PROXY: '1' },
    });
    const ip = randomIp();
    for (let i = 0; i < 3; i++) {
      expect((await request(app).get('/api/v1/auth/csrf').set('X-Forwarded-For', ip)).status).toBe(
        200,
      );
    }
    const limited = await request(app).get('/api/v1/auth/csrf').set('X-Forwarded-For', ip);
    expectError(limited, 'LSE-RATE-001', 429);
    expect(Number(limited.headers['retry-after'])).toBeGreaterThan(0);
    // Another caller is unaffected.
    expect(
      (await request(app).get('/api/v1/auth/csrf').set('X-Forwarded-For', randomIp())).status,
    ).toBe(200);
  });

  it('idempotency replay through Redis', async () => {
    const { app } = makeApp({ context: { redis } });
    const c = await login(app);
    const key = `redis-${randomBytes(8).toString('hex')}`;
    const first = await c.post('/api/v1/orgs', { name: 'Redis Org' }).set(IDEMPOTENCY_HEADER, key);
    expect(first.status).toBe(201);
    const replay = await c.post('/api/v1/orgs', { name: 'Redis Org' }).set(IDEMPOTENCY_HEADER, key);
    expect(replay.headers['idempotent-replayed']).toBe('true');
    expect(replay.body).toEqual(first.body);
    expectError(
      await c.post('/api/v1/orgs', { name: 'Changed' }).set(IDEMPOTENCY_HEADER, key),
      'LSE-VAL-004',
      409,
    );
    expect(await prisma.organization.count({ where: { name: 'Redis Org' } })).toBe(1);
    await createOrg(c, 'unrelated');
  });
});
