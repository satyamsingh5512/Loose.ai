import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { errorEnvelopeSchema } from '@loose/shared';
import { AppError } from '../src/lib/errors';
import { expectError, login, makeApp, resetDb, testPrisma } from './helpers';

const REQUEST_ID = /^req_[A-Za-z0-9_-]{21}$/;

function boom() {
  throw new Error('kaboom with sk-ant-api03-SECRETSECRETSECRET inside');
}

describe('error envelope (spec §16.2)', () => {
  const { app } = makeApp({
    extraApiRoutes: (r) => {
      r.get('/__test/boom', boom);
      r.get('/__test/async-boom', async () => {
        await Promise.resolve();
        boom();
      });
      r.get('/__test/kms', () => {
        throw new AppError('LSE-SYS-006', { devMessage: 'unwrap failed' });
      });
    },
  });
  const prod = makeApp({
    env: { NODE_ENV: 'production' },
    extraApiRoutes: (r) => r.get('/__test/boom', boom),
  });

  beforeAll(() => resetDb());
  afterAll(() => testPrisma().$disconnect());

  it('every response carries x-request-id', async () => {
    const ok = await request(app).get('/healthz');
    expect(ok.headers['x-request-id']).toMatch(REQUEST_ID);
    const err = await request(app).get('/api/v1/nope');
    expect(err.headers['x-request-id']).toMatch(REQUEST_ID);
    expect(err.headers['x-request-id']).not.toBe(ok.headers['x-request-id']);
  });

  it('unknown route → LSE-NF-001 with full envelope', async () => {
    const res = await request(app).get('/api/v1/definitely/not/here');
    expectError(res, 'LSE-NF-001', 404);
    expect(errorEnvelopeSchema.safeParse(res.body).success).toBe(true);
    expect(res.body.error).toMatchObject({
      title: expect.any(String),
      userMessage: expect.any(String),
      retryable: false,
      recoverable: true,
      docs: 'https://docs.loose.ai/errors/LSE-NF-001',
    });
  });

  it('no session → LSE-AUTH-001', async () => {
    const res = await request(app).get('/api/v1/auth/me');
    expectError(res, 'LSE-AUTH-001', 401);
    expect(res.body.error.action).toMatchObject({ type: 'navigate', href: '/signin' });
  });

  it('validation → LSE-VAL-001 with per-field messages', async () => {
    const c = await login(app);
    const res = await c.post('/api/v1/orgs', { name: '', slug: 'Bad Slug!', extra: 1 });
    expectError(res, 'LSE-VAL-001', 400);
    expect(errorEnvelopeSchema.safeParse(res.body).success).toBe(true);
    expect(Object.keys(res.body.error.fields)).toEqual(expect.arrayContaining(['name', 'slug']));
  });

  it('malformed JSON → LSE-VAL-001', async () => {
    const c = await login(app);
    const res = await c.agent
      .post('/api/v1/orgs')
      .set('x-csrf-token', c.csrf)
      .set('content-type', 'application/json')
      .send('{"name": ');
    expectError(res, 'LSE-VAL-001', 400);
  });

  it('body over 1mb → LSE-VAL-002', async () => {
    const c = await login(app);
    const res = await c.post('/api/v1/orgs', { name: 'x'.repeat(1_100_000) });
    expectError(res, 'LSE-VAL-002', 413);
  });

  it('non-JSON content type → LSE-VAL-003', async () => {
    const c = await login(app);
    const res = await c.agent
      .post('/api/v1/orgs')
      .set('x-csrf-token', c.csrf)
      .set('content-type', 'text/plain')
      .send('name=acme');
    expectError(res, 'LSE-VAL-003', 415);
  });

  it('thrown unknown error → LSE-SYS-001, secrets scrubbed from devMessage', async () => {
    for (const path of ['/api/v1/__test/boom', '/api/v1/__test/async-boom']) {
      const res = await request(app).get(path);
      expectError(res, 'LSE-SYS-001', 500);
      expect(res.body.error.devMessage).toContain('kaboom');
      expect(JSON.stringify(res.body)).not.toContain('SECRETSECRET');
      expect(JSON.stringify(res.body)).not.toMatch(/at .*\.ts:\d+/); // no stack traces
    }
  });

  it('production hides devMessage for 5xx but keeps it for 4xx', async () => {
    const res = await request(prod.app).get('/api/v1/__test/boom');
    expectError(res, 'LSE-SYS-001', 500);
    expect(res.body.error.devMessage).toBeUndefined();
    const notFound = await request(prod.app).get('/api/v1/missing');
    expectError(notFound, 'LSE-NF-001', 404);
    expect(notFound.body.error.devMessage).toBeDefined();
  });

  it('AppError keeps catalog metadata (LSE-SYS-006)', async () => {
    const res = await request(app).get('/api/v1/__test/kms');
    expectError(res, 'LSE-SYS-006', 500);
    expect(res.body.error.recoverable).toBe(false);
  });

  it('sets security headers suitable for an API', async () => {
    const res = await request(app).get('/healthz');
    expect(res.headers['content-security-policy']).toContain("default-src 'none'");
    expect(res.headers['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['referrer-policy']).toBe('no-referrer');
    expect(res.headers['permissions-policy']).toContain('camera=()');
    expect(res.headers['x-powered-by']).toBeUndefined();
  });
});
