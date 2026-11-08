/**
 * Regression tests for issues raised in the Phase 1–2 security audit.
 */
import { randomBytes } from 'node:crypto';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { SESSION_COOKIE } from '@loose/shared';
import { expectError, login, makeApp, resetDb, testPrisma } from './helpers';

beforeAll(async () => {
  await resetDb();
});
afterAll(async () => {
  await testPrisma().$disconnect();
});

describe('general rate limit cannot be bypassed with rotating credentials', () => {
  it('random session cookies from one IP share the IP bucket', async () => {
    const { app } = makeApp({ env: { RATE_LIMIT_GENERAL_MAX: '5' } });
    const statuses: number[] = [];
    for (let i = 0; i < 8; i++) {
      const res = await request(app)
        .get('/api/v1/auth/me')
        .set('Cookie', `${SESSION_COOKIE}=${randomBytes(20).toString('hex')}`);
      statuses.push(res.status);
    }
    expect(statuses.slice(0, 5).every((s) => s === 401)).toBe(true);
    expect(statuses.slice(5).every((s) => s === 429)).toBe(true);
  });

  it('random bearer tokens from one IP share the IP bucket', async () => {
    const { app } = makeApp({ env: { RATE_LIMIT_GENERAL_MAX: '5' } });
    let last: request.Response | undefined;
    for (let i = 0; i < 7; i++) {
      last = await request(app)
        .get('/api/v1/users/me')
        .set('Authorization', `Bearer loose_pat_${randomBytes(16).toString('hex')}`);
    }
    expectError(last!, 'LSE-RATE-001', 429);
  });
});

describe('Authorization header never falls back to the cookie session', () => {
  it('logout with a junk Bearer + session cookie and no CSRF is rejected and keeps the session', async () => {
    const { app } = makeApp();
    const c = await login(app);
    const res = await c.agent
      .post('/api/v1/auth/logout')
      .set('Authorization', 'Bearer junk')
      .send({});
    expectError(res, 'LSE-AUTH-002', 403);
    expect((await c.get('/api/v1/auth/me')).status).toBe(200);
  });

  it('a well-formed PAT skips CSRF but does not act on the cookie session', async () => {
    const { app } = makeApp();
    const c = await login(app);
    const res = await c.agent
      .post('/api/v1/auth/logout')
      .set('Authorization', `Bearer loose_pat_${randomBytes(16).toString('hex')}`)
      .send({});
    expect(res.status).toBe(200);
    // The cookie session was not invalidated server-side.
    expect(await testPrisma().authSession.count({ where: { userId: c.user.id } })).toBe(1);
  });

  it('cookie-authenticated state change still requires CSRF', async () => {
    const { app } = makeApp();
    const c = await login(app);
    expectError(await c.agent.post('/api/v1/orgs').send({ name: 'No CSRF' }), 'LSE-AUTH-002', 403);
    expect((await c.post('/api/v1/orgs', { name: 'With CSRF' })).status).toBe(201);
  });
});
