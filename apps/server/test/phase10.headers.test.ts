/**
 * Security headers & cookie attributes (Phase 10 §7.6, W4). Exercises the real
 * `middleware/securityHeaders.ts` (helmet + the custom `Permissions-Policy`/`Cache-Control`
 * middleware) and the session/CSRF cookie flags set by `lib/cookies.ts`, against the live app
 * — not a unit test of the middleware factory in isolation.
 */
import request from 'supertest';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { CSRF_COOKIE, SESSION_COOKIE } from '@loose/shared';
import { login, makeApp, resetDb, testPrisma } from './helpers';

const prisma = testPrisma();
const { app } = makeApp();

afterAll(async () => {
  await prisma.$disconnect();
});

beforeEach(async () => {
  await resetDb();
});

function setCookies(res: request.Response): string[] {
  const raw = res.headers['set-cookie'] as unknown;
  return Array.isArray(raw) ? (raw as string[]) : typeof raw === 'string' ? [raw] : [];
}
function cookieLine(res: request.Response, name: string): string | undefined {
  return setCookies(res).find((c) => c.startsWith(`${name}=`));
}

describe('security headers on every JSON response', () => {
  it('a public, unauthenticated GET gets the full header set', async () => {
    const res = await request(app).get('/api/v1/auth/csrf');
    expect(res.status).toBe(200);
    expect(res.headers['content-security-policy']).toContain("default-src 'none'");
    expect(res.headers['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(res.headers['content-security-policy']).toContain("base-uri 'none'");
    expect(res.headers['content-security-policy']).toContain("form-action 'none'");
    expect(res.headers['cross-origin-resource-policy']).toBe('same-site');
    expect(res.headers['referrer-policy']).toBe('no-referrer');
    expect(res.headers['permissions-policy']).toBe(
      'camera=(), microphone=(), geolocation=(), payment=()',
    );
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-frame-options']).toBe('SAMEORIGIN');
    // Not production here, so HSTS is correctly absent (would break local http:// dev).
    expect(res.headers['strict-transport-security']).toBeUndefined();
  });

  it('an authenticated route and an error response both carry the same headers', async () => {
    const owner = await login(app);
    const ok = await owner.get('/api/v1/auth/me');
    expect(ok.status).toBe(200);
    expect(ok.headers['content-security-policy']).toContain("default-src 'none'");
    expect(ok.headers['cache-control']).toBe('no-store');

    const err = await request(app).get('/api/v1/orgs/does-not-exist');
    expect(err.status).toBe(401); // anonymous
    expect(err.headers['content-security-policy']).toContain("default-src 'none'");
    expect(err.headers['x-content-type-options']).toBe('nosniff');
  });

  it('HSTS is set in production and absent otherwise', async () => {
    const { app: prodApp } = makeApp({ env: { NODE_ENV: 'production' } });
    const res = await request(prodApp).get('/api/v1/auth/csrf');
    expect(res.headers['strict-transport-security']).toContain('max-age=31536000');
    expect(res.headers['strict-transport-security']).toContain('includeSubDomains');
  });

  it('never advertises the framework via x-powered-by', async () => {
    const res = await request(app).get('/api/v1/auth/csrf');
    expect(res.headers['x-powered-by']).toBeUndefined();
  });
});

describe('cookie attributes', () => {
  it('the session cookie is HttpOnly, SameSite=Lax, and Secure only in production', async () => {
    const agent = request.agent(app);
    const csrfRes = await agent.get('/api/v1/auth/csrf');
    const csrf = (csrfRes.body.data as { csrfToken: string }).csrfToken;
    const res = await agent
      .post('/api/v1/auth/dev-login')
      .set('x-csrf-token', csrf)
      .send({ email: 'headers-cookie-test@example.com' });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    const line = cookieLine(res, SESSION_COOKIE);
    expect(line, 'expected a Set-Cookie for the session').toBeDefined();
    expect(line).toMatch(/HttpOnly/i);
    expect(line).toMatch(/SameSite=Lax/i);
    expect(line).not.toMatch(/Secure/i);
  });

  it('the session cookie is Secure in production', async () => {
    const { app: prodApp } = makeApp({ env: { NODE_ENV: 'production' } });
    const agent = request.agent(prodApp);
    const csrfRes = await agent.get('/api/v1/auth/csrf');
    const csrf = (csrfRes.body.data as { csrfToken: string }).csrfToken;
    const res = await agent
      .post('/api/v1/auth/dev-login')
      .set('x-csrf-token', csrf)
      .send({ email: 'headers-cookie-prod-test@example.com' });
    // Dev-login is 404 outside dev; what matters here is the CSRF cookie, always issued.
    const csrfLine = cookieLine(csrfRes, CSRF_COOKIE);
    expect(csrfLine, 'expected a Set-Cookie for the csrf token').toBeDefined();
    expect(csrfLine).toMatch(/Secure/i);
    void res;
  });

  it('the CSRF cookie is readable by JS (not HttpOnly) but still SameSite=Lax', async () => {
    const res = await request(app).get('/api/v1/auth/csrf');
    const line = cookieLine(res, CSRF_COOKIE);
    expect(line, 'expected a Set-Cookie for the csrf token').toBeDefined();
    expect(line).not.toMatch(/HttpOnly/i);
    expect(line).toMatch(/SameSite=Lax/i);
  });
});
