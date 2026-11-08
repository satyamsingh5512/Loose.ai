import { createHash } from 'node:crypto';
import { http, HttpResponse } from 'msw';
import request from 'supertest';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { CSRF_HEADER, SESSION_COOKIE } from '@loose/shared';
import { SessionService } from '../src/services/session.service';
import {
  createMswServer,
  csrfFor,
  expectError,
  login,
  makeApp,
  onUnhandled,
  resetDb,
  testPrisma,
  uniqueEmail,
} from './helpers';

const OAUTH_ENV = {
  GOOGLE_CLIENT_ID: 'google-client-id',
  GOOGLE_CLIENT_SECRET: 'google-client-secret',
  GITHUB_CLIENT_ID: 'github-client-id',
  GITHUB_CLIENT_SECRET: 'github-client-secret',
};

const server = createMswServer();
const prisma = testPrisma();

function setCookies(res: request.Response): string[] {
  const raw = res.headers['set-cookie'] as unknown;
  return Array.isArray(raw) ? (raw as string[]) : typeof raw === 'string' ? [raw] : [];
}
function cookieLine(res: request.Response, name: string): string | undefined {
  return setCookies(res).find((c) => c.startsWith(`${name}=`));
}
function cookieValue(res: request.Response, name: string): string | undefined {
  return cookieLine(res, name)
    ?.split(';')[0]
    ?.slice(name.length + 1);
}

interface GoogleProfile {
  sub: string;
  email: string;
  email_verified?: boolean;
  name?: string;
}

/** Mock Google; checks the PKCE verifier matches the challenge sent at start. */
function mockGoogle(profile: GoogleProfile, expectedChallenge?: { value?: string }) {
  server.use(
    http.post('https://oauth2.googleapis.com/token', async ({ request: req }) => {
      const form = new URLSearchParams(await req.text());
      if (form.get('code') !== 'good-code')
        return HttpResponse.json({ error: 'invalid_grant' }, { status: 400 });
      const verifier = form.get('code_verifier') ?? '';
      if (expectedChallenge?.value) {
        const challenge = createHash('sha256').update(verifier).digest('base64url');
        if (challenge !== expectedChallenge.value) {
          return HttpResponse.json({ error: 'invalid_grant' }, { status: 400 });
        }
      }
      return HttpResponse.json({
        access_token: 'ya29.google-access-token-value',
        refresh_token: '1//google-refresh-token',
        expires_in: 3600,
        scope: 'openid email profile',
        token_type: 'Bearer',
      });
    }),
    http.get('https://openidconnect.googleapis.com/v1/userinfo', ({ request: req }) => {
      if (req.headers.get('authorization') !== 'Bearer ya29.google-access-token-value') {
        return HttpResponse.json({}, { status: 401 });
      }
      return HttpResponse.json({
        email_verified: true,
        name: 'G User',
        picture: 'https://img/x.png',
        ...profile,
      });
    }),
  );
}

function mockGithub(user: { id: number; login: string }, email: string) {
  server.use(
    http.post('https://github.com/login/oauth/access_token', async ({ request: req }) => {
      const body = (await req.json()) as { code?: string };
      if (body.code !== 'good-code') return HttpResponse.json({ error: 'bad_verification_code' });
      return HttpResponse.json({
        access_token: 'gho_githubaccesstoken0000000000000001',
        scope: 'repo,read:user,user:email',
        token_type: 'bearer',
      });
    }),
    http.get('https://api.github.com/user', () =>
      HttpResponse.json({ ...user, name: null, avatar_url: 'https://avatars/x' }),
    ),
    http.get('https://api.github.com/user/emails', () =>
      HttpResponse.json([
        { email: 'secondary@example.com', primary: false, verified: true },
        { email, primary: true, verified: true },
      ]),
    ),
  );
}

async function startOAuth(agent: ReturnType<typeof request.agent>, provider: string, query = '') {
  const res = await agent.get(`/api/v1/auth/${provider}${query}`);
  expect(res.status, JSON.stringify(res.body)).toBe(302);
  const location = new URL(res.headers.location as string);
  return { res, location, state: location.searchParams.get('state') ?? '' };
}

beforeAll(() => server.listen({ onUnhandledRequest: onUnhandled }));
afterEach(() => server.resetHandlers());
afterAll(async () => {
  server.close();
  await prisma.$disconnect();
});
beforeEach(() => resetDb());

describe('OAuth start', () => {
  const { app } = makeApp({ env: OAUTH_ENV });

  it('google: redirects with state + PKCE S256 and sets short-lived HttpOnly cookies', async () => {
    const { res, location, state } = await startOAuth(
      request.agent(app),
      'google',
      '?returnTo=/orgs',
    );
    expect(location.origin + location.pathname).toBe(
      'https://accounts.google.com/o/oauth2/v2/auth',
    );
    expect(location.searchParams.get('client_id')).toBe('google-client-id');
    expect(location.searchParams.get('redirect_uri')).toBe(
      'http://localhost:4000/api/v1/auth/google/callback',
    );
    expect(location.searchParams.get('code_challenge_method')).toBe('S256');
    expect(location.searchParams.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(state.length).toBeGreaterThanOrEqual(40);
    for (const name of ['loose_oauth_state', 'loose_oauth_verifier', 'loose_oauth_return_to']) {
      const line = cookieLine(res, name);
      expect(line, name).toBeDefined();
      expect(line).toMatch(/HttpOnly/i);
      expect(line).toMatch(/SameSite=Lax/i);
      expect(line).toMatch(/Max-Age=600/);
      expect(line).toMatch(/Path=\/api\/v1\/auth/);
    }
    expect(cookieValue(res, 'loose_oauth_state')).toBe(state);
    // The verifier itself is never sent to the provider.
    expect(location.toString()).not.toContain(cookieValue(res, 'loose_oauth_verifier'));
  });

  it('github: redirects with state and repo scopes (no PKCE)', async () => {
    const { location } = await startOAuth(request.agent(app), 'github');
    expect(location.host).toBe('github.com');
    expect(location.searchParams.get('scope')).toBe('read:user user:email repo');
    expect(location.searchParams.get('code_challenge')).toBeNull();
  });

  it('rejects unsafe returnTo (open redirect)', async () => {
    const res = await request(app).get('/api/v1/auth/google?returnTo=//evil.com');
    expectError(res, 'LSE-VAL-001', 400);
  });

  it('unconfigured provider → LSE-AUTH-004', async () => {
    const { app: bare } = makeApp();
    const res = await request(bare).get('/api/v1/auth/github');
    expectError(res, 'LSE-AUTH-004', 502);
    expect(res.body.error.devMessage).toContain('provider not configured');
  });
});

describe('OAuth callback', () => {
  const { app, ctx } = makeApp({ env: OAUTH_ENV });

  it('state mismatch → redirect with LSE-AUTH-002', async () => {
    const agent = request.agent(app);
    await startOAuth(agent, 'google');
    const res = await agent.get('/api/v1/auth/google/callback?code=good-code&state=not-the-state');
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe(
      'http://localhost:5173/auth/callback/google?error=LSE-AUTH-002',
    );
    expect(cookieLine(res, SESSION_COOKIE)).toBeUndefined();
  });

  it('missing state cookie → LSE-AUTH-002', async () => {
    const res = await request(app).get('/api/v1/auth/google/callback?code=good-code&state=abc');
    expect(res.headers.location).toContain('error=LSE-AUTH-002');
  });

  it('user cancelled → LSE-AUTH-003', async () => {
    const agent = request.agent(app);
    const { state } = await startOAuth(agent, 'google');
    const res = await agent.get(`/api/v1/auth/google/callback?error=access_denied&state=${state}`);
    expect(res.headers.location).toBe(
      'http://localhost:5173/auth/callback/google?error=LSE-AUTH-003',
    );
  });

  it('google success creates user, encrypted tokens and a secure session cookie', async () => {
    const agent = request.agent(app);
    const { state, location } = await startOAuth(agent, 'google', '?returnTo=/orgs/new');
    const email = uniqueEmail('google');
    mockGoogle(
      { sub: 'google-sub-1', email },
      { value: location.searchParams.get('code_challenge') ?? '' },
    );

    const res = await agent.get(`/api/v1/auth/google/callback?code=good-code&state=${state}`);
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('http://localhost:5173/orgs/new');
    const session = cookieLine(res, SESSION_COOKIE);
    expect(session).toBeDefined();
    expect(session).toMatch(/HttpOnly/i);
    expect(session).toMatch(/SameSite=Lax/i);
    expect(session).toMatch(/Path=\//);
    expect(session).not.toMatch(/Secure/i); // only in production
    const token = cookieValue(res, SESSION_COOKIE) ?? '';
    expect(token.length).toBeGreaterThanOrEqual(32);
    // DB stores sha256(token), never the token.
    expect(await prisma.authSession.findUnique({ where: { id: token } })).toBeNull();
    expect(
      await prisma.authSession.findUnique({ where: { id: SessionService.hashToken(token) } }),
    ).not.toBeNull();

    const me = await agent.get('/api/v1/auth/me');
    expect(me.status).toBe(200);
    expect(me.body.data).toMatchObject({ email, name: 'G User', linkedProviders: ['google'] });

    const account = await prisma.oAuthAccount.findFirstOrThrow({ where: { provider: 'google' } });
    expect(Buffer.from(account.accessTokenEnc).toString('latin1')).not.toContain('ya29');
    const user = await prisma.user.findUniqueOrThrow({ where: { email } });
    expect(user.googleId).toBe('google-sub-1');
    const audit = await prisma.auditLog.findFirst({
      where: { actorId: user.id, action: 'auth.sign_in' },
    });
    expect(audit).not.toBeNull();

    // Second sign-in with the same Google account reuses the user.
    const again = request.agent(app);
    const s2 = await startOAuth(again, 'google');
    mockGoogle({ sub: 'google-sub-1', email });
    await again.get(`/api/v1/auth/google/callback?code=good-code&state=${s2.state}`);
    expect(await prisma.user.count({ where: { email } })).toBe(1);
  });

  it('production: session cookie is Secure', async () => {
    const prod = makeApp({ env: { ...OAUTH_ENV, NODE_ENV: 'production' } });
    const start = await request(prod.app).get('/api/v1/auth/google');
    const state = new URL(start.headers.location as string).searchParams.get('state');
    const verifier = cookieValue(start, 'loose_oauth_verifier');
    expect(cookieLine(start, 'loose_oauth_state')).toMatch(/Secure/i);
    mockGoogle({ sub: 'google-sub-prod', email: uniqueEmail('prod') });
    const res = await request(prod.app)
      .get(`/api/v1/auth/google/callback?code=good-code&state=${state}`)
      .set('Cookie', `loose_oauth_state=${state}; loose_oauth_verifier=${verifier}`);
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('http://localhost:5173/');
    expect(cookieLine(res, SESSION_COOKIE)).toMatch(/Secure/i);
  });

  it('unverified google email → LSE-AUTH-002', async () => {
    const agent = request.agent(app);
    const { state } = await startOAuth(agent, 'google');
    mockGoogle({ sub: 'unverified', email: uniqueEmail(), email_verified: false });
    const res = await agent.get(`/api/v1/auth/google/callback?code=good-code&state=${state}`);
    expect(res.headers.location).toContain('error=LSE-AUTH-002');
  });

  it('bad code (token exchange rejected) → LSE-AUTH-002', async () => {
    const agent = request.agent(app);
    const { state } = await startOAuth(agent, 'google');
    mockGoogle({ sub: 'x', email: uniqueEmail() });
    const res = await agent.get(`/api/v1/auth/google/callback?code=bad-code&state=${state}`);
    expect(res.headers.location).toContain('error=LSE-AUTH-002');
  });

  it('provider 5xx → LSE-AUTH-004', async () => {
    const agent = request.agent(app);
    const { state } = await startOAuth(agent, 'google');
    server.use(
      http.post(
        'https://oauth2.googleapis.com/token',
        () => new HttpResponse(null, { status: 503 }),
      ),
    );
    const res = await agent.get(`/api/v1/auth/google/callback?code=good-code&state=${state}`);
    expect(res.headers.location).toContain('error=LSE-AUTH-004');
  });

  it('email already used by another sign-in method → LSE-AUTH-005', async () => {
    const email = uniqueEmail('collide');
    await login(app, email); // existing user (no google account)
    const agent = request.agent(app);
    const { state } = await startOAuth(agent, 'google');
    mockGoogle({ sub: 'google-sub-collide', email });
    const res = await agent.get(`/api/v1/auth/google/callback?code=good-code&state=${state}`);
    expect(res.headers.location).toBe(
      'http://localhost:5173/auth/callback/google?error=LSE-AUTH-005',
    );
    expect(cookieLine(res, SESSION_COOKIE)).toBeUndefined();
    expect(
      await prisma.oAuthAccount.count({ where: { providerAccountId: 'google-sub-collide' } }),
    ).toBe(0);
  });

  it('github sign-in uses the primary verified email', async () => {
    const agent = request.agent(app);
    const { state } = await startOAuth(agent, 'github');
    const email = uniqueEmail('gh');
    mockGithub({ id: 4242, login: 'octo' }, email);
    const res = await agent.get(`/api/v1/auth/github/callback?code=good-code&state=${state}`);
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('http://localhost:5173/');
    const me = await agent.get('/api/v1/auth/me');
    expect(me.body.data).toMatchObject({ email, name: 'octo', linkedProviders: ['github'] });
    const account = await prisma.oAuthAccount.findFirstOrThrow({ where: { provider: 'github' } });
    expect(account.scopes).toEqual(expect.arrayContaining(['repo', 'read:user', 'user:email']));
    expect(await ctx.crypto.decryptPackedString(account.accessTokenEnc, 'oauth-token')).toBe(
      'gho_githubaccesstoken0000000000000001',
    );
  });

  it('github ?link=1 links GitHub to the signed-in user', async () => {
    const c = await login(app);
    const { res: start, state } = await startOAuth(c.agent, 'github', '?link=1&returnTo=/settings');
    expect(cookieLine(start, 'loose_oauth_link')).toBeDefined();
    mockGithub({ id: 777, login: 'linker' }, uniqueEmail('other-email'));
    const res = await c.agent.get(`/api/v1/auth/github/callback?code=good-code&state=${state}`);
    expect(res.headers.location).toBe('http://localhost:5173/settings');
    const me = await c.get('/api/v1/auth/me');
    expect(me.body.data.linkedProviders).toEqual(['github']);
    expect((await prisma.user.findUniqueOrThrow({ where: { id: c.user.id } })).githubId).toBe(
      '777',
    );
    expect(await prisma.user.count()).toBe(1);
  });

  it('link=1 without a session → LSE-AUTH-001 redirect', async () => {
    const res = await request(app).get('/api/v1/auth/github?link=1');
    expect(res.headers.location).toBe(
      'http://localhost:5173/auth/callback/github?error=LSE-AUTH-001',
    );
  });
});

describe('sessions', () => {
  const { app } = makeApp();

  it('/auth/me: 401 without a session, 200 with one', async () => {
    expectError(await request(app).get('/api/v1/auth/me'), 'LSE-AUTH-001', 401);
    const c = await login(app, uniqueEmail('me'), 'Me');
    const res = await c.get('/api/v1/auth/me');
    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({
      email: c.user.email,
      name: 'Me',
      preferredMode: 'SIMPLE',
      linkedProviders: [],
    });
  });

  it('logout invalidates the session; reusing the cookie → 401', async () => {
    const csrfRes = await request(app).get('/api/v1/auth/csrf');
    const csrf = csrfRes.body.data.csrfToken as string;
    const signIn = await request(app)
      .post('/api/v1/auth/dev-login')
      .set('Cookie', `loose_csrf=${csrf}`)
      .set(CSRF_HEADER, csrf)
      .send({ email: uniqueEmail('logout') });
    const token = cookieValue(signIn, SESSION_COOKIE) ?? '';
    expect(token).not.toBe('');
    const cookies = `${SESSION_COOKIE}=${token}; loose_csrf=${csrf}`;
    expect((await request(app).get('/api/v1/auth/me').set('Cookie', cookies)).status).toBe(200);

    const out = await request(app)
      .post('/api/v1/auth/logout')
      .set('Cookie', cookies)
      .set(CSRF_HEADER, csrf);
    expect(out.status).toBe(200);
    expect(out.body).toEqual({ data: { ok: true } });
    expect(cookieLine(out, SESSION_COOKIE)).toMatch(/Expires=Thu, 01 Jan 1970/);
    expect(await prisma.authSession.count()).toBe(0);

    const replay = await request(app).get('/api/v1/auth/me').set('Cookie', cookies);
    expectError(replay, 'LSE-AUTH-001', 401);
  });

  it('logout-all ends every session of the user', async () => {
    const email = uniqueEmail('multi');
    const a = await login(app, email);
    const b = await login(app, email);
    expect((await a.get('/api/v1/auth/sessions')).body.data).toHaveLength(2);
    expect((await a.post('/api/v1/auth/logout-all')).status).toBe(200);
    expectError(await a.get('/api/v1/auth/me'), 'LSE-AUTH-001', 401);
    expectError(await b.get('/api/v1/auth/me'), 'LSE-AUTH-001', 401);
  });

  it('GET /auth/sessions marks the current session and hides full ids', async () => {
    const c = await login(app);
    const res = await c.get('/api/v1/auth/sessions');
    expect(res.status).toBe(200);
    expect(res.body.data[0]).toMatchObject({ current: true });
    expect(res.body.data[0].id).toHaveLength(16);
  });

  it('expired session → 401 and row removed', async () => {
    const c = await login(app);
    await prisma.authSession.updateMany({ data: { expiresAt: new Date(Date.now() - 1000) } });
    expectError(await c.get('/api/v1/auth/me'), 'LSE-AUTH-001', 401);
    expect(await prisma.authSession.count()).toBe(0);
  });

  it('sliding renewal extends sessions with < 15 days left', async () => {
    const user = await prisma.user.create({ data: { email: uniqueEmail('slide') } });
    let now = new Date('2026-01-01T00:00:00Z');
    const svc = new SessionService(prisma, () => now);
    const { token, session } = await svc.create(user.id);
    expect(session.expiresAt.toISOString()).toBe('2026-01-31T00:00:00.000Z');
    now = new Date('2026-01-10T00:00:00Z'); // 21 days left
    expect((await svc.validate(token))?.fresh).toBe(false);
    now = new Date('2026-01-20T00:00:00Z'); // 11 days left
    const renewed = await svc.validate(token);
    expect(renewed?.fresh).toBe(true);
    expect(renewed?.session.expiresAt.toISOString()).toBe('2026-02-19T00:00:00.000Z');
    now = new Date('2026-03-01T00:00:00Z');
    expect(await svc.validate(token)).toBeNull();
    expect(await svc.validate('not a token')).toBeNull();
  });
});

describe('CSRF', () => {
  const { app } = makeApp();

  it('state-changing request without x-csrf-token → 403 LSE-AUTH-002', async () => {
    const c = await login(app);
    const res = await c.agent.post('/api/v1/orgs').send({ name: 'Acme' });
    expectError(res, 'LSE-AUTH-002', 403);
  });

  it('mismatched token → 403', async () => {
    const c = await login(app);
    const res = await c.agent
      .post('/api/v1/orgs')
      .set(CSRF_HEADER, `${c.csrf}x`)
      .send({ name: 'Acme' });
    expectError(res, 'LSE-AUTH-002', 403);
  });

  it('forged (unsigned) cookie + matching header → 403', async () => {
    const res = await request(app)
      .post('/api/v1/auth/dev-login')
      .set('Cookie', 'loose_csrf=forged.value')
      .set(CSRF_HEADER, 'forged.value')
      .send({ email: uniqueEmail() });
    expectError(res, 'LSE-AUTH-002', 403);
  });

  it('GET issues a readable csrf cookie', async () => {
    const res = await request(app).get('/api/v1/auth/csrf');
    const line = cookieLine(res, 'loose_csrf');
    expect(line).toBeDefined();
    expect(line).not.toMatch(/HttpOnly/i);
    expect(line).toMatch(/SameSite=Lax/i);
    expect(cookieValue(res, 'loose_csrf')).toBe(res.body.data.csrfToken);
  });
});

describe('dev login gating', () => {
  async function postDevLogin(app: ReturnType<typeof makeApp>['app']) {
    const csrfRes = await request(app).get('/api/v1/auth/csrf');
    const token = csrfRes.body.data.csrfToken as string;
    return request(app)
      .post('/api/v1/auth/dev-login')
      .set('Cookie', `loose_csrf=${token}`)
      .set(CSRF_HEADER, token)
      .send({ email: uniqueEmail() });
  }

  it('is NOT mounted in production even when DEV_LOGIN_ENABLED=true', async () => {
    const { app } = makeApp({ env: { NODE_ENV: 'production', DEV_LOGIN_ENABLED: 'true' } });
    expectError(await postDevLogin(app), 'LSE-NF-001', 404);
    expect(await prisma.user.count()).toBe(0);
  });

  it('is not mounted when DEV_LOGIN_ENABLED is false', async () => {
    const { app } = makeApp({ env: { DEV_LOGIN_ENABLED: 'false' } });
    expectError(await postDevLogin(app), 'LSE-NF-001', 404);
  });

  it('works in development when enabled', async () => {
    const { app } = makeApp();
    const res = await postDevLogin(app);
    expect(res.status).toBe(200);
    expect(cookieLine(res, SESSION_COOKIE)).toBeDefined();
  });
});

describe('auth rate limiting', () => {
  it('more than RATE_LIMIT_AUTH_MAX attempts/min per IP → 429 LSE-AUTH-008 with Retry-After', async () => {
    const { app } = makeApp({ env: { RATE_LIMIT_AUTH_MAX: '3' } });
    for (let i = 0; i < 3; i++) {
      const res = await request(app).get('/api/v1/auth/google');
      expect(res.status).toBe(502); // not configured, but counted
    }
    const limited = await request(app).get('/api/v1/auth/google');
    expectError(limited, 'LSE-AUTH-008', 429);
    expect(Number(limited.headers['retry-after'])).toBeGreaterThan(0);
    expect(limited.body.error.retryable).toBe(true);
  });

  it('defaults to 20/min', async () => {
    const { app } = makeApp({ env: { RATE_LIMIT_AUTH_MAX: undefined } });
    const agent = request.agent(app);
    const csrf = await csrfFor(agent);
    let last: request.Response | undefined;
    for (let i = 0; i < 21; i++) {
      last = await agent
        .post('/api/v1/auth/dev-login')
        .set(CSRF_HEADER, csrf)
        .send({ email: uniqueEmail() });
    }
    expectError(last as request.Response, 'LSE-AUTH-008', 429);
  });
});
