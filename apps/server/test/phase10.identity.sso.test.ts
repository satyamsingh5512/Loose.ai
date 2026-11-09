/**
 * Phase 10 / W1 — org SSO (OIDC): connection CRUD (secret never returned), verified domains
 * (DNS TXT, LSE-ORG-011), discovery by email, the authorization-code + PKCE round trip, ID-token
 * verification failures (tampered / expired / wrong audience / wrong nonce / wrong issuer /
 * unaccepted alg / unknown kid), state replay, JIT provisioning, key rotation, and enforce-SSO
 * (LSE-AUTH-006) including the owner break-glass.
 */
import request from 'supertest';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import type { RequestHandler } from 'msw';
import { API_PREFIX, SSO_STATE_COOKIE } from '@loose/shared';
import { invalidateOrgSecurityCache } from '../src/services/identity/accessPolicy';
import { mswFetch } from './agentHelpers';
import {
  addMember,
  createOrg,
  expectError,
  login,
  makeApp,
  resetDb,
  testPrisma,
  type Client,
} from './helpers';
import {
  authorizeParams,
  createFakeDns,
  createMockIdp,
  IDP_CLIENT_ID,
  IDP_CLIENT_SECRET,
  IDP_ISSUER,
  makeEcKey,
  makeIdToken,
  makeRsaKey,
} from './phase10.identityHelpers';

const prisma = testPrisma();
const handlers: { current: RequestHandler[] } = { current: [] };
const dns = createFakeDns();
const { app, ctx } = makeApp({ context: { fetch: mswFetch(handlers), dns } });

const rsa = makeRsaKey('rsa-1');
const ec = makeEcKey('ec-1');
let idp = createMockIdp([rsa]);

const DOMAIN = 'acme.test';

afterAll(async () => {
  await ctx.jobs.onIdle();
  await prisma.$disconnect();
});

beforeEach(async () => {
  await resetDb(prisma);
  invalidateOrgSecurityCache(ctx);
  dns.txt.clear();
  idp = createMockIdp([rsa]);
  handlers.current = idp.handlers();
});

interface World {
  owner: Client;
  org: { id: string; slug: string };
}

let orgSeq = 0;
async function world(ownerEmail = `owner@${DOMAIN}`, name?: string): Promise<World> {
  orgSeq += 1;
  const owner = await login(app, ownerEmail);
  const org = await createOrg(owner, name ?? `Acme ${orgSeq}`);
  return { owner, org };
}

function identityUrl(orgId: string, path = ''): string {
  return `${API_PREFIX}/orgs/${orgId}/identity${path}`;
}

async function addVerifiedDomain(w: World, domain = DOMAIN): Promise<string> {
  const created = await w.owner.post(identityUrl(w.org.id, '/domains'), { domain });
  expect(created.status, JSON.stringify(created.body)).toBe(201);
  const dto = created.body.data as {
    id: string;
    verificationRecord: { name: string; value: string };
  };
  dns.txt.set(dto.verificationRecord.name, [[dto.verificationRecord.value]]);
  const verified = await w.owner.post(identityUrl(w.org.id, `/domains/${dto.id}/verify`));
  expect(verified.status, JSON.stringify(verified.body)).toBe(200);
  expect(verified.body.data.verified).toBe(true);
  return dto.id;
}

async function configureSso(
  w: World,
  overrides: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const res = await w.owner.put(identityUrl(w.org.id, '/sso'), {
    protocol: 'OIDC',
    issuer: IDP_ISSUER,
    clientId: IDP_CLIENT_ID,
    clientSecret: IDP_CLIENT_SECRET,
    enabled: true,
    ...overrides,
  });
  expect(res.status, JSON.stringify(res.body)).toBe(200);
  invalidateOrgSecurityCache(ctx);
  return res.body.data as Record<string, unknown>;
}

interface SignInResult {
  agent: ReturnType<typeof request.agent>;
  callback: request.Response;
  params: URLSearchParams;
}

async function startFlow(slug: string) {
  const agent = request.agent(app);
  const start = await agent.get(`${API_PREFIX}/auth/sso/${slug}/start?returnTo=/dashboard`);
  expect(start.status, JSON.stringify(start.body)).toBe(302);
  return { agent, start, params: authorizeParams(start.headers.location as string) };
}

async function signIn(
  slug: string,
  token: (nonce: string) => string,
  opts: { code?: string } = {},
): Promise<SignInResult> {
  const { agent, params } = await startFlow(slug);
  idp.nextIdToken = token(params.get('nonce') as string);
  const state = encodeURIComponent(params.get('state') as string);
  const callback = await agent.get(
    `${API_PREFIX}/auth/sso/${slug}/callback?code=${opts.code ?? 'auth-code-1'}&state=${state}`,
  );
  return { agent, callback, params };
}

function errorOf(res: request.Response): string | null {
  const location = res.headers.location as string | undefined;
  if (!location) return null;
  return new URL(location, 'http://localhost').searchParams.get('error');
}

// ---------------------------------------------------------------------------------------------

describe('verified org domains', () => {
  it('creates a pending domain and verifies it from the DNS TXT record', async () => {
    const w = await world();
    const created = await w.owner.post(identityUrl(w.org.id, '/domains'), { domain: 'ACME.test' });
    expect(created.status).toBe(201);
    expect(created.body.data).toMatchObject({
      domain: 'acme.test',
      verified: false,
      verificationRecord: { type: 'TXT', name: '_loose-verification.acme.test' },
    });
    expect(created.body.data.verificationRecord.value).toMatch(/^loose-verify=/);

    // No record yet → LSE-ORG-011.
    const tooEarly = await w.owner.post(
      identityUrl(w.org.id, `/domains/${created.body.data.id}/verify`),
    );
    expectError(tooEarly, 'LSE-ORG-011', 422);

    // Wrong token → still LSE-ORG-011.
    dns.txt.set('_loose-verification.acme.test', [['loose-verify=not-the-token']]);
    expectError(
      await w.owner.post(identityUrl(w.org.id, `/domains/${created.body.data.id}/verify`)),
      'LSE-ORG-011',
      422,
    );

    dns.txt.set('_loose-verification.acme.test', [
      [created.body.data.verificationRecord.value as string],
    ]);
    const ok = await w.owner.post(identityUrl(w.org.id, `/domains/${created.body.data.id}/verify`));
    expect(ok.status).toBe(200);
    expect(ok.body.data.verified).toBe(true);

    const list = await w.owner.get(identityUrl(w.org.id, '/domains'));
    expect(list.body.data).toHaveLength(1);
  });

  it('refuses a domain already verified by another org and allows deleting it', async () => {
    const first = await world(`first@${DOMAIN}`);
    await addVerifiedDomain(first);
    const second = await world(`second@other.test`);
    const res = await second.owner.post(identityUrl(second.org.id, '/domains'), {
      domain: DOMAIN,
    });
    expectError(res, 'LSE-ORG-011', 422);

    const domains = await first.owner.get(identityUrl(first.org.id, '/domains'));
    const id = domains.body.data[0].id as string;
    expect((await first.owner.delete(identityUrl(first.org.id, `/domains/${id}`))).status).toBe(
      204,
    );
    // Now the second org may claim it.
    expect(
      (await second.owner.post(identityUrl(second.org.id, '/domains'), { domain: DOMAIN })).status,
    ).toBe(201);
  });

  it('only lets admins manage domains and never accepts an API token', async () => {
    const w = await world();
    const member = await login(app, `member@${DOMAIN}`);
    await addMember(w.org.id, member.user.id, 'MEMBER');
    expectError(await member.get(identityUrl(w.org.id, '/domains')), 'LSE-ORG-002', 403);

    const token = await w.owner.post(`${API_PREFIX}/users/me/tokens`, {
      name: 'ro',
      orgId: w.org.id,
      scopes: ['org:read'],
    });
    expect(token.status).toBe(201);
    const res = await request(app)
      .get(identityUrl(w.org.id, '/domains'))
      .set('authorization', `Bearer ${token.body.data.token as string}`);
    expectError(res, 'LSE-AUTH-001', 401);
  });
});

describe('SSO connection settings', () => {
  it('stores the connection without ever returning the client secret', async () => {
    const w = await world();
    const dto = await configureSso(w);
    expect(dto).toMatchObject({
      protocol: 'OIDC',
      issuer: IDP_ISSUER,
      clientId: IDP_CLIENT_ID,
      hasClientSecret: true,
      enabled: true,
      enforce: false,
      defaultRole: 'MEMBER',
      jitProvisioning: true,
      allowOwnerBypass: true,
    });
    expect(dto.redirectUri).toBe(
      `http://localhost:4000${API_PREFIX}/auth/sso/${w.org.slug}/callback`,
    );
    expect(JSON.stringify(dto)).not.toContain(IDP_CLIENT_SECRET);

    const read = await w.owner.get(identityUrl(w.org.id, '/sso'));
    expect(read.status).toBe(200);
    expect(JSON.stringify(read.body)).not.toContain(IDP_CLIENT_SECRET);
    expect(read.body.data.hasClientSecret).toBe(true);

    // Audit entries never carry the secret either.
    const audit = await prisma.auditLog.findMany({ where: { action: 'sso.update' } });
    expect(audit).toHaveLength(1);
    expect(JSON.stringify(audit[0]?.meta)).not.toContain(IDP_CLIENT_SECRET);
  });

  it('omitting clientSecret keeps the stored one; a plain-http issuer is refused', async () => {
    const w = await world();
    await configureSso(w);
    const again = await w.owner.put(identityUrl(w.org.id, '/sso'), {
      protocol: 'OIDC',
      issuer: IDP_ISSUER,
      clientId: IDP_CLIENT_ID,
      enabled: true,
      enforce: true,
    });
    expect(again.status).toBe(200);
    expect(again.body.data).toMatchObject({ hasClientSecret: true, enforce: true });

    expectError(
      await w.owner.put(identityUrl(w.org.id, '/sso'), {
        protocol: 'OIDC',
        issuer: 'http://idp.example.test',
        clientId: 'x',
        clientSecret: 'y',
        enabled: false,
      }),
      'LSE-VAL-001',
      400,
    );
  });

  it('refuses to enable a connection whose discovery document is broken', async () => {
    const w = await world();
    idp.discoveryStatus = 500;
    const res = await w.owner.put(identityUrl(w.org.id, '/sso'), {
      protocol: 'OIDC',
      issuer: IDP_ISSUER,
      clientId: IDP_CLIENT_ID,
      clientSecret: IDP_CLIENT_SECRET,
      enabled: true,
    });
    expectError(res, 'LSE-AUTH-004', 502);
  });

  it('reports discovery + JWKS health from /sso/test and deletes the connection', async () => {
    const w = await world();
    await configureSso(w);
    const ok = await w.owner.post(identityUrl(w.org.id, '/sso/test'));
    expect(ok.status).toBe(200);
    expect(ok.body.data.ok).toBe(true);
    expect(ok.body.data.checks.map((c: { name: string }) => c.name)).toEqual([
      'discovery',
      'token_endpoint',
      'jwks',
    ]);

    idp.discoveryStatus = 404;
    const bad = await w.owner.post(identityUrl(w.org.id, '/sso/test'));
    expect(bad.status).toBe(200);
    expect(bad.body.data.ok).toBe(false);

    expect((await w.owner.delete(identityUrl(w.org.id, '/sso'))).status).toBe(204);
    expect((await w.owner.get(identityUrl(w.org.id, '/sso'))).body.data).toBeNull();
  });

  it('SAML is accepted by the DTO but gated behind the sso_saml flag (LSE-SYS-007)', async () => {
    const w = await world();
    const res = await w.owner.put(identityUrl(w.org.id, '/sso'), {
      protocol: 'SAML',
      entityId: 'urn:acme:idp',
      ssoUrl: 'https://203.0.113.10/saml/sso',
      certificate: 'x'.repeat(100),
      enabled: true,
    });
    expectError(res, 'LSE-SYS-007', 503);
    // (the ACS endpoint is a cross-site POST in production; here the CSRF-carrying client is
    // used so the assertion sees the feature gate rather than the CSRF check)
    const acs = await w.owner.post(`${API_PREFIX}/auth/sso/${w.org.slug}/saml/acs`);
    expectError(acs, 'LSE-SYS-007', 503);
  });

  it('admins (not members) read the settings; only owners may change them', async () => {
    const w = await world();
    const admin = await login(app, `admin@${DOMAIN}`);
    await addMember(w.org.id, admin.user.id, 'ADMIN');
    expect((await admin.get(identityUrl(w.org.id, '/sso'))).status).toBe(200);
    expectError(
      await admin.put(identityUrl(w.org.id, '/sso'), {
        protocol: 'OIDC',
        issuer: IDP_ISSUER,
        clientId: 'x',
        clientSecret: 'y',
        enabled: false,
      }),
      'LSE-ORG-002',
      403,
    );
  });
});

describe('SSO discovery by email', () => {
  it('returns the org only for verified domains of an enabled connection', async () => {
    const w = await world();
    const before = await request(app).get(
      `${API_PREFIX}/auth/sso/discover?email=someone@${DOMAIN}`,
    );
    expect(before.status).toBe(200);
    expect(before.body.data).toMatchObject({ sso: false, orgSlug: null, startUrl: null });

    await addVerifiedDomain(w);
    await configureSso(w, { enforce: true });
    const after = await request(app).get(`${API_PREFIX}/auth/sso/discover?email=SOMEONE@ACME.test`);
    expect(after.body.data).toMatchObject({
      sso: true,
      orgSlug: w.org.slug,
      protocol: 'OIDC',
      enforced: true,
      startUrl: `${API_PREFIX}/auth/sso/${w.org.slug}/start`,
    });
    // Unrelated domains leak nothing.
    const other = await request(app).get(`${API_PREFIX}/auth/sso/discover?email=x@other.test`);
    expect(other.body.data.sso).toBe(false);
    expectError(
      await request(app).get(`${API_PREFIX}/auth/sso/discover?email=nope`),
      'LSE-VAL-001',
    );
  });
});

describe('SSO sign-in', () => {
  it('runs the authorization-code + PKCE flow and provisions the user (JIT)', async () => {
    const w = await world();
    await addVerifiedDomain(w);
    await configureSso(w);

    const { agent, params } = await startFlow(w.org.slug);
    expect(params.get('response_type')).toBe('code');
    expect(params.get('client_id')).toBe(IDP_CLIENT_ID);
    expect(params.get('code_challenge_method')).toBe('S256');
    expect(params.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(params.get('scope')).toBe('openid email profile');
    expect(params.get('redirect_uri')).toBe(
      `http://localhost:4000${API_PREFIX}/auth/sso/${w.org.slug}/callback`,
    );
    const nonce = params.get('nonce') as string;
    const state = params.get('state') as string;
    expect(nonce).not.toBe(state);

    idp.nextIdToken = makeIdToken({ key: rsa, nonce, name: 'Sso User' });
    const callback = await agent.get(
      `${API_PREFIX}/auth/sso/${w.org.slug}/callback?code=code-1&state=${encodeURIComponent(state)}`,
    );
    expect(callback.status, JSON.stringify(callback.body)).toBe(302);
    expect(callback.headers.location).toBe('http://localhost:5173/dashboard');

    // PKCE verifier and client authentication reached the IdP.
    const tokenCall = idp.tokenRequests.at(0);
    expect(tokenCall?.body.grant_type).toBe('authorization_code');
    expect(tokenCall?.body.code).toBe('code-1');
    expect(tokenCall?.body.code_verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(tokenCall?.authorization).toMatch(/^Basic /);

    const me = await agent.get(`${API_PREFIX}/auth/me`);
    expect(me.status).toBe(200);
    expect(me.body.data.email).toBe('sso-user@acme.test');
    expect(me.body.data.name).toBe('Sso User');

    const member = await prisma.orgMember.findFirst({
      where: { orgId: w.org.id, user: { email: 'sso-user@acme.test' } },
    });
    expect(member?.role).toBe('MEMBER');
    const session = await prisma.authSession.findFirst({
      where: { user: { email: 'sso-user@acme.test' } },
    });
    expect(session?.ssoOrgId).toBe(w.org.id);
    const audit = await prisma.auditLog.findFirst({ where: { action: 'auth.sso_sign_in' } });
    expect(audit?.orgId).toBe(w.org.id);
  });

  it('links an existing *member* by verified-domain email and reuses it on the next sign-in', async () => {
    const w = await world();
    await addVerifiedDomain(w);
    await configureSso(w, { defaultRole: 'ADMIN' });
    const existing = await prisma.user.create({ data: { email: 'staff@acme.test' } });
    // P10-SEC-001: only an account that already belongs to this org (by invite) is linked.
    await addMember(w.org.id, existing.id, 'MEMBER');

    const first = await signIn(w.org.slug, (nonce) =>
      makeIdToken({ key: rsa, nonce, email: 'staff@acme.test', sub: 'idp-staff' }),
    );
    expect(first.callback.status).toBe(302);
    expect(errorOf(first.callback)).toBeNull();
    const membership = await prisma.orgMember.findUnique({
      where: { userId_orgId: { userId: existing.id, orgId: w.org.id } },
    });
    // The existing membership is kept as is (defaultRole only applies to new memberships).
    expect(membership?.role).toBe('MEMBER');
    expect(await prisma.user.count({ where: { email: 'staff@acme.test' } })).toBe(1);
    expect(await prisma.auditLog.count({ where: { action: 'auth.sso_linked' } })).toBe(1);

    const second = await signIn(w.org.slug, (nonce) =>
      makeIdToken({ key: rsa, nonce, email: 'staff@acme.test', sub: 'idp-staff' }),
    );
    expect(errorOf(second.callback)).toBeNull();
    expect(await prisma.ssoIdentity.count()).toBe(1);
  });

  it('refuses an email outside the verified domains and honours jitProvisioning=false', async () => {
    const w = await world();
    await addVerifiedDomain(w);
    await configureSso(w);
    const outside = await signIn(w.org.slug, (nonce) =>
      makeIdToken({ key: rsa, nonce, email: 'intruder@evil.test', sub: 'idp-evil' }),
    );
    expect(errorOf(outside.callback)).toBe('LSE-AUTH-006');

    await configureSso(w, { jitProvisioning: false });
    const noJit = await signIn(w.org.slug, (nonce) =>
      makeIdToken({ key: rsa, nonce, email: 'fresh@acme.test', sub: 'idp-fresh' }),
    );
    expect(errorOf(noJit.callback)).toBe('LSE-ORG-001');
    expect(await prisma.user.count({ where: { email: 'fresh@acme.test' } })).toBe(0);
  });

  it('accepts ES256 and follows JWKS key rotation', async () => {
    const w = await world();
    await addVerifiedDomain(w);
    await configureSso(w);
    // Prime the cache with the RSA key only, then rotate to EC at the IdP.
    const primed = await signIn(w.org.slug, (nonce) => makeIdToken({ key: rsa, nonce }));
    expect(errorOf(primed.callback)).toBeNull();

    idp.keys = [ec];
    await prisma.ssoConnection.updateMany({
      where: { orgId: w.org.id },
      // jwksFetchedAt in the past so the rotation refetch is allowed.
      data: { metadata: await staleMetadata(w.org.id) },
    });
    const rotated = await signIn(w.org.slug, (nonce) =>
      makeIdToken({ key: ec, nonce, sub: 'idp-ec' }),
    );
    expect(errorOf(rotated.callback)).toBeNull();
  });
});

/** The cached metadata with `jwksFetchedAt` far enough in the past to allow a refetch. */
async function staleMetadata(orgId: string): Promise<object> {
  const row = await prisma.ssoConnection.findUniqueOrThrow({ where: { orgId } });
  const meta = row.metadata as Record<string, unknown>;
  return { ...meta, jwksFetchedAt: 0 };
}

describe('SSO response verification (LSE-AUTH-011)', () => {
  let w: World;
  beforeEach(async () => {
    w = await world();
    await addVerifiedDomain(w);
    await configureSso(w);
  });

  const cases: { name: string; token: (nonce: string) => string }[] = [
    {
      name: 'tampered signature',
      token: (n) => makeIdToken({ key: rsa, nonce: n, sign: { tamper: true } }),
    },
    { name: 'expired', token: (n) => makeIdToken({ key: rsa, nonce: n, expiresInSec: -3600 }) },
    {
      name: 'wrong audience',
      token: (n) => makeIdToken({ key: rsa, nonce: n, audience: 'other-client' }),
    },
    {
      name: 'audience array without matching azp',
      token: (n) =>
        makeIdToken({ key: rsa, nonce: n, audience: [IDP_CLIENT_ID, 'x'], azp: 'someone-else' }),
    },
    {
      name: 'wrong issuer',
      token: (n) => makeIdToken({ key: rsa, nonce: n, issuer: 'https://evil.test' }),
    },
    { name: 'wrong nonce', token: () => makeIdToken({ key: rsa, nonce: 'not-the-nonce' }) },
    {
      name: 'iat in the future',
      token: (n) => makeIdToken({ key: rsa, nonce: n, issuedAtOffsetSec: 3600 }),
    },
    {
      name: 'unaccepted alg (HS256 header)',
      token: (n) => makeIdToken({ key: rsa, nonce: n, sign: { header: { alg: 'HS256' } } }),
    },
    {
      name: 'alg none',
      token: (n) => {
        const jwt = makeIdToken({ key: rsa, nonce: n, sign: { header: { alg: 'none' } } });
        const [h, p] = jwt.split('.');
        return `${h as string}.${p as string}.`;
      },
    },
    {
      name: 'unknown kid',
      token: (n) => makeIdToken({ key: rsa, nonce: n, sign: { header: { kid: 'nope' } } }),
    },
    {
      name: 'signed by a foreign key',
      token: (n) => makeIdToken({ key: makeRsaKey('rsa-1'), nonce: n }),
    },
    { name: 'not a JWS', token: () => 'not-a-token' },
    {
      name: 'email reported unverified',
      token: (n) => makeIdToken({ key: rsa, nonce: n, emailVerified: false }),
    },
    { name: 'no email claim', token: (n) => makeIdToken({ key: rsa, nonce: n, email: null }) },
  ];

  it.each(cases)('rejects an id_token with a $name', async ({ token }) => {
    const res = await signIn(w.org.slug, token);
    expect(res.callback.status).toBe(302);
    expect(errorOf(res.callback)).toBe('LSE-AUTH-011');
    expect(await prisma.authSession.count({ where: { ssoOrgId: w.org.id } })).toBe(0);
    const failure = await prisma.auditLog.findFirst({
      where: { action: 'auth.sso_sign_in_failed' },
    });
    expect(failure).not.toBeNull();
  });

  it('rejects a replayed state and a callback without the start cookies', async () => {
    const { agent, params } = await startFlow(w.org.slug);
    const state = encodeURIComponent(params.get('state') as string);
    idp.nextIdToken = makeIdToken({ key: rsa, nonce: params.get('nonce') as string });
    const first = await agent.get(
      `${API_PREFIX}/auth/sso/${w.org.slug}/callback?code=c1&state=${state}`,
    );
    expect(errorOf(first)).toBeNull();

    // Replay with the same state: the cookies were cleared and the state is consumed.
    const replay = await agent.get(
      `${API_PREFIX}/auth/sso/${w.org.slug}/callback?code=c1&state=${state}`,
    );
    expect(errorOf(replay)).toBe('LSE-AUTH-011');

    // Even keeping the cookie does not help — the state is single use.
    const keeper = request.agent(app);
    const started = await keeper.get(`${API_PREFIX}/auth/sso/${w.org.slug}/start`);
    const p2 = authorizeParams(started.headers.location as string);
    const cookie = (started.headers['set-cookie'] as unknown as string[]).find((c) =>
      c.startsWith(`${SSO_STATE_COOKIE}=`),
    );
    expect(cookie).toBeDefined();
    idp.nextIdToken = makeIdToken({ key: rsa, nonce: p2.get('nonce') as string, sub: 'idp-2' });
    const okAgain = await keeper.get(
      `${API_PREFIX}/auth/sso/${w.org.slug}/callback?code=c2&state=${encodeURIComponent(p2.get('state') as string)}`,
    );
    expect(errorOf(okAgain)).toBeNull();
    const second = await keeper
      .get(
        `${API_PREFIX}/auth/sso/${w.org.slug}/callback?code=c2&state=${encodeURIComponent(p2.get('state') as string)}`,
      )
      .set('cookie', cookie as string);
    expect(errorOf(second)).toBe('LSE-AUTH-011');
  });

  it('maps IdP-reported errors and a failing token endpoint', async () => {
    const denied = await request(app).get(
      `${API_PREFIX}/auth/sso/${w.org.slug}/callback?error=access_denied`,
    );
    expect(errorOf(denied)).toBe('LSE-AUTH-003');
    const other = await request(app).get(
      `${API_PREFIX}/auth/sso/${w.org.slug}/callback?error=server_error`,
    );
    expect(errorOf(other)).toBe('LSE-AUTH-004');

    idp.tokenStatus = 400;
    const failed = await signIn(w.org.slug, (nonce) => makeIdToken({ key: rsa, nonce }));
    expect(errorOf(failed.callback)).toBe('LSE-AUTH-011');
  });

  it('refuses to start when SSO is not enabled for the org', async () => {
    const plain = await world('plain@other.test');
    expectError(
      await request(app).get(`${API_PREFIX}/auth/sso/${plain.org.slug}/start`),
      'LSE-AUTH-004',
      502,
    );
    expectError(
      await request(app).get(`${API_PREFIX}/auth/sso/nope-nope/start`),
      'LSE-ORG-003',
      404,
    );
  });
});

describe('enforce-SSO (LSE-AUTH-006)', () => {
  it('blocks the password-less dev-login fallback for verified-domain members', async () => {
    const w = await world();
    await addVerifiedDomain(w);
    const member = await login(app, `member@${DOMAIN}`);
    await addMember(w.org.id, member.user.id, 'MEMBER');
    // Before enforcing: the cookie session works.
    expect((await member.get(`${API_PREFIX}/orgs/${w.org.id}`)).status).toBe(200);

    await configureSso(w, { enforce: true });
    expectError(await member.get(`${API_PREFIX}/orgs/${w.org.id}`), 'LSE-AUTH-006', 403);
    // A member outside the verified domain is unaffected.
    const outside = await login(app, 'contractor@other.test');
    await addMember(w.org.id, outside.user.id, 'MEMBER');
    expect((await outside.get(`${API_PREFIX}/orgs/${w.org.id}`)).status).toBe(200);

    // Signing in through SSO yields a session that passes.
    const signedIn = await signIn(w.org.slug, (nonce) =>
      makeIdToken({ key: rsa, nonce, email: `member@${DOMAIN}`, sub: 'idp-member' }),
    );
    expect(errorOf(signedIn.callback)).toBeNull();
    expect((await signedIn.agent.get(`${API_PREFIX}/orgs/${w.org.id}`)).status).toBe(200);
  });

  it('owner break-glass: allowOwnerBypass keeps owners in, turning it off locks them out too', async () => {
    const w = await world();
    await addVerifiedDomain(w);
    await configureSso(w, { enforce: true });
    expect((await w.owner.get(`${API_PREFIX}/orgs/${w.org.id}`)).status).toBe(200);

    await configureSso(w, { enforce: true, allowOwnerBypass: false });
    expectError(await w.owner.get(`${API_PREFIX}/orgs/${w.org.id}`), 'LSE-AUTH-006', 403);
    // Still fixable through SSO itself.
    const signedIn = await signIn(w.org.slug, (nonce) =>
      makeIdToken({ key: rsa, nonce, email: `owner@${DOMAIN}`, sub: 'idp-owner' }),
    );
    expect(errorOf(signedIn.callback)).toBeNull();
    expect((await signedIn.agent.get(`${API_PREFIX}/orgs/${w.org.id}`)).status).toBe(200);
  });

  it('does not apply to unverified domains or disabled connections', async () => {
    const w = await world();
    const member = await login(app, `member@${DOMAIN}`);
    await addMember(w.org.id, member.user.id, 'MEMBER');
    // enforce=true but the domain is not verified → no enforcement.
    await configureSso(w, { enforce: true });
    expect((await member.get(`${API_PREFIX}/orgs/${w.org.id}`)).status).toBe(200);

    await addVerifiedDomain(w);
    invalidateOrgSecurityCache(ctx);
    expectError(await member.get(`${API_PREFIX}/orgs/${w.org.id}`), 'LSE-AUTH-006', 403);

    await configureSso(w, { enabled: false, enforce: true });
    expect((await member.get(`${API_PREFIX}/orgs/${w.org.id}`)).status).toBe(200);
  });
});

describe('feature flags', () => {
  it('turning sso_oidc off makes every SSO route answer LSE-SYS-007', async () => {
    const off = makeApp({
      env: { FEATURE_FLAGS: 'sso_oidc=off' },
      context: { fetch: mswFetch(handlers), dns },
    });
    const owner = await login(off.app, `flagowner@${DOMAIN}`);
    const org = await createOrg(owner, 'Flagged');
    expectError(await owner.get(identityUrl(org.id, '/sso')), 'LSE-SYS-007', 503);
    expectError(
      await request(off.app).get(`${API_PREFIX}/auth/sso/${org.slug}/start`),
      'LSE-SYS-007',
      503,
    );
    const discover = await request(off.app).get(
      `${API_PREFIX}/auth/sso/discover?email=someone@${DOMAIN}`,
    );
    expect(discover.body.data.sso).toBe(false);
  });
});
