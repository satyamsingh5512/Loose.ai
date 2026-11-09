/**
 * Phase 10 security-audit regressions owned by fix-identity:
 *
 * - P10-SEC-001 SSO JIT must never take over an existing global account by email.
 * - P10-SEC-002 PATs and stale SSO sessions must satisfy the org's *current* SSO / 2FA policy.
 * - P10-SEC-008 a TOTP step is consumed atomically (no double use under concurrency).
 * - P10-SEC-009 disabling 2FA signs out parked (unverified) sessions instead of promoting them.
 * - P10-SEC-010 a domain can be verified by one org only, even under concurrent verification.
 * - P10-SEC-014 SCIM tokens expire and SCIM writes respect the org deletion freeze.
 *
 * Each test fails against the pre-fix code (see status-p10-fix-identity.md).
 */
import request from 'supertest';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import type { RequestHandler } from 'msw';
import { Prisma } from '@prisma/client';
import {
  API_PREFIX,
  CSRF_HEADER,
  SCIM_BASE_PATH,
  SCIM_CONTENT_TYPE,
  SCIM_SCHEMAS,
  SCIM_TOKEN_DEFAULT_TTL_DAYS,
} from '@loose/shared';
import { invalidateOrgSecurityCache } from '../src/services/identity/accessPolicy';
import { base32Decode, totpCode, totpStep } from '../src/services/identity/totp';
import {
  activateEnrollment,
  regenerateRecoveryCodes,
} from '../src/services/identity/twoFactor.service';
import { isAppError } from '../src/lib/errors';
import { mswFetch } from './agentHelpers';
import {
  addMember,
  createOrg,
  csrfFor,
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
  makeIdToken,
  makeRsaKey,
} from './phase10.identityHelpers';

const prisma = testPrisma();
const handlers: { current: RequestHandler[] } = { current: [] };
const dns = createFakeDns();
const { app, ctx } = makeApp({ context: { fetch: mswFetch(handlers), dns } });

const rsa = makeRsaKey('rsa-fix');
let idp = createMockIdp([rsa]);

const DOMAIN = 'acme.test';
const SCIM = `${API_PREFIX}${SCIM_BASE_PATH}`;

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

// ---- helpers ---------------------------------------------------------------------------------

interface World {
  owner: Client;
  org: { id: string; slug: string };
}

let seq = 0;
async function world(ownerEmail?: string): Promise<World> {
  seq += 1;
  const owner = await login(app, ownerEmail ?? `owner-${seq}@${DOMAIN}`);
  const org = await createOrg(owner, `Fix ${seq}-${Math.random().toString(36).slice(2, 7)}`);
  return { owner, org };
}

const identityUrl = (orgId: string, path = '') => `${API_PREFIX}/orgs/${orgId}/identity${path}`;

async function createDomainClaim(w: World, domain = DOMAIN) {
  const created = await w.owner.post(identityUrl(w.org.id, '/domains'), { domain });
  expect(created.status, JSON.stringify(created.body)).toBe(201);
  return created.body.data as { id: string; verificationRecord: { name: string; value: string } };
}

async function addVerifiedDomain(w: World, domain = DOMAIN): Promise<void> {
  const dto = await createDomainClaim(w, domain);
  dns.txt.set(dto.verificationRecord.name, [[dto.verificationRecord.value]]);
  const verified = await w.owner.post(identityUrl(w.org.id, `/domains/${dto.id}/verify`));
  expect(verified.status, JSON.stringify(verified.body)).toBe(200);
}

async function configureSso(w: World, overrides: Record<string, unknown> = {}): Promise<void> {
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
}

type Agent = ReturnType<typeof request.agent>;

/** Run the SSO round trip on `agent` (a fresh one by default) and return the callback. */
async function signIn(
  slug: string,
  token: (nonce: string) => string,
  agent: Agent = request.agent(app),
): Promise<{ agent: Agent; callback: request.Response }> {
  const start = await agent.get(`${API_PREFIX}/auth/sso/${slug}/start`);
  expect(start.status, JSON.stringify(start.body)).toBe(302);
  const params = authorizeParams(start.headers.location as string);
  idp.nextIdToken = token(params.get('nonce') as string);
  const state = encodeURIComponent(params.get('state') as string);
  const callback = await agent.get(
    `${API_PREFIX}/auth/sso/${slug}/callback?code=c-${seq}&state=${state}`,
  );
  expect(callback.status).toBe(302);
  return { agent, callback };
}

function errorOf(res: request.Response): string | null {
  const location = res.headers.location as string | undefined;
  if (!location) return null;
  return new URL(location, 'http://localhost').searchParams.get('error');
}

async function mintPat(agent: Agent, orgId: string, csrf?: string): Promise<string> {
  const token = csrf ?? (await csrfFor(agent));
  const res = await agent
    .post(`${API_PREFIX}/users/me/tokens`)
    .set(CSRF_HEADER, token)
    .send({ name: `pat-${Math.random().toString(36).slice(2, 7)}`, orgId, scopes: ['org:read'] });
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  return res.body.data.token as string;
}

const withPat = (url: string, pat: string) =>
  request(app).get(url).set('authorization', `Bearer ${pat}`);

const twoFa = (path = '') => `${API_PREFIX}/users/me/2fa${path}`;

async function enroll(client: Client): Promise<Buffer> {
  const started = await client.post(twoFa('/enroll'));
  expect(started.status, JSON.stringify(started.body)).toBe(200);
  const secret = base32Decode(started.body.data.secret as string) as Buffer;
  const activated = await client.post(twoFa('/activate'), {
    code: totpCode(secret, totpStep()),
  });
  expect(activated.status, JSON.stringify(activated.body)).toBe(200);
  return secret;
}

function scim(
  method: 'get' | 'post' | 'patch' | 'delete',
  path: string,
  token: string,
  body?: object,
) {
  let req = request(app)[method](`${SCIM}${path}`).set('authorization', `Bearer ${token}`);
  if (body !== undefined) req = req.set('content-type', SCIM_CONTENT_TYPE).send(body);
  return req;
}

const scimUser = (email: string) => ({
  schemas: [SCIM_SCHEMAS.user],
  userName: email,
  emails: [{ value: email, primary: true }],
  active: true,
});

async function scimToken(w: World, body: Record<string, unknown> = {}) {
  const res = await w.owner.post(identityUrl(w.org.id, '/scim-tokens'), { name: 'okta', ...body });
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  return res.body.data as { id: string; token: string; expiresAt: string | null };
}

// ---- P10-SEC-001 -----------------------------------------------------------------------------

describe('P10-SEC-001 SSO never takes over an existing account by email', () => {
  it('refuses to link a victim account of another org (new subject, verified domain)', async () => {
    // The victim has a normal account and their own org B.
    const victim = await login(app, `victim@${DOMAIN}`);
    const orgB = await createOrg(victim, 'Victim Org');
    // The attacker owns org A, verifies acme.test and runs the configured IdP.
    const attacker = await world('attacker@evil.test');
    await addVerifiedDomain(attacker);
    await configureSso(attacker);

    const { agent, callback } = await signIn(attacker.org.slug, (nonce) =>
      makeIdToken({ key: rsa, nonce, email: `victim@${DOMAIN}`, sub: 'attacker-controlled' }),
    );
    expect(errorOf(callback)).toBe('LSE-AUTH-005');

    expect(await prisma.ssoIdentity.count()).toBe(0);
    expect(
      await prisma.authSession.count({
        where: { userId: victim.user.id, ssoOrgId: { not: null } },
      }),
    ).toBe(0);
    expect(
      await prisma.orgMember.count({ where: { userId: victim.user.id, orgId: attacker.org.id } }),
    ).toBe(0);
    // The attacker's browser holds no session for the victim: org B stays out of reach.
    expectError(await agent.get(`${API_PREFIX}/orgs/${orgB.id}`), 'LSE-AUTH-001', 401);
    const refused = await prisma.auditLog.findFirst({ where: { action: 'auth.sso_link_refused' } });
    expect(refused).toMatchObject({ orgId: attacker.org.id, target: victim.user.id });
  });

  it('a SCIM-provisioned membership does not authorize linking either', async () => {
    const victim = await login(app, `victim2@${DOMAIN}`);
    const attacker = await world('attacker2@evil.test');
    await addVerifiedDomain(attacker);
    await configureSso(attacker);
    // The attacker's SCIM token pulls the existing account into org A first.
    const { token } = await scimToken(attacker);
    const provisioned = await scim('post', '/Users', token, scimUser(`victim2@${DOMAIN}`));
    expect(provisioned.status, JSON.stringify(provisioned.body)).toBe(201);
    expect(
      await prisma.orgMember.count({ where: { userId: victim.user.id, orgId: attacker.org.id } }),
    ).toBe(1);

    const { callback } = await signIn(attacker.org.slug, (nonce) =>
      makeIdToken({ key: rsa, nonce, email: `victim2@${DOMAIN}`, sub: 'attacker-2' }),
    );
    expect(errorOf(callback)).toBe('LSE-AUTH-005');
    expect(await prisma.ssoIdentity.count()).toBe(0);
  });

  it('requires email_verified=true for a first-time sign-in (missing claim is refused)', async () => {
    const w = await world();
    await addVerifiedDomain(w);
    await configureSso(w);
    const { callback } = await signIn(w.org.slug, (nonce) =>
      makeIdToken({ key: rsa, nonce, email: `fresh@${DOMAIN}`, sub: 'fresh', emailVerified: null }),
    );
    expect(errorOf(callback)).toBe('LSE-AUTH-011');
    expect(await prisma.user.count({ where: { email: `fresh@${DOMAIN}` } })).toBe(0);
  });

  it('links explicitly when the account owner is signed in and starts SSO', async () => {
    const user = await login(app, `linker@${DOMAIN}`);
    const w = await world('admin@other.test');
    await addVerifiedDomain(w);
    await configureSso(w);

    const { agent, callback } = await signIn(
      w.org.slug,
      (nonce) => makeIdToken({ key: rsa, nonce, email: `linker@${DOMAIN}`, sub: 'linker' }),
      user.agent,
    );
    expect(errorOf(callback)).toBeNull();
    const identity = await prisma.ssoIdentity.findFirst({ where: { subject: 'linker' } });
    expect(identity?.userId).toBe(user.user.id);
    expect((await agent.get(`${API_PREFIX}/auth/me`)).body.data.id).toBe(user.user.id);
    const linked = await prisma.auditLog.findFirst({ where: { action: 'auth.sso_linked' } });
    expect(linked?.meta).toMatchObject({ via: 'signed_in' });
  });
});

// ---- P10-SEC-002 -----------------------------------------------------------------------------

describe('P10-SEC-002 PATs and stale SSO sessions follow the current policy', () => {
  it('a PAT minted outside SSO is refused once SSO is enforced; an SSO-minted one works', async () => {
    const w = await world();
    await addVerifiedDomain(w);
    await configureSso(w);
    const member = await login(app, `member@${DOMAIN}`);
    await addMember(w.org.id, member.user.id, 'MEMBER');
    const orgUrl = `${API_PREFIX}/orgs/${w.org.id}`;

    const oldPat = await mintPat(member.agent, w.org.id, member.csrf);
    expect((await withPat(orgUrl, oldPat)).status).toBe(200);

    await configureSso(w, { enforce: true });
    expectError(await withPat(orgUrl, oldPat), 'LSE-AUTH-006', 403);

    const sso = await signIn(w.org.slug, (nonce) =>
      makeIdToken({ key: rsa, nonce, email: `member@${DOMAIN}`, sub: 'idp-member' }),
    );
    expect(errorOf(sso.callback)).toBeNull();
    const ssoPat = await mintPat(sso.agent, w.org.id);
    expect((await withPat(orgUrl, ssoPat)).status).toBe(200);
    expect((await sso.agent.get(orgUrl)).status).toBe(200);

    // IdP migration (new client id): the old SSO session and its PAT lose their assurance.
    await configureSso(w, { enforce: true, clientId: 'migrated-client' });
    expectError(await sso.agent.get(orgUrl), 'LSE-AUTH-006', 403);
    expectError(await withPat(orgUrl, ssoPat), 'LSE-AUTH-006', 403);
  });

  it('an SSO session from a deleted connection no longer satisfies enforce-SSO', async () => {
    const w = await world();
    await addVerifiedDomain(w);
    await configureSso(w, { enforce: true });
    const member = await login(app, `member@${DOMAIN}`);
    await addMember(w.org.id, member.user.id, 'MEMBER');
    const orgUrl = `${API_PREFIX}/orgs/${w.org.id}`;
    const sso = await signIn(w.org.slug, (nonce) =>
      makeIdToken({ key: rsa, nonce, email: `member@${DOMAIN}`, sub: 'idp-member' }),
    );
    expect((await sso.agent.get(orgUrl)).status).toBe(200);
    const before = await prisma.authSession.findFirstOrThrow({
      where: { userId: member.user.id, ssoOrgId: w.org.id },
    });

    expect((await w.owner.delete(identityUrl(w.org.id, '/sso'))).status).toBe(204);
    await configureSso(w, { enforce: true });
    // Keep the original assurance columns to model a session left over from the old connection.
    await prisma.authSession.update({
      where: { id: before.id },
      data: { ssoOrgId: before.ssoOrgId, ssoConnectionId: before.ssoConnectionId },
    });
    invalidateOrgSecurityCache(ctx);
    expectError(await sso.agent.get(orgUrl), 'LSE-AUTH-006', 403);
  });

  it('under requireAdmin2fa a PAT minted before 2FA enrollment is refused until re-issued', async () => {
    const w = await world('owner-2fa@example.com');
    const orgUrl = `${API_PREFIX}/orgs/${w.org.id}`;
    const oldPat = await mintPat(w.owner.agent, w.org.id, w.owner.csrf);
    await enroll(w.owner);
    const on = await w.owner.put(identityUrl(w.org.id, '/security'), { requireAdmin2fa: true });
    expect(on.status, JSON.stringify(on.body)).toBe(200);

    expectError(await withPat(orgUrl, oldPat), 'LSE-AUTH-012', 403);
    const freshPat = await mintPat(w.owner.agent, w.org.id, w.owner.csrf);
    expect((await withPat(orgUrl, freshPat)).status).toBe(200);
    const row = await prisma.apiToken.findFirstOrThrow({ orderBy: { createdAt: 'desc' } });
    expect(row.mfaVerifiedAt).not.toBeNull();
  });
});

// ---- P10-SEC-008 -----------------------------------------------------------------------------

describe('P10-SEC-008 TOTP steps are consumed atomically', () => {
  it('two requests holding the same stale user row cannot both use one code', async () => {
    const client = await login(app);
    const secret = await enroll(client);
    const stale = await prisma.user.findUniqueOrThrow({ where: { id: client.user.id } });
    const code = totpCode(secret, totpStep() + 1);

    await regenerateRecoveryCodes(ctx, stale, code, undefined);
    // Same pre-loaded row (as a concurrent request would have): must be a replay now.
    const second = await regenerateRecoveryCodes(ctx, stale, code, undefined).catch((e) => e);
    expect(isAppError(second) && second.code).toBe('LSE-AUTH-010');
  });

  it('concurrent HTTP requests with one code: exactly one succeeds', async () => {
    const client = await login(app);
    const secret = await enroll(client);
    const code = totpCode(secret, totpStep() + 1);
    const results = await Promise.all(
      [0, 1, 2].map(() => client.post(twoFa('/recovery-codes'), { code })),
    );
    const statuses = results.map((r) => r.status).sort();
    expect(statuses).toEqual([200, 401, 401]);
    for (const r of results.filter((x) => x.status === 401)) expectError(r, 'LSE-AUTH-010', 401);
  });

  it('enrollment activation is single-shot', async () => {
    const client = await login(app);
    const started = await client.post(twoFa('/enroll'));
    const secret = base32Decode(started.body.data.secret as string) as Buffer;
    const stale = await prisma.user.findUniqueOrThrow({ where: { id: client.user.id } });
    const code = totpCode(secret, totpStep());

    await activateEnrollment(ctx, stale, code, undefined, undefined);
    const again = await activateEnrollment(ctx, stale, code, undefined, undefined).catch((e) => e);
    expect(isAppError(again) && again.code).toBe('LSE-AUTH-010');
    expect(await prisma.totpRecoveryCode.count({ where: { userId: client.user.id } })).toBe(10);
  });
});

// ---- P10-SEC-009 -----------------------------------------------------------------------------

describe('P10-SEC-009 disabling 2FA does not promote parked sessions', () => {
  it('signs out other sessions and rotates the caller session', async () => {
    const email = 'parked@example.com';
    const owner = await login(app, email);
    const secret = await enroll(owner);
    // The attacker's session (e.g. a stolen OAuth cookie) is parked at the challenge.
    const parked = await login(app, email);
    expectError(await parked.get(`${API_PREFIX}/orgs`), 'LSE-AUTH-012', 403);
    const callerBefore = await prisma.authSession.findMany({ where: { userId: owner.user.id } });

    const disabled = await owner.post(twoFa('/disable'), {
      code: totpCode(secret, totpStep() + 1),
    });
    expect(disabled.status, JSON.stringify(disabled.body)).toBe(204);
    expect(String(disabled.headers['set-cookie'])).toContain('loose_session=');

    // The parked session is gone rather than promoted.
    expectError(await parked.get(`${API_PREFIX}/orgs`), 'LSE-AUTH-001', 401);
    // The caller keeps working on its rotated cookie; only one (new) session remains.
    expect((await owner.get(`${API_PREFIX}/orgs`)).status).toBe(200);
    const after = await prisma.authSession.findMany({ where: { userId: owner.user.id } });
    expect(after).toHaveLength(1);
    expect(callerBefore.map((s) => s.id)).not.toContain(after[0]?.id);
    const audit = await prisma.auditLog.findFirst({ where: { action: 'auth.2fa_disabled' } });
    expect(audit?.meta).toMatchObject({ revokedSessions: 1 });
  });
});

// ---- P10-SEC-010 -----------------------------------------------------------------------------

describe('P10-SEC-010 a domain is verified by one org only', () => {
  it('concurrent verification of two pending claims: exactly one wins', async () => {
    const a = await world('a@one.test');
    const b = await world('b@two.test');
    const claimA = await createDomainClaim(a, 'race.test');
    const claimB = await createDomainClaim(b, 'race.test');
    dns.txt.set(claimA.verificationRecord.name, [
      [claimA.verificationRecord.value],
      [claimB.verificationRecord.value],
    ]);
    const results = await Promise.all([
      a.owner.post(identityUrl(a.org.id, `/domains/${claimA.id}/verify`)),
      b.owner.post(identityUrl(b.org.id, `/domains/${claimB.id}/verify`)),
    ]);
    const statuses = results.map((r) => r.status).sort();
    expect(statuses).toEqual([200, 422]);
    const loser = results.find((r) => r.status === 422) as request.Response;
    expectError(loser, 'LSE-ORG-011', 422);
    expect(
      await prisma.orgDomain.count({ where: { domain: 'race.test', verifiedAt: { not: null } } }),
    ).toBe(1);
  });

  it('the database itself rejects a second verified row for the same domain', async () => {
    const a = await world('a@one.test');
    const b = await world('b@two.test');
    await prisma.orgDomain.create({
      data: {
        orgId: a.org.id,
        domain: 'db.test',
        verificationToken: 't1',
        verifiedAt: new Date(),
        verifiedDomain: 'db.test',
      },
    });
    const err = await prisma.orgDomain
      .create({
        data: {
          orgId: b.org.id,
          domain: 'db.test',
          verificationToken: 't2',
          verifiedAt: new Date(),
          verifiedDomain: 'db.test',
        },
      })
      .catch((e: unknown) => e);
    expect(err instanceof Prisma.PrismaClientKnownRequestError && err.code).toBe('P2002');
  });
});

// ---- P10-SEC-014 -----------------------------------------------------------------------------

describe('P10-SEC-014 SCIM tokens expire and follow the org lifecycle', () => {
  it('new tokens carry an expiry and an expired token is refused (LSE-AUTH-007)', async () => {
    const w = await world('scim-exp@example.com');
    const dflt = await scimToken(w);
    const days = (new Date(dflt.expiresAt as string).getTime() - Date.now()) / 86_400_000;
    expect(Math.round(days)).toBe(SCIM_TOKEN_DEFAULT_TTL_DAYS);

    const short = await scimToken(w, { name: 'short', expiresInDays: 1 });
    expect((await scim('get', '/Users', short.token)).status).toBe(200);
    await prisma.scimToken.update({
      where: { id: short.id },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });
    const res = await scim('get', '/Users', short.token);
    expect(res.status).toBe(401);
    expect(res.headers['x-loose-error-code']).toBe('LSE-AUTH-007');
    expect((await scim('get', '/Users', dflt.token)).status).toBe(200);

    expectError(
      await w.owner.post(identityUrl(w.org.id, '/scim-tokens'), { name: 'x', expiresInDays: 9999 }),
      'LSE-VAL-001',
      400,
    );
  });

  it('SCIM writes are frozen while the org is scheduled for deletion; reads still work', async () => {
    const w = await world('scim-del@example.com');
    const { token } = await scimToken(w);
    const created = await scim('post', '/Users', token, scimUser('keep@example.com'));
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    const id = created.body.id as string;

    await prisma.organization.update({
      where: { id: w.org.id },
      data: { deletionScheduledAt: new Date(Date.now() + 7 * 86_400_000) },
    });
    const writes = [
      scim('post', '/Users', token, scimUser('new@example.com')),
      scim('patch', `/Users/${id}`, token, {
        schemas: [SCIM_SCHEMAS.patchOp],
        Operations: [{ op: 'replace', path: 'active', value: false }],
      }),
      scim('delete', `/Users/${id}`, token),
      scim('post', '/Groups', token, { schemas: [SCIM_SCHEMAS.group], displayName: 'Eng' }),
    ];
    for (const res of await Promise.all(writes)) {
      expect(res.status, JSON.stringify(res.body)).toBe(409);
      expect(res.headers['x-loose-error-code']).toBe('LSE-ORG-012');
    }
    expect((await scim('get', `/Users/${id}`, token)).status).toBe(200);
    expect((await scim('get', '/ServiceProviderConfig', token)).status).toBe(200);
    expect(await prisma.scimIdentity.count({ where: { orgId: w.org.id } })).toBe(1);
  });
});
