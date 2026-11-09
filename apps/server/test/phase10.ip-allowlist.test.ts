/**
 * Phase 10 / W1 — per-org IP allowlists (spec §8.20): CIDR matching (IPv4, IPv6, IPv4-mapped),
 * the `X-Forwarded-For` trust rules driven by `TRUST_PROXY`, self-lockout protection,
 * enforcement on cookie *and* token requests (LSE-ORG-010), the WS/job caller shapes, and the
 * `ip_allowlist` feature flag.
 */
import request from 'supertest';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { API_PREFIX, cidrContains, ipAllowed, normalizeCidr } from '@loose/shared';
import { clientIpFromChain } from '../src/lib/net/clientIp';
import {
  enforceOrgAccess,
  orgAccessSubjectFromCaller,
} from '../src/services/identity/accessPolicy';
import { addMember, createOrg, expectError, login, makeApp, resetDb, testPrisma } from './helpers';

const prisma = testPrisma();
/** TRUST_PROXY=0 (the default): `X-Forwarded-For` is ignored. */
const direct = makeApp();
/** TRUST_PROXY=1: the last `X-Forwarded-For` entry is the client. */
const behindProxy = makeApp({ env: { TRUST_PROXY: '1' } });

afterAll(async () => {
  await direct.ctx.jobs.onIdle();
  await behindProxy.ctx.jobs.onIdle();
  await prisma.$disconnect();
});

beforeEach(async () => {
  await resetDb(prisma);
});

let seq = 0;
async function world(app = direct.app) {
  seq += 1;
  const owner = await login(app, `ip-owner-${seq}@example.com`);
  const org = await createOrg(owner, `Net ${seq}-${Math.random().toString(36).slice(2, 7)}`);
  return { owner, org };
}

const securityUrl = (orgId: string) => `${API_PREFIX}/orgs/${orgId}/identity/security`;

/** Apply an allowlist directly (bypassing the self-lockout guard) for enforcement tests. */
async function setAllowlist(orgId: string, ipAllowlist: string[], enabled = true) {
  await prisma.organization.update({
    where: { id: orgId },
    data: { ipAllowlist, ipAllowlistEnabled: enabled },
  });
}

// ---------------------------------------------------------------------------------------------

describe('CIDR helpers (shared) and client IP resolution', () => {
  it('matches IPv4, IPv6 and IPv4-mapped addresses', () => {
    expect(ipAllowed('203.0.113.5', ['203.0.113.0/24'])).toBe(true);
    expect(ipAllowed('203.0.114.5', ['203.0.113.0/24'])).toBe(false);
    expect(ipAllowed('::ffff:203.0.113.5', ['203.0.113.0/24'])).toBe(true);
    expect(ipAllowed('2001:db8::5', ['2001:db8::/32'])).toBe(true);
    expect(ipAllowed('2001:db9::5', ['2001:db8::/32'])).toBe(false);
    // Address families never cross.
    expect(ipAllowed('203.0.113.5', ['2001:db8::/32'])).toBe(false);
    expect(ipAllowed('2001:db8::5', ['0.0.0.0/0'])).toBe(false);
    expect(ipAllowed('not-an-ip', ['0.0.0.0/0'])).toBe(false);
    expect(ipAllowed('203.0.113.5', ['garbage', '203.0.113.5'])).toBe(true);
    expect(cidrContains('10.0.0.0/8', '10.1.2.3')).toBe(true);
    expect(normalizeCidr('10.1.2.3/8')).toBe('10.0.0.0/8');
  });

  it('honours the TRUST_PROXY hop count', () => {
    expect(clientIpFromChain('::ffff:127.0.0.1', '203.0.113.5', 0)).toBe('127.0.0.1');
    expect(clientIpFromChain('::ffff:127.0.0.1', '203.0.113.5', 1)).toBe('203.0.113.5');
    expect(clientIpFromChain('127.0.0.1', '198.51.100.1, 203.0.113.5', 1)).toBe('203.0.113.5');
    expect(clientIpFromChain('127.0.0.1', '198.51.100.1, 203.0.113.5', 2)).toBe('198.51.100.1');
  });
});

describe('security settings', () => {
  it('reports the caller IP and normalizes stored ranges', async () => {
    const w = await world();
    const dto = await w.owner.get(securityUrl(w.org.id));
    expect(dto.status).toBe(200);
    expect(dto.body.data).toMatchObject({
      ipAllowlistEnabled: false,
      ipAllowlist: [],
      callerIp: '127.0.0.1',
      callerIpAllowed: true,
    });

    const saved = await w.owner.put(securityUrl(w.org.id), {
      ipAllowlistEnabled: true,
      ipAllowlist: ['127.0.0.1', '10.1.2.3/8', '2001:DB8::/32'],
    });
    expect(saved.status, JSON.stringify(saved.body)).toBe(200);
    expect(saved.body.data.ipAllowlist).toEqual(['127.0.0.1/32', '10.0.0.0/8', '2001:db8::/32']);
    expect(saved.body.data.callerIpAllowed).toBe(true);
    const audit = await prisma.auditLog.findFirst({ where: { action: 'security.update' } });
    expect(audit?.meta).toMatchObject({ ipAllowlistEnabled: true, ipAllowlistEntries: 3 });
  });

  it('refuses an allowlist that would lock the caller out unless confirmed', async () => {
    const w = await world();
    const blocked = await w.owner.put(securityUrl(w.org.id), {
      ipAllowlistEnabled: true,
      ipAllowlist: ['203.0.113.0/24'],
    });
    expectError(blocked, 'LSE-VAL-001', 400);
    expect(blocked.body.error.fields.ipAllowlist[0]).toContain('127.0.0.1');
    expect(
      (await prisma.organization.findUniqueOrThrow({ where: { id: w.org.id } })).ipAllowlist,
    ).toEqual([]);

    // Enabling with an empty list is refused too.
    expectError(
      await w.owner.put(securityUrl(w.org.id), { ipAllowlistEnabled: true, ipAllowlist: [] }),
      'LSE-VAL-001',
      400,
    );

    const confirmed = await w.owner.put(securityUrl(w.org.id), {
      ipAllowlistEnabled: true,
      ipAllowlist: ['203.0.113.0/24'],
      confirmLockout: true,
    });
    expect(confirmed.status).toBe(200);
    // The caller is now outside the allowlist, as announced.
    expectError(await w.owner.get(`${API_PREFIX}/orgs/${w.org.id}`), 'LSE-ORG-010', 403);
  });

  it('rejects malformed ranges and empty updates', async () => {
    const w = await world();
    expectError(
      await w.owner.put(securityUrl(w.org.id), { ipAllowlist: ['not-a-cidr'] }),
      'LSE-VAL-001',
      400,
    );
    expectError(
      await w.owner.put(securityUrl(w.org.id), { ipAllowlist: ['10.0.0.0/8', '10.0.0.0/8'] }),
      'LSE-VAL-001',
      400,
    );
    expectError(await w.owner.put(securityUrl(w.org.id), {}), 'LSE-VAL-001', 400);
  });

  it('is admin-readable but owner-only to change', async () => {
    const w = await world();
    const admin = await login(direct.app, `ip-admin-${seq}@example.com`);
    await addMember(w.org.id, admin.user.id, 'ADMIN');
    expect((await admin.get(securityUrl(w.org.id))).status).toBe(200);
    expectError(
      await admin.put(securityUrl(w.org.id), { requireAdmin2fa: true }),
      'LSE-ORG-002',
      403,
    );
  });
});

describe('enforcement (LSE-ORG-010)', () => {
  it('allows an address inside the list and blocks everything else', async () => {
    const w = await world();
    await setAllowlist(w.org.id, ['127.0.0.1/32']);
    expect((await w.owner.get(`${API_PREFIX}/orgs/${w.org.id}`)).status).toBe(200);

    await setAllowlist(w.org.id, ['203.0.113.0/24']);
    const blocked = await w.owner.get(`${API_PREFIX}/orgs/${w.org.id}`);
    expectError(blocked, 'LSE-ORG-010', 403);
    expect(blocked.body.error.recoverable).toBe(false);
    const audit = await prisma.auditLog.findFirst({ where: { action: 'security.ip_blocked' } });
    expect(audit?.orgId).toBe(w.org.id);
    expect(audit?.ip).toBe('127.0.0.1');
    expect(audit?.meta).toMatchObject({ via: 'session', method: 'GET' });

    // Only org-scoped routes are affected; the account itself stays reachable.
    expect((await w.owner.get(`${API_PREFIX}/users/me`)).status).toBe(200);
    expect((await w.owner.get(`${API_PREFIX}/orgs`)).status).toBe(200);

    // Disabling the list (or emptying it) restores access.
    await setAllowlist(w.org.id, ['203.0.113.0/24'], false);
    expect((await w.owner.get(`${API_PREFIX}/orgs/${w.org.id}`)).status).toBe(200);
    await setAllowlist(w.org.id, [], true);
    expect((await w.owner.get(`${API_PREFIX}/orgs/${w.org.id}`)).status).toBe(200);
  });

  it('ignores X-Forwarded-For when TRUST_PROXY is 0', async () => {
    const w = await world();
    await setAllowlist(w.org.id, ['203.0.113.0/24']);
    const spoofed = await w.owner
      .get(`${API_PREFIX}/orgs/${w.org.id}`)
      .set('x-forwarded-for', '203.0.113.5');
    expectError(spoofed, 'LSE-ORG-010', 403);
  });

  it('trusts the forwarded address when TRUST_PROXY is 1', async () => {
    const w = await world(behindProxy.app);
    await setAllowlist(w.org.id, ['203.0.113.0/24']);
    const url = `${API_PREFIX}/orgs/${w.org.id}`;
    expect((await w.owner.get(url).set('x-forwarded-for', '203.0.113.5')).status).toBe(200);
    // IPv4-mapped form of the same address.
    expect((await w.owner.get(url).set('x-forwarded-for', '::ffff:203.0.113.5')).status).toBe(200);
    expectError(await w.owner.get(url).set('x-forwarded-for', '198.51.100.7'), 'LSE-ORG-010', 403);
    // Without the header the socket address (127.0.0.1) is used → blocked.
    expectError(await w.owner.get(url), 'LSE-ORG-010', 403);
  });

  it('matches IPv6 ranges behind a proxy', async () => {
    const w = await world(behindProxy.app);
    await setAllowlist(w.org.id, ['2001:db8::/32']);
    const url = `${API_PREFIX}/orgs/${w.org.id}`;
    expect((await w.owner.get(url).set('x-forwarded-for', '2001:db8::5')).status).toBe(200);
    expect((await w.owner.get(url).set('x-forwarded-for', '2001:DB8:1234::abcd')).status).toBe(200);
    expectError(await w.owner.get(url).set('x-forwarded-for', '2001:db9::5'), 'LSE-ORG-010', 403);
  });

  it('applies to API-token requests as well', async () => {
    const w = await world();
    const created = await w.owner.post(`${API_PREFIX}/users/me/tokens`, {
      orgId: w.org.id,
      name: 'ci',
      scopes: ['org:read'],
    });
    expect(created.status).toBe(201);
    const token = created.body.data.token as string;
    const call = () =>
      request(direct.app)
        .get(`${API_PREFIX}/orgs/${w.org.id}`)
        .set('authorization', `Bearer ${token}`);
    expect((await call()).status).toBe(200);
    await setAllowlist(w.org.id, ['203.0.113.0/24']);
    expectError(await call(), 'LSE-ORG-010', 403);
    const audit = await prisma.auditLog.findFirst({ where: { action: 'security.ip_blocked' } });
    expect(audit?.meta).toMatchObject({ via: 'token' });
  });

  it('applies to the WS/session caller shape but never to internal job callers', async () => {
    const w = await world();
    await setAllowlist(w.org.id, ['203.0.113.0/24']);
    const user = await prisma.user.findUniqueOrThrow({ where: { id: w.owner.user.id } });
    const membership = await prisma.orgMember.findFirstOrThrow({
      where: { orgId: w.org.id, userId: user.id },
    });

    // A WebSocket caller carries the resolved upgrade IP.
    const wsSubject = orgAccessSubjectFromCaller({ user, ip: '198.51.100.9' });
    expect(wsSubject.via).toBe('session');
    await expect(
      enforceOrgAccess(direct.ctx, wsSubject, w.org.id, membership),
    ).rejects.toMatchObject({ code: 'LSE-ORG-010' });

    const allowed = orgAccessSubjectFromCaller({ user, ip: '203.0.113.7' });
    await expect(
      enforceOrgAccess(direct.ctx, allowed, w.org.id, membership),
    ).resolves.toBeUndefined();

    // Job-driven runs/triggers have no request: no IP check.
    const internal = orgAccessSubjectFromCaller({ user });
    expect(internal.via).toBe('internal');
    await expect(
      enforceOrgAccess(direct.ctx, internal, w.org.id, membership),
    ).resolves.toBeUndefined();
  });

  it('is skipped entirely when the ip_allowlist flag is off', async () => {
    const off = makeApp({ env: { FEATURE_FLAGS: 'ip_allowlist=off' } });
    const owner = await login(
      off.app,
      `ip-flag-${Math.random().toString(36).slice(2, 7)}@example.com`,
    );
    const org = await createOrg(owner, `Flag ${Math.random().toString(36).slice(2, 7)}`);
    await setAllowlist(org.id, ['203.0.113.0/24']);
    expect((await owner.get(`${API_PREFIX}/orgs/${org.id}`)).status).toBe(200);
    await off.ctx.jobs.onIdle();
  });
});
