/**
 * P10-SEC-011 (identity remainder): security-sensitive identity and credential mutations append
 * their audit row inside the same transaction as the change. When the audit append fails, the
 * request fails with LSE-SYS-001 AND the change is rolled back — never "committed but unaudited".
 *
 * Covered: SSO connection upsert/delete, domain create/verify/delete, SCIM token create/revoke,
 * org security settings, 2FA disable, personal API token create/delete, BYOK key delete,
 * retention settings, policy-pack application, SSO JIT provisioning (account + identity +
 * membership), linking an existing account to an SSO identity (`auth.sso_linked`) and the
 * sole-owner failure path of the account-deletion sweep.
 */
import request from 'supertest';
import type { RequestHandler } from 'msw';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { API_PREFIX, RECOVERY_CODE_COUNT } from '@loose/shared';
import { invalidateOrgSecurityCache } from '../src/services/identity/accessPolicy';
import { runDeletionSweep } from '../src/services/governance/deletion';
import { base32Decode, totpCode, totpStep } from '../src/services/identity/totp';
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
  makeIdToken,
  makeRsaKey,
} from './phase10.identityHelpers';
import { createReadyProject } from './sessionHelpers';

const prisma = testPrisma();
const dns = createFakeDns();
const handlers: { current: RequestHandler[] } = { current: [] };
const { app, ctx } = makeApp({ context: { dns, fetch: mswFetch(handlers) } });
const rsa = makeRsaKey('rsa-atomic');

afterAll(async () => {
  await ctx.jobs.onIdle();
  await prisma.$disconnect();
});

beforeEach(async () => {
  vi.restoreAllMocks();
  await resetDb(prisma);
  invalidateOrgSecurityCache(ctx);
  dns.txt.clear();
  handlers.current = [];
});

/** Make every audit append fail (the chain key is read inside the append). */
function breakAuditStore() {
  return vi.spyOn(ctx.audit, 'chainKey', 'get').mockImplementation(() => {
    throw new Error('audit store unavailable');
  });
}

const identityUrl = (orgId: string, path: string) => `${API_PREFIX}/orgs/${orgId}/identity${path}`;

async function ownerWithOrg(): Promise<{ owner: Client; org: { id: string; slug: string } }> {
  const owner = await login(app);
  const org = await createOrg(owner);
  return { owner, org };
}

const ssoBody = {
  protocol: 'OIDC',
  issuer: IDP_ISSUER,
  clientId: IDP_CLIENT_ID,
  clientSecret: IDP_CLIENT_SECRET,
  // Disabled, so saving does not fetch the discovery document.
  enabled: false,
};

describe('P10-SEC-011: identity mutations and their audit row are one transaction', () => {
  it('SSO connection upsert and delete roll back when the audit append fails', async () => {
    const { owner, org } = await ownerWithOrg();
    const spy = breakAuditStore();
    expectError(await owner.put(identityUrl(org.id, '/sso'), ssoBody), 'LSE-SYS-001', 500);
    expect(await prisma.ssoConnection.count({ where: { orgId: org.id } })).toBe(0);

    spy.mockRestore();
    const saved = await owner.put(identityUrl(org.id, '/sso'), ssoBody);
    expect(saved.status, JSON.stringify(saved.body)).toBe(200);
    expect(await prisma.auditLog.count({ where: { action: 'sso.update' } })).toBe(1);

    // An IdP change that strips SSO assurance from sessions must roll that back too.
    const session = await prisma.authSession.findFirstOrThrow({ where: { userId: owner.user.id } });
    const conn = await prisma.ssoConnection.findUniqueOrThrow({ where: { orgId: org.id } });
    await prisma.authSession.update({
      where: { id: session.id },
      data: { ssoOrgId: org.id, ssoConnectionId: conn.id },
    });
    breakAuditStore();
    expectError(
      await owner.put(identityUrl(org.id, '/sso'), { ...ssoBody, clientId: 'another-client' }),
      'LSE-SYS-001',
      500,
    );
    expect(
      (await prisma.ssoConnection.findUniqueOrThrow({ where: { orgId: org.id } })).clientId,
    ).toBe(IDP_CLIENT_ID);
    expect(
      (await prisma.authSession.findUniqueOrThrow({ where: { id: session.id } })).ssoConnectionId,
    ).toBe(conn.id);

    expectError(await owner.delete(identityUrl(org.id, '/sso')), 'LSE-SYS-001', 500);
    expect(await prisma.ssoConnection.count({ where: { orgId: org.id } })).toBe(1);
    expect(await prisma.auditLog.count({ where: { action: 'sso.delete' } })).toBe(0);
  });

  it('domain create, verify and delete roll back when the audit append fails', async () => {
    const { owner, org } = await ownerWithOrg();
    const spy = breakAuditStore();
    expectError(
      await owner.post(identityUrl(org.id, '/domains'), { domain: 'atomic.example.com' }),
      'LSE-SYS-001',
      500,
    );
    expect(await prisma.orgDomain.count({ where: { orgId: org.id } })).toBe(0);

    spy.mockRestore();
    const created = await owner.post(identityUrl(org.id, '/domains'), {
      domain: 'atomic.example.com',
    });
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    const dto = created.body.data as {
      id: string;
      verificationRecord: { name: string; value: string };
    };
    dns.txt.set(dto.verificationRecord.name, [[dto.verificationRecord.value]]);

    breakAuditStore();
    expectError(
      await owner.post(identityUrl(org.id, `/domains/${dto.id}/verify`)),
      'LSE-SYS-001',
      500,
    );
    const row = await prisma.orgDomain.findUniqueOrThrow({ where: { id: dto.id } });
    expect(row.verifiedAt).toBeNull();
    expect(row.verifiedDomain).toBeNull();

    expectError(await owner.delete(identityUrl(org.id, `/domains/${dto.id}`)), 'LSE-SYS-001', 500);
    expect(await prisma.orgDomain.count({ where: { id: dto.id } })).toBe(1);
  });

  it('SCIM token create and revoke roll back when the audit append fails', async () => {
    const { owner, org } = await ownerWithOrg();
    const spy = breakAuditStore();
    expectError(
      await owner.post(identityUrl(org.id, '/scim-tokens'), { name: 'okta' }),
      'LSE-SYS-001',
      500,
    );
    expect(await prisma.scimToken.count({ where: { orgId: org.id } })).toBe(0);

    spy.mockRestore();
    const created = await owner.post(identityUrl(org.id, '/scim-tokens'), { name: 'okta' });
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    const id = created.body.data.id as string;

    breakAuditStore();
    expectError(await owner.delete(identityUrl(org.id, `/scim-tokens/${id}`)), 'LSE-SYS-001', 500);
    expect((await prisma.scimToken.findUniqueOrThrow({ where: { id } })).revokedAt).toBeNull();
  });

  it('security settings roll back when the audit append fails', async () => {
    const { owner, org } = await ownerWithOrg();
    breakAuditStore();
    expectError(
      await owner.put(identityUrl(org.id, '/security'), { requireAdmin2fa: true }),
      'LSE-SYS-001',
      500,
    );
    expect(
      (await prisma.organization.findUniqueOrThrow({ where: { id: org.id } })).requireAdmin2fa,
    ).toBe(false);
  });

  it('2FA disable rolls back (2FA stays on, other sessions survive) when the audit append fails', async () => {
    const email = `atomic-2fa-${Date.now()}@example.com`;
    const client = await login(app, email);
    const started = await client.post(`${API_PREFIX}/users/me/2fa/enroll`);
    expect(started.status, JSON.stringify(started.body)).toBe(200);
    const secret = base32Decode(started.body.data.secret as string) as Buffer;
    const activated = await client.post(`${API_PREFIX}/users/me/2fa/activate`, {
      code: totpCode(secret, totpStep()),
    });
    expect(activated.status, JSON.stringify(activated.body)).toBe(200);
    await login(app, email); // a second, parked session of the same user
    expect(await prisma.authSession.count({ where: { userId: client.user.id } })).toBe(2);

    breakAuditStore();
    expectError(
      await client.post(`${API_PREFIX}/users/me/2fa/disable`, {
        code: totpCode(secret, totpStep() + 1),
      }),
      'LSE-SYS-001',
      500,
    );
    const user = await prisma.user.findUniqueOrThrow({ where: { id: client.user.id } });
    expect(user.totpEnabledAt).not.toBeNull();
    expect(user.totpSecretEnc).not.toBeNull();
    expect(await prisma.totpRecoveryCode.count({ where: { userId: client.user.id } })).toBe(
      RECOVERY_CODE_COUNT,
    );
    expect(await prisma.authSession.count({ where: { userId: client.user.id } })).toBe(2);
  });

  it('personal API token create/delete and BYOK key delete roll back when the audit append fails', async () => {
    const { owner, org } = await ownerWithOrg();
    const spy = breakAuditStore();
    expectError(
      await owner.post(`${API_PREFIX}/users/me/tokens`, {
        orgId: org.id,
        name: 'CI',
        scopes: ['org:read'],
      }),
      'LSE-SYS-001',
      500,
    );
    expect(await prisma.apiToken.count({ where: { userId: owner.user.id } })).toBe(0);

    spy.mockRestore();
    const created = await owner.post(`${API_PREFIX}/users/me/tokens`, {
      orgId: org.id,
      name: 'CI',
      scopes: ['org:read'],
    });
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    const key = await prisma.apiKey.create({
      data: {
        userId: owner.user.id,
        provider: 'anthropic',
        keyEnc: Buffer.from('x'),
        dataKeyEnc: Buffer.from('x'),
        iv: Buffer.from('x'),
        last4: 'abcd',
        status: 'ACTIVE',
      },
    });

    breakAuditStore();
    expectError(
      await owner.delete(`${API_PREFIX}/users/me/tokens/${created.body.data.id as string}`),
      'LSE-SYS-001',
      500,
    );
    expect(await prisma.apiToken.count({ where: { userId: owner.user.id } })).toBe(1);
    expectError(
      await owner.delete(`${API_PREFIX}/users/me/api-keys/${key.id}`),
      'LSE-SYS-001',
      500,
    );
    expect(await prisma.apiKey.count({ where: { id: key.id } })).toBe(1);
  });

  it('the healthy path still writes exactly one audit row per change', async () => {
    const { owner, org } = await ownerWithOrg();
    expect((await owner.put(identityUrl(org.id, '/sso'), ssoBody)).status).toBe(200);
    expect(
      (await owner.put(identityUrl(org.id, '/security'), { requireAdmin2fa: false })).status,
    ).toBe(200);
    expect((await owner.delete(identityUrl(org.id, '/sso'))).status).toBe(204);
    const actions = (
      await prisma.auditLog.findMany({ where: { orgId: org.id }, orderBy: { createdAt: 'asc' } })
    ).map((r) => r.action);
    expect(actions.filter((a) => a === 'sso.update')).toHaveLength(1);
    expect(actions.filter((a) => a === 'security.update')).toHaveLength(1);
    expect(actions.filter((a) => a === 'sso.delete')).toHaveLength(1);
  });
});

describe('P10-SEC-011 remainder: governance, JIT and deletion-sweep audits are in the same transaction', () => {
  it('retention settings roll back when the audit append fails', async () => {
    const { owner, org } = await ownerWithOrg();
    const before = (await prisma.organization.findUniqueOrThrow({ where: { id: org.id } })).policy;
    breakAuditStore();
    expectError(
      await owner.put(`${API_PREFIX}/orgs/${org.id}/retention`, {
        transcripts: 30,
        rawToolOutput: 7,
        screenshots: 14,
        auditLog: 90,
      }),
      'LSE-SYS-001',
      500,
    );
    expect((await prisma.organization.findUniqueOrThrow({ where: { id: org.id } })).policy).toEqual(
      before,
    );
    expect(await prisma.auditLog.count({ where: { action: 'retention.update' } })).toBe(0);
  });

  it('policy-pack application rolls back on every project when the audit append fails', async () => {
    const { owner, org } = await ownerWithOrg();
    const p1 = await createReadyProject(ctx, org.id, { deniedFilePatterns: ['secrets/**'] });
    const p2 = await createReadyProject(ctx, org.id, { deniedFilePatterns: ['secrets/**'] });
    const snapshot = async () =>
      prisma.project.findMany({
        where: { id: { in: [p1.id, p2.id] } },
        orderBy: { id: 'asc' },
        select: {
          deniedFilePatterns: true,
          commandPolicy: true,
          approvalGates: true,
          appliedPolicyPacks: true,
        },
      });
    const before = await snapshot();
    breakAuditStore();
    expectError(
      await owner.post(
        `${API_PREFIX}/orgs/${org.id}/policy-packs/builtin:no-dependency-changes/apply`,
        {
          projectIds: [p1.id, p2.id],
        },
      ),
      'LSE-SYS-001',
      500,
    );
    expect(await snapshot()).toEqual(before);
    expect(await prisma.auditLog.count({ where: { action: 'policy_pack.apply' } })).toBe(0);
  });

  it('SSO JIT provisioning leaves no account, identity or membership when the audit append fails', async () => {
    const idp = createMockIdp([rsa]);
    handlers.current = idp.handlers();
    const owner = await login(app, 'owner@atomic-jit.test');
    const org = await createOrg(owner);
    const domain = await owner.post(identityUrl(org.id, '/domains'), { domain: 'atomic-jit.test' });
    expect(domain.status, JSON.stringify(domain.body)).toBe(201);
    const rec = domain.body.data.verificationRecord as { name: string; value: string };
    dns.txt.set(rec.name, [[rec.value]]);
    expect(
      (await owner.post(identityUrl(org.id, `/domains/${domain.body.data.id}/verify`))).status,
    ).toBe(200);
    const sso = await owner.put(identityUrl(org.id, '/sso'), {
      ...ssoBody,
      enabled: true,
      jitProvisioning: true,
    });
    expect(sso.status, JSON.stringify(sso.body)).toBe(200);
    invalidateOrgSecurityCache(ctx);

    const agent = request.agent(app);
    const start = await agent.get(`${API_PREFIX}/auth/sso/${org.slug}/start?returnTo=/dashboard`);
    expect(start.status, JSON.stringify(start.body)).toBe(302);
    const params = authorizeParams(start.headers.location as string);
    idp.nextIdToken = makeIdToken({
      key: rsa,
      nonce: params.get('nonce') as string,
      email: 'jit@atomic-jit.test',
    });
    const usersBefore = await prisma.user.count();
    const membersBefore = await prisma.orgMember.count({ where: { orgId: org.id } });

    breakAuditStore();
    const callback = await agent.get(
      `${API_PREFIX}/auth/sso/${org.slug}/callback?code=c1&state=${encodeURIComponent(
        params.get('state') as string,
      )}`,
    );
    expect(callback.status).toBe(302);
    const location = new URL(callback.headers.location as string, 'http://localhost');
    expect(location.searchParams.get('error')).toBe('LSE-SYS-001');
    vi.restoreAllMocks();
    expect((await agent.get(`${API_PREFIX}/auth/me`)).status).toBe(401);
    expect(await prisma.user.count()).toBe(usersBefore);
    expect(await prisma.user.count({ where: { email: 'jit@atomic-jit.test' } })).toBe(0);
    expect(await prisma.ssoIdentity.count()).toBe(0);
    expect(await prisma.orgMember.count({ where: { orgId: org.id } })).toBe(membersBefore);
    expect(await prisma.authSession.count({ where: { ssoOrgId: org.id } })).toBe(0);
  });

  it('linking an existing account to an SSO identity rolls back (no identity, no session) when the audit append fails', async () => {
    const idp = createMockIdp([rsa]);
    handlers.current = idp.handlers();
    const owner = await login(app, 'owner@atomic-link.test');
    const org = await createOrg(owner);
    // An existing account that joined the org by its own action (not SCIM): linking is allowed.
    const member = await login(app, 'member@atomic-link.test');
    await addMember(org.id, member.user.id, 'MEMBER');
    const domain = await owner.post(identityUrl(org.id, '/domains'), {
      domain: 'atomic-link.test',
    });
    expect(domain.status, JSON.stringify(domain.body)).toBe(201);
    const rec = domain.body.data.verificationRecord as { name: string; value: string };
    dns.txt.set(rec.name, [[rec.value]]);
    expect(
      (await owner.post(identityUrl(org.id, `/domains/${domain.body.data.id}/verify`))).status,
    ).toBe(200);
    const sso = await owner.put(identityUrl(org.id, '/sso'), { ...ssoBody, enabled: true });
    expect(sso.status, JSON.stringify(sso.body)).toBe(200);
    invalidateOrgSecurityCache(ctx);

    const signIn = async (code: string) => {
      const agent = request.agent(app);
      const start = await agent.get(`${API_PREFIX}/auth/sso/${org.slug}/start?returnTo=/dashboard`);
      expect(start.status, JSON.stringify(start.body)).toBe(302);
      const params = authorizeParams(start.headers.location as string);
      idp.nextIdToken = makeIdToken({
        key: rsa,
        nonce: params.get('nonce') as string,
        email: 'member@atomic-link.test',
      });
      const callback = await agent.get(
        `${API_PREFIX}/auth/sso/${org.slug}/callback?code=${code}&state=${encodeURIComponent(
          params.get('state') as string,
        )}`,
      );
      expect(callback.status).toBe(302);
      return {
        agent,
        error: new URL(callback.headers.location as string, 'http://localhost').searchParams.get(
          'error',
        ),
      };
    };

    breakAuditStore();
    const failed = await signIn('c1');
    expect(failed.error).toBe('LSE-SYS-001');
    vi.restoreAllMocks();
    expect((await failed.agent.get(`${API_PREFIX}/auth/me`)).status).toBe(401);
    expect(await prisma.ssoIdentity.count({ where: { userId: member.user.id } })).toBe(0);
    expect(await prisma.authSession.count({ where: { ssoOrgId: org.id } })).toBe(0);
    expect(await prisma.auditLog.count({ where: { action: 'auth.sso_linked' } })).toBe(0);

    // Healthy store: the link and exactly one `auth.sso_linked` row land together.
    const ok = await signIn('c2');
    expect(ok.error).toBeNull();
    expect((await ok.agent.get(`${API_PREFIX}/auth/me`)).status).toBe(200);
    expect(await prisma.ssoIdentity.count({ where: { userId: member.user.id } })).toBe(1);
    expect(await prisma.auditLog.count({ where: { action: 'auth.sso_linked' } })).toBe(1);
  });

  it('the sole-owner failure of an account-deletion sweep stays PENDING when the audit append fails', async () => {
    const leaving = await login(app, 'leaving-owner@example.com');
    const org = await createOrg(leaving);
    const other = await login(app);
    await addMember(org.id, other.user.id, 'OWNER');
    const scheduled = await leaving.post(`${API_PREFIX}/users/me/privacy/deletion`, {
      confirm: 'leaving-owner@example.com',
    });
    expect(scheduled.status, JSON.stringify(scheduled.body)).toBe(201);
    const due = new Date(scheduled.body.data.scheduledFor as string);
    // The co-owner leaves during the grace period: the account is now the org's only owner.
    await prisma.orgMember.deleteMany({ where: { orgId: org.id, userId: other.user.id } });

    breakAuditStore();
    const out = await runDeletionSweep(ctx, { now: new Date(due.getTime() + 1000) });
    expect(out.failed).toBe(1);
    const req = await prisma.deletionRequest.findUniqueOrThrow({
      where: { id: scheduled.body.data.id as string },
    });
    expect(req.status).toBe('PENDING');
    expect(
      (await prisma.user.findUniqueOrThrow({ where: { id: leaving.user.id } })).deletionScheduledAt,
    ).not.toBeNull();
    expect(
      await prisma.auditLog.count({
        where: { action: 'deletion.cancel', actorId: leaving.user.id },
      }),
    ).toBe(0);

    // Healthy store: the FAILED transition and its audit row land together.
    vi.restoreAllMocks();
    expect((await runDeletionSweep(ctx, { now: new Date(due.getTime() + 2000) })).failed).toBe(1);
    expect((await prisma.deletionRequest.findUniqueOrThrow({ where: { id: req.id } })).status).toBe(
      'FAILED',
    );
    expect(
      await prisma.auditLog.count({
        where: { action: 'deletion.cancel', actorId: leaving.user.id },
      }),
    ).toBe(1);
  });
});
