/**
 * Phase 10 foundation: migration (audit immutability trigger, new tables), new error codes and
 * their envelopes, env vars, feature flags, mount points of the W1/W2/W3 stub routers, job names,
 * client IP resolution and the Caller → OrgAccessSubject mapping (phase10-design.md).
 */
import { Prisma } from '@prisma/client';
import request from 'supertest';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import {
  API_PREFIX,
  ERROR_CODES,
  FEATURE_FLAGS,
  SCIM_BASE_PATH,
  type ErrorCode,
} from '@loose/shared';
import { EnvError, loadEnv } from '../src/config/env';
import { AppError } from '../src/lib/errors';
import { HARDENING_SCHEDULES, QUEUE_NAMES } from '../src/lib/jobs';
import { clientIpFromChain, normalizeClientIp } from '../src/lib/net/clientIp';
import { S3ObjectStorage, s3ConfigFromEnv } from '../src/lib/storage';
import { orgAccessSubjectFromCaller } from '../src/services/identity/accessPolicy';
import { MAINTENANCE_SCHEDULES } from '../src/services/sessionJobs.service';
import {
  addMember,
  createOrg,
  expectError,
  login,
  makeApp,
  resetDb,
  TEST_SECRETS,
  testEnv,
  testPrisma,
  type Client,
} from './helpers';

const PHASE10_CODES = [
  'LSE-AUTH-010',
  'LSE-AUTH-011',
  'LSE-AUTH-012',
  'LSE-ORG-010',
  'LSE-ORG-011',
  'LSE-ORG-012',
  'LSE-SYS-008',
] as const satisfies readonly ErrorCode[];

const prisma = testPrisma();
const { app, ctx } = makeApp({
  extraApiRoutes: (r) => {
    r.get('/__phase10-error/:code', (req) => {
      throw new AppError(req.params.code as ErrorCode, { devMessage: 'phase 10 envelope test' });
    });
  },
});

afterAll(async () => {
  await ctx.jobs.onIdle();
  await prisma.$disconnect();
});

beforeEach(async () => {
  await ctx.jobs.onIdle();
  await resetDb(prisma);
});

async function orgWithRoles() {
  const owner = await login(app);
  const org = await createOrg(owner);
  const member = await login(app);
  await addMember(org.id, member.user.id, 'MEMBER');
  const viewer = await login(app);
  await addMember(org.id, viewer.user.id, 'VIEWER');
  return { owner, member, viewer, org };
}

describe('new error codes (catalog → envelope)', () => {
  it.each(PHASE10_CODES)('%s renders a §16.2 envelope with its catalog status', async (code) => {
    const res = await request(app).get(`${API_PREFIX}/__phase10-error/${code}`);
    expectError(res, code, ERROR_CODES[code].status);
    expect(res.body.error.userMessage).toBe(ERROR_CODES[code].userMessage);
    expect(res.body.error.docs).toBe(`https://docs.loose.ai/errors/${code}`);
    if (code === 'LSE-SYS-008') expect(res.body.error.retryable).toBe(true);
  });
});

describe('migration 20261017120000_phase10_hardening', () => {
  async function auditRow(orgId: string | null, actorId: string | null) {
    return prisma.auditLog.create({
      data: {
        orgId,
        actorId,
        action: 'org.update',
        target: 't',
        ip: '203.0.113.9',
        meta: { a: 1 },
      },
    });
  }

  it('makes audit rows immutable (UPDATE/DELETE refused)', async () => {
    const { owner, org } = await orgWithRoles();
    const row = await auditRow(org.id, owner.user.id);
    await expect(
      prisma.auditLog.update({ where: { id: row.id }, data: { action: 'org.delete' } }),
    ).rejects.toThrow(/immutable/);
    await expect(
      prisma.auditLog.update({ where: { id: row.id }, data: { meta: { a: 2 } } }),
    ).rejects.toThrow(/immutable/);
    await expect(
      prisma.auditLog.update({ where: { id: row.id }, data: { actorId: 'someone-else' } }),
    ).rejects.toThrow();
    await expect(prisma.auditLog.delete({ where: { id: row.id } })).rejects.toThrow(/immutable/);
    await expect(prisma.auditLog.deleteMany({ where: { orgId: org.id } })).rejects.toThrow(
      /immutable/,
    );
    const still = await prisma.auditLog.findUnique({ where: { id: row.id } });
    expect(still?.action).toBe('org.update');
  });

  it('allows GDPR redaction (actorId / ip → NULL) and FK cascades', async () => {
    const { owner, member, org } = await orgWithRoles();
    const a = await auditRow(org.id, owner.user.id);
    const redacted = await prisma.auditLog.update({
      where: { id: a.id },
      data: { ip: null, actorId: null },
    });
    expect(redacted.ip).toBeNull();
    // user deletion → FK SET NULL on actorId (fired by an RI trigger)
    const b = await auditRow(null, member.user.id);
    await prisma.user.delete({ where: { id: member.user.id } });
    expect((await prisma.auditLog.findUnique({ where: { id: b.id } }))?.actorId).toBeNull();
    // org deletion → cascade delete of its audit rows
    await prisma.organization.delete({ where: { id: org.id } });
    expect(await prisma.auditLog.count({ where: { id: a.id } })).toBe(0);
  });

  it('allows deletes inside a loose.audit_maintenance transaction only', async () => {
    const { owner, org } = await orgWithRoles();
    const row = await auditRow(org.id, owner.user.id);
    await prisma.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT set_config('loose.audit_maintenance', 'on', true)`;
      await tx.auditLog.delete({ where: { id: row.id } });
    });
    expect(await prisma.auditLog.count({ where: { id: row.id } })).toBe(0);
    // the setting is transaction-local
    const again = await auditRow(org.id, owner.user.id);
    await expect(prisma.auditLog.delete({ where: { id: again.id } })).rejects.toThrow(/immutable/);
  });

  it('enforces one chain position per (chain, seq)', async () => {
    const { org } = await orgWithRoles();
    // A position far past the org's own entries (rows must be filed under their org's chain).
    const base = { orgId: org.id, action: 'org.update', chain: org.id, prevHash: 'GENESIS' };
    await prisma.auditLog.create({ data: { ...base, seq: 1000, hash: 'a' } });
    await expect(
      prisma.auditLog.create({ data: { ...base, seq: 1000, hash: 'b' } }),
    ).rejects.toThrow(Prisma.PrismaClientKnownRequestError);
  });

  it('creates the identity and governance tables with safe defaults', async () => {
    const { owner, org } = await orgWithRoles();
    const o = await prisma.organization.findUniqueOrThrow({ where: { id: org.id } });
    expect(o).toMatchObject({
      ipAllowlistEnabled: false,
      ipAllowlist: [],
      requireAdmin2fa: false,
      featureFlags: {},
      deletionScheduledAt: null,
    });
    const sso = await prisma.ssoConnection.create({ data: { orgId: org.id } });
    expect(sso).toMatchObject({
      protocol: 'OIDC',
      enabled: false,
      defaultRole: 'MEMBER',
      jitProvisioning: true,
      enforce: false,
      allowOwnerBypass: true,
    });
    await prisma.orgDomain.create({
      data: { orgId: org.id, domain: 'example.com', verificationToken: 'tok' },
    });
    await prisma.scimToken.create({ data: { orgId: org.id, name: 'okta', hash: 'h1' } });
    await prisma.policyPack.create({
      data: { orgId: org.id, slug: 'docs', name: 'Docs', rules: { maxBudgetUsd: 1 } },
    });
    await prisma.dataExport.create({
      data: { kind: 'ORG', orgId: org.id, requestedById: owner.user.id },
    });
    const del = await prisma.deletionRequest.create({
      data: { kind: 'ORG', orgId: org.id, requestedById: owner.user.id, scheduledFor: new Date() },
    });
    // the deletion record survives (de-identified) as proof of deletion
    await prisma.organization.delete({ where: { id: org.id } });
    expect(await prisma.deletionRequest.findUnique({ where: { id: del.id } })).toMatchObject({
      orgId: null,
      status: 'PENDING',
    });
    expect(await prisma.ssoConnection.count()).toBe(0);
    const user = await prisma.user.findUniqueOrThrow({ where: { id: owner.user.id } });
    expect(user).toMatchObject({
      totpSecretEnc: null,
      totpEnabledAt: null,
      deletionScheduledAt: null,
    });
  });
});

/**
 * Mount points only: these assertions stay true when W1/W2/W3 replace the 503 stubs, so owners
 * never need to edit this file. "Routed" = not the global 404 handler and not a 500.
 */
function expectRouted(res: request.Response) {
  const dev = String(res.body?.error?.devMessage ?? '');
  expect(dev.startsWith('No route for'), `${res.status} ${JSON.stringify(res.body)}`).toBe(false);
  expect(res.status).not.toBe(500);
}

describe('mounted Phase 10 routes', () => {
  let r: { owner: Client; member: Client; viewer: Client; org: { id: string } };
  beforeEach(async () => {
    r = await orgWithRoles();
  });

  it('identity (W1): SCIM before cookies, SSO / 2FA before /auth, org identity ADMIN+', async () => {
    // sanity: the global 404 is what expectRouted rejects
    const missing = await request(app).get(`${API_PREFIX}/definitely-not-a-route`);
    expect(String(missing.body.error.devMessage)).toMatch(/^No route for/);
    expectRouted(await request(app).get(`${API_PREFIX}${SCIM_BASE_PATH}/Users`));
    expectRouted(await request(app).get(`${API_PREFIX}/auth/sso/discover?email=a@example.com`));
    expectRouted(await r.owner.post(`${API_PREFIX}/auth/2fa/verify`, { code: '123456' }));
    expectRouted(await r.owner.get(`${API_PREFIX}/users/me/2fa`));
    // existing /users/me keeps working next to /users/me/2fa
    expect((await r.owner.get(`${API_PREFIX}/users/me`)).status).toBe(200);
    expectRouted(await r.owner.get(`${API_PREFIX}/orgs/${r.org.id}/identity/security`));
    expectError(
      await r.member.get(`${API_PREFIX}/orgs/${r.org.id}/identity/security`),
      'LSE-ORG-002',
      403,
    );
  });

  it('governance (W2): privacy, audit export/verify, retention, exports, deletion, packs', async () => {
    const base = `${API_PREFIX}/orgs/${r.org.id}`;
    expectRouted(await r.owner.get(`${API_PREFIX}/users/me/privacy/exports`));
    expectRouted(await r.owner.get(`${base}/audit-log/verify`));
    // the existing audit list keeps working next to the new sub-routes
    const list = await r.owner.get(`${base}/audit-log`);
    expect(list.status).toBe(200);
    expect(Array.isArray(list.body.data)).toBe(true);
    for (const path of ['retention', 'data-exports', 'deletion', 'policy-packs']) {
      expectRouted(await r.owner.get(`${base}/${path}`));
    }
    expectError(await r.member.get(`${base}/retention`), 'LSE-ORG-002', 403);
    expectError(await r.member.get(`${base}/policy-packs`), 'LSE-ORG-002', 403);
    expectError(await r.member.get(`${base}/data-exports`), 'LSE-ORG-002', 403);
  });

  it('observability (W3): /metrics hidden without a token, feature flags readable', async () => {
    expect((await request(app).get('/metrics')).status).toBe(404);
    const pub = await request(app).get(`${API_PREFIX}/feature-flags`);
    expect(pub.status).toBe(200);
    expect(Object.keys(pub.body.data.flags).sort()).toEqual([...FEATURE_FLAGS].sort());
    expect(pub.body.data.flags.sso_saml).toBe(false);

    await prisma.organization.update({
      where: { id: r.org.id },
      data: { featureFlags: { plugins: false, bogus: true } },
    });
    const orgFlags = await r.viewer.get(`${API_PREFIX}/orgs/${r.org.id}/feature-flags`);
    expect(orgFlags.status).toBe(200);
    expect(orgFlags.body.data.flags.plugins).toBe(false);
    expect(orgFlags.body.data.flags.scim).toBe(true);
    expect(orgFlags.body.data.orgControllable).toContain('plugins');
    expectError(
      await r.member.put(`${API_PREFIX}/orgs/${r.org.id}/feature-flags`, {
        flags: { plugins: true },
      }),
      'LSE-ORG-002',
      403,
    );
  });
});

describe('context, jobs and helpers', () => {
  it('exposes instanceId, metrics, feature flags and DNS on the context', () => {
    expect(ctx.instanceId).toMatch(/^[A-Za-z0-9_.-]+-\d+-[0-9a-f]{6}$/);
    expect(ctx.metrics.enabled).toBe(true); // real registry since W3 (was the disabled stub)
    expect(ctx.featureFlags.isEnabled('sso_oidc')).toBe(true);
    expect(typeof ctx.dns.lookup).toBe('function');
    const custom = makeApp({
      env: { FEATURE_FLAGS: 'sso_oidc=off' },
      context: { instanceId: 'api-1' },
    });
    expect(custom.ctx.instanceId).toBe('api-1');
    expect(custom.ctx.featureFlags.isEnabled('sso_oidc')).toBe(false);
    expect(() => custom.ctx.featureFlags.assertEnabled('sso_oidc')).toThrow(AppError);
  });

  it('registers the Phase 10 queues and schedules', async () => {
    for (const q of ['data-export', 'retention-purge', 'deletion-sweep'] as const) {
      expect(QUEUE_NAMES).toContain(q);
    }
    expect(HARDENING_SCHEDULES.map((s) => s.queue)).toEqual(['retention-purge', 'deletion-sweep']);
    for (const s of HARDENING_SCHEDULES) expect(MAINTENANCE_SCHEDULES).toContainEqual(s);
    await ctx.jobs.enqueue('data-export', { exportId: 'nope' });
    await ctx.jobs.onIdle();
  });

  it('resolves client IPs like Express trust proxy', () => {
    expect(clientIpFromChain('::ffff:10.0.0.5', undefined, 0)).toBe('10.0.0.5');
    expect(clientIpFromChain('10.0.0.5', '203.0.113.9', 0)).toBe('10.0.0.5');
    expect(clientIpFromChain('10.0.0.5', '203.0.113.9', 1)).toBe('203.0.113.9');
    expect(clientIpFromChain('10.0.0.5', '198.51.100.1, 203.0.113.9', 1)).toBe('203.0.113.9');
    expect(clientIpFromChain('10.0.0.5', ['198.51.100.1', '203.0.113.9'], 2)).toBe('198.51.100.1');
    expect(clientIpFromChain('10.0.0.5', '203.0.113.9', 5)).toBe('203.0.113.9');
    expect(clientIpFromChain(undefined, undefined, 0)).toBeUndefined();
    expect(normalizeClientIp(' 2001:DB8::1 ')).toBe('2001:db8::1');
  });

  it('maps callers to org access subjects (internal callers have no IP)', async () => {
    const user = await prisma.user.create({ data: { email: 'subject@example.com' } });
    expect(orgAccessSubjectFromCaller({ user }).via).toBe('internal');
    expect(orgAccessSubjectFromCaller({ user, ip: '203.0.113.9' }).via).toBe('session');
    const token = { orgId: 'o', scopes: [] } as unknown as Parameters<
      typeof orgAccessSubjectFromCaller
    >[0]['apiToken'];
    expect(orgAccessSubjectFromCaller({ user, apiToken: token, ip: '1.1.1.1' }).via).toBe('token');
  });
});

describe('Phase 10 environment', () => {
  const base = {
    DATABASE_URL: 'postgresql://x@localhost/db',
    REDIS_URL: 'redis://localhost:6379',
    SESSION_SECRET: TEST_SECRETS.SESSION_SECRET,
    LOCAL_KMS_MASTER_KEY: TEST_SECRETS.LOCAL_KMS_MASTER_KEY,
  };
  const problems = (src: Record<string, string>) => {
    try {
      loadEnv({ ...base, ...src });
      return [];
    } catch (err) {
      expect(err).toBeInstanceOf(EnvError);
      return (err as EnvError).problems;
    }
  };

  it('defaults keep every new feature off / safe', () => {
    const env = loadEnv(base);
    expect(env).toMatchObject({
      DELETION_GRACE_DAYS: 30,
      DATA_EXPORT_TTL_HOURS: 72,
      TOTP_ISSUER: 'loose.ai',
      SSO_HTTP_TIMEOUT_MS: 5000,
      S3_REGION: 'us-east-1',
      S3_FORCE_PATH_STYLE: false,
      S3_SIGNED_URL_TTL_SEC: 300,
      METRICS_HOST: '127.0.0.1',
      FEATURE_FLAG_OVERRIDES: {},
    });
    expect(env.METRICS_TOKEN).toBeUndefined();
    expect(env.AUDIT_CHAIN_SECRET).toBeUndefined();
    expect(loadEnv({ ...base, SANDBOX_PROVIDER: 'fake' }).READYZ_CHECK_E2B).toBe(false);
    expect(loadEnv({ ...base, SANDBOX_PROVIDER: 'e2b' }).READYZ_CHECK_E2B).toBe(true);
    expect(loadEnv({ ...base, FEATURE_FLAGS: 'plugins=off' }).FEATURE_FLAG_OVERRIDES).toEqual({
      plugins: false,
    });
    // production still needs nothing new
    expect(() => loadEnv({ ...base, NODE_ENV: 'production', E2B_API_KEY: 'x' })).not.toThrow();
  });

  it('refuses bad configuration without echoing values', () => {
    expect(problems({ FEATURE_FLAGS: 'not_a_flag=on' }).join()).toMatch(/FEATURE_FLAGS/);
    expect(problems({ ARTIFACT_STORAGE: 's3' }).join()).toMatch(/S3_BUCKET/);
    expect(problems({ S3_ACCESS_KEY_ID: 'AKIAEXAMPLE' }).join()).toMatch(/S3_SECRET_ACCESS_KEY/);
    expect(
      problems({
        NODE_ENV: 'production',
        E2B_API_KEY: 'x',
        ARTIFACT_STORAGE: 's3',
        S3_BUCKET: 'b',
        S3_ENDPOINT: 'http://minio:9000',
      }).join(),
    ).toMatch(/S3_ENDPOINT/);
    const short = problems({ METRICS_TOKEN: 'short-token-value' });
    expect(short.join()).toMatch(/METRICS_TOKEN/);
    expect(short.join()).not.toContain('short-token-value');
    expect(problems({ AUDIT_CHAIN_SECRET: 'tiny' }).join()).toMatch(/AUDIT_CHAIN_SECRET/);
    expect(problems({ DELETION_GRACE_DAYS: '365' }).join()).toMatch(/DELETION_GRACE_DAYS/);
  });

  it('maps S3 settings for the storage driver (stub until W2)', async () => {
    const env = testEnv({
      ARTIFACT_STORAGE: 's3',
      S3_BUCKET: 'loose-artifacts',
      S3_ENDPOINT: 'http://127.0.0.1:9000',
      S3_FORCE_PATH_STYLE: 'true',
      S3_PREFIX: 'test',
    });
    const cfg = s3ConfigFromEnv(env);
    expect(cfg).toMatchObject({
      bucket: 'loose-artifacts',
      endpoint: 'http://127.0.0.1:9000',
      forcePathStyle: true,
      prefix: 'test/',
      signedUrlTtlSec: 300,
    });
    // The driver itself is covered by phase10.s3.test.ts (the W1 stub this used to assert is gone).
    expect(new S3ObjectStorage(cfg)).toBeInstanceOf(S3ObjectStorage);
  });
});
