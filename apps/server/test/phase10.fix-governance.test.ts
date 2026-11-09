/**
 * Phase 10 audit fixes (governance / infrastructure): regression tests for
 * P10-SEC-005, -006, -011, -012, -013, -015, -016, -017 and the acceptance gaps P1 (Dockerfiles),
 * P4 (OrgDto.deletionScheduledAt) and P5 (retention staleness gauge + alert).
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { Readable } from 'node:stream';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { METRIC_NAMES, createMetricsRegistry } from '../src/lib/metrics';
import { EnvError, loadEnv } from '../src/config/env';
import { isLoopbackHost, isNonPublicAddress } from '../src/lib/net/ip';
import { isPrivateAddress, resolvePublicAddresses, safeFetch } from '../src/lib/net/safeFetch';
import { S3ObjectStorage } from '../src/lib/storage';
import { FAIL_CLOSED_AUDIT_ACTIONS } from '../src/services/audit.service';
import { getAuditCutover, verifyChain } from '../src/services/governance/auditChain';
import { exportLinkTtlSec, openDataExportDownload } from '../src/services/governance/dataExport';
import {
  RETENTION_LAST_SUCCESS_KEY,
  runRetentionPurge,
  sealLegacyAuditRows,
} from '../src/services/governance/retention';
import { startMetricsServer } from '../src/services/observability/register';
import {
  TEST_SECRETS,
  addMember,
  createOrg,
  expectError,
  login,
  makeApp,
  resetDb,
  testPrisma,
} from './helpers';
import type { AppContext } from '../src/context';
import { legacyAuditRow } from './auditFixtures';

const prisma = testPrisma();
const { app, ctx } = makeApp();
const read = (rel: string) => readFileSync(new URL(`../../../${rel}`, import.meta.url), 'utf8');

afterAll(async () => {
  await ctx.jobs.onIdle();
  await prisma.$disconnect();
});

beforeEach(async () => {
  await ctx.jobs.onIdle();
  await resetDb(prisma);
});

afterEach(() => {
  vi.restoreAllMocks();
});

/** Make every audit append fail (the chain key cannot be read). */
function breakAuditStore() {
  return vi.spyOn(ctx.audit, 'chainKey', 'get').mockImplementation(() => {
    throw new Error('audit store unavailable');
  });
}

// ---------------------------------------------------------------------------------------------
describe('P10-SEC-005: no immediate organization deletion', () => {
  it('DELETE /orgs/:orgId does not exist and leaves the organization intact', async () => {
    const owner = await login(app);
    const org = await createOrg(owner);
    expectError(await owner.delete(`/api/v1/orgs/${org.id}`), 'LSE-NF-001', 404);
    expect(await prisma.organization.count({ where: { id: org.id } })).toBe(1);
    expect(await prisma.orgMember.count({ where: { orgId: org.id } })).toBe(1);
  });

  it('the only way to delete is the confirmed, grace-period flow (nothing is removed at once)', async () => {
    const owner = await login(app);
    const org = await createOrg(owner);
    const url = `/api/v1/orgs/${org.id}/deletion`;
    expectError(await owner.post(url, { confirm: 'wrong-slug' }), 'LSE-VAL-001', 400);
    expect(await prisma.deletionRequest.count()).toBe(0);
    const res = await owner.post(url, { confirm: org.slug });
    expect(res.status).toBe(201);
    expect(res.body.data).toMatchObject({ kind: 'ORG', status: 'PENDING' });
    expect(await prisma.organization.count({ where: { id: org.id } })).toBe(1);
  });
});

// ---------------------------------------------------------------------------------------------
describe('P10-SEC-006: audit verification fails on unchained rows after the cutover', () => {
  async function setup() {
    const owner = await login(app);
    const org = await createOrg(owner);
    await ctx.audit.record({ orgId: org.id, action: 'org.update', target: 'chained' });
    return { owner, org, key: ctx.audit.chainKey };
  }

  it('pre-cutover legacy rows are tolerated (and sealable); a post-cutover unchained row is a break', async () => {
    const { owner, org, key } = await setup();
    await legacyAuditRow(prisma, {
      orgId: org.id,
      action: 'org.update',
      target: 'legacy',
      createdAt: new Date(Date.UTC(2025, 0, 1)),
    });
    expect(await verifyChain(prisma, key, org.id)).toMatchObject({
      ok: true,
      legacyUnchained: 1,
      brokenAt: null,
    });

    // Forged "legacy" row inserted after the cutover (what an attacker with INSERT access can do).
    const forged = await prisma.auditLog.create({
      data: { orgId: org.id, action: 'member.remove', target: 'forged' },
    });
    const v = await verifyChain(prisma, key, org.id);
    expect(v.ok).toBe(false);
    expect(v.brokenAt).toEqual({ seq: null, id: forged.id, reason: 'unchained_after_cutover' });
    expect(v.legacyUnchained).toBe(1);

    // The HTTP endpoint reports the same.
    const res = await owner.get(`/api/v1/orgs/${org.id}/audit-log/verify`);
    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({
      ok: false,
      brokenAt: { id: forged.id, reason: 'unchained_after_cutover' },
    });

    // Sealing must not launder the forged row into the chain: only the legacy row is sealed.
    expect(await sealLegacyAuditRows(ctx)).toBe(1);
    expect(await prisma.auditLog.findUniqueOrThrow({ where: { id: forged.id } })).toMatchObject({
      chain: null,
      hash: null,
    });
    expect((await verifyChain(prisma, key, org.id)).ok).toBe(false);
  });

  it('the global chain (user-level events) is covered too', async () => {
    const { key } = await setup();
    const forged = await prisma.auditLog.create({
      data: { orgId: null, action: 'auth.sign_in', target: 'forged-global' },
    });
    const v = await verifyChain(prisma, key, 'global');
    expect(v).toMatchObject({ ok: false, brokenAt: { id: forged.id } });
  });

  it('a backdated forged row cannot pose as legacy (insert guard trigger)', async () => {
    const { owner, org, key } = await setup();
    const cutover = await getAuditCutover(prisma);
    // ORM insert with a caller-chosen, pre-cutover createdAt.
    const forged = await prisma.auditLog.create({
      data: {
        orgId: org.id,
        action: 'member.remove',
        target: 'backdated',
        createdAt: new Date(Date.UTC(2025, 0, 1)),
      },
    });
    expect(forged.createdAt.getTime()).toBeGreaterThanOrEqual(cutover.getTime());
    let v = await verifyChain(prisma, key, org.id);
    expect(v).toMatchObject({
      ok: false,
      legacyUnchained: 0,
      brokenAt: { seq: null, id: forged.id, reason: 'unchained_after_cutover' },
    });
    expect((await owner.get(`/api/v1/orgs/${org.id}/audit-log/verify`)).body.data.ok).toBe(false);

    // Raw SQL is overridden the same way.
    await prisma.$executeRaw`
      INSERT INTO "AuditLog" ("id", "orgId", "action", "target", "createdAt", "updatedAt")
      VALUES ('raw-backdated', ${org.id}, 'member.remove', 'raw', TIMESTAMP '2020-01-01', now())`;
    const raw = await prisma.auditLog.findUniqueOrThrow({ where: { id: 'raw-backdated' } });
    expect(raw.createdAt.getTime()).toBeGreaterThanOrEqual(cutover.getTime());

    // Maintenance mode (which the app role can enter) cannot move createdAt back either.
    await expect(
      prisma.$transaction(async (tx) => {
        await tx.$executeRaw`SELECT set_config('loose.audit_maintenance', 'on', true)`;
        await tx.auditLog.update({
          where: { id: forged.id },
          data: { createdAt: new Date(Date.UTC(2025, 0, 1)) },
        });
      }),
    ).rejects.toThrow(/immutable/);
    v = await verifyChain(prisma, key, org.id);
    expect(v.ok).toBe(false);
    expect(v.legacyUnchained).toBe(0);
  });

  it('rows cannot be filed under another chain, and verification catches a misfiled one', async () => {
    const { org, key } = await setup();
    const chained = await prisma.auditLog.findFirstOrThrow({
      where: { chain: org.id },
      orderBy: { seq: 'desc' },
    });
    await expect(
      prisma.auditLog.create({
        data: { orgId: org.id, action: 'org.update', chain: 'elsewhere', seq: 1, hash: 'x' },
      }),
    ).rejects.toThrow(/must be chained/);
    // A chained row can't leave its chain, even in maintenance mode.
    await expect(
      prisma.$transaction(async (tx) => {
        await tx.$executeRaw`SELECT set_config('loose.audit_maintenance', 'on', true)`;
        await tx.auditLog.update({
          where: { id: chained.id },
          data: { chain: null, seq: null, hash: null, prevHash: null },
        });
      }),
    ).rejects.toThrow(/immutable/);
    // Superuser-level bypass of the triggers: verification still reports the misfiled row.
    const misfiled = await legacyAuditRow(prisma, {
      orgId: org.id,
      action: 'member.remove',
      target: 'hidden',
      chain: 'elsewhere',
      seq: 1,
      prevHash: 'GENESIS',
      hash: 'x',
    });
    expect(await verifyChain(prisma, key, org.id)).toMatchObject({
      ok: false,
      brokenAt: { id: misfiled.id, reason: 'hash_mismatch' },
    });
  });

  it('a row in the chain without seq/hash can neither be written nor hide from verification', async () => {
    const { org, key } = await setup();
    await expect(
      prisma.auditLog.create({ data: { orgId: org.id, action: 'org.update', chain: org.id } }),
    ).rejects.toThrow(/no seq\/prevHash\/hash/);
    const chained = await prisma.auditLog.findFirstOrThrow({ where: { chain: org.id } });
    await expect(
      prisma.$transaction(async (tx) => {
        await tx.$executeRaw`SELECT set_config('loose.audit_maintenance', 'on', true)`;
        await tx.auditLog.update({ where: { id: chained.id }, data: { seq: null } });
      }),
    ).rejects.toThrow(/immutable/);
    const hidden = await legacyAuditRow(prisma, {
      orgId: org.id,
      action: 'member.remove',
      target: 'positionless',
      chain: org.id,
    });
    expect(await verifyChain(prisma, key, org.id)).toMatchObject({
      ok: false,
      brokenAt: { seq: null, id: hidden.id, reason: 'missing_hash' },
    });
  });

  it('a missing cutover marker fails closed', async () => {
    const { org, key } = await setup();
    await legacyAuditRow(prisma, {
      orgId: org.id,
      action: 'org.update',
      target: 'legacy',
      createdAt: new Date(Date.UTC(2025, 0, 1)),
    });
    const marker = await prisma.auditChainCutover.findUniqueOrThrow({ where: { id: 'singleton' } });
    await prisma.auditChainCutover.delete({ where: { id: 'singleton' } });
    try {
      const v = await verifyChain(prisma, key, org.id);
      expect(v).toMatchObject({ ok: false, brokenAt: { reason: 'unchained_after_cutover' } });
    } finally {
      await prisma.auditChainCutover.create({ data: marker });
    }
  });
});

// ---------------------------------------------------------------------------------------------
describe('P10-SEC-011: security-sensitive mutations fail closed when the audit append fails', () => {
  async function org3() {
    const owner = await login(app);
    const org = await createOrg(owner);
    const admin = await login(app);
    await addMember(org.id, admin.user.id, 'ADMIN');
    return { owner, admin, org };
  }

  it('lists the privileged actions', () => {
    for (const a of [
      'member.role_change',
      'member.remove',
      'sso.update',
      'scim_token.create',
      'deletion.schedule',
      'deletion.cancel',
      'policy.update',
      'security.update',
    ] as const)
      expect(FAIL_CLOSED_AUDIT_ACTIONS.has(a)).toBe(true);
    expect(FAIL_CLOSED_AUDIT_ACTIONS.has('org.update')).toBe(false);
  });

  it('role change rolls back', async () => {
    const { owner, admin, org } = await org3();
    breakAuditStore();
    const res = await owner.put(`/api/v1/orgs/${org.id}/members/${admin.user.id}`, {
      role: 'MEMBER',
    });
    expectError(res, 'LSE-SYS-001', 500);
    expect(
      (await prisma.orgMember.findFirstOrThrow({ where: { orgId: org.id, userId: admin.user.id } }))
        .role,
    ).toBe('ADMIN');
  });

  it('member removal (and its token revocation) rolls back', async () => {
    const { owner, admin, org } = await org3();
    await prisma.apiToken.create({
      data: {
        userId: admin.user.id,
        orgId: org.id,
        name: 't',
        hash: 'h'.repeat(64),
        scopes: ['projects:read'],
      },
    });
    breakAuditStore();
    expectError(
      await owner.delete(`/api/v1/orgs/${org.id}/members/${admin.user.id}`),
      'LSE-SYS-001',
      500,
    );
    expect(await prisma.orgMember.count({ where: { orgId: org.id } })).toBe(2);
    expect(await prisma.apiToken.count({ where: { orgId: org.id } })).toBe(1);
  });

  it('policy update rolls back', async () => {
    const { owner, org } = await org3();
    const before = (await prisma.organization.findUniqueOrThrow({ where: { id: org.id } })).policy;
    breakAuditStore();
    expectError(
      await owner.put(`/api/v1/orgs/${org.id}/policy`, { commitToMainEnabled: true }),
      'LSE-SYS-001',
      500,
    );
    expect((await prisma.organization.findUniqueOrThrow({ where: { id: org.id } })).policy).toEqual(
      before,
    );
  });

  it('scheduling and cancelling deletion roll back', async () => {
    const { owner, org } = await org3();
    const spy = breakAuditStore();
    expectError(
      await owner.post(`/api/v1/orgs/${org.id}/deletion`, { confirm: org.slug }),
      'LSE-SYS-001',
      500,
    );
    expect(await prisma.deletionRequest.count()).toBe(0);
    expect(
      (await prisma.organization.findUniqueOrThrow({ where: { id: org.id } })).deletionScheduledAt,
    ).toBeNull();

    spy.mockRestore();
    expect(
      (await owner.post(`/api/v1/orgs/${org.id}/deletion`, { confirm: org.slug })).status,
    ).toBe(201);
    breakAuditStore();
    expectError(await owner.delete(`/api/v1/orgs/${org.id}/deletion`), 'LSE-SYS-001', 500);
    expect(await prisma.deletionRequest.count({ where: { status: 'PENDING' } })).toBe(1);
    expect(
      (await prisma.organization.findUniqueOrThrow({ where: { id: org.id } })).deletionScheduledAt,
    ).not.toBeNull();
  });

  it('succeeds and audits when the store is healthy; low-value actions stay best effort', async () => {
    const { owner, admin, org } = await org3();
    expect(
      (
        await owner.put(`/api/v1/orgs/${org.id}/members/${admin.user.id}`, {
          role: 'MEMBER',
        })
      ).status,
    ).toBe(200);
    expect(
      await prisma.auditLog.count({ where: { orgId: org.id, action: 'member.role_change' } }),
    ).toBe(1);
    breakAuditStore();
    // org.update is not in the fail-closed set: the rename still goes through.
    expect((await owner.put(`/api/v1/orgs/${org.id}`, { name: 'Renamed' })).status).toBe(200);
  });
});

// ---------------------------------------------------------------------------------------------
describe('P10-SEC-012: SSRF address classification', () => {
  const blocked = [
    // IPv6 loopback / unspecified, any spelling
    '::1',
    '0:0:0:0:0:0:0:1',
    '0000:0000:0000:0000:0000:0000:0000:0001',
    '::',
    '0:0:0:0:0:0:0:0',
    '[::1]',
    // IPv4-mapped, compressed / expanded / hex / dotted
    '::ffff:127.0.0.1',
    '0:0:0:0:0:ffff:127.0.0.1',
    '0000:0000:0000:0000:0000:ffff:7f00:0001',
    '::ffff:7f00:1',
    '::FFFF:10.0.0.1',
    '::ffff:169.254.169.254',
    '[::ffff:192.168.1.1]',
    // IPv4-compatible (deprecated)
    '::127.0.0.1',
    '::7f00:1',
    '::10.0.0.1',
    // NAT64
    '64:ff9b::7f00:1',
    '64:ff9b::10.0.0.1',
    '64:ff9b:1::1',
    // 6to4 / Teredo
    '2002:7f00:1::',
    '2002:0a00:0001::1',
    '2001:0:4136:e378:8000:63bf:3fff:fdd2',
    // multicast, site-local, link-local, ULA, discard, documentation
    'ff02::1',
    'ff00::',
    'ffff::1',
    'fec0::1',
    'feff::1',
    'fe80::1',
    'fe80::1%eth0',
    'fc00::1',
    'fd12:3456:789a::1',
    '100::1',
    '2001:db8::1',
    '3fff::1',
    // IPv4 special use
    '0.0.0.0',
    '127.0.0.1',
    '10.0.0.1',
    '172.16.0.1',
    '172.31.255.255',
    '192.168.0.1',
    '169.254.169.254',
    '100.64.0.1',
    '192.0.0.1',
    '192.0.2.1',
    '198.51.100.1',
    '203.0.113.1',
    '224.0.0.1',
    '255.255.255.255',
    // legacy IPv4 spellings (inet_aton): decimal, hex, octal, short forms
    '2130706433',
    '0x7f000001',
    '0x7f.0.0.1',
    '0177.0.0.1',
    '017700000001',
    '127.1',
    '127.0.1',
    '0',
    '0x0',
    '4294967295',
    '10.1',
    '0xa9fea9fe',
    '2852039166',
    // garbage is never public
    'garbage',
    '1.2.3.4.5',
    '::g',
    ':::',
    '1::2::3',
    '',
  ];
  const allowed = [
    '8.8.8.8',
    '1.1.1.1',
    '93.184.216.34',
    '2606:4700:4700::1111',
    '2001:4860:4860::8888',
    '2a00:1450:4001:81b::200e',
    '::ffff:8.8.8.8',
    '0:0:0:0:0:ffff:808:808',
  ];

  it.each(blocked)('blocks %j', (address) => {
    expect(isPrivateAddress(address)).toBe(true);
    expect(isNonPublicAddress(address)).toBe(true);
  });

  it.each(allowed)('allows public %s', (address) => {
    expect(isPrivateAddress(address)).toBe(false);
  });

  type Answer = { address: string; family: 4 | 6 };
  const stub = (
    lookup = vi.fn(async (): Promise<Answer[]> => [{ address: '93.184.216.34', family: 4 }]),
  ) =>
    ({
      env: { NODE_ENV: 'test' },
      dns: { lookup, resolveTxt: async () => [] },
      metrics: createMetricsRegistry(),
      fetch: vi.fn(async () => new Response('should not be reached')),
    }) as unknown as AppContext & { fetch: ReturnType<typeof vi.fn> };

  it.each([
    '[::1]',
    '[::ffff:127.0.0.1]',
    '[0:0:0:0:0:ffff:7f00:1]',
    '[ff02::1]',
    '[fec0::1]',
    '[64:ff9b::7f00:1]',
    '[2002:7f00:1::]',
    '2130706433',
    '0x7f.1',
    '0177.0.0.1',
    '127.1',
  ])('resolvePublicAddresses refuses the host literal %s without consulting DNS', async (host) => {
    const c = stub();
    await expect(resolvePublicAddresses(c, host, 'LSE-VAL-001')).rejects.toMatchObject({
      code: 'LSE-VAL-001',
    });
    expect(c.dns.lookup).not.toHaveBeenCalled();
    expect(await c.metrics.render()).toContain(
      'loose_ssrf_blocked_total{reason="private_address"} 1',
    );
  });

  it.each([
    'http://[::ffff:7f00:1]/',
    'http://[0:0:0:0:0:ffff:127.0.0.1]/x',
    'http://[ff02::1]:8080/',
    'http://[fec0::1]/',
    'http://2130706433/',
    'http://0x7f.1/',
    'http://0177.0.0.1:9000/',
    'http://017700000001/',
    'https://[::1]/',
  ])('safeFetch never opens a connection to %s', async (url) => {
    const c = stub();
    await expect(safeFetch(c, url, { errorCode: 'LSE-VAL-001' })).rejects.toMatchObject({
      code: 'LSE-VAL-001',
    });
    expect(c.fetch).not.toHaveBeenCalled();
    expect(c.dns.lookup).not.toHaveBeenCalled();
  });

  it('a DNS answer in any of these forms is refused (rebinding / hostile resolver)', async () => {
    for (const address of [
      '0:0:0:0:0:ffff:127.0.0.1',
      'ff02::1',
      'fec0::1',
      '::',
      '64:ff9b::a00:1',
    ]) {
      const c = stub(vi.fn(async (): Promise<Answer[]> => [{ address, family: 6 }]));
      await expect(resolvePublicAddresses(c, 'evil.example', 'LSE-VAL-001')).rejects.toMatchObject({
        code: 'LSE-VAL-001',
      });
    }
  });

  it('classifies loopback bind hosts', () => {
    for (const h of ['127.0.0.1', '127.5.5.5', 'localhost', '::1', '[::1]', '::ffff:127.0.0.1'])
      expect(isLoopbackHost(h)).toBe(true);
    for (const h of [
      '0.0.0.0',
      '::',
      '10.0.0.5',
      '192.168.1.2',
      'metrics.internal',
      '::ffff:10.0.0.1',
    ])
      expect(isLoopbackHost(h)).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------------
describe('P10-SEC-013: web origin security headers (nginx)', () => {
  const stripComments = (t: string) => t.replace(/^\s*#.*$/gm, '');
  const conf = stripComments(read('docker/nginx.conf'));
  const snippet = stripComments(read('docker/nginx-security-headers.conf'));

  /** Body of every `location …{ … }` block. */
  function locations(): { head: string; body: string }[] {
    const out: { head: string; body: string }[] = [];
    const re = /location\s+([^{]+)\{([^}]*)\}/g;
    for (let m = re.exec(conf); m; m = re.exec(conf)) out.push({ head: m[1]!.trim(), body: m[2]! });
    return out;
  }

  it('the shared snippet carries the full base header set (incl. HSTS)', () => {
    for (const h of [
      'X-Frame-Options',
      'X-Content-Type-Options',
      'Referrer-Policy',
      'Permissions-Policy',
      'Strict-Transport-Security',
      'Cross-Origin-Opener-Policy',
    ])
      expect(snippet).toMatch(new RegExp(`add_header ${h} .* always;`));
    expect(snippet).toMatch(/max-age=31536000/);
  });

  it('EVERY location includes the snippet and sets a CSP (add_header is not inherited)', () => {
    const locs = locations();
    expect(locs.map((l) => l.head)).toEqual(
      expect.arrayContaining(['/', '= /index.html', '/status/']),
    );
    for (const l of locs) {
      expect(l.body, `location ${l.head}`).toContain(
        'include /etc/nginx/snippets/loose-security-headers.conf;',
      );
      expect(l.body, `location ${l.head}`).toMatch(/add_header Content-Security-Policy \S+/);
    }
    // No server-level add_header: it would silently disappear in locations that declare their own.
    const serverLevel = conf.replace(/location\s+[^{]+\{[^}]*\}/g, '');
    expect(serverLevel).not.toMatch(/^\s*add_header /m);
  });

  it('the SPA CSP is restrictive', () => {
    const csp = /set \$spa_csp "([^"]+)"/.exec(conf)?.[1] ?? '';
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).not.toMatch(/script-src[^;]*'unsafe-(inline|eval)'/);
    for (const d of ["object-src 'none'", "base-uri 'self'", "frame-ancestors 'none'"])
      expect(csp).toContain(d);
  });

  it('the status page CSP pins the inline script and style by hash (stays in sync with status/index.html)', () => {
    const html = read('status/index.html');
    const hash = (x: string) => `'sha256-${createHash('sha256').update(x).digest('base64')}'`;
    const script = /<script>([\s\S]*?)<\/script>/.exec(html)![1]!;
    const style = /<style>([\s\S]*?)<\/style>/.exec(html)![1]!;
    expect(html.match(/<script/g)).toHaveLength(1);
    expect(conf).toContain(`script-src ${hash(script)}`);
    expect(conf).toContain(`style-src ${hash(style)}`);
  });

  it('the web image installs the snippet where the config includes it', () => {
    expect(read('docker/web.Dockerfile')).toContain(
      'COPY docker/nginx-security-headers.conf /etc/nginx/snippets/loose-security-headers.conf',
    );
  });
});

// ---------------------------------------------------------------------------------------------
describe('P10-SEC-015 / -017: environment guards', () => {
  const base = {
    DATABASE_URL: 'postgresql://x@localhost/db',
    REDIS_URL: 'redis://localhost:6379',
    SESSION_SECRET: TEST_SECRETS.SESSION_SECRET,
    LOCAL_KMS_MASTER_KEY: TEST_SECRETS.LOCAL_KMS_MASTER_KEY,
  };
  const prod = { ...base, NODE_ENV: 'production', E2B_API_KEY: 'x' };
  const problems = (src: Record<string, string>) => {
    try {
      loadEnv({ ...prod, ...src });
      return [];
    } catch (err) {
      expect(err).toBeInstanceOf(EnvError);
      return (err as EnvError).problems;
    }
  };

  it('production refuses a numeric TRUST_PROXY hop count unless acknowledged', () => {
    expect(problems({ TRUST_PROXY: '1' }).join()).toMatch(/TRUST_PROXY/);
    expect(problems({ TRUST_PROXY: '2' }).join()).toMatch(/TRUST_PROXY_HOPS_ACKNOWLEDGED/);
    expect(problems({ TRUST_PROXY: '1', TRUST_PROXY_HOPS_ACKNOWLEDGED: 'true' })).toEqual([]);
    expect(problems({ TRUST_PROXY: '0' })).toEqual([]);
    expect(problems({})).toEqual([]);
    // development / test keep working without the acknowledgement
    expect(loadEnv({ ...base, TRUST_PROXY: '1' }).TRUST_PROXY).toBe(1);
  });

  it('a non-loopback METRICS_HOST requires METRICS_TOKEN; loopback defaults do not', () => {
    for (const host of ['0.0.0.0', '::', '10.1.2.3', 'metrics.internal'])
      expect(problems({ METRICS_PORT: '9464', METRICS_HOST: host }).join(), host).toMatch(
        /METRICS_TOKEN/,
      );
    const token = 'm'.repeat(40);
    expect(
      problems({ METRICS_PORT: '9464', METRICS_HOST: '0.0.0.0', METRICS_TOKEN: token }),
    ).toEqual([]);
    expect(problems({ METRICS_PORT: '9464' })).toEqual([]); // default bind is 127.0.0.1
    expect(loadEnv({ ...base, METRICS_PORT: '9464' }).METRICS_HOST).toBe('127.0.0.1');
    expect(problems({ METRICS_PORT: '9464', METRICS_HOST: '::1' })).toEqual([]);
    // without a listener the host is irrelevant
    expect(problems({ METRICS_HOST: '0.0.0.0' })).toEqual([]);
  });
});

async function freePort(): Promise<number> {
  return await new Promise((resolve, reject) => {
    const s = createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address() as { port: number };
      s.close(() => resolve(port));
    });
  });
}

describe('P10-SEC-017: secondary metrics listener', () => {
  const metricsCtx = (env: Record<string, unknown>) => {
    const metrics = createMetricsRegistry();
    metrics.counter('loose_errors_total', 'errors').inc();
    return { env, metrics } as unknown as AppContext;
  };

  it('refuses to start on a non-loopback host without a token', async () => {
    const port = await freePort();
    await expect(
      startMetricsServer(metricsCtx({ METRICS_PORT: port, METRICS_HOST: '0.0.0.0' })),
    ).rejects.toThrow(/METRICS_TOKEN/);
  });

  it('non-loopback binds demand the bearer token (404 otherwise)', async () => {
    const port = await freePort();
    const token = 't'.repeat(40);
    const h = await startMetricsServer(
      metricsCtx({ METRICS_PORT: port, METRICS_HOST: '0.0.0.0', METRICS_TOKEN: token }),
    );
    try {
      const url = `http://127.0.0.1:${port}/metrics`;
      expect((await fetch(url)).status).toBe(404);
      expect((await fetch(url, { headers: { authorization: 'Bearer nope' } })).status).toBe(404);
      expect((await fetch(url, { headers: { authorization: `Bearer ${token}` } })).status).toBe(
        200,
      );
      expect(
        await (await fetch(url, { headers: { authorization: `Bearer ${token}` } })).text(),
      ).toContain('loose_errors_total');
    } finally {
      await h?.close();
    }
  });

  it('a loopback listener stays open for a local scraper', async () => {
    const port = await freePort();
    const h = await startMetricsServer(
      metricsCtx({ METRICS_PORT: port, METRICS_HOST: '127.0.0.1' }),
    );
    try {
      expect((await fetch(`http://127.0.0.1:${port}/metrics`)).status).toBe(200);
    } finally {
      await h?.close();
    }
  });
});

// ---------------------------------------------------------------------------------------------
describe('P10-SEC-016: presigned export links never outlive the export', () => {
  it('exportLinkTtlSec = min(configured, 5 min, remaining validity)', () => {
    const now = new Date('2026-10-15T10:00:00Z');
    const at = (sec: number) => new Date(now.getTime() + sec * 1000);
    expect(exportLinkTtlSec(3600, at(7200), now)).toBe(300);
    expect(exportLinkTtlSec(120, at(7200), now)).toBe(120);
    expect(exportLinkTtlSec(3600, at(45), now)).toBe(45);
    expect(exportLinkTtlSec(3600, at(0.4), now)).toBe(0);
    expect(exportLinkTtlSec(3600, at(-5), now)).toBe(0);
    expect(exportLinkTtlSec(3600, null, now)).toBe(300);
  });

  const s3 = new S3ObjectStorage({
    bucket: 'b',
    region: 'us-east-1',
    endpoint: 'https://s3.example.test',
    accessKeyId: 'AKIAFAKEFAKEFAKE',
    secretAccessKey: 'fake-secret-access-key',
    forcePathStyle: true,
    prefix: '',
    signedUrlTtlSec: 3600,
  });
  const row = (expiresAt: Date | null) =>
    ({
      id: 'exp1',
      kind: 'USER',
      orgId: null,
      status: 'SUCCEEDED',
      storageKey: 'exports/exp1.zip',
      expiresAt,
    }) as never;
  const stubCtx = (storage: unknown) =>
    ({ env: { S3_SIGNED_URL_TTL_SEC: 3600 }, storage }) as unknown as AppContext;

  it('signs for the remaining validity when the export is about to expire', async () => {
    const out = await openDataExportDownload(stubCtx(s3), row(new Date(Date.now() + 20_000)));
    expect(out.kind).toBe('redirect');
    const expires = Number(new URL((out as { url: string }).url).searchParams.get('X-Amz-Expires'));
    expect(expires).toBeGreaterThanOrEqual(15);
    expect(expires).toBeLessThanOrEqual(20);
  });

  it('is capped at five minutes for long-lived exports, even with a 1 h storage TTL', async () => {
    const out = await openDataExportDownload(
      stubCtx(s3),
      row(new Date(Date.now() + 72 * 3_600_000)),
    );
    expect(new URL((out as { url: string }).url).searchParams.get('X-Amz-Expires')).toBe('300');
  });

  it('streams through the API instead of signing when less than a second is left', async () => {
    const storage = {
      signedUrl: vi.fn(async () => 'https://should-not-be-used'),
      get: vi.fn(async () => ({ stream: Readable.from(['zip']), bytes: 3 })),
    };
    const out = await openDataExportDownload(stubCtx(storage), row(new Date(Date.now() + 400)));
    expect(storage.signedUrl).not.toHaveBeenCalled();
    expect(out.kind).toBe('stream');
  });
});

// ---------------------------------------------------------------------------------------------
describe('P1: api/worker Dockerfiles contain only valid COPY instructions', () => {
  it.each(['docker/api.Dockerfile', 'docker/worker.Dockerfile'])('%s', (file) => {
    const lines = read(file)
      .split('\n')
      .filter((l) => /^\s*COPY\b/.test(l));
    expect(lines.length).toBeGreaterThan(5);
    for (const l of lines) {
      // COPY is not run in a shell: redirections / `|| true` become bogus path arguments.
      expect(l).not.toMatch(/2>\/dev\/null|\|\||&&|\btrue\b/);
    }
  });
});

// ---------------------------------------------------------------------------------------------
describe('P5: retention staleness signal', () => {
  it('records a last-success timestamp (KV + gauge) after a fully successful run', async () => {
    await ctx.kv.del(RETENTION_LAST_SUCCESS_KEY);
    const before = Math.floor(Date.now() / 1000);
    const res = await runRetentionPurge(ctx);
    expect(res.failed).toBe(0);
    const stored = Number(await ctx.kv.get(RETENTION_LAST_SUCCESS_KEY));
    expect(stored).toBeGreaterThanOrEqual(before);
    const m = /^loose_retention_last_success_timestamp_seconds (\d+)$/m.exec(
      await ctx.metrics.render(),
    );
    expect(Number(m?.[1])).toBeGreaterThanOrEqual(before);
  });

  it('a run scoped to one org, or one with a failing org, does not count as success', async () => {
    const owner = await login(app);
    const org = await createOrg(owner);
    await ctx.kv.del(RETENTION_LAST_SUCCESS_KEY);
    await runRetentionPurge(ctx, { orgId: org.id });
    expect(await ctx.kv.get(RETENTION_LAST_SUCCESS_KEY)).toBeNull();

    vi.spyOn(ctx.kv, 'setIfAbsent').mockRejectedValue(new Error('kv down')); // org lock fails
    const res = await runRetentionPurge(ctx);
    expect(res.failed).toBeGreaterThan(0);
    expect(await ctx.kv.get(RETENTION_LAST_SUCCESS_KEY)).toBeNull();
  });

  it('the gauge is exported from the stored timestamp even in a process that never ran the job', async () => {
    await ctx.kv.set(RETENTION_LAST_SUCCESS_KEY, '1760000000', 60);
    expect(await ctx.metrics.render()).toContain(
      'loose_retention_last_success_timestamp_seconds 1760000000',
    );
    await ctx.kv.del(RETENTION_LAST_SUCCESS_KEY);
  });

  it('the alert measures a timestamp gauge that exists', () => {
    expect(METRIC_NAMES).toContain('loose_retention_last_success_timestamp_seconds');
    const alerts = read('ops/prometheus/alerts.yml');
    const rule = alerts.slice(alerts.indexOf('alert: LooseRetentionJobStale'));
    expect(rule).toContain('time() - max(loose_retention_last_success_timestamp_seconds)');
    expect(rule).toContain('absent(loose_retention_last_success_timestamp_seconds)');
    expect(rule).not.toContain('last_over_time(loose_jobs_total');
    expect(read('docs/runbooks/sys.md')).toContain('## Retention purge stale');
  });
});

// ---------------------------------------------------------------------------------------------
describe('P4: OrgDto.deletionScheduledAt', () => {
  it('is null normally and an ISO timestamp while deletion is scheduled', async () => {
    const owner = await login(app);
    const org = await createOrg(owner);
    expect((await owner.get(`/api/v1/orgs/${org.id}`)).body.data.deletionScheduledAt).toBeNull();
    await owner.post(`/api/v1/orgs/${org.id}/deletion`, { confirm: org.slug });
    const one = await owner.get(`/api/v1/orgs/${org.id}`);
    expect(one.body.data.deletionScheduledAt).toEqual(expect.stringMatching(/^\d{4}-\d\d-\d\dT/));
    const list = await owner.get('/api/v1/orgs');
    expect(
      (list.body.data as { id: string; deletionScheduledAt: string | null }[]).find(
        (o) => o.id === org.id,
      )?.deletionScheduledAt,
    ).toBe(one.body.data.deletionScheduledAt);
    await owner.delete(`/api/v1/orgs/${org.id}/deletion`);
    expect((await owner.get(`/api/v1/orgs/${org.id}`)).body.data.deletionScheduledAt).toBeNull();
  });
});
