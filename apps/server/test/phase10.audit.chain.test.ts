/**
 * Phase 10 (W2): tamper-evident audit log — hash chain, concurrent appends, verification,
 * legacy backfill, GDPR redaction compatibility and `GET /orgs/:orgId/audit-log/verify`.
 */
import type { Prisma } from '@prisma/client';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { AUDIT_GENESIS_HASH, AUDIT_GLOBAL_CHAIN, auditChainVerifyDtoSchema } from '@loose/shared';
import { createLogger } from '../src/lib/logger';
import { createMetricsRegistry } from '../src/lib/metrics';
import { AuditService } from '../src/services/audit.service';
import {
  actorDigestOf,
  backfillChain,
  canonicalJson,
  computeEntryHash,
  deriveAuditChainKey,
  verifyChain,
} from '../src/services/governance/auditChain';
import { sealLegacyAuditRows } from '../src/services/governance/retention';
import { addMember, createOrg, expectError, login, makeApp, resetDb, testPrisma } from './helpers';
import { legacyAuditRow, withoutAuditTriggers } from './auditFixtures';

const prisma = testPrisma();
const metrics = createMetricsRegistry({ enabled: true });
const { app, ctx } = makeApp({ context: { metrics } });

afterAll(async () => {
  await ctx.jobs.onIdle();
  await prisma.$disconnect();
});

beforeEach(async () => {
  await ctx.jobs.onIdle();
  await resetDb(prisma);
});

/** Bypass the immutability trigger the way an attacker with raw DB access (or an operator) would. */
async function asMaintenance<T>(fn: (tx: Prisma.TransactionClient) => Promise<T>): Promise<T> {
  return prisma.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT set_config('loose.audit_maintenance', 'on', true)`;
    return fn(tx);
  });
}

async function setup() {
  const owner = await login(app);
  const org = await createOrg(owner);
  const admin = await login(app);
  await addMember(org.id, admin.user.id, 'ADMIN');
  const member = await login(app);
  await addMember(org.id, member.user.id, 'MEMBER');
  return { owner, admin, member, org, key: ctx.audit.chainKey };
}

async function appendMany(orgId: string | null, n: number, actorId?: string) {
  for (let i = 0; i < n; i++) {
    await ctx.audit.record({
      orgId,
      actorId: actorId ?? null,
      action: 'org.update',
      target: `t${i}`,
      meta: { i },
    });
  }
}

const rowsOf = (chain: string) =>
  prisma.auditLog.findMany({ where: { chain }, orderBy: { seq: 'asc' } });

describe('hash chain basics', () => {
  it('canonicalJson sorts keys recursively and is stable', () => {
    expect(canonicalJson({ b: 1, a: { d: [3, { y: 1, x: 2 }], c: null } })).toBe(
      '{"a":{"c":null,"d":[3,{"x":2,"y":1}]},"b":1}',
    );
    expect(canonicalJson({ a: undefined, b: 'x' })).toBe('{"b":"x"}');
    expect(canonicalJson(null)).toBe('null');
  });

  it('chains every entry per org: seq 1..n, prevHash links, GENESIS first', async () => {
    const { org, owner } = await setup();
    await appendMany(org.id, 4, owner.user.id);
    const rows = await rowsOf(org.id);
    expect(rows.length).toBeGreaterThanOrEqual(5); // org.create + 4
    rows.forEach((r, i) => {
      expect(r.seq).toBe(i + 1);
      expect(r.chain).toBe(org.id);
      expect(r.hash).toMatch(/^[0-9a-f]{64}$/);
      expect(r.prevHash).toBe(i === 0 ? AUDIT_GENESIS_HASH : rows[i - 1]?.hash);
      expect(r.actorDigest === null || /^[0-9a-f]{64}$/.test(r.actorDigest)).toBe(true);
    });
    expect(rows[0]?.action).toBe('org.create');
    const sample = rows.find((r) => r.actorId === owner.user.id);
    expect(sample?.actorDigest).toBe(actorDigestOf(owner.user.id));
  });

  it('keeps user-level entries (no org) on the global chain', async () => {
    await appendMany(null, 3);
    const rows = await rowsOf(AUDIT_GLOBAL_CHAIN);
    expect(rows.map((r) => r.seq)).toEqual([1, 2, 3]);
    expect(rows.every((r) => r.orgId === null)).toBe(true);
    const res = await verifyChain(prisma, ctx.audit.chainKey, AUDIT_GLOBAL_CHAIN);
    expect(res).toMatchObject({ ok: true, checked: 3, firstSeq: 1, lastSeq: 3, anchoredAt: null });
  });

  it('survives the JSONB round trip for awkward meta (unicode, nesting, numbers, nulls)', async () => {
    const { org } = await setup();
    await ctx.audit.record({
      orgId: org.id,
      action: 'org.update',
      meta: {
        z: 1,
        a: [1, 2, { b: null }],
        u: 'héllo ✓ 日本語 "quoted" \\ back',
        n: 1.5,
        big: 1e21,
        neg: -0.000001,
        empty: {},
        list: [],
        nested: { k: { j: { i: 'deep' } } },
      },
    });
    expect(await verifyChain(prisma, ctx.audit.chainKey, org.id)).toMatchObject({ ok: true });
  });

  it('derives the key from AUDIT_CHAIN_SECRET or HKDF(SESSION_SECRET)', () => {
    const a = deriveAuditChainKey({ SESSION_SECRET: 's'.repeat(40) });
    const b = deriveAuditChainKey({ SESSION_SECRET: 's'.repeat(40) });
    const c = deriveAuditChainKey({ SESSION_SECRET: 't'.repeat(40) });
    const d = deriveAuditChainKey({
      SESSION_SECRET: 's'.repeat(40),
      AUDIT_CHAIN_SECRET: 'x'.repeat(32),
    });
    expect(a.equals(b)).toBe(true);
    expect(a.equals(c)).toBe(false);
    expect(a.length).toBe(32);
    expect(d.toString('utf8')).toBe('x'.repeat(32));
  });

  it('a different key does not verify (the MAC is keyed, not just a hash)', async () => {
    const { org } = await setup();
    await appendMany(org.id, 2);
    const wrong = await verifyChain(
      prisma,
      Buffer.from('another-key-of-sufficient-length!!'),
      org.id,
    );
    expect(wrong).toMatchObject({ ok: false, brokenAt: { seq: 1, reason: 'hash_mismatch' } });
  });

  it('logs (and swallows) audit failures instead of failing the request', async () => {
    const errors: unknown[] = [];
    const logger = createLogger({ level: 'silent' });
    vi.spyOn(logger, 'error').mockImplementation(((...a: unknown[]) => {
      errors.push(a);
    }) as never);
    const noKey = new AuditService(prisma, logger); // key never configured
    await expect(noKey.record({ action: 'org.update' })).resolves.toBeUndefined();
    expect(errors.length).toBe(1);
  });
});

describe('concurrency', () => {
  it('serialises concurrent appends: gap-free, linked chains for several chains at once', async () => {
    const { org } = await setup();
    const other = await createOrg(await login(app));
    const before = (await rowsOf(org.id)).length;
    const jobs: Promise<void>[] = [];
    for (let i = 0; i < 30; i++) {
      jobs.push(ctx.audit.record({ orgId: org.id, action: 'org.update', target: `a${i}` }));
      if (i % 3 === 0)
        jobs.push(ctx.audit.record({ orgId: other.id, action: 'org.update', target: `b${i}` }));
      if (i % 5 === 0) jobs.push(ctx.audit.record({ action: 'auth.sign_in', target: `g${i}` }));
    }
    await Promise.all(jobs);

    const rows = await rowsOf(org.id);
    expect(rows.length).toBe(before + 30);
    expect(rows.map((r) => r.seq)).toEqual(rows.map((_, i) => i + 1));
    for (const chain of [org.id, other.id, AUDIT_GLOBAL_CHAIN]) {
      const v = await verifyChain(prisma, ctx.audit.chainKey, chain);
      expect(v.ok, JSON.stringify(v)).toBe(true);
      expect(v.checked).toBe((await rowsOf(chain)).length);
    }
  });

  it('serialises appends from two independent AuditService instances (two API processes)', async () => {
    const { org } = await setup();
    const second = new AuditService(prisma, createLogger({ level: 'silent' }), ctx.audit.chainKey);
    const writers = [ctx.audit, second];
    await Promise.all(
      Array.from({ length: 24 }, (_, i) =>
        writers[i % 2]!.record({ orgId: org.id, action: 'org.update', target: `p${i}` }),
      ),
    );
    const v = await verifyChain(prisma, ctx.audit.chainKey, org.id);
    expect(v.ok, JSON.stringify(v)).toBe(true);
    expect(v.lastSeq).toBe(v.checked);
  });

  it('writes inside the caller transaction: commit keeps it, rollback leaves no gap', async () => {
    const { org } = await setup();
    await prisma.$transaction(async (tx) => {
      await ctx.audit.record({ orgId: org.id, action: 'org.update', target: 'in-tx' }, tx);
    });
    await expect(
      prisma.$transaction(async (tx) => {
        await ctx.audit.record({ orgId: org.id, action: 'org.update', target: 'rolled-back' }, tx);
        throw new Error('boom');
      }),
    ).rejects.toThrow('boom');
    await ctx.audit.record({ orgId: org.id, action: 'org.update', target: 'after' });
    const rows = await rowsOf(org.id);
    expect(rows.filter((r) => r.action === 'org.update').map((r) => r.target)).toEqual([
      'in-tx',
      'after',
    ]);
    expect(rows.map((r) => r.seq)).toEqual(rows.map((_, i) => i + 1));
    expect((await verifyChain(prisma, ctx.audit.chainKey, org.id)).ok).toBe(true);
  });
});

describe('tamper detection', () => {
  async function seeded() {
    const s = await setup();
    await appendMany(s.org.id, 6, s.owner.user.id);
    const rows = await rowsOf(s.org.id);
    expect(rows.length).toBeGreaterThanOrEqual(7);
    return { ...s, rows };
  }
  const verify = (orgId: string) => verifyChain(prisma, ctx.audit.chainKey, orgId);

  it('is clean before tampering', async () => {
    const { org, rows } = await seeded();
    const v = await verify(org.id);
    expect(v).toMatchObject({
      ok: true,
      chain: org.id,
      checked: rows.length,
      firstSeq: 1,
      lastSeq: rows.length,
      lastHash: rows[rows.length - 1]?.hash,
      legacyUnchained: 0,
      anchoredAt: null,
      brokenAt: null,
    });
    expect(auditChainVerifyDtoSchema.safeParse(v).success).toBe(true);
  });

  it.each([
    ['action', (id: string) => ({ id, set: `"action" = 'org.delete'` })],
    ['target', (id: string) => ({ id, set: `"target" = 'forged'` })],
    ['meta', (id: string) => ({ id, set: `"meta" = '{"i": 999}'::jsonb` })],
    ['createdAt', (id: string) => ({ id, set: `"createdAt" = "createdAt" - interval '1 day'` })],
  ])('detects an edited %s', async (_name, mk) => {
    const { org, rows } = await seeded();
    const victim = rows[3]!;
    const { id, set } = mk(victim.id);
    // Superuser-level tampering (createdAt can't be edited even in maintenance mode any more).
    await withoutAuditTriggers(prisma, (tx) =>
      tx.$executeRawUnsafe(`UPDATE "AuditLog" SET ${set} WHERE "id" = '${id}'`),
    );
    const v = await verify(org.id);
    expect(v.ok).toBe(false);
    expect(v.brokenAt).toEqual({ seq: victim.seq, id: victim.id, reason: 'hash_mismatch' });
    expect(v.checked).toBe(3); // seq 1..3 verified before the break
  });

  it('detects a forged actor (actorId no longer matches the signed digest)', async () => {
    const { org, rows, member } = await seeded();
    const victim = rows.find((r) => r.actorId)!;
    // REAUDIT-007: refused by the trigger in every mode; simulate a superuser bypassing it.
    await expect(
      asMaintenance((tx) =>
        tx.auditLog.update({ where: { id: victim.id }, data: { actorId: member.user.id } }),
      ),
    ).rejects.toThrow(/immutable/);
    await withoutAuditTriggers(prisma, (tx) =>
      tx.auditLog.update({ where: { id: victim.id }, data: { actorId: member.user.id } }),
    );
    const v = await verify(org.id);
    expect(v.brokenAt).toMatchObject({ id: victim.id, reason: 'hash_mismatch' });
  });

  it('detects a deleted row as a sequence gap', async () => {
    const { org, rows } = await seeded();
    const victim = rows[2]!;
    await asMaintenance((tx) => tx.auditLog.delete({ where: { id: victim.id } }));
    const v = await verify(org.id);
    expect(v.ok).toBe(false);
    expect(v.brokenAt).toMatchObject({ seq: rows[3]?.seq, reason: 'seq_gap' });
  });

  it('detects a rewritten link (prevHash) and a cleared hash', async () => {
    const { org, rows } = await seeded();
    await expect(
      asMaintenance((tx) =>
        tx.auditLog.update({ where: { id: rows[4]!.id }, data: { prevHash: 'f'.repeat(64) } }),
      ),
    ).rejects.toThrow(/immutable/);
    await withoutAuditTriggers(prisma, (tx) =>
      tx.auditLog.update({ where: { id: rows[4]!.id }, data: { prevHash: 'f'.repeat(64) } }),
    );
    expect((await verify(org.id)).brokenAt).toMatchObject({
      seq: rows[4]?.seq,
      reason: 'prev_mismatch',
    });

    await withoutAuditTriggers(prisma, (tx) =>
      tx.auditLog.update({ where: { id: rows[4]!.id }, data: { prevHash: rows[3]!.hash } }),
    );
    expect((await verify(org.id)).ok).toBe(true);

    // Clearing a chained row's hash is refused even in maintenance mode; simulate a superuser.
    await expect(
      asMaintenance((tx) =>
        tx.auditLog.update({ where: { id: rows[5]!.id }, data: { hash: null } }),
      ),
    ).rejects.toThrow(/immutable/);
    await withoutAuditTriggers(prisma, (tx) =>
      tx.auditLog.update({ where: { id: rows[5]!.id }, data: { hash: null } }),
    );
    expect((await verify(org.id)).brokenAt).toMatchObject({
      seq: rows[5]?.seq,
      reason: 'missing_hash',
    });
  });

  it('detects a recomputed-looking forgery without the key (attacker re-hashes with a guess)', async () => {
    const { org, rows } = await seeded();
    const victim = rows[3]!;
    const forged = computeEntryHash(Buffer.from('attacker-guess-of-the-key-0000000'), {
      chain: org.id,
      seq: victim.seq!,
      prevHash: victim.prevHash!,
      orgId: org.id,
      actorDigest: victim.actorDigest,
      action: 'org.delete',
      target: victim.target,
      meta: victim.meta,
      createdAt: victim.createdAt,
    });
    await withoutAuditTriggers(prisma, (tx) =>
      tx.auditLog.update({
        where: { id: victim.id },
        data: { action: 'org.delete', hash: forged },
      }),
    );
    expect((await verify(org.id)).brokenAt).toMatchObject({
      seq: victim.seq,
      reason: 'hash_mismatch',
    });
  });

  it('cannot be tampered with through normal queries (DB trigger)', async () => {
    const { rows } = await seeded();
    await expect(
      prisma.auditLog.update({ where: { id: rows[1]!.id }, data: { action: 'org.delete' } }),
    ).rejects.toThrow(/immutable/);
    await expect(prisma.auditLog.delete({ where: { id: rows[1]!.id } })).rejects.toThrow(
      /immutable/,
    );
  });
});

describe('GDPR redaction compatibility', () => {
  // REAUDIT-007: nulling ip / actorId keeps every hash valid, so redaction is only accepted when a
  // signed `audit.redacted` marker for the actor exists in the chain (written by the account
  // deletion flow, see phase10.runtime-role / phase10.privacy). Without it, it is reported.
  it('reports attribution removed without a redaction marker', async () => {
    const { org, member } = await setup();
    await ctx.audit.record({
      orgId: org.id,
      actorId: member.user.id,
      action: 'org.update',
      ip: '203.0.113.7',
    });
    const before = await prisma.auditLog.findFirstOrThrow({
      where: { actorId: member.user.id, action: 'org.update' },
    });
    expect(before.ip).toBe('203.0.113.7');
    await prisma.auditLog.updateMany({ where: { actorId: member.user.id }, data: { ip: null } });
    await prisma.user.delete({ where: { id: member.user.id } }); // FK SET NULL on actorId
    const after = await prisma.auditLog.findUniqueOrThrow({ where: { id: before.id } });
    expect(after).toMatchObject({ actorId: null, ip: null, actorDigest: before.actorDigest });
    const v = await verifyChain(prisma, ctx.audit.chainKey, org.id);
    expect(v).toMatchObject({ ok: false, brokenAt: { id: before.id, reason: 'hash_mismatch' } });

    // A signed marker announcing this actor's redaction makes the same chain valid again.
    await ctx.audit.record({
      orgId: org.id,
      action: 'audit.redacted',
      target: 'request',
      meta: { kind: 'USER', actorDigest: before.actorDigest, rows: 1 },
    });
    expect((await verifyChain(prisma, ctx.audit.chainKey, org.id)).ok).toBe(true);
  });
});

describe('legacy (pre-Phase-10) rows', () => {
  it('reports them, then seals them idempotently without breaking the chain', async () => {
    const { org, owner } = await setup();
    const old = (n: number) => new Date(Date.UTC(2025, 0, n));
    for (let i = 1; i <= 3; i++) {
      await legacyAuditRow(prisma, {
        orgId: org.id,
        actorId: owner.user.id,
        action: 'org.update',
        target: `legacy${i}`,
        meta: { i },
        ip: '198.51.100.1',
        createdAt: old(i),
      });
    }
    await legacyAuditRow(prisma, {
      orgId: null,
      action: 'auth.sign_in',
      target: 'legacy-global',
      createdAt: old(9),
    });
    const chainedBefore = (await rowsOf(org.id)).length;

    const v1 = await verifyChain(prisma, ctx.audit.chainKey, org.id);
    expect(v1).toMatchObject({ ok: true, legacyUnchained: 3, checked: chainedBefore });

    expect(await sealLegacyAuditRows(ctx)).toBe(4); // 3 org rows + 1 global row
    const v2 = await verifyChain(prisma, ctx.audit.chainKey, org.id);
    expect(v2).toMatchObject({ ok: true, legacyUnchained: 0, checked: chainedBefore + 3 });

    const sealed = (await rowsOf(org.id)).slice(chainedBefore);
    expect(sealed.map((r) => r.target)).toEqual(['legacy1', 'legacy2', 'legacy3']); // oldest first
    expect(sealed.map((r) => r.createdAt.toISOString().slice(0, 10))).toEqual([
      '2025-01-01',
      '2025-01-02',
      '2025-01-03',
    ]);
    expect((await verifyChain(prisma, ctx.audit.chainKey, AUDIT_GLOBAL_CHAIN)).ok).toBe(true);

    // idempotent; new entries continue the chain after the sealed rows
    expect(await sealLegacyAuditRows(ctx)).toBe(0);
    await ctx.audit.record({ orgId: org.id, action: 'org.update', target: 'new' });
    expect((await verifyChain(prisma, ctx.audit.chainKey, org.id)).ok).toBe(true);
  });

  it('backfill resumes in small steps (maxRows) and never reorders', async () => {
    const { org } = await setup();
    for (let i = 1; i <= 5; i++) {
      await legacyAuditRow(prisma, {
        orgId: org.id,
        action: 'org.update',
        target: `l${i}`,
        createdAt: new Date(Date.UTC(2025, 1, i)),
      });
    }
    expect(await backfillChain(prisma, ctx.audit.chainKey, org.id, { maxRows: 2 })).toBe(2);
    expect((await verifyChain(prisma, ctx.audit.chainKey, org.id)).legacyUnchained).toBe(3);
    expect(await backfillChain(prisma, ctx.audit.chainKey, org.id)).toBe(3);
    const v = await verifyChain(prisma, ctx.audit.chainKey, org.id);
    expect(v).toMatchObject({ ok: true, legacyUnchained: 0 });
  });
});

describe('GET /orgs/:orgId/audit-log/verify', () => {
  it('returns the chain status to ADMIN+ and records audit.verify; members are refused', async () => {
    const { owner, admin, member, org } = await setup();
    await appendMany(org.id, 3);
    const base = `/api/v1/orgs/${org.id}/audit-log/verify`;

    const res = await admin.get(base);
    expect(res.status).toBe(200);
    expect(auditChainVerifyDtoSchema.safeParse(res.body.data).success).toBe(true);
    expect(res.body.data).toMatchObject({ ok: true, chain: org.id, firstSeq: 1, brokenAt: null });
    expect((await owner.get(base)).status).toBe(200);
    expectError(await member.get(base), 'LSE-ORG-002', 403);

    const logged = await prisma.auditLog.findFirstOrThrow({
      where: { orgId: org.id, action: 'audit.verify' },
    });
    expect(logged.meta).toMatchObject({ ok: true });
    expect(logged.actorId).toBe(admin.user.id);
  });

  it('reports a break, counts it in loose_audit_chain_breaks_total and stays HTTP 200', async () => {
    const { owner, org } = await setup();
    await appendMany(org.id, 3);
    const victim = (await rowsOf(org.id))[1]!;
    await withoutAuditTriggers(prisma, (tx) =>
      tx.auditLog.update({ where: { id: victim.id }, data: { target: 'tampered' } }),
    );
    const res = await owner.get(`/api/v1/orgs/${org.id}/audit-log/verify`);
    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({
      ok: false,
      brokenAt: { seq: victim.seq, id: victim.id, reason: 'hash_mismatch' },
    });
    expect(await metrics.render()).toMatch(/loose_audit_chain_breaks_total\s+1/);
    const logged = await prisma.auditLog.findFirstOrThrow({
      where: { orgId: org.id, action: 'audit.verify' },
    });
    expect(logged.meta).toMatchObject({ ok: false });
  });

  it('allows one verification per org at a time (LSE-RATE-001)', async () => {
    const { owner, org } = await setup();
    await ctx.kv.setIfAbsent(`audit-verify:${org.id}`, 'other-instance', 30);
    expectError(await owner.get(`/api/v1/orgs/${org.id}/audit-log/verify`), 'LSE-RATE-001', 429);
    await ctx.kv.del(`audit-verify:${org.id}`);
    expect((await owner.get(`/api/v1/orgs/${org.id}/audit-log/verify`)).status).toBe(200);
  });

  it("does not expose another org's chain", async () => {
    const { org } = await setup();
    const stranger = await login(app);
    expectError(await stranger.get(`/api/v1/orgs/${org.id}/audit-log/verify`), 'LSE-ORG-001', 403);
  });

  it('is switched off by the audit_export feature flag (LSE-SYS-007)', async () => {
    const off = makeApp({ env: { FEATURE_FLAGS: 'audit_export=off' } });
    const owner = await login(off.app);
    const org = await createOrg(owner);
    expectError(await owner.get(`/api/v1/orgs/${org.id}/audit-log/verify`), 'LSE-SYS-007', 503);
    await off.ctx.jobs.onIdle();
  });
});

describe('audit list shows chain position', () => {
  it('adds seq and hash to entries and supports the new filters', async () => {
    const { owner, org } = await setup();
    await ctx.audit.record({
      orgId: org.id,
      actorId: owner.user.id,
      action: 'policy.update',
      target: 'p',
    });
    const res = await owner.get(
      `/api/v1/orgs/${org.id}/audit-log?actionPrefix=policy.&actorId=${owner.user.id}`,
    );
    expect(res.status).toBe(200);
    expect(res.body.data).toHaveLength(1);
    expect(res.body.data[0]).toMatchObject({ action: 'policy.update', seq: expect.any(Number) });
    expect(res.body.data[0].hash).toMatch(/^[0-9a-f]{64}$/);
    expect(res.body.data[0].prevHash).toBeUndefined();
  });
});
