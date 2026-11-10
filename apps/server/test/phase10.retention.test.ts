/**
 * Phase 10 (W2): per-org data retention — settings API, the daily purge job (boundaries, active
 * sessions, tenant isolation, idempotency, batching, storage failures) and the chain-aware audit purge.
 */
import type { Prisma, SessionStatus } from '@prisma/client';
import request from 'supertest';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { RETENTION_LIMITS, defaultOrgPolicy, parseOrgPolicy } from '@loose/shared';
import { createMetricsRegistry } from '../src/lib/metrics';
import { verifyChain } from '../src/services/governance/auditChain';
import { purgeOrg, runRetentionPurge } from '../src/services/governance/retention';
import { addMember, createOrg, expectError, login, makeApp, resetDb, testPrisma } from './helpers';
import { legacyAuditRow, withoutAuditTriggers } from './auditFixtures';
import { createReadyProject } from './sessionHelpers';

const prisma = testPrisma();
const metrics = createMetricsRegistry({ enabled: true });
const { app, ctx } = makeApp({ context: { metrics } });

const DAY = 86_400_000;
const NOW = new Date('2026-06-01T12:00:00.000Z');
const ago = (days: number, extraMs = 0) => new Date(NOW.getTime() - days * DAY - extraMs);

afterAll(async () => {
  await ctx.jobs.onIdle();
  await prisma.$disconnect();
});

beforeEach(async () => {
  await ctx.jobs.onIdle();
  await resetDb(prisma);
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

async function setup() {
  const owner = await login(app);
  const org = await createOrg(owner);
  const project = await createReadyProject(ctx, org.id);
  return { owner, org, project };
}

let seq = 0;
async function mkSession(
  projectId: string,
  userId: string,
  status: SessionStatus,
  endedAt: Date | null,
) {
  seq += 1;
  return prisma.session.create({
    data: {
      projectId,
      userId,
      mode: 'PRO',
      model: 'claude-sonnet-4-5',
      branchName: `loose/session-r${seq}`,
      status,
      endedAt,
    },
  });
}

async function mkMessage(sessionId: string, createdAt: Date, raw: object | null = { tool: 'x' }) {
  return prisma.chatMessage.create({
    data: {
      sessionId,
      role: 'ASSISTANT',
      content: 'hello',
      createdAt,
      ...(raw ? { rawContent: raw } : {}),
    },
  });
}

async function mkArtifact(
  sessionId: string,
  kind: 'screenshot' | 'log' | 'diff' | 'attachment',
  createdAt: Date,
) {
  seq += 1;
  const storageKey = `sessions/${sessionId}/art${seq}.png`;
  await ctx.storage.put(storageKey, `bytes-${seq}`);
  return prisma.artifact.create({
    data: { sessionId, kind, url: `/x/${seq}`, storageKey, createdAt },
  });
}

/**
 * Bypass the audit immutability trigger like an operator / attacker with raw superuser DB access
 * would (REAUDIT-007: content edits are refused even in `loose.audit_maintenance` mode).
 */
function asMaintenance<T>(fn: (tx: Prisma.TransactionClient) => Promise<T>): Promise<T> {
  return withoutAuditTriggers(prisma, fn);
}

const exists = async (key: string) => (await ctx.storage.get(key)) !== null;

describe('purge boundaries', () => {
  it('removes transcripts of sessions ended strictly before the cutoff — not at it', async () => {
    const { owner, org, project } = await setup();
    const u = owner.user.id;
    const old = await mkSession(project.id, u, 'COMPLETED', ago(90, 1)); // 1 ms past the cutoff
    const edge = await mkSession(project.id, u, 'COMPLETED', ago(90)); // exactly at the cutoff
    const fresh = await mkSession(project.id, u, 'ERRORED', ago(89));
    for (const s of [old, edge, fresh]) await mkMessage(s.id, ago(200));

    const counts = await purgeOrg(ctx, { id: org.id, policy: defaultOrgPolicy() }, NOW);
    expect(counts.transcripts).toBe(1);
    expect(await prisma.chatMessage.count({ where: { sessionId: old.id } })).toBe(0);
    expect(await prisma.chatMessage.count({ where: { sessionId: edge.id } })).toBe(1);
    expect(await prisma.chatMessage.count({ where: { sessionId: fresh.id } })).toBe(1);
    // the session row (cost, outcome, PR link) stays
    expect(await prisma.session.count({ where: { id: old.id } })).toBe(1);
  });

  it('never touches queued / starting / running / paused / stopping sessions', async () => {
    const { owner, org, project } = await setup();
    const statuses: SessionStatus[] = ['QUEUED', 'STARTING', 'RUNNING', 'PAUSED', 'STOPPING'];
    const kept: string[] = [];
    for (const status of statuses) {
      // even absurdly old data with a (bogus) ended timestamp must survive
      const s = await mkSession(project.id, owner.user.id, status, ago(1000));
      await mkMessage(s.id, ago(1000));
      const shot = await mkArtifact(s.id, 'screenshot', ago(1000));
      const log = await mkArtifact(s.id, 'log', ago(1000));
      kept.push(shot.storageKey, log.storageKey);
    }
    const counts = await purgeOrg(ctx, { id: org.id, policy: defaultOrgPolicy() }, NOW);
    expect(counts).toEqual({ transcripts: 0, rawToolOutput: 0, screenshots: 0, auditLog: 0 });
    expect(await prisma.chatMessage.count()).toBe(5);
    expect(await prisma.artifact.count()).toBe(10);
    for (const key of kept) expect(await exists(key)).toBe(true);
  });

  it('nulls raw tool output but keeps the visible message, and removes log artifacts + files', async () => {
    const { owner, org, project } = await setup();
    const s = await mkSession(project.id, owner.user.id, 'COMPLETED', ago(40));
    const oldMsg = await mkMessage(s.id, ago(31), { tool: 'secret-ish output' });
    const newMsg = await mkMessage(s.id, ago(29), { tool: 'recent' });
    const oldLog = await mkArtifact(s.id, 'log', ago(31));
    const newLog = await mkArtifact(s.id, 'log', ago(29));

    const counts = await purgeOrg(ctx, { id: org.id, policy: defaultOrgPolicy() }, NOW);
    expect(counts).toMatchObject({ rawToolOutput: 2, transcripts: 0, screenshots: 0 }); // 1 message + 1 log
    const a = await prisma.chatMessage.findUniqueOrThrow({ where: { id: oldMsg.id } });
    expect(a.rawContent).toBeNull();
    expect(a.content).toBe('hello');
    expect(
      (await prisma.chatMessage.findUniqueOrThrow({ where: { id: newMsg.id } })).rawContent,
    ).toEqual({
      tool: 'recent',
    });
    expect(await prisma.artifact.findUnique({ where: { id: oldLog.id } })).toBeNull();
    expect(await exists(oldLog.storageKey)).toBe(false);
    expect(await prisma.artifact.findUnique({ where: { id: newLog.id } })).not.toBeNull();
    expect(await exists(newLog.storageKey)).toBe(true);
  });

  it('removes screenshots/attachments/diffs past their own retention, rows and files together', async () => {
    const { owner, org, project } = await setup();
    const s = await mkSession(project.id, owner.user.id, 'COMPLETED', ago(2));
    const old = [
      await mkArtifact(s.id, 'screenshot', ago(30, 1)),
      await mkArtifact(s.id, 'attachment', ago(60)),
      await mkArtifact(s.id, 'diff', ago(100)),
    ];
    const edge = await mkArtifact(s.id, 'screenshot', ago(30)); // exactly at the cutoff
    const fresh = await mkArtifact(s.id, 'screenshot', ago(1));
    const counts = await purgeOrg(ctx, { id: org.id, policy: defaultOrgPolicy() }, NOW);
    expect(counts.screenshots).toBe(3);
    for (const a of old) {
      expect(await prisma.artifact.findUnique({ where: { id: a.id } })).toBeNull();
      expect(await exists(a.storageKey)).toBe(false);
    }
    for (const a of [edge, fresh]) {
      expect(await prisma.artifact.findUnique({ where: { id: a.id } })).not.toBeNull();
      expect(await exists(a.storageKey)).toBe(true);
    }
  });

  it("keeps the row when its file can't be deleted, and retries on the next run", async () => {
    const { owner, org, project } = await setup();
    const s = await mkSession(project.id, owner.user.id, 'COMPLETED', ago(2));
    const stuck = await mkArtifact(s.id, 'screenshot', ago(50));
    const fine = await mkArtifact(s.id, 'screenshot', ago(50));
    const realDelete = ctx.storage.delete.bind(ctx.storage);
    const spy = vi.spyOn(ctx.storage, 'delete').mockImplementation(async (key) => {
      if (key === stuck.storageKey) throw new Error('storage down');
      return realDelete(key);
    });
    const counts = await purgeOrg(ctx, { id: org.id, policy: defaultOrgPolicy() }, NOW);
    expect(counts.screenshots).toBe(1);
    expect(await prisma.artifact.findUnique({ where: { id: stuck.id } })).not.toBeNull();
    expect(await prisma.artifact.findUnique({ where: { id: fine.id } })).toBeNull();
    spy.mockRestore();
    expect((await purgeOrg(ctx, { id: org.id, policy: defaultOrgPolicy() }, NOW)).screenshots).toBe(
      1,
    );
    expect(await prisma.artifact.count()).toBe(0);
    expect(await exists(stuck.storageKey)).toBe(false);
  });

  it("is scoped to each org and honours that org's own retention days", async () => {
    const a = await setup();
    const b = await setup();
    const sa = await mkSession(a.project.id, a.owner.user.id, 'COMPLETED', ago(100));
    const sb = await mkSession(b.project.id, b.owner.user.id, 'COMPLETED', ago(100));
    await mkMessage(sa.id, ago(100));
    await mkMessage(sb.id, ago(100));
    // org B keeps transcripts for a year
    const policy = parseOrgPolicy({ retentionDays: { transcripts: 365 } });
    await prisma.organization.update({ where: { id: b.org.id }, data: { policy } });

    const res = await runRetentionPurge(ctx, { now: NOW });
    expect(res.orgs).toBe(2);
    expect(await prisma.chatMessage.count({ where: { sessionId: sa.id } })).toBe(0);
    expect(await prisma.chatMessage.count({ where: { sessionId: sb.id } })).toBe(1);
  });

  it('is idempotent: a second run finds nothing and writes no second summary', async () => {
    const { owner, org, project } = await setup();
    const s = await mkSession(project.id, owner.user.id, 'COMPLETED', ago(120));
    await mkMessage(s.id, ago(120));
    await mkArtifact(s.id, 'screenshot', ago(120));
    const first = await runRetentionPurge(ctx, { orgId: org.id, now: NOW });
    expect(first.totals).toMatchObject({ transcripts: 1, screenshots: 1 });
    const second = await runRetentionPurge(ctx, { orgId: org.id, now: NOW });
    expect(second.totals).toEqual({
      transcripts: 0,
      rawToolOutput: 0,
      screenshots: 0,
      auditLog: 0,
    });
    expect(
      await prisma.auditLog.count({ where: { orgId: org.id, action: 'retention.purge' } }),
    ).toBe(1);
  });

  it('works through more rows than one batch', async () => {
    const { owner, org, project } = await setup();
    const s = await mkSession(project.id, owner.user.id, 'COMPLETED', ago(120));
    await prisma.chatMessage.createMany({
      data: Array.from({ length: 1100 }, (_, i) => ({
        sessionId: s.id,
        role: 'USER' as const,
        content: `m${i}`,
        createdAt: ago(120),
      })),
    });
    const res = await runRetentionPurge(ctx, { orgId: org.id, now: NOW });
    expect(res.totals.transcripts).toBe(1100);
    expect(await prisma.chatMessage.count()).toBe(0);
  }, 60_000);

  it('records retention.purge with the counts, exposes them via the API and counts the metric', async () => {
    const { owner, org, project } = await setup();
    const s = await mkSession(project.id, owner.user.id, 'COMPLETED', ago(120));
    await mkMessage(s.id, ago(120));
    await runRetentionPurge(ctx, { orgId: org.id, now: NOW });
    const entry = await prisma.auditLog.findFirstOrThrow({
      where: { orgId: org.id, action: 'retention.purge' },
    });
    expect(entry.meta).toMatchObject({ counts: { transcripts: 1, rawToolOutput: 0 } });
    expect(entry.actorId).toBeNull();
    const res = await owner.get(`/api/v1/orgs/${org.id}/retention`);
    expect(res.body.data.lastPurgeCounts).toMatchObject({ transcripts: 1 });
    expect(typeof res.body.data.lastPurgeAt).toBe('string');
    expect(await metrics.render()).toMatch(
      /loose_retention_purged_total\{kind="transcripts"\}\s+1/,
    );
  });

  it('runs from the retention-purge job queue (inline runner) with a targeted org', async () => {
    const { owner, org, project } = await setup();
    const s = await mkSession(
      project.id,
      owner.user.id,
      'COMPLETED',
      new Date(Date.now() - 400 * DAY),
    );
    await mkMessage(s.id, new Date(Date.now() - 400 * DAY));
    await ctx.jobs.enqueue('retention-purge', { orgId: org.id });
    await ctx.jobs.onIdle();
    expect(await prisma.chatMessage.count()).toBe(0);
  });

  it('does not let one failing org stop the others', async () => {
    const a = await setup();
    const b = await setup();
    const sb = await mkSession(b.project.id, b.owner.user.id, 'COMPLETED', ago(200));
    await mkMessage(sb.id, ago(200));
    const real = ctx.kv.setIfAbsent.bind(ctx.kv);
    vi.spyOn(ctx.kv, 'setIfAbsent').mockImplementation(async (k, v, t) => {
      if (k === `retention:${a.org.id}`) throw new Error('kv down');
      return real(k, v, t);
    });
    const res = await runRetentionPurge(ctx, { now: NOW });
    expect(res).toMatchObject({ failed: 1, orgs: 1 });
    expect(await prisma.chatMessage.count({ where: { sessionId: sb.id } })).toBe(0);
  });

  it('skips an org that another worker is already purging (lock held)', async () => {
    const { owner, org, project } = await setup();
    const s = await mkSession(project.id, owner.user.id, 'COMPLETED', ago(200));
    await mkMessage(s.id, ago(200));
    await ctx.kv.setIfAbsent(`retention:${org.id}`, 'other-worker', 60);
    const res = await runRetentionPurge(ctx, { orgId: org.id, now: NOW });
    expect(res.orgs).toBe(0);
    expect(await prisma.chatMessage.count()).toBe(1);
    await ctx.kv.del(`retention:${org.id}`);
    expect((await runRetentionPurge(ctx, { orgId: org.id, now: NOW })).totals.transcripts).toBe(1);
  });
});

describe('audit-log purge keeps the hash chain verifiable', () => {
  /** Create an org without side effects so entries can be written at a faked "past" time. */
  async function bareOrg() {
    return prisma.organization.create({
      data: {
        name: 'Chain Org',
        slug: `chain-${Math.random().toString(36).slice(2, 8)}`,
        policy: defaultOrgPolicy(),
      },
    });
  }
  const key = () => ctx.audit.chainKey;
  const write = (orgId: string, target: string) =>
    ctx.audit.record({ orgId, action: 'org.update', target });

  it('purges the aged prefix, writes an anchor marker and keeps verifying (anchoredAt)', async () => {
    const org = await bareOrg();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2025-01-10T00:00:00Z'));
    for (let i = 1; i <= 5; i++) await write(org.id, `old${i}`);
    vi.setSystemTime(new Date('2026-02-10T00:00:00Z'));
    for (let i = 1; i <= 3; i++) await write(org.id, `new${i}`);
    vi.useRealTimers();

    const before = await verifyChain(prisma, key(), org.id);
    expect(before).toMatchObject({ ok: true, checked: 8, firstSeq: 1 });
    const rows = await prisma.auditLog.findMany({
      where: { chain: org.id },
      orderBy: { seq: 'asc' },
    });
    const anchorHash = rows[4]!.hash;

    const counts = await purgeOrg(ctx, org, NOW); // cutoff = 2025-06-01 (365 days)
    expect(counts.auditLog).toBe(5);

    const after = await verifyChain(prisma, key(), org.id);
    expect(after).toMatchObject({ ok: true, firstSeq: 6, anchoredAt: 6, brokenAt: null });
    const remaining = await prisma.auditLog.findMany({
      where: { chain: org.id },
      orderBy: { seq: 'asc' },
    });
    expect(remaining[0]).toMatchObject({ seq: 6, prevHash: anchorHash });
    const marker = remaining.find((r) => r.action === 'audit.retention_purged')!;
    expect(marker.meta).toMatchObject({ purgedThroughSeq: 5, anchorHash, count: 5 });
    expect(remaining.some((r) => r.action === 'retention.purge')).toBe(true);

    // appends continue the chain and it still verifies
    await write(org.id, 'after-purge');
    expect((await verifyChain(prisma, key(), org.id)).ok).toBe(true);
    // idempotent
    expect((await purgeOrg(ctx, org, NOW)).auditLog).toBe(0);
  });

  it('detects edits to the retained part and extra truncation beyond what the purge announced', async () => {
    const org = await bareOrg();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2025-01-10T00:00:00Z'));
    for (let i = 1; i <= 3; i++) await write(org.id, `old${i}`);
    vi.setSystemTime(new Date('2026-02-10T00:00:00Z'));
    for (let i = 1; i <= 3; i++) await write(org.id, `new${i}`);
    vi.useRealTimers();
    await purgeOrg(ctx, org, NOW);

    const rows = await prisma.auditLog.findMany({
      where: { chain: org.id },
      orderBy: { seq: 'asc' },
    });
    expect(rows[0]).toMatchObject({ seq: 4 }); // old1..old3 gone, new1 is the anchor
    // 1) edit a retained row
    await asMaintenance((tx) =>
      tx.auditLog.update({ where: { id: rows[1]!.id }, data: { target: 'forged' } }),
    );
    expect((await verifyChain(prisma, key(), org.id)).brokenAt).toMatchObject({
      seq: rows[1]!.seq,
      reason: 'hash_mismatch',
    });
    await asMaintenance((tx) =>
      tx.auditLog.update({ where: { id: rows[1]!.id }, data: { target: rows[1]!.target } }),
    );
    expect((await verifyChain(prisma, key(), org.id)).ok).toBe(true);

    // 2) somebody deletes more of the start than the purge marker accounts for
    await asMaintenance((tx) => tx.auditLog.delete({ where: { id: rows[0]!.id } }));
    expect((await verifyChain(prisma, key(), org.id)).brokenAt).toMatchObject({
      seq: rows[1]!.seq,
      reason: 'seq_gap',
    });
  });

  it('flags a chain that starts after seq 1 with no purge marker at all', async () => {
    const org = await bareOrg();
    for (let i = 1; i <= 4; i++) await write(org.id, `r${i}`);
    const rows = await prisma.auditLog.findMany({
      where: { chain: org.id },
      orderBy: { seq: 'asc' },
    });
    await asMaintenance((tx) =>
      tx.auditLog.deleteMany({ where: { id: { in: [rows[0]!.id, rows[1]!.id] } } }),
    );
    expect((await verifyChain(prisma, key(), org.id)).brokenAt).toMatchObject({
      seq: 3,
      reason: 'seq_gap',
    });
  });

  it('can purge everything old, leaving just the marker, and still verify', async () => {
    const org = await bareOrg();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2024-05-01T00:00:00Z'));
    for (let i = 1; i <= 4; i++) await write(org.id, `old${i}`);
    vi.useRealTimers();
    expect((await purgeOrg(ctx, org, NOW)).auditLog).toBe(4);
    const v = await verifyChain(prisma, key(), org.id);
    expect(v).toMatchObject({ ok: true, firstSeq: 5, anchoredAt: 5 });
    expect(v.checked).toBeGreaterThanOrEqual(1);
  });

  it('purges in batches (> 500 aged rows) without breaking the chain', async () => {
    const org = await bareOrg();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2024-05-01T00:00:00Z'));
    await Promise.all(Array.from({ length: 520 }, (_, i) => write(org.id, `old${i}`)));
    vi.setSystemTime(new Date('2026-05-20T00:00:00Z'));
    await write(org.id, 'recent');
    vi.useRealTimers();
    expect((await purgeOrg(ctx, org, NOW)).auditLog).toBe(520);
    const v = await verifyChain(prisma, key(), org.id);
    expect(v).toMatchObject({ ok: true, firstSeq: 521 });
    expect(await prisma.auditLog.count({ where: { chain: org.id } })).toBeLessThan(5);
  }, 60_000);

  it('deletes never-sealed legacy rows by age but not recent ones', async () => {
    const org = await bareOrg();
    await legacyAuditRow(prisma, {
      orgId: org.id,
      action: 'org.update',
      target: 'legacy-old',
      createdAt: ago(800),
    });
    await legacyAuditRow(prisma, {
      orgId: org.id,
      action: 'org.update',
      target: 'legacy-new',
      createdAt: ago(10),
    });
    // call the purge directly: runRetentionPurge would seal them into the chain first
    const counts = await purgeOrg(ctx, org, NOW);
    expect(counts.auditLog).toBe(1);
    const left = await prisma.auditLog.findMany({ where: { orgId: org.id, chain: null } });
    expect(left.map((r) => r.target)).toEqual(['legacy-new']);
  });

  it('the job seals legacy rows before purging so they age out through the chain', async () => {
    const org = await bareOrg();
    await legacyAuditRow(prisma, {
      orgId: org.id,
      action: 'org.update',
      target: 'legacy',
      createdAt: ago(10),
    });
    const res = await runRetentionPurge(ctx, { orgId: org.id, now: NOW });
    expect(res.sealedAuditRows).toBe(1);
    expect((await verifyChain(prisma, key(), org.id)).legacyUnchained).toBe(0);
  });

  it('keeps recent audit rows and respects a longer auditLog setting', async () => {
    const org = await bareOrg();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2025-09-01T00:00:00Z')); // 273 days before NOW
    await write(org.id, 'kept');
    vi.useRealTimers();
    expect((await purgeOrg(ctx, org, NOW)).auditLog).toBe(0);
    const short = parseOrgPolicy({ retentionDays: { auditLog: 30 } });
    expect((await purgeOrg(ctx, { id: org.id, policy: short }, NOW)).auditLog).toBe(1);
  });
});

describe('retention settings API', () => {
  const url = (orgId: string) => `/api/v1/orgs/${orgId}/retention`;

  it('GET returns the effective defaults to ADMIN+', async () => {
    const { owner, org } = await setup();
    const admin = await login(app);
    await addMember(org.id, admin.user.id, 'ADMIN');
    for (const c of [owner, admin]) {
      const res = await c.get(url(org.id));
      expect(res.status).toBe(200);
      expect(res.body.data).toEqual({
        settings: {
          transcripts: RETENTION_LIMITS.transcripts.default,
          rawToolOutput: RETENTION_LIMITS.rawToolOutput.default,
          screenshots: RETENTION_LIMITS.screenshots.default,
          auditLog: RETENTION_LIMITS.auditLog.default,
        },
        lastPurgeAt: null,
        lastPurgeCounts: null,
      });
    }
  });

  it('PUT is OWNER-only, validated, audited, and leaves the rest of the policy alone', async () => {
    const { owner, org } = await setup();
    const admin = await login(app);
    await addMember(org.id, admin.user.id, 'ADMIN');
    const member = await login(app);
    await addMember(org.id, member.user.id, 'MEMBER');
    await owner.put(`/api/v1/orgs/${org.id}/policy`, {
      ...defaultOrgPolicy(),
      commitToMainEnabled: true,
    });

    const body = { transcripts: 30, rawToolOutput: 7, screenshots: 14, auditLog: 90 };
    expectError(await admin.put(url(org.id), body), 'LSE-ORG-002', 403);
    expectError(await member.put(url(org.id), body), 'LSE-ORG-002', 403);
    expectError(await member.get(url(org.id)), 'LSE-ORG-002', 403);
    const stranger = await login(app);
    expectError(await stranger.put(url(org.id), body), 'LSE-ORG-001', 403);

    const res = await owner.put(url(org.id), body);
    expect(res.status).toBe(200);
    expect(res.body.data.settings).toEqual(body);

    const policy = await owner.get(`/api/v1/orgs/${org.id}/policy`);
    expect(policy.body.data.retentionDays).toEqual(body);
    expect(policy.body.data.commitToMainEnabled).toBe(true);

    const entry = await prisma.auditLog.findFirstOrThrow({
      where: { orgId: org.id, action: 'retention.update' },
    });
    expect(entry.actorId).toBe(owner.user.id);
    expect(entry.meta).toMatchObject({
      before: { transcripts: 90 },
      after: { transcripts: 30, rawToolOutput: 7, screenshots: 14, auditLog: 90 },
    });
  });

  it('PUT validates ranges (LSE-VAL-001) and rejects API tokens', async () => {
    const { owner, org } = await setup();
    const ok = { transcripts: 30, rawToolOutput: 7, screenshots: 14, auditLog: 90 };
    expectError(await owner.put(url(org.id), { ...ok, auditLog: 29 }), 'LSE-VAL-001', 400); // min 30
    expectError(await owner.put(url(org.id), { ...ok, transcripts: 0 }), 'LSE-VAL-001', 400);
    expectError(await owner.put(url(org.id), { ...ok, screenshots: 99999 }), 'LSE-VAL-001', 400);
    expectError(await owner.put(url(org.id), { ...ok, transcripts: 1.5 }), 'LSE-VAL-001', 400);
    const minted = await owner.post('/api/v1/users/me/tokens', {
      orgId: org.id,
      name: 'ci',
      scopes: ['org:read'],
    });
    expectError(
      await request(app)
        .put(url(org.id))
        .set('Authorization', `Bearer ${minted.body.data.token as string}`)
        .send(ok),
      'LSE-ORG-002',
      403,
    );
  });

  it('a changed setting changes what the next purge removes', async () => {
    const { owner, org, project } = await setup();
    const s = await mkSession(project.id, owner.user.id, 'COMPLETED', ago(40));
    await mkMessage(s.id, ago(40));
    await runRetentionPurge(ctx, { orgId: org.id, now: NOW });
    expect(await prisma.chatMessage.count()).toBe(1); // 40 d < default 90 d
    await owner.put(url(org.id), {
      transcripts: 30,
      rawToolOutput: 30,
      screenshots: 30,
      auditLog: 365,
    });
    await runRetentionPurge(ctx, { orgId: org.id, now: NOW });
    expect(await prisma.chatMessage.count()).toBe(0);
  });
});
