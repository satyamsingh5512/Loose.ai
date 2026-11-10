/**
 * Phase 10 (W2): GDPR / DPDP — personal and org data export (async job → ZIP), account and
 * organization deletion with a grace period, cancel, the write freeze (LSE-ORG-012) and the sweep.
 */
import { unzipSync } from 'fflate';
import request from 'supertest';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DATA_EXPORT_CONTENT_TYPE, MAX_ACTIVE_DATA_EXPORTS } from '@loose/shared';
import { AppError } from '../src/lib/errors';
import { verifyChain } from '../src/services/governance/auditChain';
import { buildDataExport, expireDataExports } from '../src/services/governance/dataExport';
import { runDeletionSweep } from '../src/services/governance/deletion';
import { assertOrgNotPendingDeletion } from '../src/services/governance/orgWritable';
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
import { DUMMY_ANTHROPIC_KEY, addApiKey, createReadyProject, fakeSandbox } from './sessionHelpers';

const prisma = testPrisma();
const { app, ctx } = makeApp();
const DAY = 86_400_000;

/**
 * The sweep is driven with a simulated `now`, but `loose_audit_redact_user` (REAUDIT-007) checks
 * that the request is due by the DATABASE clock. Move the request's due date into the real past.
 */
async function makeDueNow(requestId: string): Promise<void> {
  await prisma.deletionRequest.update({
    where: { id: requestId },
    data: { scheduledFor: new Date(Date.now() - 1_000) },
  });
}

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

const orgUrl = (orgId: string, path = '') => `/api/v1/orgs/${orgId}${path}`;
const mine = (path = '') => `/api/v1/users/me/privacy${path}`;

async function bytesOf(client: Client, url: string): Promise<Buffer> {
  const res = await client
    .get(url)
    .buffer(true)
    .parse((r, cb) => {
      const chunks: Buffer[] = [];
      r.on('data', (c: Buffer) => chunks.push(c));
      r.on('end', () => cb(null, Buffer.concat(chunks)));
    });
  expect(res.status, JSON.stringify(res.body)).toBe(200);
  return res.body as Buffer;
}

function unzipJson(buf: Buffer): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, data] of Object.entries(unzipSync(new Uint8Array(buf)))) {
    out[name] = Buffer.from(data).toString('utf8');
  }
  return out;
}

const ndjson = (text: string | undefined) =>
  (text ?? '')
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l) as Record<string, unknown>);

/** Org with owner + member, a project with a secret env var, a BYOK key, a PAT, and chat data. */
async function populated() {
  const owner = await login(app, 'owner@example.com', 'Olivia Owner');
  const org = await createOrg(owner, 'Acme Data');
  const member = await login(app, 'member@example.com', 'Mike Member');
  await addMember(org.id, member.user.id, 'MEMBER');
  const project = await createReadyProject(ctx, org.id, {
    env: { STRIPE_SECRET_KEY: 'sk_live_super_secret_value' },
  });
  await addApiKey(ctx, owner.user.id);
  await owner.post('/api/v1/users/me/tokens', { orgId: org.id, name: 'ci', scopes: ['org:read'] });

  const mkSession = async (userId: string, status: 'COMPLETED' | 'RUNNING', label: string) => {
    const s = await prisma.session.create({
      data: {
        projectId: project.id,
        userId,
        mode: 'PRO',
        model: 'claude-sonnet-4-5',
        branchName: `loose/session-${label}`,
        status,
        endedAt: status === 'COMPLETED' ? new Date() : null,
      },
    });
    await prisma.chatMessage.create({
      data: {
        sessionId: s.id,
        role: 'USER',
        content: `hello from ${label}`,
        rawContent: { internal: `RAW-${label}` },
      },
    });
    const key = `sessions/${s.id}/shot.png`;
    await ctx.storage.put(key, `png-${label}`);
    await prisma.artifact.create({
      data: { sessionId: s.id, kind: 'screenshot', url: '/u', storageKey: key },
    });
    await prisma.usageEvent.create({
      data: {
        sessionId: s.id,
        orgId: org.id,
        userId,
        model: 'claude-sonnet-4-5',
        tokensIn: 10,
        tokensOut: 5,
        cacheRead: 0,
        costUsd: 0.01,
      },
    });
    return { session: s, key };
  };
  const ownerSession = await mkSession(owner.user.id, 'COMPLETED', 'owner');
  const memberSession = await mkSession(member.user.id, 'COMPLETED', 'member');
  return { owner, member, org, project, ownerSession, memberSession, mkSession };
}

describe('personal data export (POST /users/me/privacy/exports)', () => {
  it("builds a ZIP of the caller's data, without credentials, raw events or others' data", async () => {
    const d = await populated();
    const created = await d.owner.post(mine('/exports'));
    expect(created.status).toBe(202);
    expect(created.body.data).toMatchObject({ kind: 'USER', orgId: null });
    await ctx.jobs.onIdle();

    const dto = (await d.owner.get(mine(`/exports/${created.body.data.id}`))).body.data;
    expect(dto).toMatchObject({ status: 'SUCCEEDED', error: null });
    expect(dto.bytes).toBeGreaterThan(100);
    expect(dto.downloadUrl).toBe(mine(`/exports/${dto.id}/download`));
    const ttlMs = new Date(dto.expiresAt as string).getTime() - Date.now();
    expect(ttlMs).toBeGreaterThan(71 * 3_600_000);
    expect(ttlMs).toBeLessThanOrEqual(72 * 3_600_000);

    const dl = await d.owner
      .get(dto.downloadUrl as string)
      .buffer(true)
      .parse((r, cb) => {
        const chunks: Buffer[] = [];
        r.on('data', (c: Buffer) => chunks.push(c));
        r.on('end', () => cb(null, Buffer.concat(chunks)));
      });
    expect(dl.headers['content-type']).toBe(DATA_EXPORT_CONTENT_TYPE);
    expect(dl.headers['content-disposition']).toMatch(
      /^attachment; filename="loose-user-export-.+\.zip"$/,
    );
    expect(dl.headers['cache-control']).toBe('no-store');
    const files = unzipJson(dl.body as Buffer);

    expect(Object.keys(files).sort()).toEqual(
      [
        'api-keys.json',
        'api-tokens.json',
        'artifacts.ndjson',
        'audit-log.ndjson',
        'manifest.json',
        'memberships.json',
        'messages.ndjson',
        'oauth-accounts.json',
        'profile.json',
        'runs.ndjson',
        'sessions.ndjson',
        'sign-in-sessions.json',
        'usage-events.ndjson',
      ].sort(),
    );
    expect(JSON.parse(files['profile.json']!)).toMatchObject({
      id: d.owner.user.id,
      email: 'owner@example.com',
      name: 'Olivia Owner',
    });
    expect(JSON.parse(files['memberships.json']!)).toHaveLength(1);
    expect(ndjson(files['sessions.ndjson']).map((s) => s.id)).toEqual([d.ownerSession.session.id]);
    expect(ndjson(files['messages.ndjson']).map((m) => m.content)).toEqual(['hello from owner']);
    expect(ndjson(files['usage-events.ndjson'])).toHaveLength(1);
    expect(JSON.parse(files['api-keys.json']!)[0]).toMatchObject({
      last4: '0000',
      status: 'ACTIVE',
    });
    expect(ndjson(files['audit-log.ndjson']).some((a) => a.action === 'org.create')).toBe(true);
    const manifest = JSON.parse(files['manifest.json']!);
    expect(manifest).toMatchObject({ kind: 'USER', subjectId: d.owner.user.id });
    expect(manifest.files.find((f: { file: string }) => f.file === 'sessions.ndjson').rows).toBe(1);

    const everything = Object.values(files).join('\n');
    // no other person's data
    expect(everything).not.toContain('hello from member');
    expect(everything).not.toContain('member@example.com');
    // no credentials, raw agent events or storage internals
    for (const secret of [
      DUMMY_ANTHROPIC_KEY,
      'sk_live_super_secret_value',
      'RAW-owner',
      'keyEnc',
      'dataKeyEnc',
      'envVarsEnc',
      'storageKey',
      'rawContent',
      'passwordHash',
      'totpSecret',
      'loose_pat_',
    ]) {
      expect(everything, secret).not.toContain(secret);
    }
    expect(JSON.parse(files['api-tokens.json']!)[0]).not.toHaveProperty('hash');
  });

  it("lists and shows only the caller's exports; other users get LSE-NF-001", async () => {
    const d = await populated();
    const a = await d.owner.post(mine('/exports'));
    await ctx.jobs.onIdle();
    expect(
      (await d.owner.get(mine('/exports'))).body.data.map((e: { id: string }) => e.id),
    ).toEqual([a.body.data.id]);
    expect((await d.member.get(mine('/exports'))).body.data).toEqual([]);
    expectError(await d.member.get(mine(`/exports/${a.body.data.id}`)), 'LSE-NF-001', 404);
    expectError(await d.member.get(mine(`/exports/${a.body.data.id}/download`)), 'LSE-NF-001', 404);
    expectError(await d.owner.get(mine('/exports/does-not-exist')), 'LSE-NF-001', 404);
  });

  it('keeps one export in flight per person: asking again returns it (200, not created)', async () => {
    const d = await populated();
    const pending = await prisma.dataExport.create({
      data: { kind: 'USER', requestedById: d.owner.user.id },
    });
    const again = await d.owner.post(mine('/exports'));
    expect(MAX_ACTIVE_DATA_EXPORTS).toBe(1);
    expect(again.status).toBe(200);
    expect(again.body.data.id).toBe(pending.id);
    expect(await prisma.dataExport.count()).toBe(1);
    // …and another user is unaffected
    expect((await d.member.post(mine('/exports'))).status).toBe(202);
  });

  it('supports Idempotency-Key replays', async () => {
    const d = await populated();
    const first = await d.owner.post(mine('/exports')).set('Idempotency-Key', 'exp-1');
    const second = await d.owner.post(mine('/exports')).set('Idempotency-Key', 'exp-1');
    expect(first.status).toBe(202);
    expect(second.headers['idempotent-replayed']).toBe('true');
    expect(second.body.data.id).toBe(first.body.data.id);
    await ctx.jobs.onIdle();
    expect(await prisma.dataExport.count()).toBe(1);
  });

  it('refuses a download before it is ready, and after it expired (file removed by the sweep)', async () => {
    const d = await populated();
    const pending = await prisma.dataExport.create({
      data: { kind: 'USER', requestedById: d.owner.user.id },
    });
    expectError(await d.owner.get(mine(`/exports/${pending.id}/download`)), 'LSE-NF-001', 404);
    await prisma.dataExport.delete({ where: { id: pending.id } });

    const created = await d.owner.post(mine('/exports'));
    await ctx.jobs.onIdle();
    const row = await prisma.dataExport.findUniqueOrThrow({ where: { id: created.body.data.id } });
    expect(await ctx.storage.get(row.storageKey!)).not.toBeNull();

    await prisma.dataExport.update({
      where: { id: row.id },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });
    // expired but not yet swept: already reported as expired and not downloadable
    const shown = (await d.owner.get(mine(`/exports/${row.id}`))).body.data;
    expect(shown).toMatchObject({ status: 'EXPIRED', downloadUrl: null });
    expectError(await d.owner.get(mine(`/exports/${row.id}/download`)), 'LSE-NF-001', 404);

    expect(await expireDataExports(ctx)).toBe(1);
    expect(await ctx.storage.get(row.storageKey!)).toBeNull();
    const swept = await prisma.dataExport.findUniqueOrThrow({ where: { id: row.id } });
    expect(swept).toMatchObject({ status: 'EXPIRED', storageKey: null });
    expect(await expireDataExports(ctx)).toBe(0);
  });

  it('honours DATA_EXPORT_TTL_HOURS', async () => {
    const short = makeApp({ env: { DATA_EXPORT_TTL_HOURS: '1' } });
    const me = await login(short.app);
    await me.post(mine('/exports'));
    await short.ctx.jobs.onIdle();
    const row = await prisma.dataExport.findFirstOrThrow();
    const ttl = row.expiresAt!.getTime() - row.completedAt!.getTime();
    expect(ttl).toBe(3_600_000);
  });

  it('records data_export.create and data_export.download in the audit log', async () => {
    const d = await populated();
    const created = await d.owner.post(mine('/exports'));
    await ctx.jobs.onIdle();
    await bytesOf(d.owner, mine(`/exports/${created.body.data.id}/download`));
    const actions = (
      await prisma.auditLog.findMany({
        where: { actorId: d.owner.user.id, action: { startsWith: 'data_export.' } },
        orderBy: { createdAt: 'asc' },
      })
    ).map((a) => a.action);
    expect(actions).toEqual(['data_export.create', 'data_export.download']);
  });

  it('fails the export (FAILED + code, no partial file) when storage is down, then recovers', async () => {
    const d = await populated();
    const spy = vi.spyOn(ctx.storage, 'put').mockRejectedValue(new AppError('LSE-SYS-008'));
    const created = await d.owner.post(mine('/exports'));
    await ctx.jobs.onIdle();
    expect((await d.owner.get(mine(`/exports/${created.body.data.id}`))).body.data).toMatchObject({
      status: 'FAILED',
      error: 'LSE-SYS-008',
      downloadUrl: null,
    });
    spy.mockRestore();
    expect((await d.owner.post(mine('/exports'))).status).toBe(202);
    await ctx.jobs.onIdle();
    expect((await d.owner.get(mine('/exports'))).body.data[0].status).toBe('SUCCEEDED');
  });

  it('is idempotent as a job (only a PENDING export is claimed) and ignores unknown ids', async () => {
    const d = await populated();
    const row = await prisma.dataExport.create({
      data: { kind: 'USER', requestedById: d.owner.user.id },
    });
    await Promise.all([buildDataExport(ctx, row.id), buildDataExport(ctx, row.id)]);
    expect((await prisma.dataExport.findUniqueOrThrow({ where: { id: row.id } })).status).toBe(
      'SUCCEEDED',
    );
    await expect(buildDataExport(ctx, 'does-not-exist')).resolves.toBeUndefined();
    await ctx.jobs.enqueue('data-export', { exportId: 'nope' });
    await ctx.jobs.enqueue('data-export', {});
    await ctx.jobs.onIdle();
  });

  it('fails exports stuck in RUNNING after an hour', async () => {
    const d = await populated();
    const row = await prisma.dataExport.create({
      data: {
        kind: 'USER',
        requestedById: d.owner.user.id,
        status: 'RUNNING',
        startedAt: new Date(Date.now() - 2 * 3_600_000),
      },
    });
    await expireDataExports(ctx);
    expect(await prisma.dataExport.findUniqueOrThrow({ where: { id: row.id } })).toMatchObject({
      status: 'FAILED',
      error: 'Export timed out',
    });
  });

  it('requires a browser session and the data_export flag', async () => {
    const d = await populated();
    expectError(await request(app).get(mine('/exports')), 'LSE-AUTH-001', 401);
    const minted = await d.owner.post('/api/v1/users/me/tokens', {
      orgId: d.org.id,
      name: 'x',
      scopes: ['org:read'],
    });
    const bearer = `Bearer ${minted.body.data.token as string}`;
    expectError(
      await request(app).get(mine('/exports')).set('Authorization', bearer),
      'LSE-AUTH-001',
      401,
    );
    expectError(
      await request(app).get(mine('/deletion')).set('Authorization', bearer),
      'LSE-AUTH-001',
      401,
    );

    const off = makeApp({ env: { FEATURE_FLAGS: 'data_export=off' } });
    const me = await login(off.app);
    expectError(await me.post(mine('/exports')), 'LSE-SYS-007', 503);
    expectError(await me.get(mine('/exports')), 'LSE-SYS-007', 503);
    await off.ctx.jobs.onIdle();
  });
});

describe('organization data export (/orgs/:orgId/data-exports)', () => {
  it('is OWNER-only and exports the whole org, never credentials', async () => {
    const d = await populated();
    const admin = await login(app, 'admin@example.com');
    await addMember(d.org.id, admin.user.id, 'ADMIN');
    expectError(await admin.post(orgUrl(d.org.id, '/data-exports')), 'LSE-ORG-002', 403);
    expectError(await d.member.get(orgUrl(d.org.id, '/data-exports')), 'LSE-ORG-002', 403);
    expectError(
      await (await login(app)).get(orgUrl(d.org.id, '/data-exports')),
      'LSE-ORG-001',
      403,
    );

    const created = await d.owner.post(orgUrl(d.org.id, '/data-exports'));
    expect(created.status).toBe(202);
    expect(created.body.data).toMatchObject({ kind: 'ORG', orgId: d.org.id });
    await ctx.jobs.onIdle();
    const dto = (await d.owner.get(orgUrl(d.org.id, `/data-exports/${created.body.data.id}`))).body
      .data;
    expect(dto.status).toBe('SUCCEEDED');
    expect(dto.downloadUrl).toBe(orgUrl(d.org.id, `/data-exports/${dto.id}/download`));

    const files = unzipJson(await bytesOf(d.owner, dto.downloadUrl as string));
    expect(JSON.parse(files['organization.json']!)).toMatchObject({
      id: d.org.id,
      name: 'Acme Data',
    });
    expect(
      JSON.parse(files['members.json']!)
        .map((m: { user: { email: string } }) => m.user.email)
        .sort(),
    ).toEqual(['admin@example.com', 'member@example.com', 'owner@example.com']);
    expect(ndjson(files['sessions.ndjson'])).toHaveLength(2);
    expect(
      ndjson(files['messages.ndjson'])
        .map((m) => m.content)
        .sort(),
    ).toEqual(['hello from member', 'hello from owner']);
    expect(ndjson(files['audit-log.ndjson']).length).toBeGreaterThan(0);
    expect(JSON.parse(files['projects.json']!)).toHaveLength(1);
    const everything = Object.values(files).join('\n');
    for (const secret of [
      'sk_live_super_secret_value',
      DUMMY_ANTHROPIC_KEY,
      'envVarsEnc',
      'RAW-owner',
      'keyEnc',
    ]) {
      expect(everything, secret).not.toContain(secret);
    }
  });

  it("cannot read another org's export, even by id", async () => {
    const a = await populated();
    const otherOwner = await login(app, 'other@example.com');
    const otherOrg = await createOrg(otherOwner, 'Other Org');
    const created = await a.owner.post(orgUrl(a.org.id, '/data-exports'));
    await ctx.jobs.onIdle();
    expectError(
      await otherOwner.get(orgUrl(otherOrg.id, `/data-exports/${created.body.data.id}`)),
      'LSE-NF-001',
      404,
    );
    expectError(
      await otherOwner.get(orgUrl(a.org.id, `/data-exports/${created.body.data.id}`)),
      'LSE-ORG-001',
      403,
    );
    // an org export is not reachable through the personal route either
    expectError(await a.owner.get(mine(`/exports/${created.body.data.id}`)), 'LSE-NF-001', 404);
  });

  it('is session-only (tokens refused) and switched off by the flag', async () => {
    const d = await populated();
    const minted = await d.owner.post('/api/v1/users/me/tokens', {
      orgId: d.org.id,
      name: 'x',
      scopes: ['org:read'],
    });
    expectError(
      await request(app)
        .get(orgUrl(d.org.id, '/data-exports'))
        .set('Authorization', `Bearer ${minted.body.data.token as string}`),
      'LSE-AUTH-001',
      401,
    );
    const off = makeApp({ env: { FEATURE_FLAGS: 'data_export=off' } });
    const owner = await login(off.app);
    const org = await createOrg(owner);
    expectError(await owner.get(orgUrl(org.id, '/data-exports')), 'LSE-SYS-007', 503);
    await off.ctx.jobs.onIdle();
  });
});

describe('organization deletion (grace period, freeze, cancel, sweep)', () => {
  it('validates the confirmation and is OWNER-only', async () => {
    const d = await populated();
    const admin = await login(app, 'admin@example.com');
    await addMember(d.org.id, admin.user.id, 'ADMIN');
    const url = orgUrl(d.org.id, '/deletion');
    const wrong = await d.owner.post(url, { confirm: 'not-the-slug' });
    expectError(wrong, 'LSE-VAL-001', 400);
    expect(wrong.body.error.fields.confirm).toBeDefined();
    expectError(await d.owner.post(url, {}), 'LSE-VAL-001', 400);
    expectError(await admin.post(url, { confirm: d.org.slug }), 'LSE-ORG-002', 403);
    expectError(await d.member.get(url), 'LSE-ORG-002', 403);
    expectError(await admin.delete(url), 'LSE-ORG-002', 403);
    expect((await d.owner.get(url)).body.data).toBeNull();
    expect(
      (await prisma.organization.findUniqueOrThrow({ where: { id: d.org.id } }))
        .deletionScheduledAt,
    ).toBeNull();
  });

  it('schedules with the grace period, is idempotent, and audits', async () => {
    const d = await populated();
    const url = orgUrl(d.org.id, '/deletion');
    const res = await d.owner.post(url, { confirm: d.org.slug });
    expect(res.status).toBe(201);
    expect(res.body.data).toMatchObject({ kind: 'ORG', status: 'PENDING', cancelledAt: null });
    const due = new Date(res.body.data.scheduledFor as string).getTime();
    expect(Math.abs(due - (Date.now() + 30 * DAY))).toBeLessThan(60_000);
    const org = await prisma.organization.findUniqueOrThrow({ where: { id: d.org.id } });
    expect(org.deletionScheduledAt?.getTime()).toBe(due);

    const again = await d.owner.post(url, { confirm: d.org.slug });
    expect(again.status).toBe(200);
    expect(again.body.data.id).toBe(res.body.data.id);
    expect(await prisma.deletionRequest.count()).toBe(1);
    expect((await d.owner.get(url)).body.data.id).toBe(res.body.data.id);

    const entry = await prisma.auditLog.findFirstOrThrow({
      where: { orgId: d.org.id, action: 'deletion.schedule' },
    });
    expect(entry).toMatchObject({ actorId: d.owner.user.id, target: d.org.id });
    expect(
      await prisma.auditLog.count({ where: { orgId: d.org.id, action: 'deletion.schedule' } }),
    ).toBe(1);
  });

  it('honours DELETION_GRACE_DAYS', async () => {
    const short = makeApp({ env: { DELETION_GRACE_DAYS: '3' } });
    const owner = await login(short.app);
    const org = await createOrg(owner);
    const res = await owner.post(orgUrl(org.id, '/deletion'), { confirm: org.slug });
    const due = new Date(res.body.data.scheduledFor as string).getTime();
    expect(Math.abs(due - (Date.now() + 3 * DAY))).toBeLessThan(60_000);
    await short.ctx.jobs.onIdle();
  });

  it('freezes writes with LSE-ORG-012 (reads, exports and cancel still work)', async () => {
    const d = await populated();
    await d.owner.post(orgUrl(d.org.id, '/deletion'), { confirm: d.org.slug });

    const blocked = [
      await d.owner.put(orgUrl(d.org.id), { name: 'Renamed' }),
      await d.owner.post(orgUrl(d.org.id, '/invites'), {
        email: 'new@example.com',
        role: 'MEMBER',
      }),
      await d.owner.put(orgUrl(d.org.id, '/memory'), { memory: 'x' }),
      await d.owner.delete(orgUrl(d.org.id, `/members/${d.member.user.id}`)),
      await d.owner.delete(orgUrl(d.org.id)),
    ];
    for (const res of blocked) expectError(res, 'LSE-ORG-012', 409);
    expect(blocked[0]!.body.error.retryable).toBe(false);

    expect((await d.owner.get(orgUrl(d.org.id))).status).toBe(200);
    expect((await d.member.get(orgUrl(d.org.id, '/sessions'))).status).toBe(200);
    expect((await d.owner.get(orgUrl(d.org.id, '/audit-log'))).status).toBe(200);
    // take your data with you
    expect((await d.owner.post(orgUrl(d.org.id, '/data-exports'))).status).toBe(202);
    await ctx.jobs.onIdle();
    expect((await prisma.organization.findUniqueOrThrow({ where: { id: d.org.id } })).name).toBe(
      'Acme Data',
    );
  });

  it('cancel restores writes, is audited, and a second cancel is LSE-NF-001', async () => {
    const d = await populated();
    const url = orgUrl(d.org.id, '/deletion');
    const first = await d.owner.post(url, { confirm: d.org.slug });
    const cancelled = await d.owner.delete(url);
    expect(cancelled.status).toBe(200);
    expect(cancelled.body.data).toMatchObject({ id: first.body.data.id, status: 'CANCELLED' });
    expect(cancelled.body.data.cancelledAt).toEqual(expect.any(String));
    expect(
      (await prisma.organization.findUniqueOrThrow({ where: { id: d.org.id } }))
        .deletionScheduledAt,
    ).toBeNull();
    expect((await d.owner.put(orgUrl(d.org.id), { name: 'Renamed OK' })).status).toBe(200);
    expectError(await d.owner.delete(url), 'LSE-NF-001', 404);
    expect((await d.owner.get(url)).body.data).toBeNull();
    expect(
      await prisma.auditLog.count({ where: { orgId: d.org.id, action: 'deletion.cancel' } }),
    ).toBe(1);

    // scheduling again after a cancel starts a fresh request
    const second = await d.owner.post(url, {
      confirm: d.org.slug.replace(
        /.*/,
        (await prisma.organization.findUniqueOrThrow({ where: { id: d.org.id } })).slug,
      ),
    });
    expect(second.status).toBe(201);
    expect(second.body.data.id).not.toBe(first.body.data.id);
  });

  it('the sweep does nothing before the grace period ends and ignores cancelled requests', async () => {
    const d = await populated();
    const url = orgUrl(d.org.id, '/deletion');
    const res = await d.owner.post(url, { confirm: d.org.slug });
    const due = new Date(res.body.data.scheduledFor as string);
    expect(await runDeletionSweep(ctx, { now: new Date(due.getTime() - 1) })).toMatchObject({
      completed: 0,
    });
    expect(await prisma.organization.count({ where: { id: d.org.id } })).toBe(1);

    await d.owner.delete(url);
    expect(await runDeletionSweep(ctx, { now: new Date(due.getTime() + DAY) })).toMatchObject({
      completed: 0,
    });
    expect(await prisma.organization.count({ where: { id: d.org.id } })).toBe(1);
  });

  it('executes after the grace period: stops sessions, removes the org, rows and stored files', async () => {
    const d = await populated();
    // a live session with a running sandbox, plus a finished export file
    const sbx = await fakeSandbox(ctx).createFromTemplate('tpl-ready-1', { timeoutMs: 60_000 });
    const live = await d.mkSession(d.owner.user.id, 'RUNNING', 'live');
    await prisma.session.update({ where: { id: live.session.id }, data: { sandboxId: sbx.id } });
    await d.owner.post(orgUrl(d.org.id, '/data-exports'));
    await ctx.jobs.onIdle();
    const exportRow = await prisma.dataExport.findFirstOrThrow({ where: { orgId: d.org.id } });
    const keys = [d.ownerSession.key, d.memberSession.key, live.key, exportRow.storageKey!];
    for (const k of keys) expect(await ctx.storage.get(k)).not.toBeNull();

    const res = await d.owner.post(orgUrl(d.org.id, '/deletion'), { confirm: d.org.slug });
    const due = new Date(res.body.data.scheduledFor as string);
    const result = await runDeletionSweep(ctx, { now: new Date(due.getTime() + 1000) });
    expect(result).toMatchObject({ completed: 1, failed: 0 });

    expect(sbx.alive).toBe(false);
    expect(await prisma.organization.count({ where: { id: d.org.id } })).toBe(0);
    expect(await prisma.project.count({ where: { orgId: d.org.id } })).toBe(0);
    expect(await prisma.session.count()).toBe(0);
    expect(await prisma.usageEvent.count()).toBe(0);
    expect(await prisma.dataExport.count({ where: { orgId: d.org.id } })).toBe(0);
    for (const k of keys) expect(await ctx.storage.get(k)).toBeNull();
    // people survive; only the membership is gone
    expect(
      await prisma.user.count({ where: { id: { in: [d.owner.user.id, d.member.user.id] } } }),
    ).toBe(2);
    expect(await prisma.orgMember.count()).toBe(0);

    const request_ = await prisma.deletionRequest.findUniqueOrThrow({
      where: { id: res.body.data.id },
    });
    expect(request_).toMatchObject({ status: 'COMPLETED', orgId: null });
    expect(request_.completedAt).not.toBeNull();
    const done = await prisma.auditLog.findFirstOrThrow({ where: { action: 'deletion.complete' } });
    expect(done).toMatchObject({ orgId: null, target: res.body.data.id });
    expect(done.meta).toMatchObject({ kind: 'ORG', orgId: d.org.id });
    // idempotent
    expect(await runDeletionSweep(ctx, { now: new Date(due.getTime() + 2000) })).toMatchObject({
      completed: 0,
    });
  });

  it('two sweeps at once complete the deletion exactly once', async () => {
    const d = await populated();
    const short = makeApp({ env: { DELETION_GRACE_DAYS: '0' } });
    const res = await d.owner.post(orgUrl(d.org.id, '/deletion'), { confirm: d.org.slug });
    const now = new Date(new Date(res.body.data.scheduledFor as string).getTime() + 1000);
    const [a, b] = await Promise.all([
      runDeletionSweep(ctx, { now }),
      runDeletionSweep(short.ctx, { now }),
    ]);
    expect(a.completed + b.completed).toBe(1);
    expect(a.failed + b.failed).toBe(0);
    expect(await prisma.auditLog.count({ where: { action: 'deletion.complete' } })).toBe(1);
    await short.ctx.jobs.onIdle();
  });

  it('runs from the deletion-sweep job queue', async () => {
    const d = await populated();
    const zero = makeApp({ env: { DELETION_GRACE_DAYS: '0' } });
    const owner = await login(zero.app);
    const org = await createOrg(owner);
    await owner.post(orgUrl(org.id, '/deletion'), { confirm: org.slug });
    await new Promise((r) => setTimeout(r, 10));
    await zero.ctx.jobs.enqueue('deletion-sweep', {});
    await zero.ctx.jobs.onIdle();
    expect(await prisma.organization.count({ where: { id: org.id } })).toBe(0);
    expect(await prisma.organization.count({ where: { id: d.org.id } })).toBe(1);
  });

  it('there is no immediate DELETE /orgs/:id any more: nothing is deleted or removed from storage', async () => {
    const d = await populated();
    expect(await ctx.storage.get(d.ownerSession.key)).not.toBeNull();
    expectError(await d.owner.delete(orgUrl(d.org.id)), 'LSE-NF-001', 404);
    expect(await prisma.organization.count({ where: { id: d.org.id } })).toBe(1);
    expect(await ctx.storage.get(d.ownerSession.key)).not.toBeNull();
  });

  it('assertOrgNotPendingDeletion throws LSE-ORG-012 only for pending orgs', () => {
    expect(() => assertOrgNotPendingDeletion({ id: 'o', deletionScheduledAt: null })).not.toThrow();
    expect(() =>
      assertOrgNotPendingDeletion({ id: 'o', deletionScheduledAt: new Date() }),
    ).toThrowError(expect.objectContaining({ code: 'LSE-ORG-012', status: 409 }));
  });
});

describe('account deletion (/users/me/privacy/deletion)', () => {
  it('requires the email as confirmation (case-insensitive) and is audited', async () => {
    const me = await login(app, 'Person@Example.com');
    expectError(
      await me.post(mine('/deletion'), { confirm: 'someone@else.com' }),
      'LSE-VAL-001',
      400,
    );
    expectError(await me.post(mine('/deletion'), {}), 'LSE-VAL-001', 400);
    expect((await me.get(mine('/deletion'))).body.data).toBeNull();

    const res = await me.post(mine('/deletion'), { confirm: ' person@example.com ' });
    expect(res.status).toBe(201);
    expect(res.body.data).toMatchObject({ kind: 'USER', status: 'PENDING' });
    const due = new Date(res.body.data.scheduledFor as string).getTime();
    expect(Math.abs(due - (Date.now() + 30 * DAY))).toBeLessThan(60_000);
    expect((await me.get('/api/v1/users/me')).body.data.deletionScheduledAt).toEqual(
      expect.any(String),
    );
    expect((await me.get(mine('/deletion'))).body.data.id).toBe(res.body.data.id);
    const again = await me.post(mine('/deletion'), { confirm: 'person@example.com' });
    expect([again.status, again.body.data.id]).toEqual([200, res.body.data.id]);
    expect(
      await prisma.auditLog.count({ where: { actorId: me.user.id, action: 'deletion.schedule' } }),
    ).toBe(1);
  });

  it('refuses while the only owner of an org (LSE-ORG-007); a second owner unblocks it', async () => {
    const owner = await login(app, 'solo@example.com');
    const org = await createOrg(owner);
    const res = await owner.post(mine('/deletion'), { confirm: 'solo@example.com' });
    expectError(res, 'LSE-ORG-007', 409);
    expect(res.body.error.devMessage).toContain(org.slug);
    expect(await prisma.deletionRequest.count()).toBe(0);

    const other = await login(app);
    await addMember(org.id, other.user.id, 'OWNER');
    expect((await owner.post(mine('/deletion'), { confirm: 'solo@example.com' })).status).toBe(201);
  });

  it('lets the person keep using the account during the grace period, and cancel', async () => {
    const me = await login(app, 'changed-mind@example.com');
    const res = await me.post(mine('/deletion'), { confirm: 'changed-mind@example.com' });
    expect((await me.get('/api/v1/users/me')).status).toBe(200);
    expect((await createOrg(me)).id).toBeDefined();
    const cancelled = await me.delete(mine('/deletion'));
    expect(cancelled.body.data).toMatchObject({ id: res.body.data.id, status: 'CANCELLED' });
    expect((await me.get('/api/v1/users/me')).body.data.deletionScheduledAt).toBeNull();
    expectError(await me.delete(mine('/deletion')), 'LSE-NF-001', 404);
    expect(await runDeletionSweep(ctx, { now: new Date(Date.now() + 90 * DAY) })).toMatchObject({
      completed: 0,
    });
    expect(await prisma.user.count({ where: { id: me.user.id } })).toBe(1);
  });

  it('erases the account after the grace period: personal rows, files and audit identifiers', async () => {
    const d = await populated();
    const keys = [d.memberSession.key];
    await d.member.post(mine('/exports'));
    await ctx.jobs.onIdle();
    const exportKey = (
      await prisma.dataExport.findFirstOrThrow({ where: { requestedById: d.member.user.id } })
    ).storageKey!;
    expect(await ctx.storage.get(exportKey)).not.toBeNull();

    // audit rows the member caused, with an IP
    await ctx.audit.record({
      orgId: d.org.id,
      actorId: d.member.user.id,
      action: 'session.start',
      target: 'x',
      ip: '203.0.113.50',
    });
    const res = await d.member.post(mine('/deletion'), { confirm: 'member@example.com' });
    const due = new Date(res.body.data.scheduledFor as string);
    expect(await runDeletionSweep(ctx, { now: new Date(due.getTime() - 1) })).toMatchObject({
      completed: 0,
    });
    expect(await prisma.user.count({ where: { id: d.member.user.id } })).toBe(1);

    await makeDueNow(res.body.data.id as string);
    const out = await runDeletionSweep(ctx, { now: new Date(due.getTime() + 1) });
    expect(out).toMatchObject({ completed: 1, failed: 0 });

    expect(await prisma.user.count({ where: { id: d.member.user.id } })).toBe(0);
    expect(await prisma.session.count({ where: { userId: d.member.user.id } })).toBe(0);
    expect(await prisma.orgMember.count({ where: { userId: d.member.user.id } })).toBe(0);
    expect(await prisma.authSession.count({ where: { userId: d.member.user.id } })).toBe(0);
    expect(await prisma.dataExport.count({ where: { requestedById: d.member.user.id } })).toBe(0);
    for (const k of [...keys, exportKey]) expect(await ctx.storage.get(k)).toBeNull();
    // their signed-in cookie no longer works
    expectError(await d.member.get('/api/v1/users/me'), 'LSE-AUTH-001', 401);

    // the org and the other person's data are intact
    expect(await prisma.organization.count({ where: { id: d.org.id } })).toBe(1);
    expect(await prisma.session.count({ where: { userId: d.owner.user.id } })).toBe(1);
    expect(await ctx.storage.get(d.ownerSession.key)).not.toBeNull();

    // audit rows are kept but de-identified; the hash chain is still valid
    const theirs = await prisma.auditLog.findFirstOrThrow({
      where: { orgId: d.org.id, action: 'session.start', target: 'x' },
    });
    expect(theirs).toMatchObject({ actorId: null, ip: null });
    expect(theirs.actorDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(await prisma.auditLog.count({ where: { ip: '203.0.113.50' } })).toBe(0);
    expect((await verifyChain(prisma, ctx.audit.chainKey, d.org.id)).ok).toBe(true);
    expect((await verifyChain(prisma, ctx.audit.chainKey, 'global')).ok).toBe(true);

    // proof of deletion: the request survives, de-identified
    expect(
      await prisma.deletionRequest.findUniqueOrThrow({ where: { id: res.body.data.id } }),
    ).toMatchObject({
      status: 'COMPLETED',
      userId: null,
      requestedById: null,
    });
    const done = await prisma.auditLog.findFirstOrThrow({ where: { action: 'deletion.complete' } });
    expect(done).toMatchObject({ orgId: null, actorId: null, target: res.body.data.id });
  });

  it('fails (and un-schedules) when the person became the only owner of an org meanwhile', async () => {
    const owner = await login(app, 'owner2@example.com');
    const org = await createOrg(owner);
    const leaver = await login(app, 'leaver@example.com');
    await addMember(org.id, leaver.user.id, 'MEMBER');
    const res = await leaver.post(mine('/deletion'), { confirm: 'leaver@example.com' });
    // the real owner leaves; the member is promoted to sole owner before the sweep
    await prisma.orgMember.update({
      where: { userId_orgId: { userId: leaver.user.id, orgId: org.id } },
      data: { role: 'OWNER' },
    });
    await prisma.orgMember.delete({
      where: { userId_orgId: { userId: owner.user.id, orgId: org.id } },
    });

    const due = new Date(res.body.data.scheduledFor as string);
    const out = await runDeletionSweep(ctx, { now: new Date(due.getTime() + 1) });
    expect(out).toMatchObject({ completed: 0, failed: 1 });
    const row = await prisma.deletionRequest.findUniqueOrThrow({ where: { id: res.body.data.id } });
    expect(row.status).toBe('FAILED');
    expect(row.error).toContain(org.slug);
    const user = await prisma.user.findUniqueOrThrow({ where: { id: leaver.user.id } });
    expect(user.deletionScheduledAt).toBeNull();
  });

  it('deletes a doomed org first, so its sole owner can be erased in the same sweep', async () => {
    const owner = await login(app, 'both@example.com');
    const org = await createOrg(owner);
    const o = await owner.post(orgUrl(org.id, '/deletion'), { confirm: org.slug });
    const u = await owner.post(mine('/deletion'), { confirm: 'both@example.com' }); // allowed: org is pending
    expect(u.status).toBe(201);
    const due = new Date(
      Math.max(
        new Date(o.body.data.scheduledFor).getTime(),
        new Date(u.body.data.scheduledFor).getTime(),
      ),
    );
    await makeDueNow(u.body.data.id as string);
    const out = await runDeletionSweep(ctx, { now: new Date(due.getTime() + 1) });
    expect(out).toMatchObject({ completed: 2, failed: 0 });
    expect(await prisma.organization.count({ where: { id: org.id } })).toBe(0);
    expect(await prisma.user.count({ where: { id: owner.user.id } })).toBe(0);
  });

  it('is a no-op for requests whose subject is already gone', async () => {
    const row = await prisma.deletionRequest.create({
      data: { kind: 'USER', userId: null, scheduledFor: new Date(Date.now() - 1000) },
    });
    expect(await runDeletionSweep(ctx)).toMatchObject({ completed: 1 });
    expect((await prisma.deletionRequest.findUniqueOrThrow({ where: { id: row.id } })).status).toBe(
      'COMPLETED',
    );
  });

  it('keeps the request PENDING (retry next hour) when an attempt throws', async () => {
    const me = await login(app, 'retry@example.com');
    const res = await me.post(mine('/deletion'), { confirm: 'retry@example.com' });
    const due = new Date(res.body.data.scheduledFor as string);
    const spy = vi.spyOn(prisma.artifact, 'findMany').mockRejectedValueOnce(new Error('db hiccup'));
    const out = await runDeletionSweep(ctx, { now: new Date(due.getTime() + 1) });
    expect(out.failed).toBe(1);
    spy.mockRestore();
    expect(
      (await prisma.deletionRequest.findUniqueOrThrow({ where: { id: res.body.data.id } })).status,
    ).toBe('PENDING');
    await makeDueNow(res.body.data.id as string);
    expect(await runDeletionSweep(ctx, { now: new Date(due.getTime() + 2) })).toMatchObject({
      completed: 1,
    });
    expect(await prisma.user.count({ where: { id: me.user.id } })).toBe(0);
  });
});
