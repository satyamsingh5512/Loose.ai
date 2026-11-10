/**
 * Phase 9 / W1 — outbound webhooks: admin CRUD (roles, secrets, SSRF, idempotency), event fan-out,
 * HMAC signatures, retry/backoff, auto-disable, delivery log, test/redeliver, sweep, and the real
 * session → webhook flow.
 */
import { createHmac, timingSafeEqual } from 'node:crypto';
import { http, HttpResponse, type RequestHandler } from 'msw';
import request from 'supertest';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  WEBHOOK_DELIVERY_HEADER,
  WEBHOOK_EVENT_HEADER,
  WEBHOOK_EVENT_TYPES,
  WEBHOOK_MAX_ATTEMPTS,
  WEBHOOK_MAX_CONSECUTIVE_FAILURES,
  WEBHOOK_RETRY_DELAYS_MS,
  WEBHOOK_SECRET_PREFIX,
  WEBHOOK_SIGNATURE_HEADER,
  WEBHOOK_SIGNATURE_TOLERANCE_SEC,
  WEBHOOK_TIMESTAMP_HEADER,
  WEBHOOK_USER_AGENT,
  createWebhookResponseSchema,
  webhookDeliveryDtoSchema,
  webhookDtoSchema,
  webhookPayloadSchema,
  webhookSignedPayload,
  type BudgetExceededData,
} from '@loose/shared';
import { createRun } from '../src/services/runs.service';
import {
  createWebhook,
  deliverWebhook,
  signWebhook,
  webhookSweep,
} from '../src/services/webhooks.service';
import {
  FakeGit,
  installFakeRunner,
  mswFetch,
  playTurn,
  waitFor,
  type RunnerScript,
} from './agentHelpers';
import {
  addMember,
  createOrg,
  expectError,
  GITHUB_API,
  linkGithub,
  login,
  makeApp,
  resetDb,
  testPrisma,
  type Client,
} from './helpers';
import { addApiKey, createReadyProject, fakeSandbox } from './sessionHelpers';

const prisma = testPrisma();
const handlers: { current: RequestHandler[] } = { current: [] };
const calls: Request[] = [];
const { app, ctx } = makeApp({ context: { fetch: mswFetch(handlers, calls) } });
const fake = fakeSandbox(ctx);
const script: { current: RunnerScript } = { current: () => undefined };
let git: FakeGit;

/** A public IP literal (not a documentation range: those are blocked since P10-SEC-012). */
const HOOK_URL = 'https://93.184.216.34/loose';
const REPO = `${GITHUB_API}/repos/acme/web`;
const FILE = 'src/components/Header.tsx';

const BUDGET: BudgetExceededData = {
  scope: 'org',
  errorCode: 'LSE-KEY-012',
  action: 'blocked',
  userId: 'u1',
  projectId: null,
  sessionId: null,
  spentUsd: 2,
  budgetUsd: 1,
};

afterAll(async () => {
  await ctx.agent.idle();
  await ctx.jobs.onIdle();
  await prisma.$disconnect();
});

beforeEach(async () => {
  await ctx.agent.shutdownAll();
  await ctx.jobs.onIdle();
  fake.reset();
  installFakeRunner(fake, script);
  git = new FakeGit().install(fake);
  script.current = (cmd, r) => {
    if (cmd.type !== 'user_message') return;
    git.set(FILE, ' M', ['<h1>Howdy</h1>']);
    playTurn(r, { text: 'Updated.', files: [FILE] });
  };
  handlers.current = [];
  calls.length = 0;
  await resetDb();
  ctx.platformEvents.clearHistory();
});

afterEach(() => {
  vi.restoreAllMocks();
});

interface World {
  admin: Client;
  member: Client;
  viewer: Client;
  orgId: string;
}

async function world(): Promise<World> {
  const admin = await login(app, undefined, 'Ada Admin');
  const org = await createOrg(admin);
  const member = await login(app, undefined, 'Mo Member');
  await addMember(org.id, member.user.id, 'MEMBER');
  const viewer = await login(app, undefined, 'Vi Viewer');
  await addMember(org.id, viewer.user.id, 'VIEWER');
  return { admin, member, viewer, orgId: org.id };
}

const base = (w: { orgId: string }) => `/api/v1/orgs/${w.orgId}/webhooks`;

async function createHook(
  w: World,
  body: Record<string, unknown> = {},
): Promise<{ id: string; secret: string }> {
  const res = await w.admin.post(base(w), {
    name: 'CI',
    url: HOOK_URL,
    events: [...WEBHOOK_EVENT_TYPES],
    ...body,
  });
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  return { id: res.body.data.id as string, secret: res.body.data.secret as string };
}

/** Respond to the hook URL with `status` (default 200) and record nothing else. */
function hookReplies(status = 200, body = 'ok', headers: Record<string, string> = {}) {
  handlers.current = [http.post(HOOK_URL, () => new HttpResponse(body, { status, headers }))];
}

function expectedSignature(secret: string, timestamp: string, body: string): string {
  return `sha256=${createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex')}`;
}

/** What a receiver does: constant-time compare + timestamp tolerance. */
function verifyLikeAReceiver(secret: string, rawBody: string, headers: Headers, nowSec: number) {
  const ts = headers.get(WEBHOOK_TIMESTAMP_HEADER) ?? '';
  const sig = headers.get(WEBHOOK_SIGNATURE_HEADER) ?? '';
  if (Math.abs(nowSec - Number(ts)) > WEBHOOK_SIGNATURE_TOLERANCE_SEC) return false;
  const want = Buffer.from(expectedSignature(secret, ts, rawBody));
  const got = Buffer.from(sig);
  return want.length === got.length && timingSafeEqual(want, got);
}

const delivery = (webhookId: string) =>
  prisma.webhookDelivery.findFirstOrThrow({ where: { webhookId }, orderBy: { createdAt: 'asc' } });
const hookRow = (id: string) => prisma.webhook.findUniqueOrThrow({ where: { id } });

async function emitBudget(orgId: string) {
  const e = await ctx.platformEvents.emit('budget.exceeded', orgId, BUDGET);
  await ctx.jobs.onIdle();
  return e;
}

// ---- CRUD & access ---------------------------------------------------------------------------

describe('webhook admin API', () => {
  it('create → one-time secret; read/list/update/delete never expose it', async () => {
    const w = await world();
    const res = await w.admin.post(base(w), {
      name: 'Deploy bot',
      url: HOOK_URL,
      events: ['pr.created', 'session.completed'],
    });
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    const created = createWebhookResponseSchema.parse(res.body.data);
    expect(created).toMatchObject({
      orgId: w.orgId,
      name: 'Deploy bot',
      url: HOOK_URL,
      events: ['pr.created', 'session.completed'],
      active: true,
      failureCount: 0,
      lastDeliveryAt: null,
      lastStatus: null,
      disabledAt: null,
    });
    expect(created.secret.startsWith(WEBHOOK_SECRET_PREFIX)).toBe(true);
    expect(created.secret.length).toBeGreaterThan(40);

    // Stored encrypted: the plaintext is nowhere in the row.
    const row = await hookRow(created.id);
    expect(Buffer.from(row.secretEnc).includes(Buffer.from(created.secret))).toBe(false);
    expect(await ctx.crypto.decryptPackedString(row.secretEnc, 'generic')).toBe(created.secret);

    const get = await w.admin.get(`${base(w)}/${created.id}`);
    expect(webhookDtoSchema.parse(get.body.data).id).toBe(created.id);
    const list = await w.admin.get(base(w));
    expect(list.body.data).toHaveLength(1);
    expect(list.body.nextCursor).toBeNull();
    for (const body of [get.body, list.body]) {
      expect(JSON.stringify(body)).not.toContain(created.secret);
      expect(JSON.stringify(body)).not.toContain('secret');
    }

    const put = await w.admin.put(`${base(w)}/${created.id}`, {
      name: 'Renamed',
      events: ['budget.exceeded'],
    });
    expect(put.status).toBe(200);
    expect(put.body.data).toMatchObject({
      name: 'Renamed',
      events: ['budget.exceeded'],
      url: HOOK_URL,
    });
    expect(JSON.stringify(put.body)).not.toContain(created.secret);

    const del = await w.admin.delete(`${base(w)}/${created.id}`);
    expect(del.status).toBe(204);
    expectError(await w.admin.get(`${base(w)}/${created.id}`), 'LSE-NF-001', 404);
    expect((await w.admin.get(base(w))).body.data).toEqual([]);
  });

  it('rotate-secret returns a new secret once and signs with it from then on', async () => {
    const w = await world();
    const { id, secret } = await createHook(w);
    const rot = await w.admin.post(`${base(w)}/${id}/rotate-secret`);
    expect(rot.status).toBe(200);
    const next = rot.body.data.secret as string;
    expect(next.startsWith(WEBHOOK_SECRET_PREFIX)).toBe(true);
    expect(next).not.toBe(secret);

    hookReplies();
    await emitBudget(w.orgId);
    expect(calls).toHaveLength(1);
    const body = await calls[0]!.text();
    expect(verifyLikeAReceiver(next, body, calls[0]!.headers, Date.now() / 1000)).toBe(true);
    expect(verifyLikeAReceiver(secret, body, calls[0]!.headers, Date.now() / 1000)).toBe(false);
  });

  it('role matrix: ADMIN+ only, browser session only, tenant isolated', async () => {
    const w = await world();
    const { id } = await createHook(w);
    for (const c of [w.member, w.viewer]) {
      expectError(await c.get(base(w)), 'LSE-ORG-002', 403);
      expectError(await c.post(base(w), { url: HOOK_URL, events: ['pr.created'] }), 'LSE-ORG-002');
      expectError(await c.put(`${base(w)}/${id}`, { name: 'x' }), 'LSE-ORG-002');
      expectError(await c.delete(`${base(w)}/${id}`), 'LSE-ORG-002');
      expectError(await c.post(`${base(w)}/${id}/rotate-secret`), 'LSE-ORG-002');
      expectError(await c.post(`${base(w)}/${id}/test`), 'LSE-ORG-002');
      expectError(await c.get(`${base(w)}/${id}/deliveries`), 'LSE-ORG-002');
    }
    const outsider = await login(app, undefined, 'Olga Outsider');
    expectError(await outsider.get(base(w)), 'LSE-ORG-001', 403);

    // Another org's admin cannot reach this org's webhook through their own org path.
    const other = await world();
    expectError(await other.admin.get(`${base(other)}/${id}`), 'LSE-NF-001', 404);
    expectError(await other.admin.delete(`${base(other)}/${id}`), 'LSE-NF-001', 404);
    expectError(await other.admin.get(`${base(w)}/${id}`), 'LSE-ORG-001', 403);

    // Personal API tokens (even with org:read) never manage webhooks.
    const tok = await w.admin.post('/api/v1/users/me/tokens', {
      orgId: w.orgId,
      name: 't',
      scopes: ['org:read'],
    });
    const t = tok.body.data.token as string;
    expectError(
      await request(app).get(base(w)).set('Authorization', `Bearer ${t}`),
      'LSE-AUTH-001',
      401,
    );
    expectError(
      await request(app)
        .post(base(w))
        .set('Authorization', `Bearer ${t}`)
        .send({ url: HOOK_URL, events: ['pr.created'] }),
      'LSE-ORG-002',
    );
    expect(await prisma.webhook.count({ where: { orgId: w.orgId } })).toBe(1);
  });

  it('validates input', async () => {
    const w = await world();
    const { id } = await createHook(w);
    for (const body of [
      {},
      { url: HOOK_URL },
      { url: HOOK_URL, events: [] },
      { url: HOOK_URL, events: ['pr.created', 'pr.created'] },
      { url: HOOK_URL, events: ['session.exploded'] },
      { url: 'not a url', events: ['pr.created'] },
      { url: 'ftp://93.184.216.34/x', events: ['pr.created'] },
      { url: 'https://user:pw@93.184.216.34/x', events: ['pr.created'] },
      { url: HOOK_URL, events: ['pr.created'], secret: 'whsec_mine' },
    ]) {
      expectError(await w.admin.post(base(w), body), 'LSE-VAL-001', 400);
    }
    expectError(await w.admin.put(`${base(w)}/${id}`, {}), 'LSE-VAL-001');
    expectError(await w.admin.put(`${base(w)}/${id}`, { events: [] }), 'LSE-VAL-001');
    expectError(await w.admin.get(`${base(w)}/bad%20id`), 'LSE-VAL-001');
    expectError(await w.admin.get(`${base(w)}/${id}/deliveries?status=NOPE`), 'LSE-VAL-001');
    expect(await prisma.webhook.count()).toBe(1);
  });

  it('SSRF: private, loopback, link-local and internal hosts are rejected on create and update', async () => {
    const w = await world();
    const { id } = await createHook(w);
    for (const url of [
      'http://127.0.0.1:8080/hook',
      'https://localhost/hook',
      'https://api.localhost/hook',
      'https://10.1.2.3/hook',
      'https://192.168.0.5/hook',
      'https://172.16.0.9/hook',
      'https://169.254.169.254/latest/meta-data',
      'https://[::1]/hook',
      'https://service.internal/hook',
      'https://printer.local/hook',
      'https://0.0.0.0/hook',
    ]) {
      const res = await w.admin.post(base(w), { url, events: ['pr.created'] });
      expectError(res, 'LSE-VAL-001', 400);
      expect(res.body.error.fields.url, url).toBeDefined();
      expectError(await w.admin.put(`${base(w)}/${id}`, { url }), 'LSE-VAL-001', 400);
    }
    expect((await hookRow(id)).url).toBe(HOOK_URL);
    expect(await prisma.webhook.count()).toBe(1);
  });

  it('https is required in production, http is fine elsewhere', async () => {
    const w = await world();
    const prod = { ...ctx, env: { ...ctx.env, NODE_ENV: 'production' as const } };
    const actor = { userId: w.admin.user.id };
    await expect(
      createWebhook(prod, w.orgId, actor, {
        name: '',
        url: 'http://93.184.216.34/x',
        events: ['pr.created'],
        active: true,
      }),
    ).rejects.toMatchObject({ code: 'LSE-VAL-001' });
    await expect(
      createWebhook(prod, w.orgId, actor, {
        name: '',
        url: HOOK_URL,
        events: ['pr.created'],
        active: true,
      }),
    ).resolves.toMatchObject({ url: HOOK_URL });
    const dev = await w.admin.post(base(w), {
      url: 'http://93.184.216.34/x',
      events: ['pr.created'],
    });
    expect(dev.status).toBe(201);
  });

  it('Idempotency-Key: a retried create returns the same webhook and secret', async () => {
    const w = await world();
    const send = (body: object) =>
      w.admin.agent
        .post(base(w))
        .set('x-csrf-token', w.admin.csrf)
        .set('Idempotency-Key', 'wh-create-1')
        .send(body);
    const body = { url: HOOK_URL, events: ['pr.created'] };
    const a = await send(body);
    const b = await send(body);
    expect(a.status).toBe(201);
    expect(b.status).toBe(201);
    expect(b.headers['idempotent-replayed']).toBe('true');
    expect(b.body.data).toEqual(a.body.data);
    expect(await prisma.webhook.count()).toBe(1);
    expectError(await send({ url: HOOK_URL, events: ['session.started'] }), 'LSE-VAL-004', 409);
  });

  it('limits the number of webhooks per org (LSE-ORG-009)', async () => {
    const w = await world();
    const enc = await ctx.crypto.encryptPacked('whsec_x', 'generic');
    await prisma.webhook.createMany({
      data: Array.from({ length: 25 }, (_, i) => ({
        orgId: w.orgId,
        name: `h${i}`,
        url: HOOK_URL,
        secretEnc: enc,
        events: ['pr.created'],
      })),
    });
    expectError(
      await w.admin.post(base(w), { url: HOOK_URL, events: ['pr.created'] }),
      'LSE-ORG-009',
      403,
    );
  });

  it('writes audit entries (no secrets) for every admin action', async () => {
    const w = await world();
    hookReplies();
    const { id, secret } = await createHook(w, { name: 'Audited' });
    await w.admin.put(`${base(w)}/${id}`, { active: false });
    await w.admin.post(`${base(w)}/${id}/rotate-secret`);
    await w.admin.post(`${base(w)}/${id}/test`);
    await w.admin.delete(`${base(w)}/${id}`);
    const rows = await prisma.auditLog.findMany({
      where: { orgId: w.orgId, action: { startsWith: 'webhook.' } },
      orderBy: { createdAt: 'asc' },
    });
    expect(rows.map((r) => r.action)).toEqual([
      'webhook.create',
      'webhook.update',
      'webhook.rotate_secret',
      'webhook.test',
      'webhook.delete',
    ]);
    for (const r of rows) {
      expect(r.actorId).toBe(w.admin.user.id);
      expect(r.target).toBe(id);
      expect(JSON.stringify(r)).not.toContain('whsec_');
      expect(JSON.stringify(r)).not.toContain(secret);
    }
    expect(rows[0]!.meta).toMatchObject({ name: 'Audited', host: '93.184.216.34' });
  });

  it('re-enabling a disabled webhook clears the failure bookkeeping', async () => {
    const w = await world();
    const { id } = await createHook(w);
    await prisma.webhook.update({
      where: { id },
      data: { active: false, disabledAt: new Date(), failureCount: 20 },
    });
    const res = await w.admin.put(`${base(w)}/${id}`, { active: true });
    expect(res.body.data).toMatchObject({ active: true, failureCount: 0, disabledAt: null });
  });
});

// ---- signing & fan-out ---------------------------------------------------------------------------

describe('signature', () => {
  it('signWebhook is HMAC-SHA256 over "<timestamp>.<body>" with a sha256= prefix', () => {
    const sig = signWebhook('whsec_secret', 1_700_000_000, '{"a":1}');
    expect(sig).toBe(
      `sha256=${createHmac('sha256', 'whsec_secret').update('1700000000.{"a":1}').digest('hex')}`,
    );
    expect(sig).toMatch(/^sha256=[0-9a-f]{64}$/);
    expect(sig).not.toBe(signWebhook('whsec_other', 1_700_000_000, '{"a":1}'));
    expect(sig).not.toBe(signWebhook('whsec_secret', 1_700_000_001, '{"a":1}'));
    expect(sig).not.toBe(signWebhook('whsec_secret', 1_700_000_000, '{"a":2}'));
    expect(webhookSignedPayload(5, 'x')).toBe('5.x');
  });

  it('a delivery carries the documented headers and a verifiable signature + payload', async () => {
    const w = await world();
    const { id, secret } = await createHook(w);
    hookReplies(200, 'received');
    const evt = await emitBudget(w.orgId);

    expect(calls).toHaveLength(1);
    const req = calls[0]!;
    expect(req.method).toBe('POST');
    expect(req.url).toBe(HOOK_URL);
    expect(req.redirect).toBe('manual');
    expect(req.headers.get('content-type')).toBe('application/json');
    expect(req.headers.get('user-agent')).toBe(WEBHOOK_USER_AGENT);
    expect(req.headers.get(WEBHOOK_EVENT_HEADER)).toBe('budget.exceeded');
    const row = await delivery(id);
    expect(req.headers.get(WEBHOOK_DELIVERY_HEADER)).toBe(row.id);
    const now = Date.now() / 1000;
    expect(Math.abs(Number(req.headers.get(WEBHOOK_TIMESTAMP_HEADER)) - now)).toBeLessThan(5);

    const raw = await req.text();
    expect(verifyLikeAReceiver(secret, raw, req.headers, now)).toBe(true);
    // Tampered body, wrong secret and stale timestamps are all rejected.
    expect(
      verifyLikeAReceiver(secret, raw.replace('LSE-KEY-012', 'LSE-KEY-013'), req.headers, now),
    ).toBe(false);
    expect(verifyLikeAReceiver('whsec_wrong', raw, req.headers, now)).toBe(false);
    expect(
      verifyLikeAReceiver(secret, raw, req.headers, now + WEBHOOK_SIGNATURE_TOLERANCE_SEC + 60),
    ).toBe(false);

    const payload = webhookPayloadSchema.parse(JSON.parse(raw));
    expect(payload).toMatchObject({
      id: evt.id,
      type: 'budget.exceeded',
      orgId: w.orgId,
      data: BUDGET,
    });
    expect(row).toMatchObject({
      eventId: evt.id,
      event: 'budget.exceeded',
      status: 'SUCCEEDED',
      attempts: 1,
      responseStatus: 200,
      responseSnippet: 'received',
      error: null,
      nextAttemptAt: null,
    });
    expect(row.deliveredAt).not.toBeNull();
    expect(row.durationMs).not.toBeNull();
    expect(await hookRow(id)).toMatchObject({ lastStatus: 'succeeded', failureCount: 0 });
  });
});

describe('fan-out', () => {
  it('delivers to every active webhook subscribed to the event, of that org only', async () => {
    const w = await world();
    const other = await world();
    const all = await createHook(w, { name: 'all' });
    const onlyPr = await createHook(w, { name: 'pr', events: ['pr.created'] });
    const off = await createHook(w, { name: 'off', active: false });
    const foreign = await other.admin.post(base(other), {
      url: HOOK_URL,
      events: [...WEBHOOK_EVENT_TYPES],
    });
    expect(foreign.status).toBe(201);
    hookReplies();

    await emitBudget(w.orgId);
    expect(calls).toHaveLength(1);
    expect(await prisma.webhookDelivery.count({ where: { webhookId: all.id } })).toBe(1);
    expect(await prisma.webhookDelivery.count({ where: { webhookId: onlyPr.id } })).toBe(0);
    expect(await prisma.webhookDelivery.count({ where: { webhookId: off.id } })).toBe(0);
    expect(await prisma.webhookDelivery.count({ where: { orgId: other.orgId } })).toBe(0);
  });

  it('internal events are never delivered; the payload contract is enforced', async () => {
    const w = await world();
    const { id } = await createHook(w);
    hookReplies();
    await ctx.platformEvents.emit('session.turn_completed', w.orgId, {
      sessionId: 's',
      projectId: 'p',
      userId: 'u',
      messageId: 'm',
      filesChanged: [],
      errorCode: null,
      interrupted: false,
      planPending: false,
    });
    await ctx.platformEvents.emit('run.completed', w.orgId, {
      runId: 'r',
      sessionId: null,
      projectId: 'p',
      triggerId: null,
      status: 'SUCCEEDED',
      prUrl: null,
      prNumber: null,
      errorCode: null,
      summary: null,
      externalRef: null,
    });
    // An event that violates the shared schema is dropped, not sent.
    await ctx.platformEvents.emit('budget.exceeded', w.orgId, {
      ...BUDGET,
      scope: 'galaxy' as never,
    });
    await ctx.jobs.onIdle();
    expect(calls).toHaveLength(0);
    expect(await prisma.webhookDelivery.count({ where: { webhookId: id } })).toBe(0);
  });

  it('an event is stored once per webhook (unique eventId) even if fanned out twice', async () => {
    const w = await world();
    const { id } = await createHook(w);
    hookReplies();
    const e = await emitBudget(w.orgId);
    // Replay the same event id straight to the subscribers.
    await ctx.platformEvents.emit('budget.exceeded', w.orgId, BUDGET);
    await ctx.jobs.onIdle();
    expect(await prisma.webhookDelivery.count({ where: { webhookId: id } })).toBe(2);
    await expect(
      prisma.webhookDelivery.create({
        data: { webhookId: id, orgId: w.orgId, eventId: e.id, event: e.type, payload: {} },
      }),
    ).rejects.toMatchObject({ code: 'P2002' });
  });
});

// ---- retry, backoff, auto-disable ---------------------------------------------------------------------

describe('retries', () => {
  /** Capture jobs instead of running/timing them: tests drive attempts by hand. */
  function captureJobs() {
    const jobs: {
      queue: string;
      data: Record<string, unknown>;
      opts?: { jobId?: string; delayMs?: number };
    }[] = [];
    vi.spyOn(ctx.jobs, 'enqueue').mockImplementation(async (queue, data, opts) => {
      jobs.push({ queue, data, ...(opts ? { opts } : {}) });
    });
    return jobs;
  }

  const due = (id: string) =>
    prisma.webhookDelivery.update({ where: { id }, data: { nextAttemptAt: new Date() } });

  it('backs off 1m, 5m, 30m, 2h, 6h with ±10% jitter, then fails the delivery', async () => {
    const w = await world();
    const { id } = await createHook(w);
    const jobs = captureJobs();
    hookReplies(500, 'boom');
    await emitBudget(w.orgId);
    const d = await delivery(id);
    expect(jobs[0]).toMatchObject({ queue: 'webhook-delivery', data: { deliveryId: d.id } });
    jobs.length = 0;

    for (let attempt = 1; attempt <= WEBHOOK_MAX_ATTEMPTS; attempt += 1) {
      await due(d.id);
      const before = Date.now();
      await deliverWebhook(ctx, d.id);
      const row = await delivery(id);
      expect(row.attempts).toBe(attempt);
      expect(row).toMatchObject({ responseStatus: 500, responseSnippet: 'boom' });
      if (attempt < WEBHOOK_MAX_ATTEMPTS) {
        const base = WEBHOOK_RETRY_DELAYS_MS[attempt - 1]!;
        expect(row.status).toBe('PENDING');
        expect(row.error).toBe('HTTP 500');
        const gap = row.nextAttemptAt!.getTime() - before;
        expect(gap).toBeGreaterThanOrEqual(base * 0.9 - 50);
        expect(gap).toBeLessThanOrEqual(base * 1.1 + 2_000);
        const job = jobs.at(-1)!;
        expect(job).toMatchObject({
          queue: 'webhook-delivery',
          data: { deliveryId: d.id },
          opts: { jobId: `wh:${d.id}:${attempt}` },
        });
        expect(job.opts!.delayMs!).toBeGreaterThanOrEqual(base * 0.9);
        expect(job.opts!.delayMs!).toBeLessThanOrEqual(base * 1.1);
        expect(await hookRow(id)).toMatchObject({
          failureCount: 0,
          lastStatus: 'failed',
          active: true,
        });
      } else {
        expect(row.status).toBe('FAILED');
        expect(row.nextAttemptAt).toBeNull();
      }
    }
    expect(calls).toHaveLength(WEBHOOK_MAX_ATTEMPTS);
    expect(WEBHOOK_MAX_ATTEMPTS).toBe(6);
    // Retries re-sign with a fresh timestamp but send the very same body and delivery id.
    const bodies = await Promise.all(calls.map((c) => c.text()));
    expect(new Set(bodies).size).toBe(1);
    expect(new Set(calls.map((c) => c.headers.get(WEBHOOK_DELIVERY_HEADER))).size).toBe(1);
    // One exhausted delivery counts once towards auto-disable.
    expect(await hookRow(id)).toMatchObject({
      failureCount: 1,
      lastStatus: 'failed',
      active: true,
    });
    // A finished delivery is never attempted again.
    await deliverWebhook(ctx, d.id);
    expect(calls).toHaveLength(WEBHOOK_MAX_ATTEMPTS);
  });

  it('a retry that is not due yet, and a concurrent attempt, send nothing extra', async () => {
    const w = await world();
    const { id } = await createHook(w);
    captureJobs();
    let hits = 0;
    handlers.current = [
      http.post(HOOK_URL, async () => {
        hits += 1;
        await new Promise((r) => setTimeout(r, 60));
        return new HttpResponse('nope', { status: 503 });
      }),
    ];
    await emitBudget(w.orgId);
    const d = await delivery(id);
    await Promise.all([
      deliverWebhook(ctx, d.id),
      deliverWebhook(ctx, d.id),
      deliverWebhook(ctx, d.id),
    ]);
    expect(hits).toBe(1);
    expect((await delivery(id)).attempts).toBe(1);
    // nextAttemptAt is ~1 minute away: an early job run does nothing.
    await deliverWebhook(ctx, d.id);
    expect(hits).toBe(1);
  });

  it('a success after failures resets the consecutive-failure count', async () => {
    const w = await world();
    const { id } = await createHook(w);
    captureJobs();
    await prisma.webhook.update({ where: { id }, data: { failureCount: 7, lastStatus: 'failed' } });
    hookReplies(200);
    await emitBudget(w.orgId);
    await deliverWebhook(ctx, (await delivery(id)).id);
    expect(await hookRow(id)).toMatchObject({ failureCount: 0, lastStatus: 'succeeded' });
  });

  it('20 consecutive failed deliveries switch the webhook off (webhook.disabled) and stop fan-out', async () => {
    const w = await world();
    const { id } = await createHook(w);
    captureJobs();
    hookReplies(500);
    await prisma.webhook.update({
      where: { id },
      data: { failureCount: WEBHOOK_MAX_CONSECUTIVE_FAILURES - 1 },
    });
    await emitBudget(w.orgId);
    const d = await delivery(id);
    await prisma.webhookDelivery.update({
      where: { id: d.id },
      data: { attempts: WEBHOOK_MAX_ATTEMPTS - 1, nextAttemptAt: new Date() },
    });
    await deliverWebhook(ctx, d.id);

    const row = await hookRow(id);
    expect(row).toMatchObject({ active: false, failureCount: WEBHOOK_MAX_CONSECUTIVE_FAILURES });
    expect(row.disabledAt).not.toBeNull();
    expect((await delivery(id)).status).toBe('FAILED');
    const audit = await prisma.auditLog.findFirstOrThrow({ where: { action: 'webhook.disabled' } });
    expect(audit).toMatchObject({ orgId: w.orgId, actorId: null, target: id });
    expect(audit.meta).toMatchObject({ reason: 'consecutive_failures', failures: 20 });

    // No more deliveries are created, and a leftover pending one fails without being sent.
    const sent = calls.length;
    await emitBudget(w.orgId);
    expect(await prisma.webhookDelivery.count({ where: { webhookId: id } })).toBe(1);
    const stale = await prisma.webhookDelivery.create({
      data: {
        webhookId: id,
        orgId: w.orgId,
        eventId: 'evt_stale',
        event: 'pr.created',
        payload: {},
      },
    });
    await deliverWebhook(ctx, stale.id);
    expect(calls).toHaveLength(sent);
    expect(
      await prisma.webhookDelivery.findUniqueOrThrow({ where: { id: stale.id } }),
    ).toMatchObject({
      status: 'FAILED',
      error: 'The webhook is disabled',
    });
  });

  it('410 Gone disables the webhook immediately', async () => {
    const w = await world();
    const { id } = await createHook(w);
    const jobs = captureJobs();
    hookReplies(410, 'gone');
    await emitBudget(w.orgId);
    jobs.length = 0;
    await deliverWebhook(ctx, (await delivery(id)).id);
    expect((await delivery(id)).status).toBe('FAILED');
    expect(jobs).toHaveLength(0);
    expect(await hookRow(id)).toMatchObject({ active: false, failureCount: 1 });
    const audit = await prisma.auditLog.findFirstOrThrow({ where: { action: 'webhook.disabled' } });
    expect(audit.meta).toMatchObject({ reason: 'gone' });
  });

  it('redirects are not followed and count as failures', async () => {
    const w = await world();
    const { id } = await createHook(w);
    captureJobs();
    handlers.current = [
      http.post(
        HOOK_URL,
        () =>
          new HttpResponse(null, {
            status: 302,
            headers: { location: 'https://93.184.216.35/steal' },
          }),
      ),
    ];
    await emitBudget(w.orgId);
    await deliverWebhook(ctx, (await delivery(id)).id);
    const row = await delivery(id);
    expect(row).toMatchObject({ status: 'PENDING', responseStatus: 302, attempts: 1 });
    expect(row.error).toBe('Redirects are not followed (HTTP 302)');
    expect(calls).toHaveLength(1);
    expect(calls[0]!.redirect).toBe('manual');
  });

  it('network errors and timeouts are recorded and retried', async () => {
    const w = await world();
    const { id } = await createHook(w);
    captureJobs();
    await emitBudget(w.orgId);
    const d = await delivery(id);

    const real = ctx.fetch;
    try {
      ctx.fetch = async () => {
        throw new TypeError('fetch failed: connect ECONNREFUSED 93.184.216.34:443');
      };
      await deliverWebhook(ctx, d.id);
      expect((await delivery(id)).error).toContain('Request failed: fetch failed');

      await due(d.id);
      ctx.fetch = async () => {
        throw Object.assign(new Error('The operation was aborted due to timeout'), {
          name: 'TimeoutError',
        });
      };
      await deliverWebhook(ctx, d.id);
      const row = await delivery(id);
      expect(row).toMatchObject({ status: 'PENDING', attempts: 2, responseStatus: null });
      expect(row.error).toBe('Timed out after 10s');
    } finally {
      ctx.fetch = real;
    }
  });

  it('response snippets are capped at 1 KB and scrubbed of secrets and NUL bytes', async () => {
    const w = await world();
    const { id } = await createHook(w);
    captureJobs();
    const key = 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789';
    hookReplies(500, `bad\0 ${key} ${'x'.repeat(5000)}`);
    await emitBudget(w.orgId);
    await deliverWebhook(ctx, (await delivery(id)).id);
    const row = await delivery(id);
    expect(row.responseSnippet!.length).toBeLessThanOrEqual(1024);
    expect(row.responseSnippet).not.toContain(key);
    expect(row.responseSnippet).not.toContain('\0');
    expect(row.responseSnippet!.startsWith('bad')).toBe(true);
  });

  it('production re-check rejects an existing public http URL before delivery', async () => {
    const w = await world();
    const enc = await ctx.crypto.encryptPacked('whsec_x', 'generic');
    const hook = await prisma.webhook.create({
      data: {
        orgId: w.orgId,
        name: 'old insecure hook',
        url: 'http://93.184.216.34/loose',
        secretEnc: enc,
        events: ['budget.exceeded'],
      },
    });
    captureJobs();
    await emitBudget(w.orgId);
    const d = await delivery(hook.id);
    const previous = ctx.env.NODE_ENV;
    try {
      ctx.env.NODE_ENV = 'production';
      await deliverWebhook(ctx, d.id);
    } finally {
      ctx.env.NODE_ENV = previous;
    }
    expect((await delivery(hook.id)).error).toContain('Blocked');
    expect(calls).toHaveLength(0);
  });

  it('SSRF at delivery time: a blocked target is recorded and never contacted', async () => {
    const w = await world();
    const enc = await ctx.crypto.encryptPacked('whsec_x', 'generic');
    captureJobs();
    // Rows written behind the API's back (or a host that now resolves privately).
    for (const url of [
      'http://127.0.0.1:9999/x',
      'https://169.254.169.254/x',
      'https://svc.internal/x',
    ]) {
      const hook = await prisma.webhook.create({
        data: { orgId: w.orgId, name: url, url, secretEnc: enc, events: ['budget.exceeded'] },
      });
      await emitBudget(w.orgId);
      const d = await prisma.webhookDelivery.findFirstOrThrow({ where: { webhookId: hook.id } });
      await deliverWebhook(ctx, d.id);
      const row = await prisma.webhookDelivery.findUniqueOrThrow({ where: { id: d.id } });
      expect(row.error, url).toContain('Blocked');
      expect(row.responseStatus).toBeNull();
      expect(row.attempts).toBe(1);
    }
    expect(calls).toHaveLength(0);
  });
});

// ---- test ping, delivery log, redeliver, sweep ----------------------------------------------------------

describe('test ping, delivery log and redeliver', () => {
  it('POST /:id/test sends one signed webhook.ping synchronously, even to an inactive hook', async () => {
    const w = await world();
    const { id, secret } = await createHook(w, { active: false });
    hookReplies(200, 'pong');
    const res = await w.admin.post(`${base(w)}/${id}/test`);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    const dto = webhookDeliveryDtoSchema.parse(res.body.data);
    expect(dto).toMatchObject({
      webhookId: id,
      event: 'webhook.ping',
      status: 'SUCCEEDED',
      attempts: 1,
      responseStatus: 200,
      responseSnippet: 'pong',
    });
    expect(calls).toHaveLength(1);
    const raw = await calls[0]!.text();
    expect(calls[0]!.headers.get(WEBHOOK_EVENT_HEADER)).toBe('webhook.ping');
    expect(verifyLikeAReceiver(secret, raw, calls[0]!.headers, Date.now() / 1000)).toBe(true);
    const payload = webhookPayloadSchema.parse(JSON.parse(raw));
    expect(payload).toMatchObject({
      type: 'webhook.ping',
      orgId: w.orgId,
      data: { webhookId: id },
    });
    expect(await hookRow(id)).toMatchObject({ lastStatus: 'succeeded' });
  });

  it('a failing ping is reported (FAILED, no retries) and does not move the failure count', async () => {
    const w = await world();
    const { id } = await createHook(w);
    hookReplies(500, 'down');
    const jobsBefore = vi.spyOn(ctx.jobs, 'enqueue');
    const res = await w.admin.post(`${base(w)}/${id}/test`);
    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({
      status: 'FAILED',
      responseStatus: 500,
      error: 'HTTP 500',
    });
    expect(jobsBefore).not.toHaveBeenCalled();
    expect(await hookRow(id)).toMatchObject({
      failureCount: 0,
      lastStatus: 'failed',
      active: true,
    });
    expectError(await w.admin.post(`${base(w)}/cmissing/test`), 'LSE-NF-001', 404);
  });

  it('lists deliveries newest first with a status filter and cursor; detail has the payload', async () => {
    const w = await world();
    const { id } = await createHook(w);
    hookReplies(200);
    await emitBudget(w.orgId);
    await emitBudget(w.orgId);
    hookReplies(500);
    await prisma.webhookDelivery.updateMany({ data: { createdAt: new Date(Date.now() - 60_000) } });
    vi.spyOn(ctx.jobs, 'enqueue').mockResolvedValue(undefined);
    await emitBudget(w.orgId);

    const list = await w.admin.get(`${base(w)}/${id}/deliveries`);
    expect(list.body.data).toHaveLength(3);
    expect(list.body.data[0].status).toBe('PENDING');
    expect(list.body.data[0]).not.toHaveProperty('payload');
    expect(
      (await w.admin.get(`${base(w)}/${id}/deliveries?status=SUCCEEDED`)).body.data,
    ).toHaveLength(2);
    const p1 = await w.admin.get(`${base(w)}/${id}/deliveries?limit=2`);
    expect(p1.body.data).toHaveLength(2);
    const p2 = await w.admin.get(
      `${base(w)}/${id}/deliveries?limit=2&cursor=${p1.body.nextCursor}`,
    );
    expect(p2.body.data).toHaveLength(1);
    expect(p2.body.nextCursor).toBeNull();

    const detail = await w.admin.get(`${base(w)}/${id}/deliveries/${list.body.data[0].id}`);
    expect(detail.body.data.payload).toMatchObject({ type: 'budget.exceeded', orgId: w.orgId });
    expectError(await w.admin.get(`${base(w)}/${id}/deliveries/cmissing`), 'LSE-NF-001', 404);
  });

  it('redeliver resets a finished delivery and sends it again (same event id)', async () => {
    const w = await world();
    const { id } = await createHook(w);
    vi.spyOn(ctx.jobs, 'enqueue').mockResolvedValue(undefined);
    hookReplies(404, 'gone fishing');
    await emitBudget(w.orgId);
    const d = await delivery(id);
    await prisma.webhookDelivery.update({
      where: { id: d.id },
      data: { attempts: WEBHOOK_MAX_ATTEMPTS - 1, nextAttemptAt: new Date() },
    });
    await deliverWebhook(ctx, d.id);
    expect((await delivery(id)).status).toBe('FAILED');

    // Still pending deliveries cannot be redelivered; disabled hooks need re-enabling first.
    const pending = await prisma.webhookDelivery.create({
      data: { webhookId: id, orgId: w.orgId, eventId: 'evt_p', event: 'pr.created', payload: {} },
    });
    expectError(
      await w.admin.post(`${base(w)}/${id}/deliveries/${pending.id}/redeliver`),
      'LSE-CONF-001',
      409,
    );
    await prisma.webhook.update({ where: { id }, data: { active: false } });
    expectError(
      await w.admin.post(`${base(w)}/${id}/deliveries/${d.id}/redeliver`),
      'LSE-CONF-001',
      409,
    );
    await prisma.webhook.update({ where: { id }, data: { active: true } });

    const sent = calls.length;
    vi.restoreAllMocks();
    hookReplies(200, 'now ok');
    const res = await w.admin.post(`${base(w)}/${id}/deliveries/${d.id}/redeliver`);
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(res.body.data).toMatchObject({ id: d.id, status: 'PENDING', attempts: 0 });
    await ctx.jobs.onIdle();
    const row = await delivery(id);
    expect(row).toMatchObject({ id: d.id, status: 'SUCCEEDED', attempts: 1, eventId: d.eventId });
    expect(calls.length).toBe(sent + 1);
    expectError(
      await w.admin.post(`${base(w)}/${id}/deliveries/cmissing/redeliver`),
      'LSE-NF-001',
      404,
    );
  });
});

describe('webhookSweep', () => {
  it('re-enqueues overdue pending deliveries and prunes old finished ones', async () => {
    const w = await world();
    const { id } = await createHook(w);
    const jobs: { data: Record<string, unknown> }[] = [];
    vi.spyOn(ctx.jobs, 'enqueue').mockImplementation(async (_q, data) => {
      jobs.push({ data });
    });
    const mk = (eventId: string, extra: Record<string, unknown>) =>
      prisma.webhookDelivery.create({
        data: {
          webhookId: id,
          orgId: w.orgId,
          eventId,
          event: 'pr.created',
          payload: {},
          ...extra,
        },
      });
    const now = new Date();
    const overdue = await mk('evt_overdue', {
      nextAttemptAt: new Date(now.getTime() - 10 * 60_000),
    });
    const unscheduled = await mk('evt_unscheduled', {
      createdAt: new Date(now.getTime() - 10 * 60_000),
    });
    await mk('evt_future', { nextAttemptAt: new Date(now.getTime() + 10 * 60_000) });
    await mk('evt_fresh', { nextAttemptAt: new Date(now.getTime() - 1_000) });
    const old = await mk('evt_old', {
      status: 'SUCCEEDED',
      createdAt: new Date(now.getTime() - 31 * 86_400_000),
    });
    const oldPending = await mk('evt_oldpending', {
      nextAttemptAt: new Date(now.getTime() + 60_000),
      createdAt: new Date(now.getTime() - 31 * 86_400_000),
    });
    await mk('evt_recent', { status: 'FAILED' });

    const out = await webhookSweep(ctx, now);
    expect(out).toEqual({ requeued: 2, pruned: 1 });
    expect(jobs.map((j) => j.data.deliveryId).sort()).toEqual([overdue.id, unscheduled.id].sort());
    expect(await prisma.webhookDelivery.findUnique({ where: { id: old.id } })).toBeNull();
    expect(
      await prisma.webhookDelivery.findUnique({ where: { id: oldPending.id } }),
    ).not.toBeNull();
    expect(await prisma.webhookDelivery.count({ where: { webhookId: id } })).toBe(6);
  });

  it('the sweep job is registered and runs', async () => {
    vi.restoreAllMocks();
    await expect(ctx.jobs.enqueue('webhook-sweep', {})).resolves.toBeUndefined();
    await ctx.jobs.onIdle();
  });
});

// ---- the real thing: sessions and runs produce webhooks ---------------------------------------------------------

describe('platform events → webhooks (real sessions)', () => {
  async function liveWorld() {
    const w = await world();
    await linkGithub(ctx, w.member.user.id);
    await addApiKey(ctx, w.member.user.id);
    const project = await createReadyProject(ctx, w.orgId);
    const user = await prisma.user.findUniqueOrThrow({ where: { id: w.member.user.id } });
    return { w, project, user };
  }

  it('a run with a PR delivers session.started, pr.created and session.completed — signed', async () => {
    const { w, project, user } = await liveWorld();
    const { id, secret } = await createHook(w);
    handlers.current = [
      http.post(HOOK_URL, () => new HttpResponse('ok', { status: 200 })),
      http.get(`${REPO}/pulls`, () => HttpResponse.json([])),
      http.post(`${REPO}/pulls`, () =>
        HttpResponse.json(
          { number: 42, html_url: 'https://github.com/acme/web/pull/42' },
          { status: 201 },
        ),
      ),
    ];
    const run = await createRun(
      ctx,
      { user },
      {
        projectId: project.id,
        prompt: 'Change the header',
        options: { createPr: true, draft: false },
        source: 'API',
      },
    );
    await waitFor(
      async () =>
        (await prisma.run.findUniqueOrThrow({ where: { id: run.id } })).status === 'SUCCEEDED',
      {
        timeoutMs: 15_000,
      },
    );
    await ctx.jobs.onIdle();
    await waitFor(
      async () =>
        (await prisma.webhookDelivery.count({ where: { webhookId: id, status: 'SUCCEEDED' } })) >=
        3,
    );

    const rows = await prisma.webhookDelivery.findMany({ where: { webhookId: id } });
    expect(rows.map((r) => r.event).sort()).toEqual([
      'pr.created',
      'session.completed',
      'session.started',
    ]);
    for (const r of rows) {
      expect(r.status).toBe('SUCCEEDED');
      expect(webhookPayloadSchema.safeParse(r.payload).success, r.event).toBe(true);
    }
    const hookCalls = calls.filter((c) => c.url === HOOK_URL);
    expect(hookCalls).toHaveLength(3);
    for (const c of hookCalls) {
      const raw = await c.clone().text();
      expect(verifyLikeAReceiver(secret, raw, c.headers, Date.now() / 1000)).toBe(true);
    }
    const pr = rows.find((r) => r.event === 'pr.created')!.payload as {
      data: { pr: { number: number; url: string } };
    };
    expect(pr.data.pr).toMatchObject({ number: 42, url: 'https://github.com/acme/web/pull/42' });
  });

  it('a failed provisioning delivers session.errored', async () => {
    const { w, project, user } = await liveWorld();
    const { id } = await createHook(w, { events: ['session.errored'] });
    hookReplies();
    fake.failNextCreate('start_failed', 5);
    await createRun(
      ctx,
      { user },
      {
        projectId: project.id,
        prompt: 'Go',
        options: { createPr: false, draft: false },
        source: 'API',
      },
    );
    await waitFor(
      async () =>
        (await prisma.webhookDelivery.count({ where: { webhookId: id, status: 'SUCCEEDED' } })) ===
        1,
      {
        timeoutMs: 15_000,
      },
    );
    const d = await delivery(id);
    expect(d.event).toBe('session.errored');
    const payload = webhookPayloadSchema.parse(d.payload);
    expect(payload.type === 'session.errored' && payload.data.session.status).toBe('ERRORED');
  });
});
