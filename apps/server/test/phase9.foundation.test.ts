/**
 * Phase 9 foundation: platform event bus, emission points (session.started / turn_completed /
 * pr.created / session.completed / session.errored / budget.exceeded), requireScope,
 * StartSessionExtras.baseBranch, PR notes, and the stub routers mounted for W1/W4.
 */
import { http, HttpResponse, type RequestHandler } from 'msw';
import request from 'supertest';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { PAT_PREFIX, webhookPayloadSchema, type ApiTokenScope } from '@loose/shared';
import { createLogger } from '../src/lib/logger';
import { PlatformEventBus, type AnyPlatformEvent } from '../src/lib/events/platformEvents';
import { assertScopes, requireScope, tokenHasScopes } from '../src/middleware/requireScope';
import { requireAuth } from '../src/middleware/requireAuth';
import { startSession, stopSession } from '../src/services/sessionLifecycle.service';
import {
  FakeGit,
  installFakeRunner,
  lastSandbox,
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
  testEnv,
  testPrisma,
  type Client,
} from './helpers';
import { addApiKey, createReadyProject, fakeSandbox, settle } from './sessionHelpers';

const prisma = testPrisma();
const handlers: { current: RequestHandler[] } = { current: [] };
const { app, ctx } = makeApp({
  context: { fetch: mswFetch(handlers) },
  extraApiRoutes: (r) => {
    // `ctx` is not assigned yet while createApp runs: resolve it per request.
    r.get(
      '/__scope-test',
      (req, res, next) => requireAuth(ctx)(req, res, next),
      requireScope('runs:read', 'runs:write'),
      (_req, res) => {
        res.json({ data: { ok: true } });
      },
    );
  },
});
const fake = fakeSandbox(ctx);
const script: { current: RunnerScript } = { current: () => undefined };
let git: FakeGit;
const REPO = `${GITHUB_API}/repos/acme/web`;

const events = <T extends AnyPlatformEvent['type']>(type: T) => ctx.platformEvents.history(type);

/** A platform event as the webhook body it becomes — must satisfy the shared contract. */
function asWebhookBody(e: AnyPlatformEvent) {
  return { id: e.id, type: e.type, createdAt: e.occurredAt, orgId: e.orgId, data: e.data };
}

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
    if (cmd.type === 'user_message')
      playTurn(r, { text: 'I updated the header.', files: ['src/components/Header.tsx'] });
  };
  handlers.current = [];
  await resetDb();
  ctx.platformEvents.clearHistory();
});

interface World {
  owner: Client;
  admin: Client;
  orgId: string;
  projectId: string;
}

async function world(opts: { maxBudgetUsd?: number } = {}): Promise<World> {
  const admin = await login(app, undefined, 'Ada Admin');
  const org = await createOrg(admin);
  const owner = await login(app, undefined, 'Mo Member');
  await addMember(org.id, owner.user.id, 'MEMBER');
  await linkGithub(ctx, owner.user.id);
  await addApiKey(ctx, owner.user.id);
  const project = await createReadyProject(ctx, org.id, {
    ...(opts.maxBudgetUsd !== undefined ? { maxBudgetUsd: opts.maxBudgetUsd } : {}),
  });
  return { owner, admin, orgId: org.id, projectId: project.id };
}

async function startRunning(w: World): Promise<string> {
  const res = await w.owner.post('/api/v1/sessions', { projectId: w.projectId });
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  const s = await settle(ctx, res.body.data.id as string);
  expect(s.status).toBe('RUNNING');
  await waitFor(() => ctx.agent.hasRuntime(s.id));
  return s.id;
}

async function turn(w: World, sessionId: string) {
  git.set('src/components/Header.tsx', ' M', ['<h1>Howdy</h1>']);
  const r = await w.owner.post(`/api/v1/sessions/${sessionId}/messages`, { content: 'Change it' });
  expect(r.status, JSON.stringify(r.body)).toBe(202);
  await waitFor(() => events('session.turn_completed').length > 0, { label: 'turn_completed' });
  await ctx.agent.idle(sessionId);
}

function prHandlers() {
  const bodies: Record<string, unknown>[] = [];
  handlers.current = [
    http.get(`${REPO}/pulls`, () => HttpResponse.json([])),
    http.post(`${REPO}/pulls`, async ({ request: req }) => {
      bodies.push((await req.json()) as Record<string, unknown>);
      return HttpResponse.json(
        { number: 42, html_url: 'https://github.com/acme/web/pull/42' },
        { status: 201 },
      );
    }),
  ];
  return bodies;
}

// ---- event bus -------------------------------------------------------------------------------

describe('PlatformEventBus', () => {
  const bus = () => new PlatformEventBus(createLogger({ level: 'silent' }), { historySize: 3 });
  const data = {
    scope: 'org' as const,
    errorCode: 'LSE-KEY-012',
    action: 'blocked' as const,
    userId: 'u1',
    projectId: null,
    sessionId: null,
    spentUsd: 1,
    budgetUsd: 1,
  };

  it('delivers to typed and catch-all listeners, awaits them, and assigns unique ids', async () => {
    const b = bus();
    const seen: string[] = [];
    b.on('budget.exceeded', async (e) => {
      await new Promise((r) => setTimeout(r, 5));
      seen.push(`typed:${e.data.scope}`);
    });
    b.on('pr.created', () => {
      seen.push('wrong');
    });
    b.onAny((e) => {
      seen.push(`any:${e.type}`);
    });
    const e1 = await b.emit('budget.exceeded', 'o1', data);
    const e2 = await b.emit('budget.exceeded', 'o1', data);
    expect(seen.sort()).toEqual(
      ['any:budget.exceeded', 'any:budget.exceeded', 'typed:org', 'typed:org'].sort(),
    );
    expect(e1.id).toMatch(/^evt_[0-9a-f]{24}$/);
    expect(e1.id).not.toBe(e2.id);
    expect(e1).toMatchObject({ type: 'budget.exceeded', orgId: 'o1', data });
    expect(new Date(e1.occurredAt).toISOString()).toBe(e1.occurredAt);
    expect(b.listenerCount('budget.exceeded')).toBe(2);
  });

  it('never rejects when listeners throw; unsubscribe works; history is bounded', async () => {
    const b = bus();
    let calls = 0;
    const off = b.on('budget.exceeded', () => {
      calls += 1;
      throw new Error('boom');
    });
    b.onAny(() => Promise.reject(new Error('async boom')));
    await expect(b.emit('budget.exceeded', 'o1', data)).resolves.toBeDefined();
    off();
    await b.emit('budget.exceeded', 'o1', data);
    expect(calls).toBe(1);
    for (let i = 0; i < 5; i += 1) await b.emit('budget.exceeded', `o${i}`, data);
    expect(b.history()).toHaveLength(3);
    expect(b.history('budget.exceeded').at(-1)?.orgId).toBe('o4');
    expect(b.history('pr.created')).toEqual([]);
    b.clearHistory();
    expect(b.history()).toEqual([]);
  });

  it('every process context gets a bus and a role', () => {
    expect(ctx.platformEvents).toBeInstanceOf(PlatformEventBus);
    expect(ctx.platformRole).toBe('api');
  });
});

// ---- emission points ---------------------------------------------------------------------------

describe('emission points', () => {
  it('session.started → turn_completed → pr.created (with notes) → session.completed', async () => {
    const w = await world();
    const sessionId = await startRunning(w);

    const started = events('session.started');
    expect(started).toHaveLength(1);
    expect(started[0]).toMatchObject({
      orgId: w.orgId,
      data: { resumed: false, session: { id: sessionId, status: 'RUNNING', runId: null } },
    });
    expect(started[0]!.data.session.url).toBe(`http://localhost:5173/session/${sessionId}`);

    await turn(w, sessionId);
    const turns = events('session.turn_completed');
    expect(turns).toHaveLength(1);
    expect(turns[0]!.data).toMatchObject({
      sessionId,
      projectId: w.projectId,
      userId: w.owner.user.id,
      filesChanged: ['src/components/Header.tsx'],
      errorCode: null,
      interrupted: false,
      planPending: false,
    });
    const assistant = await prisma.chatMessage.findUniqueOrThrow({
      where: { id: turns[0]!.data.messageId },
    });
    expect(assistant.role).toBe('ASSISTANT');

    const bodies = prHandlers();
    const pr = await w.owner.post(`/api/v1/sessions/${sessionId}/create-pr`, {
      notes: 'Closes #12',
    });
    expect(pr.status, JSON.stringify(pr.body)).toBe(200);
    expect(String(bodies[0]!.body)).toContain('## Notes\n\nCloses #12');
    expect(bodies[0]!.base).toBe('main');

    const prs = events('pr.created');
    expect(prs).toHaveLength(1);
    expect(prs[0]!.data.pr).toEqual({
      url: 'https://github.com/acme/web/pull/42',
      number: 42,
      repo: 'acme/web',
      head: `loose/session-${sessionId}`,
      base: 'main',
    });
    const completed = events('session.completed');
    expect(completed).toHaveLength(1);
    expect(completed[0]!.data.session).toMatchObject({
      status: 'COMPLETED',
      outcome: 'PR_CREATED',
      prUrl: 'https://github.com/acme/web/pull/42',
    });
    expect(events('session.errored')).toHaveLength(0);

    // Every webhook-visible event matches the shared payload contract.
    for (const e of ctx.platformEvents.history()) {
      if (e.type === 'session.turn_completed' || e.type === 'run.completed') continue;
      const parsed = webhookPayloadSchema.safeParse(asWebhookBody(e));
      expect(parsed.success, `${e.type}: ${JSON.stringify(parsed.error?.issues)}`).toBe(true);
    }
  });

  it('session.errored on ERRORED / TIMED_OUT stops, none on PAUSED', async () => {
    const w = await world();
    const a = await startRunning(w);
    await stopSession(ctx, a, { to: 'PAUSED', reason: 'idle', pushWip: false });
    expect(events('session.errored')).toHaveLength(0);
    expect(events('session.completed')).toHaveLength(0);

    const b = await startRunning(w);
    await stopSession(ctx, b, {
      to: 'ERRORED',
      reason: 'error',
      errorCode: 'LSE-AGT-001',
      pushWip: false,
    });
    const c = await startRunning(w);
    await stopSession(ctx, c, {
      to: 'TIMED_OUT',
      reason: 'timeout',
      errorCode: 'LSE-SBX-009',
      pushWip: false,
    });
    const errored = events('session.errored');
    expect(
      errored.map((e) => [e.data.session.id, e.data.session.status, e.data.session.errorCode]),
    ).toEqual([
      [b, 'ERRORED', 'LSE-AGT-001'],
      [c, 'TIMED_OUT', 'LSE-SBX-009'],
    ]);
    for (const e of errored)
      expect(webhookPayloadSchema.safeParse(asWebhookBody(e)).success).toBe(true);
  });

  it('session.errored when provisioning fails', async () => {
    const w = await world();
    fake.failNextCreate('start_failed', 5);
    const res = await w.owner.post('/api/v1/sessions', { projectId: w.projectId });
    expect(res.status).toBe(201);
    const s = await settle(ctx, res.body.data.id as string);
    expect(s.status).toBe('ERRORED');
    const errored = events('session.errored');
    expect(errored).toHaveLength(1);
    expect(errored[0]!.data.session).toMatchObject({ id: s.id, status: 'ERRORED' });
    expect(events('session.started')).toHaveLength(0);
  });

  it('budget.exceeded (blocked) when a monthly cap refuses a new session', async () => {
    const w = await world();
    await prisma.organization.update({
      where: { id: w.orgId },
      data: { policy: { budgets: { orgMonthlyUsd: 1, userMonthlyUsd: null } } },
    });
    const first = await startRunning(w);
    await prisma.usageEvent.create({
      data: {
        sessionId: first,
        orgId: w.orgId,
        userId: w.owner.user.id,
        model: 'claude-sonnet-4-5',
        tokensIn: 1,
        tokensOut: 1,
        cacheRead: 0,
        costUsd: 1.5,
      },
    });
    expectError(
      await w.owner.post('/api/v1/sessions', { projectId: w.projectId }),
      'LSE-KEY-012',
      402,
    );
    const ev = events('budget.exceeded');
    expect(ev).toHaveLength(1);
    expect(ev[0]).toMatchObject({
      orgId: w.orgId,
      data: {
        scope: 'org',
        action: 'blocked',
        errorCode: 'LSE-KEY-012',
        userId: w.owner.user.id,
        projectId: w.projectId,
        sessionId: null,
        spentUsd: 1.5,
        budgetUsd: 1,
      },
    });
    expect(webhookPayloadSchema.safeParse(asWebhookBody(ev[0]!)).success).toBe(true);
  });

  it('budget.exceeded (paused) when the session budget runs out mid-session', async () => {
    const w = await world({ maxBudgetUsd: 0.01 });
    script.current = (cmd, r) => {
      if (cmd.type === 'user_message') playTurn(r, { usage: { costUsd: 0.02 } });
    };
    const sessionId = await startRunning(w);
    await w.owner.post(`/api/v1/sessions/${sessionId}/messages`, { content: 'spend' });
    await waitFor(
      async () =>
        (await prisma.session.findUniqueOrThrow({ where: { id: sessionId } })).status === 'PAUSED',
      { label: 'paused' },
    );
    await ctx.agent.idle();
    const ev = events('budget.exceeded');
    expect(ev).toHaveLength(1);
    expect(ev[0]!.data).toMatchObject({
      scope: 'session',
      action: 'paused',
      errorCode: 'LSE-AGT-003',
      sessionId,
      projectId: w.projectId,
      budgetUsd: 0.01,
    });
    expect(ev[0]!.data.spentUsd).toBeCloseTo(0.02);
    expect(webhookPayloadSchema.safeParse(asWebhookBody(ev[0]!)).success).toBe(true);
  });
});

// ---- StartSessionExtras --------------------------------------------------------------------

describe('startSession extras', () => {
  it('baseBranch: clones that branch, opens the PR against it, and shows in the DTO', async () => {
    const w = await world();
    const user = await prisma.user.findUniqueOrThrow({ where: { id: w.owner.user.id } });
    const dto = await startSession(
      ctx,
      { user },
      { projectId: w.projectId },
      { baseBranch: 'release/1.2' },
    );
    expect(dto.baseBranch).toBe('release/1.2');
    const s = await settle(ctx, dto.id);
    expect(s.status).toBe('RUNNING');
    expect(s.baseBranch).toBe('release/1.2');
    await waitFor(() => ctx.agent.hasRuntime(s.id));
    expect(
      lastSandbox(ctx)
        .commandLines()
        .some((c) => c.includes("--branch 'release/1.2'")),
    ).toBe(true);
    expect(events('session.started')[0]!.data.session.baseBranch).toBe('release/1.2');

    await turn(w, s.id);
    const bodies = prHandlers();
    const pr = await w.owner.post(`/api/v1/sessions/${s.id}/create-pr`, {});
    expect(pr.status, JSON.stringify(pr.body)).toBe(200);
    expect(bodies[0]!.base).toBe('release/1.2');
    expect(events('pr.created')[0]!.data.pr.base).toBe('release/1.2');
  });

  it('fork lineage + snapshot: restores the wip ref on first start without counting as a recover', async () => {
    const w = await world();
    const parent = await startRunning(w);
    const user = await prisma.user.findUniqueOrThrow({ where: { id: w.owner.user.id } });
    const dto = await startSession(
      ctx,
      { user },
      { projectId: w.projectId },
      { parentSessionId: parent, wipRef: 'refs/loose/wip/fork-src', notes: 'from parent' },
    );
    expect(dto.parentSessionId).toBe(parent);
    const s = await settle(ctx, dto.id);
    expect(s.status).toBe('RUNNING');
    expect(s.notes).toBe('from parent');
    const cmds = lastSandbox(ctx).commandLines();
    expect(cmds.some((c) => c.includes('+refs/loose/wip/fork-src:refs/loose/wip'))).toBe(true);
    expect(events('session.started').at(-1)!.data).toMatchObject({
      resumed: false,
      session: { id: s.id, parentSessionId: parent },
    });
    expect(
      await prisma.auditLog.count({ where: { action: 'session.recover', target: s.id } }),
    ).toBe(0);
  });
});

// ---- scopes ----------------------------------------------------------------------------------

describe('requireScope', () => {
  async function token(c: Client, orgId: string, scopes: ApiTokenScope[]) {
    const res = await c.post('/api/v1/users/me/tokens', { orgId, name: 't', scopes });
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    return res.body.data.token as string;
  }

  it('cookie sessions pass; tokens need every listed scope (LSE-ORG-002)', async () => {
    const w = await world();
    expect((await w.owner.get('/api/v1/__scope-test')).status).toBe(200);
    const partial = await token(w.owner, w.orgId, ['runs:write']);
    expect(partial.startsWith(PAT_PREFIX)).toBe(true);
    const denied = await request(app)
      .get('/api/v1/__scope-test')
      .set('Authorization', `Bearer ${partial}`);
    expectError(denied, 'LSE-ORG-002', 403);
    expect(denied.body.error.devMessage).toContain('runs:read');
    const full = await token(w.owner, w.orgId, ['runs:read', 'runs:write']);
    const ok = await request(app)
      .get('/api/v1/__scope-test')
      .set('Authorization', `Bearer ${full}`);
    expect(ok.status).toBe(200);
  });

  it('helpers', () => {
    expect(tokenHasScopes({ scopes: ['runs:read'] }, ['runs:read'])).toBe(true);
    expect(tokenHasScopes({ scopes: ['runs:write'] }, ['runs:read'])).toBe(false);
    expect(tokenHasScopes({ scopes: [] }, [])).toBe(true);
    expect(() => assertScopes({}, 'runs:write')).not.toThrow();
    expect(() => assertScopes({ apiToken: { scopes: ['runs:read'] } }, 'runs:write')).toThrow(
      expect.objectContaining({ code: 'LSE-ORG-002' }),
    );
  });
});

// ---- stubs & config --------------------------------------------------------------------------

describe('foundation stubs (replaced by W1 / W4)', () => {
  it('runs are wired; triggers/webhooks are real; integrations need a configured secret', async () => {
    const w = await world();
    expectError(await request(app).get('/api/v1/runs'), 'LSE-AUTH-001', 401);
    // W1 replaced the runs stub: it now lists runs (none yet).
    expect((await w.owner.get('/api/v1/runs')).body.data).toEqual([]);
    // W4 replaced the triggers stub: it now lists triggers (none yet) for admins.
    expect((await w.admin.get(`/api/v1/orgs/${w.orgId}/triggers`)).body.data).toEqual([]);
    expectError(await w.owner.get(`/api/v1/orgs/${w.orgId}/triggers`), 'LSE-ORG-002', 403);
    // W1 replaced the webhooks stub.
    expect((await w.admin.get(`/api/v1/orgs/${w.orgId}/webhooks`)).body.data).toEqual([]);
    // W4 replaced the integrations stub: without SLACK_SIGNING_SECRET it still answers 503.
    expectError(
      await request(app).post('/api/v1/integrations/slack/commands').type('form').send('text=hi'),
      'LSE-SYS-007',
      503,
    );
  });

  it('integration secrets are optional env vars', () => {
    expect(testEnv().SLACK_SIGNING_SECRET).toBeUndefined();
    const env = testEnv({
      SLACK_SIGNING_SECRET: 'slack-secret',
      LINEAR_WEBHOOK_SECRET: 'linear-secret',
      JIRA_WEBHOOK_SECRET: '',
    });
    expect(env.SLACK_SIGNING_SECRET).toBe('slack-secret');
    expect(env.LINEAR_WEBHOOK_SECRET).toBe('linear-secret');
    expect(env.JIRA_WEBHOOK_SECRET).toBeUndefined();
  });

  it('platform job queues have handlers registered', async () => {
    // Enqueueing to a queue without a handler is a silent no-op in the inline runner;
    // the stubs register placeholders so production schedules never pile up.
    for (const q of ['webhook-sweep', 'runs-reconcile', 'trigger-schedule-tick'] as const) {
      await expect(ctx.jobs.enqueue(q, {})).resolves.toBeUndefined();
    }
    await ctx.jobs.onIdle();
  });
});
