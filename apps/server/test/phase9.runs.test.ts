/**
 * Phase 9 / W1 — headless runs: `POST /runs`, `GET /runs[/:id]`, `POST /runs/:id/cancel`,
 * SSE `GET /runs/:id/events`, the run driver (fake sandbox + scripted mock runner + MSW GitHub),
 * scopes, idempotency, access control, reconcile.
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { http as mswHttp, HttpResponse, type RequestHandler } from 'msw';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  createRunBodySchema,
  runDtoSchema,
  runClientMessageId,
  type ApiTokenScope,
  type RunDto,
} from '@loose/shared';
import {
  cancelRun,
  createRun,
  getRun,
  listRuns,
  reconcileRuns,
  resolveRunProject,
  runDriverIdle,
  RUN_MAX_AGE_MS,
  RUN_PR_STALE_MS,
  subscribeRun,
  type RunStreamEvent,
} from '../src/services/runs.service';
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
import { addApiKey, createReadyProject, fakeSandbox, settle } from './sessionHelpers';

const prisma = testPrisma();
const handlers: { current: RequestHandler[] } = { current: [] };
const prRequests: Record<string, unknown>[] = [];
const { app, ctx } = makeApp({ context: { fetch: mswFetch(handlers) } });
const fake = fakeSandbox(ctx);
const script: { current: RunnerScript } = { current: () => undefined };
let git: FakeGit;
const REPO = `${GITHUB_API}/repos/acme/web`;
const FILE = 'src/components/Header.tsx';

/** A turn that edits one file. */
function editScript(text = 'I updated the header.') {
  script.current = (cmd, r) => {
    if (cmd.type !== 'user_message') return;
    git.set(FILE, ' M', ['<h1>Howdy</h1>']);
    playTurn(r, { text, files: [FILE] });
  };
}

/** Hold the agent's turn until `release()` (to observe a running run). */
function gatedScript() {
  let release: () => void = () => undefined;
  const gate = new Promise<void>((r) => {
    release = r;
  });
  script.current = async (cmd, r) => {
    if (cmd.type !== 'user_message') return;
    await gate;
    git.set(FILE, ' M', ['<h1>Howdy</h1>']);
    playTurn(r, { text: 'Done after the gate.', files: [FILE] });
  };
  return { release: () => release() };
}

function prHandlers() {
  prRequests.length = 0;
  handlers.current = [
    mswHttp.get(`${REPO}/pulls`, () => HttpResponse.json([])),
    mswHttp.post(`${REPO}/pulls`, async ({ request: req }) => {
      prRequests.push((await req.json()) as Record<string, unknown>);
      return HttpResponse.json(
        { number: 42, html_url: 'https://github.com/acme/web/pull/42' },
        { status: 201 },
      );
    }),
  ];
}

let server: http.Server;
let baseUrl = '';

beforeAll(async () => {
  server = http.createServer(app);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await ctx.agent.idle();
  await ctx.jobs.onIdle();
  await new Promise<void>((r) => server.close(() => r()));
  await prisma.$disconnect();
});

beforeEach(async () => {
  await ctx.agent.shutdownAll();
  await ctx.jobs.onIdle();
  fake.reset();
  installFakeRunner(fake, script);
  git = new FakeGit().install(fake);
  editScript();
  prHandlers();
  await resetDb();
  ctx.platformEvents.clearHistory();
});

interface World {
  owner: Client;
  admin: Client;
  orgId: string;
  projectId: string;
}

async function world(
  project: Parameters<typeof createReadyProject>[2] = {},
  opts: { key?: boolean } = {},
): Promise<World> {
  const admin = await login(app, undefined, 'Ada Admin');
  const org = await createOrg(admin);
  const owner = await login(app, undefined, 'Mo Member');
  await addMember(org.id, owner.user.id, 'MEMBER');
  await linkGithub(ctx, owner.user.id);
  if (opts.key !== false) await addApiKey(ctx, owner.user.id);
  const p = await createReadyProject(ctx, org.id, project);
  return { owner, admin, orgId: org.id, projectId: p.id };
}

async function mintToken(c: Client, orgId: string, scopes: ApiTokenScope[]): Promise<string> {
  const res = await c.post('/api/v1/users/me/tokens', { orgId, name: 'ci', scopes });
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  return res.body.data.token as string;
}

const RW: ApiTokenScope[] = ['runs:read', 'runs:write'];

class Api {
  constructor(private readonly token: string) {}
  get(url: string) {
    return request(app).get(url).set('Authorization', `Bearer ${this.token}`);
  }
  post(url: string, body?: object, headers: Record<string, string> = {}) {
    const r = request(app).post(url).set('Authorization', `Bearer ${this.token}`).set(headers);
    return body === undefined ? r : r.send(body);
  }
}

async function dbRun(id: string) {
  return prisma.run.findUniqueOrThrow({ where: { id } });
}

/** Terminal in the DB AND fully wound down (session released, `run.completed` emitted). */
async function waitTerminal(id: string, timeoutMs = 15_000) {
  return waitFor(
    async () => {
      const r = await dbRun(id);
      if (!['SUCCEEDED', 'FAILED', 'CANCELLED'].includes(r.status)) return null;
      return ctx.platformEvents.history('run.completed').some((e) => e.data.runId === id)
        ? r
        : null;
    },
    { timeoutMs, label: `run ${id} to finish` },
  );
}

async function waitStatus(id: string, status: string) {
  return waitFor(async () => ((await dbRun(id)).status === status ? true : null), {
    timeoutMs: 15_000,
    label: `run ${id} to be ${status}`,
  });
}

const sessionRow = (id: string) => prisma.session.findUniqueOrThrow({ where: { id } });
const runCompleted = () => ctx.platformEvents.history('run.completed');

// ---- SSE client ----------------------------------------------------------------------------

interface SseEvent {
  event: string;
  id: string | null;
  data: unknown;
}

async function readSse(
  path: string,
  headers: Record<string, string>,
  opts: { onEvent?: (e: SseEvent) => void; stopAfter?: (events: SseEvent[]) => boolean } = {},
): Promise<{ status: number; events: SseEvent[]; pings: number }> {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), 20_000);
  const res = await fetch(`${baseUrl}${path}`, { headers, signal: ac.signal });
  const events: SseEvent[] = [];
  let pings = 0;
  if (res.status !== 200 || !res.body) {
    clearTimeout(timer);
    return { status: res.status, events, pings };
  }
  const decoder = new TextDecoder();
  const reader = res.body.getReader();
  let buf = '';
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let idx: number;
      while ((idx = buf.indexOf('\n\n')) >= 0) {
        const block = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        let event = 'message';
        let id: string | null = null;
        let data = '';
        for (const line of block.split('\n')) {
          if (line.startsWith(':')) pings += 1;
          else if (line.startsWith('event: ')) event = line.slice(7);
          else if (line.startsWith('id: ')) id = line.slice(4);
          else if (line.startsWith('data: ')) data += line.slice(6);
        }
        if (!data) continue;
        const e: SseEvent = { event, id, data: JSON.parse(data) };
        events.push(e);
        opts.onEvent?.(e);
        if (opts.stopAfter?.(events)) {
          ac.abort();
          return { status: 200, events, pings };
        }
      }
    }
  } catch (err) {
    if ((err as Error).name !== 'AbortError') throw err;
  } finally {
    clearTimeout(timer);
  }
  return { status: 200, events, pings };
}

const statuses = (events: SseEvent[]) =>
  events.filter((e) => e.event === 'status').map((e) => (e.data as RunDto).status);

// ---- happy path ------------------------------------------------------------------------------

describe('POST /runs → session → prompt → PR', () => {
  it('runs a prompt end to end with an API token and opens the PR', async () => {
    const w = await world();
    const api = new Api(await mintToken(w.owner, w.orgId, RW));
    const res = await api.post(
      '/api/v1/runs',
      {
        project: 'acme/web',
        prompt: 'Change the header to Howdy',
        options: { createPr: true, prTitle: 'Howdy header', prNotes: 'Closes #12', draft: true },
        source: 'CLI',
        metadata: { ci: 'https://ci.example.com/run/9' },
      },
      { 'Idempotency-Key': 'run-happy-1' },
    );
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    const created = runDtoSchema.parse(res.body.data);
    expect(created).toMatchObject({
      orgId: w.orgId,
      projectId: w.projectId,
      projectName: 'Web',
      userId: w.owner.user.id,
      source: 'CLI',
      prompt: 'Change the header to Howdy',
      metadata: { ci: 'https://ci.example.com/run/9' },
      options: { createPr: true, draft: true, prTitle: 'Howdy header', prNotes: 'Closes #12' },
      triggerId: null,
      prUrl: null,
    });
    expect(['PROVISIONING', 'RUNNING']).toContain(created.status);
    expect(created.sessionUrl).toBe(`http://localhost:5173/session/${created.sessionId}`);

    const done = await waitTerminal(created.id);
    expect(done).toMatchObject({
      status: 'SUCCEEDED',
      prUrl: 'https://github.com/acme/web/pull/42',
      prNumber: 42,
      filesChanged: [FILE],
      summary: 'I updated the header.',
      errorCode: null,
    });
    expect(done.startedAt).not.toBeNull();
    expect(done.endedAt).not.toBeNull();
    expect(Number(done.costUsd)).toBeGreaterThan(0);

    // The PR carries the run's title, draft flag and notes.
    expect(prRequests).toHaveLength(1);
    expect(prRequests[0]).toMatchObject({ title: 'Howdy header', draft: true, base: 'main' });
    expect(String(prRequests[0]!.body)).toContain('## Notes\n\nCloses #12');

    // The session was driven as the run's user, with the idempotent client message id.
    const s = await sessionRow(created.sessionId!);
    expect(s).toMatchObject({
      status: 'COMPLETED',
      outcome: 'PR_CREATED',
      userId: w.owner.user.id,
    });
    const msg = await prisma.chatMessage.findFirstOrThrow({
      where: { sessionId: s.id, role: 'USER' },
    });
    expect(msg).toMatchObject({
      content: 'Change the header to Howdy',
      clientMessageId: runClientMessageId(created.id),
    });

    // Reads: by id (token + cookie) and list.
    const got = await api.get(`/api/v1/runs/${created.id}`);
    expect(got.status).toBe(200);
    expect(got.body.data).toMatchObject({ id: created.id, status: 'SUCCEEDED', prNumber: 42 });
    expect((await w.owner.get(`/api/v1/runs/${created.id}`)).body.data.id).toBe(created.id);
    const list = await api.get('/api/v1/runs');
    expect(list.body.data.map((r: RunDto) => r.id)).toEqual([created.id]);
    expect(list.body.nextCursor).toBeNull();

    // run.completed carries everything triggers need.
    const ev = runCompleted();
    expect(ev).toHaveLength(1);
    expect(ev[0]!.data).toMatchObject({
      runId: created.id,
      sessionId: s.id,
      projectId: w.projectId,
      triggerId: null,
      status: 'SUCCEEDED',
      prUrl: 'https://github.com/acme/web/pull/42',
      prNumber: 42,
      errorCode: null,
      summary: 'I updated the header.',
      externalRef: null,
    });

    const audit = await prisma.auditLog.findFirstOrThrow({ where: { action: 'run.create' } });
    expect(audit).toMatchObject({ orgId: w.orgId, actorId: w.owner.user.id, target: created.id });
    expect(audit.meta).toMatchObject({ source: 'CLI', createPr: true, via: 'token' });
  });

  it('works with a cookie session (CSRF) and project selected by id; branch becomes the base', async () => {
    const w = await world();
    const res = await w.owner.post('/api/v1/runs', {
      projectId: w.projectId,
      prompt: 'Fix it',
      options: { createPr: true, branch: 'release/1.2' },
    });
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    const done = await waitTerminal(res.body.data.id as string);
    expect(done.status).toBe('SUCCEEDED');
    expect(prRequests[0]!.base).toBe('release/1.2');
    expect((await sessionRow(done.sessionId!)).baseBranch).toBe('release/1.2');
    expect(res.body.data.source).toBe('API');
  });

  it('without createPr the work is kept on the WIP ref and the session is paused', async () => {
    const w = await world();
    const res = await w.owner.post('/api/v1/runs', { projectId: w.projectId, prompt: 'Try it' });
    const done = await waitTerminal(res.body.data.id as string);
    expect(done).toMatchObject({ status: 'SUCCEEDED', prUrl: null, filesChanged: [FILE] });
    expect(done.summary).toBe('I updated the header.');
    expect(prRequests).toHaveLength(0);
    await waitFor(async () => (await sessionRow(done.sessionId!)).status === 'PAUSED');
    expect((await sessionRow(done.sessionId!)).wipRef).not.toBeNull();
  });

  it('createPr with nothing changed still succeeds, without a PR', async () => {
    const w = await world();
    script.current = (cmd, r) => {
      if (cmd.type === 'user_message') playTurn(r, { text: 'Nothing to change.', files: [] });
    };
    const res = await w.owner.post('/api/v1/runs', {
      projectId: w.projectId,
      prompt: 'Is anything broken?',
      options: { createPr: true },
    });
    const done = await waitTerminal(res.body.data.id as string);
    expect(done).toMatchObject({ status: 'SUCCEEDED', prUrl: null, summary: 'Nothing to change.' });
    expect(prRequests).toHaveLength(0);
  });

  it('SUCCEEDED without a PR when one already exists for the branch (LSE-GH-008)', async () => {
    const w = await world();
    handlers.current = [
      mswHttp.get(`${REPO}/pulls`, () =>
        HttpResponse.json([{ number: 7, html_url: 'https://github.com/acme/web/pull/7' }]),
      ),
    ];
    const res = await w.owner.post('/api/v1/runs', {
      projectId: w.projectId,
      prompt: 'Again',
      options: { createPr: true },
    });
    const done = await waitTerminal(res.body.data.id as string);
    expect(done).toMatchObject({ status: 'SUCCEEDED', prUrl: null, errorCode: null });
    expect(done.filesChanged).toEqual([FILE]);
    await waitFor(async () => (await sessionRow(done.sessionId!)).status === 'PAUSED');
  });

  it('Simple mode runs report a Simple-mode summary', async () => {
    const w = await world();
    const res = await w.owner.post('/api/v1/runs', {
      projectId: w.projectId,
      prompt: 'Make it friendlier',
      options: { mode: 'SIMPLE' },
    });
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    const done = await waitTerminal(res.body.data.id as string);
    expect(done.status).toBe('SUCCEEDED');
    expect((await sessionRow(done.sessionId!)).mode).toBe('SIMPLE');
    expect(done.summary).toBeTruthy();
  });
});

// ---- failures --------------------------------------------------------------------------------

describe('failure paths', () => {
  it('preflight errors are returned as-is and no run is kept (no API key → LSE-KEY-001)', async () => {
    const w = await world({}, { key: false });
    const res = await w.owner.post('/api/v1/runs', { projectId: w.projectId, prompt: 'Go' });
    expectError(res, 'LSE-KEY-001', 400);
    expect(await prisma.run.count()).toBe(0);
    expect(await prisma.session.count()).toBe(0);
  });

  it('monthly budget exhausted → LSE-KEY-012 and a budget.exceeded event', async () => {
    const w = await world();
    await prisma.organization.update({
      where: { id: w.orgId },
      data: { policy: { budgets: { orgMonthlyUsd: 1, userMonthlyUsd: null } } },
    });
    const first = await w.owner.post('/api/v1/runs', { projectId: w.projectId, prompt: 'One' });
    const firstRun = await waitTerminal(first.body.data.id as string);
    await prisma.usageEvent.create({
      data: {
        sessionId: firstRun.sessionId!,
        orgId: w.orgId,
        userId: w.owner.user.id,
        model: 'claude-sonnet-4-5',
        tokensIn: 1,
        tokensOut: 1,
        cacheRead: 0,
        costUsd: 2,
      },
    });
    expectError(
      await w.owner.post('/api/v1/runs', { projectId: w.projectId, prompt: 'Two' }),
      'LSE-KEY-012',
      402,
    );
    expect(ctx.platformEvents.history('budget.exceeded')).toHaveLength(1);
    expect(await prisma.run.count()).toBe(1);
  });

  it('a template that is not ready → LSE-TPL-001', async () => {
    const w = await world({ e2bTemplateId: null, templateStatus: 'PENDING' });
    expectError(
      await w.owner.post('/api/v1/runs', { projectId: w.projectId, prompt: 'Go' }),
      'LSE-TPL-001',
    );
    expect(await prisma.run.count()).toBe(0);
  });

  it('a blocking turn error fails the run with that code and pauses the session', async () => {
    const w = await world();
    script.current = (cmd, r) => {
      if (cmd.type !== 'user_message') return;
      r.emit('error', { code: 'LSE-KEY-002', detail: 'credit balance is too low' });
      r.emit('turn_complete', { filesChanged: [], stopReason: 'error' });
    };
    const res = await w.owner.post('/api/v1/runs', {
      projectId: w.projectId,
      prompt: 'Go',
      options: { createPr: true },
    });
    const done = await waitTerminal(res.body.data.id as string);
    expect(done).toMatchObject({ status: 'FAILED', errorCode: 'LSE-KEY-002', prUrl: null });
    expect(prRequests).toHaveLength(0);
    await waitFor(async () => (await sessionRow(done.sessionId!)).status === 'PAUSED');
    expect(runCompleted()[0]!.data).toMatchObject({ status: 'FAILED', errorCode: 'LSE-KEY-002' });
  });

  it('provisioning failure → FAILED with the session error code', async () => {
    const w = await world();
    fake.failNextCreate('start_failed', 5);
    const res = await w.owner.post('/api/v1/runs', { projectId: w.projectId, prompt: 'Go' });
    expect(res.status).toBe(201);
    const done = await waitTerminal(res.body.data.id as string);
    const s = await sessionRow(done.sessionId!);
    expect(s.status).toBe('ERRORED');
    expect(done).toMatchObject({ status: 'FAILED', errorCode: s.errorCode });
    expect(done.errorCode).toMatch(/^LSE-SBX-/);
    expect(runCompleted()).toHaveLength(1);
  });

  it('a PR that cannot be created fails the run with the GitHub code', async () => {
    const w = await world();
    handlers.current = [
      mswHttp.get(`${REPO}/pulls`, () => HttpResponse.json([])),
      mswHttp.post(`${REPO}/pulls`, () =>
        HttpResponse.json({ message: 'Resource not accessible' }, { status: 403 }),
      ),
    ];
    const res = await w.owner.post('/api/v1/runs', {
      projectId: w.projectId,
      prompt: 'Go',
      options: { createPr: true },
    });
    const done = await waitTerminal(res.body.data.id as string);
    expect(done.status).toBe('FAILED');
    expect(done.errorCode).toMatch(/^LSE-GH-/);
    expect(done.filesChanged).toEqual([FILE]);
  });

  it('the session budget running out fails the run (LSE-AGT-003)', async () => {
    const w = await world({ maxBudgetUsd: 0.01 });
    script.current = (cmd, r) => {
      if (cmd.type === 'user_message') playTurn(r, { usage: { costUsd: 0.02 } });
    };
    const res = await w.owner.post('/api/v1/runs', { projectId: w.projectId, prompt: 'Spend' });
    const done = await waitTerminal(res.body.data.id as string);
    expect(done).toMatchObject({ status: 'FAILED', errorCode: 'LSE-AGT-003' });
    expect(Number(done.costUsd)).toBeGreaterThan(0.01);
    expect(prRequests).toHaveLength(0);
  });

  it('the monthly spending cap running out fails the run (LSE-KEY-012)', async () => {
    const w = await world();
    await prisma.organization.update({
      where: { id: w.orgId },
      data: { policy: { budgets: { orgMonthlyUsd: 0.01, userMonthlyUsd: null } } },
    });
    script.current = (cmd, r) => {
      if (cmd.type === 'user_message') playTurn(r, { files: [FILE], usage: { costUsd: 0.02 } });
    };
    const res = await w.owner.post('/api/v1/runs', {
      projectId: w.projectId,
      prompt: 'Spend',
      options: { createPr: true },
    });
    const done = await waitTerminal(res.body.data.id as string);
    expect(done).toMatchObject({ status: 'FAILED', errorCode: 'LSE-KEY-012', prUrl: null });
    expect(prRequests).toHaveLength(0);
  });
});

// ---- plan approval -----------------------------------------------------------------------------

describe('approvals', () => {
  it('a plan turn parks the run in WAITING_APPROVAL; approving it finishes the run', async () => {
    const w = await world({ planMode: 'ALWAYS' });
    script.current = (cmd, r) => {
      if (cmd.type !== 'user_message') return;
      if (cmd.data.permissionMode === 'plan') {
        playTurn(r, { text: 'Here is my plan.', plan: '1. Edit the header\n2. Check it' });
      } else {
        git.set(FILE, ' M', ['<h1>Howdy</h1>']);
        playTurn(r, { text: 'Plan executed.', files: [FILE] });
      }
    };
    const res = await w.owner.post('/api/v1/runs', {
      projectId: w.projectId,
      prompt: 'Change the header',
      options: { createPr: true },
    });
    const id = res.body.data.id as string;
    await waitStatus(id, 'WAITING_APPROVAL');
    expect(((await w.owner.get(`/api/v1/runs/${id}`)).body.data as RunDto).status).toBe(
      'WAITING_APPROVAL',
    );

    const run = await dbRun(id);
    const approval = await prisma.toolApproval.findFirstOrThrow({
      where: { sessionId: run.sessionId!, status: 'PENDING' },
    });
    const ok = await w.owner.post(`/api/v1/sessions/${run.sessionId}/approvals/${approval.id}`, {
      decision: 'approve',
    });
    expect(ok.status, JSON.stringify(ok.body)).toBe(200);

    const done = await waitTerminal(id);
    expect(done).toMatchObject({ status: 'SUCCEEDED', prNumber: 42, summary: 'Plan executed.' });
  });
});

// ---- scopes, auth & access ---------------------------------------------------------------------

describe('authentication, scopes and access', () => {
  it('requires authentication', async () => {
    expectError(await request(app).get('/api/v1/runs'), 'LSE-AUTH-001', 401);
    expectError(
      await request(app)
        .post('/api/v1/runs')
        .set('Authorization', 'Bearer loose_pat_nope')
        .send({}),
      'LSE-AUTH-007',
      401,
    );
    expectError(
      await request(app).get('/api/v1/runs').set('Authorization', 'Bearer loose_pat_nope'),
      'LSE-AUTH-007',
      401,
    );
  });

  it('runs:write does not grant reads and runs:read does not grant writes (LSE-ORG-002)', async () => {
    const w = await world();
    const writer = new Api(await mintToken(w.owner, w.orgId, ['runs:write']));
    const reader = new Api(await mintToken(w.owner, w.orgId, ['runs:read']));
    const other = new Api(await mintToken(w.owner, w.orgId, ['sessions:read', 'sessions:write']));

    const denied = await reader.post('/api/v1/runs', { projectId: w.projectId, prompt: 'Go' });
    expectError(denied, 'LSE-ORG-002', 403);
    expect(denied.body.error.devMessage).toContain('runs:write');
    expectError(
      await other.post('/api/v1/runs', { projectId: w.projectId, prompt: 'Go' }),
      'LSE-ORG-002',
    );
    expect(await prisma.run.count()).toBe(0);

    const created = await writer.post('/api/v1/runs', { projectId: w.projectId, prompt: 'Go' });
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    const id = created.body.data.id as string;
    const readDenied = await writer.get(`/api/v1/runs/${id}`);
    expectError(readDenied, 'LSE-ORG-002', 403);
    expect(readDenied.body.error.devMessage).toContain('runs:read');
    expectError(await writer.get('/api/v1/runs'), 'LSE-ORG-002');
    expectError(await writer.get(`/api/v1/runs/${id}/events`), 'LSE-ORG-002');
    expectError(await reader.post(`/api/v1/runs/${id}/cancel`), 'LSE-ORG-002');
    expect((await reader.get(`/api/v1/runs/${id}`)).status).toBe(200);
    await waitTerminal(id);
  });

  it('tokens are bound to one org: another org gets LSE-NF-001 / LSE-ORG-001', async () => {
    const w = await world();
    const w2 = await world();
    const foreign = new Api(await mintToken(w2.owner, w2.orgId, RW));
    expectError(
      await foreign.post('/api/v1/runs', { projectId: w.projectId, prompt: 'Go' }),
      'LSE-NF-001',
      404,
    );
    expectError(
      await foreign.post('/api/v1/runs', { project: 'acme/web', orgId: w.orgId, prompt: 'Go' }),
      'LSE-ORG-001',
      403,
    );
    expectError(await foreign.get(`/api/v1/runs?orgId=${w.orgId}`), 'LSE-ORG-001');
    expect(await prisma.run.count()).toBe(0);
  });

  it('viewers cannot start runs; unknown projects are not found', async () => {
    const w = await world();
    const viewer = await login(app, undefined, 'Vi Viewer');
    await addMember(w.orgId, viewer.user.id, 'VIEWER');
    expectError(
      await viewer.post('/api/v1/runs', { projectId: w.projectId, prompt: 'Go' }),
      'LSE-ORG-002',
      403,
    );
    expectError(
      await w.owner.post('/api/v1/runs', { project: 'nope/nothing', prompt: 'Go' }),
      'LSE-NF-001',
      404,
    );
    expectError(
      await w.owner.post('/api/v1/runs', { projectId: 'cdoesnotexist', prompt: 'Go' }),
      'LSE-NF-001',
    );
  });

  it('validates the body (exactly one project reference, known keys, prompt length)', async () => {
    const w = await world();
    for (const body of [
      { prompt: 'Go' },
      { projectId: w.projectId, project: 'acme/web', prompt: 'Go' },
      { projectId: w.projectId, prompt: '' },
      { projectId: w.projectId, prompt: 'Go', extra: 1 },
      { projectId: w.projectId, prompt: 'Go', options: { branch: 'bad..branch' } },
      { projectId: w.projectId, prompt: 'Go', source: 'SLACK' },
    ]) {
      expectError(await w.owner.post('/api/v1/runs', body), 'LSE-VAL-001', 400);
    }
    expect(createRunBodySchema.safeParse({ projectId: 'abc', prompt: 'x' }).success).toBe(true);
    expect(await prisma.run.count()).toBe(0);
  });

  it('project by name / repo; ambiguity needs the id', async () => {
    const w = await world();
    const twin = await createReadyProject(ctx, w.orgId, { name: 'Web twin' });
    const caller = {
      user: await prisma.user.findUniqueOrThrow({ where: { id: w.owner.user.id } }),
    };
    expect((await resolveRunProject(ctx, caller, { project: 'web twin' })).id).toBe(twin.id);
    expect((await resolveRunProject(ctx, caller, { project: twin.id })).id).toBe(twin.id);
    // Both projects point at acme/web.
    const ambiguous = await w.owner.post('/api/v1/runs', { project: 'ACME/web', prompt: 'Go' });
    expectError(ambiguous, 'LSE-VAL-001', 400);
    expect(ambiguous.body.error.fields.project).toBeDefined();
    expect((await resolveRunProject(ctx, caller, { projectId: w.projectId })).id).toBe(w.projectId);
  });

  it('only the owner or an org admin can see a run; lists are scoped per role', async () => {
    const w = await world();
    const peer = await login(app, undefined, 'Pia Peer');
    await addMember(w.orgId, peer.user.id, 'MEMBER');
    await linkGithub(ctx, peer.user.id);
    await addApiKey(ctx, peer.user.id);
    const mine = await w.owner.post('/api/v1/runs', { projectId: w.projectId, prompt: 'Mine' });
    const hers = await peer.post('/api/v1/runs', { projectId: w.projectId, prompt: 'Hers' });
    const mineId = mine.body.data.id as string;
    const hersId = hers.body.data.id as string;
    await waitTerminal(mineId);
    await waitTerminal(hersId);

    expectError(await peer.get(`/api/v1/runs/${mineId}`), 'LSE-ORG-002', 403);
    expectError(await peer.post(`/api/v1/runs/${mineId}/cancel`), 'LSE-ORG-002', 403);
    expect((await w.admin.get(`/api/v1/runs/${mineId}`)).status).toBe(200);

    const stranger = await login(app, undefined, 'Sam Stranger');
    expectError(await stranger.get(`/api/v1/runs/${mineId}`), 'LSE-NF-001', 404);
    expectError(await stranger.get('/api/v1/runs?orgId=' + w.orgId), 'LSE-ORG-001', 403);
    expect((await stranger.get('/api/v1/runs')).body.data).toEqual([]);

    const ownList = (await w.owner.get('/api/v1/runs')).body.data as RunDto[];
    expect(ownList.map((r) => r.id)).toEqual([mineId]);
    const adminList = (await w.admin.get('/api/v1/runs')).body.data as RunDto[];
    expect(adminList.map((r) => r.id).sort()).toEqual([mineId, hersId].sort());

    // Filters + cursor pagination (newest first).
    const page1 = await w.admin.get('/api/v1/runs?limit=1');
    expect(page1.body.data).toHaveLength(1);
    expect(page1.body.nextCursor).toBeTruthy();
    const page2 = await w.admin.get(`/api/v1/runs?limit=1&cursor=${page1.body.nextCursor}`);
    expect(page2.body.data).toHaveLength(1);
    expect(page2.body.nextCursor).toBeNull();
    expect(page1.body.data[0].id).not.toBe(page2.body.data[0].id);
    expect((await w.admin.get('/api/v1/runs?status=FAILED')).body.data).toEqual([]);
    expect(
      (await w.admin.get(`/api/v1/runs?projectId=${w.projectId}&status=SUCCEEDED`)).body.data,
    ).toHaveLength(2);
    expectError(await w.admin.get('/api/v1/runs?status=BOGUS'), 'LSE-VAL-001');
    expectError(await w.admin.get('/api/v1/runs/not%20an%20id'), 'LSE-VAL-001');
    expectError(await w.admin.get('/api/v1/runs/cmissing'), 'LSE-NF-001', 404);
  });
});

// ---- idempotency ----------------------------------------------------------------------------------

describe('Idempotency-Key', () => {
  it('replays the stored response: one run, one session', async () => {
    const w = await world();
    const api = new Api(await mintToken(w.owner, w.orgId, RW));
    const body = { projectId: w.projectId, prompt: 'Once only' };
    const a = await api.post('/api/v1/runs', body, { 'Idempotency-Key': 'key-1' });
    const b = await api.post('/api/v1/runs', body, { 'Idempotency-Key': 'key-1' });
    expect(a.status).toBe(201);
    expect(b.status).toBe(201);
    expect(b.headers['idempotent-replayed']).toBe('true');
    expect(b.body.data.id).toBe(a.body.data.id);
    expect(await prisma.run.count()).toBe(1);
    expect(await prisma.session.count()).toBe(1);
    await waitTerminal(a.body.data.id as string);
  });

  it('the same key with another body is LSE-VAL-004; no key creates a new run each time', async () => {
    const w = await world();
    const a = await w.owner.agent
      .post('/api/v1/runs')
      .set('x-csrf-token', w.owner.csrf)
      .set('Idempotency-Key', 'key-2')
      .send({ projectId: w.projectId, prompt: 'First' });
    expect(a.status).toBe(201);
    const b = await w.owner.agent
      .post('/api/v1/runs')
      .set('x-csrf-token', w.owner.csrf)
      .set('Idempotency-Key', 'key-2')
      .send({ projectId: w.projectId, prompt: 'Second' });
    expectError(b, 'LSE-VAL-004', 409);
    expect(await prisma.run.count()).toBe(1);
    await waitTerminal(a.body.data.id as string);
    const c = await w.owner.post('/api/v1/runs', { projectId: w.projectId, prompt: 'First' });
    const d = await w.owner.post('/api/v1/runs', { projectId: w.projectId, prompt: 'First' });
    expect(c.body.data.id).not.toBe(d.body.data.id);
    await waitTerminal(c.body.data.id as string);
    await waitTerminal(d.body.data.id as string);
  });
});

// ---- cancel -------------------------------------------------------------------------------------------

describe('POST /runs/:id/cancel', () => {
  it('interrupts the turn, pauses the session and cancels the run exactly once', async () => {
    const w = await world();
    const gate = gatedScript();
    const api = new Api(await mintToken(w.owner, w.orgId, RW));
    const res = await api.post('/api/v1/runs', {
      projectId: w.projectId,
      prompt: 'Slow task',
      options: { createPr: true },
    });
    const id = res.body.data.id as string;
    await waitStatus(id, 'RUNNING');

    const cancelled = await api.post(`/api/v1/runs/${id}/cancel`);
    expect(cancelled.status, JSON.stringify(cancelled.body)).toBe(200);
    expect(cancelled.body.data).toMatchObject({ id, status: 'CANCELLED' });
    expect(cancelled.body.data.endedAt).not.toBeNull();
    await waitFor(async () => (await sessionRow((await dbRun(id)).sessionId!)).status === 'PAUSED');

    // A second cancel (or a late turn) cannot resurrect or re-finish it.
    expectError(await api.post(`/api/v1/runs/${id}/cancel`), 'LSE-CONF-001', 409);
    gate.release();
    await ctx.agent.idle();
    await runDriverIdle(ctx, id);
    expect((await dbRun(id)).status).toBe('CANCELLED');
    expect(prRequests).toHaveLength(0);
    expect(runCompleted()).toHaveLength(1);
    expect(runCompleted()[0]!.data.status).toBe('CANCELLED');
    expect(await prisma.auditLog.count({ where: { action: 'run.cancel', target: id } })).toBe(1);
  });

  it('an admin can cancel a member’s run; finished runs → LSE-CONF-001', async () => {
    const w = await world();
    gatedScript();
    const res = await w.owner.post('/api/v1/runs', { projectId: w.projectId, prompt: 'Slow' });
    const id = res.body.data.id as string;
    await waitStatus(id, 'RUNNING');
    const out = await w.admin.post(`/api/v1/runs/${id}/cancel`);
    expect(out.status, JSON.stringify(out.body)).toBe(200);
    expect(out.body.data.status).toBe('CANCELLED');
    expectError(await w.owner.post(`/api/v1/runs/${id}/cancel`), 'LSE-CONF-001', 409);

    editScript();
    const done = await w.owner.post('/api/v1/runs', { projectId: w.projectId, prompt: 'Quick' });
    await waitTerminal(done.body.data.id as string);
    expectError(
      await w.owner.post(`/api/v1/runs/${done.body.data.id as string}/cancel`),
      'LSE-CONF-001',
    );
  });

  it('cancelling while the sandbox is still provisioning stops the session once it is up', async () => {
    const w = await world();
    const caller = {
      user: await prisma.user.findUniqueOrThrow({ where: { id: w.owner.user.id } }),
    };
    const dto = await createRun(ctx, caller, {
      projectId: w.projectId,
      prompt: 'Race',
      options: { createPr: false, draft: false },
      source: 'API',
    });
    await cancelRun(ctx, caller, dto.id);
    expect((await dbRun(dto.id)).status).toBe('CANCELLED');
    await ctx.jobs.onIdle();
    await ctx.agent.idle();
    await waitFor(async () => {
      const s = await sessionRow(dto.sessionId!);
      return ['PAUSED', 'COMPLETED', 'ERRORED'].includes(s.status);
    });
    // The prompt was never sent.
    expect(
      await prisma.chatMessage.count({ where: { sessionId: dto.sessionId!, role: 'USER' } }),
    ).toBe(0);
  });
});

// ---- SSE ---------------------------------------------------------------------------------------------------

describe('GET /runs/:id/events (SSE)', () => {
  it('streams status + session events live, ends with the final run', async () => {
    const w = await world();
    const gate = gatedScript();
    const token = await mintToken(w.owner, w.orgId, RW);
    const api = new Api(token);
    const res = await api.post('/api/v1/runs', {
      projectId: w.projectId,
      prompt: 'Stream me',
      options: { createPr: true },
    });
    const id = res.body.data.id as string;
    await waitStatus(id, 'RUNNING');

    let connected = false;
    const streaming = readSse(
      `/api/v1/runs/${id}/events`,
      { Authorization: `Bearer ${token}` },
      {
        onEvent: () => {
          connected = true;
        },
      },
    );
    await waitFor(() => connected, { label: 'sse connected' });
    gate.release();
    const out = await streaming;
    expect(out.status).toBe(200);

    const st = statuses(out.events);
    expect(st[0]).toBe('RUNNING');
    expect(st).toContain('CREATING_PR');
    expect(st.at(-1)).toBe('SUCCEEDED');
    expect(out.events.at(-1)!.event).toBe('end');
    expect(out.events.at(-1)!.id).toBeNull();
    expect(out.events.at(-1)!.data).toMatchObject({ id, status: 'SUCCEEDED', prNumber: 42 });
    expect(out.events.filter((e) => e.event === 'end')).toHaveLength(1);

    const evs = out.events.filter((e) => e.event === 'event');
    expect(evs.length).toBeGreaterThan(2);
    const seqs = evs.map((e) => Number(e.id));
    expect(seqs).toEqual([...seqs].sort((a, b) => a - b));
    expect(new Set(seqs).size).toBe(seqs.length);
    for (const e of evs) expect((e.data as { seq: number }).seq).toBe(Number(e.id));
    const types = evs.map((e) => (e.data as { type: string }).type);
    expect(types).toContain('chat_message');
    expect(types).toContain('session_ended');
  });

  it('replays retained events after Last-Event-ID, then status and end', async () => {
    const w = await world();
    const token = await mintToken(w.owner, w.orgId, RW);
    const res = await w.owner.post('/api/v1/runs', { projectId: w.projectId, prompt: 'Replay me' });
    const id = res.body.data.id as string;
    await waitTerminal(id);
    const headers = { Authorization: `Bearer ${token}` };

    const full = await readSse(`/api/v1/runs/${id}/events`, headers);
    const all = full.events.filter((e) => e.event === 'event');
    expect(all.length).toBeGreaterThan(3);
    expect(full.events.at(-1)!.event).toBe('end');
    expect(statuses(full.events).at(-1)).toBe('SUCCEEDED');

    const cut = Number(all[2]!.id);
    const partial = await readSse(`/api/v1/runs/${id}/events`, {
      ...headers,
      'Last-Event-ID': String(cut),
    });
    const rest = partial.events.filter((e) => e.event === 'event');
    expect(rest.map((e) => e.id)).toEqual(all.filter((e) => Number(e.id) > cut).map((e) => e.id));
    expect(rest.length).toBeLessThan(all.length);
    expect(partial.events.at(-1)!.event).toBe('end');

    // Past the last event: nothing to replay, but the current state and the end still arrive.
    const none = await readSse(`/api/v1/runs/${id}/events`, {
      ...headers,
      'Last-Event-ID': String(Number(all.at(-1)!.id) + 100),
    });
    expect(none.events.map((e) => e.event)).toEqual(['status', 'end']);
  });

  it('is authorised before streaming (JSON errors, not an event stream)', async () => {
    const w = await world();
    const reader = new Api(await mintToken(w.owner, w.orgId, ['runs:read']));
    const created = await w.owner.post('/api/v1/runs', { projectId: w.projectId, prompt: 'x' });
    const id = created.body.data.id as string;
    await waitTerminal(id);
    const stranger = await login(app, undefined, 'Sam Stranger');
    const r = await stranger.get(`/api/v1/runs/${id}/events`);
    expectError(r, 'LSE-NF-001', 404);
    expect(r.headers['content-type']).toMatch(/json/);
    expectError(await reader.get('/api/v1/runs/cmissing/events'), 'LSE-NF-001', 404);
    expectError(await request(app).get(`/api/v1/runs/${id}/events`), 'LSE-AUTH-001', 401);
  });

  it('stops cleanly when the client disconnects mid-run', async () => {
    const w = await world();
    const gate = gatedScript();
    const token = await mintToken(w.owner, w.orgId, RW);
    const res = await w.owner.post('/api/v1/runs', { projectId: w.projectId, prompt: 'Hold' });
    const id = res.body.data.id as string;
    await waitStatus(id, 'RUNNING');
    const out = await readSse(
      `/api/v1/runs/${id}/events`,
      { Authorization: `Bearer ${token}` },
      {
        stopAfter: (events) => events.some((e) => e.event === 'status'),
      },
    );
    expect(statuses(out.events)).toEqual(['RUNNING']);
    gate.release();
    const done = await waitTerminal(id);
    expect(done.status).toBe('SUCCEEDED');
  });

  it('subscribeRun delivers status transitions, session events and end', async () => {
    const w = await world();
    gatedScript();
    const caller = {
      user: await prisma.user.findUniqueOrThrow({ where: { id: w.owner.user.id } }),
    };
    const seen: RunStreamEvent[] = [];
    const dto = await createRun(ctx, caller, {
      projectId: w.projectId,
      prompt: 'Watch',
      options: { createPr: false, draft: false },
      source: 'API',
    });
    const off = subscribeRun(ctx, dto.id, (e) => seen.push(e));
    await waitStatus(dto.id, 'RUNNING');
    await cancelRun(ctx, caller, dto.id);
    await waitFor(() => seen.some((e) => e.kind === 'end'));
    off();
    expect(seen.some((e) => e.kind === 'event')).toBe(true);
    const end = seen.find((e) => e.kind === 'end');
    expect(end && end.kind === 'end' && end.run.status).toBe('CANCELLED');
    expect(
      seen.filter((e) => e.kind === 'status').map((e) => (e.kind === 'status' ? e.run.status : '')),
    ).toContain('CANCELLED');
  });
});

// ---- reconcile & session-driven endings -----------------------------------------------------------------------

describe('reconcile and session endings', () => {
  async function runWithSession(
    w: World,
    sessionStatus: 'PAUSED' | 'COMPLETED' | 'ERRORED' | 'TIMED_OUT',
    extra: Record<string, unknown> = {},
  ) {
    const s = await prisma.session.create({
      data: {
        projectId: w.projectId,
        userId: w.owner.user.id,
        mode: 'PRO',
        model: 'claude-sonnet-4-5',
        branchName: `loose/session-x${Math.random().toString(36).slice(2)}`,
        status: sessionStatus,
        ...extra,
      },
    });
    const run = await prisma.run.create({
      data: {
        orgId: w.orgId,
        projectId: w.projectId,
        userId: w.owner.user.id,
        sessionId: s.id,
        status: 'RUNNING',
        prompt: 'x',
        options: { createPr: false, draft: false },
      },
    });
    return run.id;
  }

  it('a worker settles runs whose session ended (no hosting)', async () => {
    const w = await world();
    const cases = {
      errored: await runWithSession(w, 'ERRORED', { errorCode: 'LSE-SBX-005' }),
      timedOut: await runWithSession(w, 'TIMED_OUT'),
      budget: await runWithSession(w, 'PAUSED', { errorCode: 'LSE-AGT-003' }),
      stopped: await runWithSession(w, 'PAUSED'),
      delivered: await runWithSession(w, 'COMPLETED', {
        outcome: 'PR_CREATED',
        prUrl: 'https://github.com/acme/web/pull/9',
        prNumber: 9,
      }),
      discarded: await runWithSession(w, 'COMPLETED', { outcome: 'DISCARDED' }),
    };
    await reconcileRuns(ctx, 'worker');
    const out = Object.fromEntries(
      await Promise.all(
        Object.entries(cases).map(async ([k, id]) => [k, await dbRun(id)] as const),
      ),
    );
    expect(out.errored).toMatchObject({ status: 'FAILED', errorCode: 'LSE-SBX-005' });
    expect(out.timedOut).toMatchObject({ status: 'FAILED', errorCode: 'LSE-SBX-009' });
    expect(out.budget).toMatchObject({ status: 'FAILED', errorCode: 'LSE-AGT-003' });
    expect(out.stopped).toMatchObject({ status: 'CANCELLED', errorCode: null });
    expect(out.delivered).toMatchObject({
      status: 'SUCCEEDED',
      prUrl: 'https://github.com/acme/web/pull/9',
      prNumber: 9,
    });
    expect(out.discarded?.status).toBe('CANCELLED');
    expect(runCompleted()).toHaveLength(6);
    // Idempotent: nothing left to settle.
    expect(await reconcileRuns(ctx, 'worker')).toEqual({ attached: 0, failedStale: 0 });
  });

  it('an API boot re-attaches a run whose session is already running and drives it', async () => {
    const w = await world();
    const start = await w.owner.post('/api/v1/sessions', { projectId: w.projectId });
    const s = await settle(ctx, start.body.data.id as string);
    expect(s.status).toBe('RUNNING');
    await waitFor(() => ctx.agent.hasRuntime(s.id));
    const run = await prisma.run.create({
      data: {
        orgId: w.orgId,
        projectId: w.projectId,
        userId: w.owner.user.id,
        sessionId: s.id,
        status: 'PROVISIONING',
        prompt: 'Resume me',
        options: { createPr: true, draft: false },
      },
    });
    const out = await reconcileRuns(ctx, 'api');
    expect(out.attached).toBe(1);
    const done = await waitTerminal(run.id);
    expect(done).toMatchObject({ status: 'SUCCEEDED', prNumber: 42 });
    // A second pass finds nothing in flight.
    expect(await reconcileRuns(ctx, 'api')).toEqual({ attached: 0, failedStale: 0 });
  });

  it('fails runs that outlived the maximum age (LSE-SBX-009)', async () => {
    const w = await world();
    const id = await runWithSession(w, 'PAUSED');
    await prisma.session.update({
      where: { id: (await dbRun(id)).sessionId! },
      data: { status: 'STOPPING' },
    });
    const out = await reconcileRuns(ctx, 'api', new Date(Date.now() + RUN_MAX_AGE_MS + 60_000));
    expect(out.failedStale).toBe(1);
    expect(await dbRun(id)).toMatchObject({ status: 'FAILED', errorCode: 'LSE-SBX-009' });
  });

  it('a run that lost its driver mid-PR is failed after the PR step goes stale', async () => {
    const w = await world();
    const id = await runWithSession(w, 'PAUSED');
    await prisma.session.update({
      where: { id: (await dbRun(id)).sessionId! },
      data: { status: 'STOPPING' },
    });
    await prisma.run.update({ where: { id }, data: { status: 'CREATING_PR' } });
    // Fresh: left alone. Stale: failed.
    expect(await reconcileRuns(ctx, 'worker')).toEqual({ attached: 0, failedStale: 0 });
    expect((await dbRun(id)).status).toBe('CREATING_PR');
    const out = await reconcileRuns(ctx, 'worker', new Date(Date.now() + RUN_PR_STALE_MS + 1_000));
    expect(out.failedStale).toBe(1);
    expect(await dbRun(id)).toMatchObject({ status: 'FAILED', errorCode: 'LSE-SYS-001' });
  });

  it('the job handler is registered and listRuns/getRun enforce scopes at the service level', async () => {
    const w = await world();
    const user = await prisma.user.findUniqueOrThrow({ where: { id: w.owner.user.id } });
    const token = await prisma.apiToken.create({
      data: {
        userId: user.id,
        orgId: w.orgId,
        name: 't',
        hash: `h${Math.random()}`,
        scopes: ['sessions:read'],
      },
    });
    await expect(getRun(ctx, { user, apiToken: token }, 'cx')).rejects.toMatchObject({
      code: 'LSE-ORG-002',
    });
    await expect(
      listRuns(ctx, { user, apiToken: token }, { limit: 10 } as never),
    ).rejects.toMatchObject({ code: 'LSE-ORG-002' });
    await expect(
      createRun(
        ctx,
        { user, apiToken: token },
        {
          projectId: w.projectId,
          prompt: 'x',
          options: { createPr: false, draft: false },
          source: 'API',
        },
      ),
    ).rejects.toMatchObject({ code: 'LSE-ORG-002' });
    await expect(ctx.jobs.enqueue('runs-reconcile', {})).resolves.toBeUndefined();
    await ctx.jobs.onIdle();
  });
});
