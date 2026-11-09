import { http, HttpResponse, type RequestHandler } from 'msw';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import {
  busEvents,
  FakeGit,
  installFakeRunner,
  mswFetch,
  playTurn,
  waitFor,
  type FakeRunner,
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
const { app, ctx } = makeApp({ context: { fetch: mswFetch(handlers) } });
const fake = fakeSandbox(ctx);
const script: { current: RunnerScript } = { current: () => undefined };
let runners: FakeRunner[] = [];
let git: FakeGit;

afterAll(async () => {
  await ctx.agent.idle();
  await ctx.jobs.onIdle();
  await prisma.$disconnect();
});

beforeEach(async () => {
  await ctx.agent.shutdownAll();
  await ctx.jobs.onIdle();
  fake.reset();
  handlers.current = [];
  runners = installFakeRunner(fake, script);
  git = new FakeGit().install(fake);
  await resetDb();
});

interface World {
  owner: Client;
  admin: Client;
  orgId: string;
  sessionId: string;
}

async function world(opts: { ownerRole?: 'MEMBER' | 'ADMIN' } = {}): Promise<World> {
  const admin = await login(app, undefined, 'Ada Admin');
  const org = await createOrg(admin);
  const owner = await login(app, undefined, 'Mo Member');
  await addMember(org.id, owner.user.id, opts.ownerRole ?? 'MEMBER');
  await linkGithub(ctx, owner.user.id);
  await addApiKey(ctx, owner.user.id);
  const project = await createReadyProject(ctx, org.id, {});
  const res = await owner.post('/api/v1/sessions', { projectId: project.id, mode: 'PRO' });
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  const s = await settle(ctx, res.body.data.id as string);
  expect(s.status).toBe('RUNNING');
  await waitFor(() => runners.at(-1) !== undefined, { label: 'runner start' });
  await waitFor(() => ctx.agent.hasRuntime(s.id), { label: 'agent runtime' });
  return { owner, admin, orgId: org.id, sessionId: s.id };
}

async function send(c: Client, sessionId: string, content: string) {
  const res = await c.post(`/api/v1/sessions/${sessionId}/messages`, { content });
  expect(res.status, JSON.stringify(res.body)).toBe(202);
  return res;
}

async function turnDone(sessionId: string, n = 1) {
  await waitFor(
    async () =>
      (await prisma.chatMessage.count({
        where: { sessionId, role: 'ASSISTANT', rawContent: { path: ['pending'], equals: false } },
      })) >= n,
    { label: `turn ${n} complete` },
  );
}

/** Runner-emitted `error` events are the generic path for every `BLOCKING_RUNNER_ERRORS` code
 * (orchestrator.service.ts) — the same mechanism the existing LSE-KEY-002/003 tests use. */
async function runnerError(w: World, code: string, detail: string) {
  script.current = (cmd, r) => {
    if (cmd.type === 'user_message') {
      r.emit('error', { code, detail });
      r.emit('turn_complete', { filesChanged: [], stopReason: 'error' });
    }
  };
  await send(w.owner, w.sessionId, 'go');
  await turnDone(w.sessionId);
  const evs = await busEvents(ctx, w.sessionId);
  const err = evs.find((e) => e.message.type === 'error');
  expect(err, `no error event for ${code}`).toBeDefined();
  return (err!.message.payload as { error: { code: string } }).error.code;
}

describe('LSE-AGT-002: step limit reached (runner stopReason max_turns)', () => {
  it('turn_complete with stopReason "max_turns" tags the assistant message with LSE-AGT-002', async () => {
    const w = await world();
    script.current = (cmd, r) => {
      if (cmd.type === 'user_message') playTurn(r, { text: 'working...', stopReason: 'max_turns' });
    };
    await send(w.owner, w.sessionId, 'do a lot of things');
    await turnDone(w.sessionId);
    const msg = await prisma.chatMessage.findFirstOrThrow({
      where: { sessionId: w.sessionId, role: 'ASSISTANT' },
    });
    expect((msg.metadata as { errorCode?: string }).errorCode).toBe('LSE-AGT-002');
    const dto = (await w.owner.get(`/api/v1/sessions/${w.sessionId}/messages`)).body.data;
    const assistantDto = (dto as { role: string; metadata?: { errorCode?: string } }[]).find(
      (m) => m.role === 'ASSISTANT',
    );
    expect(assistantDto?.metadata?.errorCode).toBe('LSE-AGT-002');
  });
});

describe('LSE-AGT-008: runner reports it could not get the change working', () => {
  it('runner error event with LSE-AGT-008 blocks the turn and is reported verbatim', async () => {
    const w = await world();
    const code = await runnerError(w, 'LSE-AGT-008', 'exhausted retries fixing the build');
    expect(code).toBe('LSE-AGT-008');
  });
});

describe('LSE-AGT-012: plan cancelled returns the session to idle', () => {
  it('denying a proposed plan reports LSE-AGT-012 in the system message metadata', async () => {
    const w = await world();
    script.current = (cmd, r) => {
      if (cmd.type === 'user_message' && cmd.data.permissionMode === 'plan') {
        playTurn(r, { text: 'Here is my plan.', plan: '## Plan\n1. Do the thing' });
      }
    };
    const res = await w.owner.post(`/api/v1/sessions/${w.sessionId}/messages`, {
      content: 'Plan it',
      plan: true,
    });
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    await turnDone(w.sessionId);
    const approval = await prisma.toolApproval.findFirstOrThrow({
      where: { sessionId: w.sessionId, status: 'PENDING' },
    });
    const decideRes = await w.owner.post(
      `/api/v1/sessions/${w.sessionId}/approvals/${approval.id}`,
      { decision: 'deny' },
    );
    expect(decideRes.status, JSON.stringify(decideRes.body)).toBe(200);
    await ctx.agent.idle(w.sessionId);
    const sys = await prisma.chatMessage.findFirstOrThrow({
      where: { sessionId: w.sessionId, role: 'SYSTEM' },
    });
    expect((sys.metadata as { errorCode?: string } | null)?.errorCode).toBe('LSE-AGT-012');
  });
});

describe('LSE-KEY-007: conversation too long', () => {
  it('runner error event with LSE-KEY-007 blocks the turn', async () => {
    const w = await world();
    const code = await runnerError(w, 'LSE-KEY-007', 'context window exceeded');
    expect(code).toBe('LSE-KEY-007');
  });
});

describe('LSE-KEY-008: request declined by the model', () => {
  it('runner error event with LSE-KEY-008 blocks the turn', async () => {
    const w = await world();
    const code = await runnerError(w, 'LSE-KEY-008', 'the model declined to continue');
    expect(code).toBe('LSE-KEY-008');
  });
});

/**
 * LSE-SBX-010 (workspace lost) already has a real trigger-path test in `sessionJobs.test.ts`
 * ("RUNNING sessions whose sandbox vanished → ERRORED LSE-SBX-010") via `orphanReconciliation` +
 * `sandbox.lost = true` — not duplicated here.
 */

describe('LSE-GH-004: no free branch name after retries', () => {
  it('every candidate branch name already exists remotely → session ERRORED LSE-GH-004', async () => {
    const admin = await login(app, undefined, 'Ada Admin');
    const org = await createOrg(admin);
    const owner = await login(app, undefined, 'Mo Member');
    await addMember(org.id, owner.user.id, 'MEMBER');
    await linkGithub(ctx, owner.user.id);
    await addApiKey(ctx, owner.user.id);
    const project = await createReadyProject(ctx, org.id, {});
    // Every candidate name (base + "-2".."-5") already exists on the remote → exhausts
    // maxAttempts (5) and throws LSE-GH-004 instead of ever reaching `git checkout -b`.
    fake.onCommand(/^git ls-remote/, () => ({ exitCode: 0 }));
    const created = await owner.post('/api/v1/sessions', { projectId: project.id, mode: 'PRO' });
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    const s = await settle(ctx, created.body.data.id as string);
    expect(s).toMatchObject({ status: 'ERRORED', errorCode: 'LSE-GH-004' });
  });
});

describe('LSE-GH-006: merge conflict on commit-to-main', () => {
  it('a 409 from the GitHub merge API surfaces LSE-GH-006 and keeps the PR open', async () => {
    const w = await world({ ownerRole: 'ADMIN' });
    await prisma.organization.update({
      where: { id: w.orgId },
      data: { policy: { commitToMainEnabled: true } },
    });
    git.set('src/components/Header.tsx', ' M', ['<h1>Howdy</h1>']);
    script.current = (cmd, r) => {
      if (cmd.type === 'user_message')
        playTurn(r, { text: 'done', files: ['src/components/Header.tsx'] });
    };
    await send(w.owner, w.sessionId, 'Change it');
    await turnDone(w.sessionId);
    const repo = `${GITHUB_API}/repos/acme/web`;
    handlers.current = [
      http.get(`${repo}/pulls`, () => HttpResponse.json([])),
      http.post(`${repo}/pulls`, () =>
        HttpResponse.json(
          { number: 42, html_url: 'https://github.com/acme/web/pull/42' },
          { status: 201 },
        ),
      ),
      http.put(`${repo}/pulls/42/merge`, () =>
        HttpResponse.json({ message: 'Merge conflict' }, { status: 409 }),
      ),
    ];
    const res = await w.owner.post(`/api/v1/sessions/${w.sessionId}/commit-to-main`, {});
    expectError(res, 'LSE-GH-006', 409);
    const s = await prisma.session.findUniqueOrThrow({ where: { id: w.sessionId } });
    expect(s.status).toBe('RUNNING');
  });
});

/**
 * LSE-MCP-003 (connection test timeout) and LSE-EXT-004 (skill import unreachable) live in
 * `phase10.codes.extensions.test.ts` — a separate file with its own `makeApp`/MSW fetch wiring
 * and no agent-runtime fixtures, which avoids the cross-test interference the shared agent
 * runtime causes with the `AbortSignal.timeout` used by the MCP connection-test code path
 * (confirmed in this session: the MCP-003 timeout test is reliable in isolation and in files
 * without agent-runtime teardown, but intermittently fails to fire within 30s when run after
 * `ctx.agent.shutdownAll()`-heavy tests in the same file).
 */
