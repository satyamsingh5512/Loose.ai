/**
 * Phase 9 — session fork & resume (spec §8.14, §10.5).
 *
 * Fork sources (checkpoint, live working tree, saved WIP ref, pushed branch), the fork's own
 * preflight (key, budget, concurrency), the copied transcript and lineage, LSE-SBX-015 when
 * there is nothing to copy from, and resuming a paused / PR-created session.
 */
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { wipRefName } from '@loose/shared';
import { stopSession } from '../src/services/sessionLifecycle.service';
import { FakeGit, installFakeRunner, playTurn, waitFor, type RunnerScript } from './agentHelpers';
import {
  addMember,
  createOrg,
  expectError,
  linkGithub,
  login,
  makeApp,
  resetDb,
  testPrisma,
  type Client,
} from './helpers';
import { addApiKey, createReadyProject, fakeSandbox, settle } from './sessionHelpers';

const prisma = testPrisma();
const { app, ctx } = makeApp();
const fake = fakeSandbox(ctx);
const script: { current: RunnerScript } = { current: () => undefined };
let git: FakeGit;

afterAll(async () => {
  await ctx.agent.shutdownAll();
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
    if (cmd.type === 'user_message') playTurn(r, { text: 'Done.', files: ['src/a.ts'] });
  };
  await resetDb();
  ctx.platformEvents.clearHistory();
});

interface World {
  admin: Client;
  owner: Client;
  mate: Client;
  orgId: string;
  projectId: string;
}

async function world(): Promise<World> {
  const admin = await login(app, undefined, 'Ada Admin');
  const org = await createOrg(admin);
  await linkGithub(ctx, admin.user.id);
  await addApiKey(ctx, admin.user.id);
  const owner = await login(app, undefined, 'Olive Owner');
  await addMember(org.id, owner.user.id, 'MEMBER');
  await linkGithub(ctx, owner.user.id);
  await addApiKey(ctx, owner.user.id);
  const mate = await login(app, undefined, 'Milo Mate');
  await addMember(org.id, mate.user.id, 'MEMBER');
  await linkGithub(ctx, mate.user.id);
  await addApiKey(ctx, mate.user.id);
  const project = await createReadyProject(ctx, org.id);
  await prisma.organization.update({
    where: { id: org.id },
    data: { policy: { maxConcurrentSessionsPerUser: 10, maxConcurrentSessionsPerOrg: 50 } },
  });
  return { admin, owner, mate, orgId: org.id, projectId: project.id };
}

async function startRunning(w: World, client: Client = w.owner): Promise<string> {
  const res = await client.post('/api/v1/sessions', { projectId: w.projectId });
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  const s = await settle(ctx, res.body.data.id as string);
  expect(s.status).toBe('RUNNING');
  await waitFor(() => ctx.agent.hasRuntime(s.id));
  return s.id;
}

/** Run one turn so the session has a checkpoint and a transcript. */
async function turn(client: Client, sessionId: string, content = 'Change the header') {
  git.set('src/a.ts', ' M', ['<h1>Howdy</h1>']);
  const before = await prisma.chatMessage.count({ where: { sessionId } });
  const r = await client.post(`/api/v1/sessions/${sessionId}/messages`, { content });
  expect(r.status, JSON.stringify(r.body)).toBe(202);
  await waitFor(
    async () => (await prisma.chatMessage.count({ where: { sessionId } })) > before + 1,
  );
  await ctx.agent.idle(sessionId);
}

/** Every command run in any sandbox of this test (the fork pushes in the PARENT's sandbox). */
const allCommands = () => [...fake.sandboxes.values()].flatMap((s) => s.commandLines() as string[]);

// ---- fork ------------------------------------------------------------------------------------

describe('POST /sessions/:id/fork', () => {
  it('forks the live working tree: new session, lineage, copied transcript and notes', async () => {
    const w = await world();
    const parent = await startRunning(w);
    await turn(w.owner, parent);
    await w.owner.put(`/api/v1/sessions/${parent}/notes`, { notes: 'Keep British spelling' });

    const res = await w.owner.post(`/api/v1/sessions/${parent}/fork`, {});
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    const dto = res.body.data as Record<string, unknown>;
    expect(dto.id).not.toBe(parent);
    expect(dto.parentSessionId).toBe(parent);
    expect(dto.forkedFromCheckpointId).toBeNull();
    expect(dto.status).toBe('QUEUED');

    const forkId = dto.id as string;
    const row = await prisma.session.findUniqueOrThrow({ where: { id: forkId } });
    expect(row.wipRef).toMatch(/^refs\/loose\/wip\/fork-/);
    expect(row.notes).toBe('Keep British spelling');
    expect(row.branchName).toBe(`loose/session-${forkId}`);

    // The parent's visible transcript was copied, tagged with where it came from.
    const copied = await prisma.chatMessage.findMany({
      where: { sessionId: forkId },
      orderBy: { createdAt: 'asc' },
    });
    const original = await prisma.chatMessage.findMany({
      where: { sessionId: parent },
      orderBy: { createdAt: 'asc' },
    });
    expect(copied.map((m) => [m.role, m.content])).toEqual(
      original.map((m) => [m.role, m.content]),
    );
    expect((copied[0]!.metadata as { forkedFrom?: unknown }).forkedFrom).toEqual({
      sessionId: parent,
      checkpointId: null,
    });
    expect(copied[0]!.clientMessageId).toBeNull();

    // The fork provisions on its own and restores the snapshot that was pushed for it.
    const s = await settle(ctx, forkId);
    expect(s.status).toBe('RUNNING');
    expect(allCommands().some((c) => c.includes(`+${row.wipRef!}:refs/loose/wip`))).toBe(true);

    expect(
      await prisma.auditLog.findFirst({ where: { action: 'session.fork', target: forkId } }),
    ).toMatchObject({ actorId: w.owner.user.id });
  });

  it('forks at a checkpoint: pushes that snapshot and copies only the earlier messages', async () => {
    const w = await world();
    const parent = await startRunning(w);
    await turn(w.owner, parent, 'First change');
    await turn(w.owner, parent, 'Second change');
    const checkpoints = await prisma.checkpoint.findMany({
      where: { sessionId: parent },
      orderBy: { turn: 'asc' },
    });
    expect(checkpoints).toHaveLength(2);
    const second = checkpoints[1]!;
    expect(second.hasCode).toBe(true);

    const res = await w.owner.post(`/api/v1/sessions/${parent}/fork`, {
      checkpointId: second.id,
      mode: 'PRO',
    });
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    const forkId = res.body.data.id as string;
    expect(res.body.data.forkedFromCheckpointId).toBe(second.id);
    expect(res.body.data.mode).toBe('PRO');

    const row = await prisma.session.findUniqueOrThrow({ where: { id: forkId } });
    // The checkpoint ref was published from the PARENT's sandbox to the fork's snapshot ref.
    expect(
      allCommands().some(
        (c) => c.includes(second.gitRef) && c.includes(`:${row.wipRef!}`) && c.includes('push'),
      ),
    ).toBe(true);

    // Only the first turn is copied: the checkpoint's own USER message and later are not.
    const copied = await prisma.chatMessage.findMany({
      where: { sessionId: forkId },
      orderBy: { createdAt: 'asc' },
    });
    expect(copied.map((m) => m.role)).toEqual(['USER', 'ASSISTANT']);
    expect(copied[0]!.content).toBe('First change');
    expect(copied.map((m) => m.content)).not.toContain('Second change');
    expect(
      (copied[0]!.metadata as { forkedFrom?: { checkpointId?: string } }).forkedFrom,
    ).toMatchObject({ checkpointId: second.id });
  });

  it('a co-worker can fork a session shared with them, on their own key and budget', async () => {
    const w = await world();
    const parent = await startRunning(w);
    await turn(w.owner, parent);
    const share = await w.owner.post(`/api/v1/sessions/${parent}/share`, {
      userId: w.mate.user.id,
      role: 'CO_EDITOR',
    });
    expect(share.status, JSON.stringify(share.body)).toBe(201);

    const res = await w.mate.post(`/api/v1/sessions/${parent}/fork`, {});
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    const row = await prisma.session.findUniqueOrThrow({
      where: { id: res.body.data.id as string },
    });
    expect(row.userId).toBe(w.mate.user.id);
    expect(row.parentSessionId).toBe(parent);
  });

  it('a VIEWER collaborator cannot fork (LSE-ORG-002)', async () => {
    const w = await world();
    const parent = await startRunning(w);
    await w.owner.post(`/api/v1/sessions/${parent}/share`, {
      userId: w.mate.user.id,
      role: 'VIEWER',
    });
    expectError(await w.mate.post(`/api/v1/sessions/${parent}/fork`, {}), 'LSE-ORG-002', 403);
  });

  it('a non-participant gets LSE-ORG-002 and someone outside the org LSE-NF-001', async () => {
    const w = await world();
    const parent = await startRunning(w);
    expectError(await w.mate.post(`/api/v1/sessions/${parent}/fork`, {}), 'LSE-ORG-002', 403);
    const outsider = await login(app);
    expectError(await outsider.post(`/api/v1/sessions/${parent}/fork`, {}), 'LSE-NF-001', 404);
  });

  it('LSE-SBX-015 when the fork source is gone', async () => {
    const w = await world();

    // Nothing saved at all: a session that never ran.
    const bare = await prisma.session.create({
      data: {
        id: `cbare${Math.random().toString(36).slice(2, 10)}`,
        projectId: w.projectId,
        userId: w.owner.user.id,
        mode: 'SIMPLE',
        model: 'claude-sonnet-4-5',
        branchName: 'loose/session-bare',
        status: 'ERRORED',
        errorCode: 'LSE-SBX-002',
      },
    });
    const gone = await w.owner.post(`/api/v1/sessions/${bare.id}/fork`, {});
    expectError(gone, 'LSE-SBX-015', 410);
    expect(gone.body.error.title).toBe("Can't copy from there");

    // A checkpoint that was rewound away.
    const parent = await startRunning(w);
    await turn(w.owner, parent);
    const cp = await prisma.checkpoint.findFirstOrThrow({ where: { sessionId: parent } });
    await prisma.checkpoint.update({ where: { id: cp.id }, data: { rewoundAt: new Date() } });
    expectError(
      await w.owner.post(`/api/v1/sessions/${parent}/fork`, { checkpointId: cp.id }),
      'LSE-SBX-015',
      410,
    );

    // A checkpoint of a stopped session: its snapshot only lived in the dead sandbox.
    await prisma.checkpoint.update({ where: { id: cp.id }, data: { rewoundAt: null } });
    await prisma.session.update({ where: { id: parent }, data: { status: 'PAUSED' } });
    expectError(
      await w.owner.post(`/api/v1/sessions/${parent}/fork`, { checkpointId: cp.id }),
      'LSE-SBX-015',
      410,
    );

    // A checkpoint whose snapshot failed when it was taken.
    await prisma.session.update({ where: { id: parent }, data: { status: 'RUNNING' } });
    await prisma.checkpoint.update({ where: { id: cp.id }, data: { hasCode: false } });
    expectError(
      await w.owner.post(`/api/v1/sessions/${parent}/fork`, { checkpointId: cp.id }),
      'LSE-SBX-015',
      410,
    );
  });

  it('falls back to the parent WIP ref, then to its pushed branch', async () => {
    const w = await world();
    const paused = await prisma.session.create({
      data: {
        id: `cwip${Math.random().toString(36).slice(2, 10)}`,
        projectId: w.projectId,
        userId: w.owner.user.id,
        mode: 'SIMPLE',
        model: 'claude-sonnet-4-5',
        branchName: 'loose/session-paused',
        status: 'PAUSED',
        wipRef: wipRefName('earlier'),
      },
    });
    const a = await w.owner.post(`/api/v1/sessions/${paused.id}/fork`, {});
    expect(a.status, JSON.stringify(a.body)).toBe(201);
    expect(
      (await prisma.session.findUniqueOrThrow({ where: { id: a.body.data.id as string } })).wipRef,
    ).toBe(wipRefName('earlier'));

    const delivered = await prisma.session.create({
      data: {
        id: `cpr${Math.random().toString(36).slice(2, 10)}`,
        projectId: w.projectId,
        userId: w.owner.user.id,
        mode: 'SIMPLE',
        model: 'claude-sonnet-4-5',
        branchName: 'loose/session-delivered',
        status: 'COMPLETED',
        outcome: 'PR_CREATED',
        prUrl: 'https://github.com/acme/web/pull/7',
        prNumber: 7,
        prState: 'open',
      },
    });
    const b = await w.owner.post(`/api/v1/sessions/${delivered.id}/fork`, {});
    expect(b.status, JSON.stringify(b.body)).toBe(201);
    const forked = await prisma.session.findUniqueOrThrow({
      where: { id: b.body.data.id as string },
    });
    expect(forked.wipRef).toBe('refs/heads/loose/session-delivered');
    // Its own branch is checked out from the parent's branch tip (commits stay commits).
    const s = await settle(ctx, forked.id);
    expect(s.status).toBe('RUNNING');
    const cmds = allCommands();
    expect(
      cmds.some((c) => c.includes('+refs/heads/loose/session-delivered:refs/loose/resume')),
    ).toBe(true);
    expect(cmds.some((c) => c.includes(`checkout -q -B '${forked.branchName}'`))).toBe(true);
  });

  it('the fork goes through the forker preflight (budget)', async () => {
    const w = await world();
    const parent = await startRunning(w);
    await prisma.organization.update({
      where: { id: w.orgId },
      data: { policy: { budgets: { orgMonthlyUsd: 1, userMonthlyUsd: null } } },
    });
    await prisma.usageEvent.create({
      data: {
        sessionId: parent,
        orgId: w.orgId,
        userId: w.owner.user.id,
        model: 'claude-sonnet-4-5',
        tokensIn: 1,
        tokensOut: 1,
        cacheRead: 0,
        costUsd: 5,
      },
    });
    expectError(await w.owner.post(`/api/v1/sessions/${parent}/fork`, {}), 'LSE-KEY-012', 402);
  });

  it('`POST /sessions {forkFrom}` is the same operation', async () => {
    const w = await world();
    const parent = await startRunning(w);
    await turn(w.owner, parent);
    const cp = await prisma.checkpoint.findFirstOrThrow({ where: { sessionId: parent } });
    const res = await w.owner.post('/api/v1/sessions', {
      projectId: w.projectId,
      forkFrom: parent,
      checkpointId: cp.id,
    });
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    expect(res.body.data).toMatchObject({
      parentSessionId: parent,
      forkedFromCheckpointId: cp.id,
    });
  });
});

// ---- resume ----------------------------------------------------------------------------------

describe('POST /sessions/:id/resume', () => {
  it('resumes a paused session from its saved work', async () => {
    const w = await world();
    const id = await startRunning(w);
    await turn(w.owner, id);
    expect(await stopSession(ctx, id, { to: 'PAUSED', reason: 'stopped', pushWip: true })).toBe(
      true,
    );
    const paused = await prisma.session.findUniqueOrThrow({ where: { id } });
    expect(paused.status).toBe('PAUSED');
    expect(paused.wipRef).toBe(wipRefName(id));

    const res = await w.owner.post(`/api/v1/sessions/${id}/resume`);
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(res.body.data.status).toBe('QUEUED');
    const s = await settle(ctx, id);
    expect(s.status).toBe('RUNNING');
    expect(allCommands().some((c) => c.includes(`+${wipRefName(id)}:refs/loose/wip`))).toBe(true);
    expect(
      await prisma.auditLog.findFirst({ where: { action: 'session.resume', target: id } }),
    ).toMatchObject({ actorId: w.owner.user.id });
  });

  it('resumes a COMPLETED session with an open PR from its branch tip', async () => {
    const w = await world();
    const session = await prisma.session.create({
      data: {
        id: `cres${Math.random().toString(36).slice(2, 10)}`,
        projectId: w.projectId,
        userId: w.owner.user.id,
        mode: 'SIMPLE',
        model: 'claude-sonnet-4-5',
        branchName: 'loose/session-open-pr',
        status: 'COMPLETED',
        outcome: 'PR_CREATED',
        prUrl: 'https://github.com/acme/web/pull/9',
        prNumber: 9,
        prState: 'open',
        endedAt: new Date(),
      },
    });
    const res = await w.owner.post(`/api/v1/sessions/${session.id}/resume`);
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(res.body.data.status).toBe('QUEUED');
    const queued = await prisma.session.findUniqueOrThrow({ where: { id: session.id } });
    expect(queued.wipRef).toBe('refs/heads/loose/session-open-pr');
    const s = await settle(ctx, session.id);
    expect(s.status).toBe('RUNNING');
    const cmds = allCommands();
    expect(
      cmds.some((c) => c.includes('+refs/heads/loose/session-open-pr:refs/loose/resume')),
    ).toBe(true);
    expect(cmds.some((c) => c.includes("checkout -q -B 'loose/session-open-pr'"))).toBe(true);
  });

  it('refuses a running session and a merged one (LSE-CONF-001)', async () => {
    const w = await world();
    const running = await startRunning(w);
    expectError(await w.owner.post(`/api/v1/sessions/${running}/resume`), 'LSE-CONF-001', 409);

    const merged = await prisma.session.create({
      data: {
        id: `cmrg${Math.random().toString(36).slice(2, 10)}`,
        projectId: w.projectId,
        userId: w.owner.user.id,
        mode: 'SIMPLE',
        model: 'claude-sonnet-4-5',
        branchName: 'loose/session-merged',
        status: 'COMPLETED',
        outcome: 'PR_CREATED',
        prUrl: 'https://github.com/acme/web/pull/3',
        prState: 'merged',
      },
    });
    expectError(await w.owner.post(`/api/v1/sessions/${merged.id}/resume`), 'LSE-CONF-001', 409);
  });

  it('a VIEWER collaborator cannot resume; an org admin can', async () => {
    const w = await world();
    const session = await prisma.session.create({
      data: {
        id: `cerr${Math.random().toString(36).slice(2, 10)}`,
        projectId: w.projectId,
        userId: w.owner.user.id,
        mode: 'SIMPLE',
        model: 'claude-sonnet-4-5',
        branchName: 'loose/session-errored',
        status: 'ERRORED',
        errorCode: 'LSE-SBX-002',
        wipRef: wipRefName('errored'),
      },
    });
    await w.owner.post(`/api/v1/sessions/${session.id}/share`, {
      userId: w.mate.user.id,
      role: 'VIEWER',
    });
    expectError(await w.mate.post(`/api/v1/sessions/${session.id}/resume`), 'LSE-ORG-002', 403);
    const asAdmin = await w.admin.post(`/api/v1/sessions/${session.id}/resume`);
    expect(asAdmin.status, JSON.stringify(asAdmin.body)).toBe(202);
  });
});
