/**
 * Phase 7 (agent side): checkpoints before each turn, rewind (code / conversation /
 * both, /undo), plan mode (manual, auto, approve / edit / cancel, supersede), `#` notes.
 * FakeSandboxProvider + scripted fake runner (no real agent).
 */
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { leakCheck } from '../src/services/translation';
import {
  busEvents,
  FakeGit,
  installFakeRunner,
  lastSandbox,
  playTurn,
  waitFor,
  type FakeRunner,
  type RunnerScript,
} from './agentHelpers';
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
let runners: FakeRunner[] = [];
let anchorSeq = 0;

afterAll(async () => {
  await ctx.agent.idle();
  await ctx.jobs.onIdle();
  await prisma.$disconnect();
});

beforeEach(async () => {
  await ctx.agent.shutdownAll();
  await ctx.jobs.onIdle();
  fake.reset();
  runners = installFakeRunner(fake, script);
  new FakeGit().install(fake);
  anchorSeq = 0;
  script.current = (cmd, r) => {
    if (cmd.type === 'user_message') playTurn(r, { anchor: `anchor-${(anchorSeq += 1)}` });
  };
  await resetDb();
});

interface World {
  owner: Client;
  admin: Client;
  orgId: string;
  sessionId: string;
  runner: FakeRunner;
}

async function world(
  opts: { mode?: 'SIMPLE' | 'PRO'; planMode?: string; ownerRole?: 'MEMBER' | 'ADMIN' } = {},
): Promise<World> {
  const admin = await login(app, undefined, 'Ada Admin');
  const org = await createOrg(admin);
  const owner = await login(app, undefined, 'Mo Member');
  await addMember(org.id, owner.user.id, opts.ownerRole ?? 'MEMBER');
  await linkGithub(ctx, owner.user.id);
  await addApiKey(ctx, owner.user.id);
  const project = await createReadyProject(ctx, org.id, {
    componentLabels: { 'src/components/Header*': 'the site header' },
    ...(opts.planMode ? { planMode: opts.planMode } : {}),
  });
  const res = await owner.post('/api/v1/sessions', {
    projectId: project.id,
    mode: opts.mode ?? 'SIMPLE',
  });
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  const s = await settle(ctx, res.body.data.id as string);
  expect(s.status).toBe('RUNNING');
  const runner = await waitFor(() => runners.at(-1), { label: 'runner start' });
  await waitFor(() => ctx.agent.hasRuntime(s.id), { label: 'agent runtime' });
  return { owner, admin, orgId: org.id, sessionId: s.id, runner };
}

const send = (c: Client, sessionId: string, content: string, extra: object = {}) =>
  c.post(`/api/v1/sessions/${sessionId}/messages`, { content, ...extra });

async function turnDone(sessionId: string, n = 1) {
  await waitFor(
    async () =>
      (await prisma.chatMessage.count({
        where: { sessionId, role: 'ASSISTANT', rawContent: { path: ['pending'], equals: false } },
      })) >= n,
    { label: `turn ${n} complete` },
  );
  await ctx.agent.idle(sessionId);
}

const ofType = (entries: Awaited<ReturnType<typeof busEvents>>, type: string, aud?: string) =>
  entries.filter((e) => e.message.type === type && (!aud || e.audience === aud));

describe('checkpoints & rewind', () => {
  it('snapshots before every turn and lists checkpoints', async () => {
    const w = await world();
    expect((await send(w.owner, w.sessionId, 'Make the title red')).status).toBe(202);
    await turnDone(w.sessionId);
    const sbx = lastSandbox(ctx);
    const snap = sbx.commands.find(
      (c) => c.cmd.includes('commit-tree') && c.cmd.includes('checkpoint'),
    );
    expect(snap?.cmd).toMatch(/git update-ref 'refs\/loose\/checkpoints\/c[a-z0-9]+'/);
    expect(snap?.cmd).not.toContain('git push');
    const list = await w.owner.get(`/api/v1/sessions/${w.sessionId}/checkpoints`);
    expect(list.status).toBe(200);
    expect(list.body.data).toHaveLength(1);
    expect(list.body.data[0]).toMatchObject({
      turn: 1,
      label: 'Make the title red',
      hasCode: true,
    });
    const created = ofType(await busEvents(ctx, w.sessionId), 'checkpoint_created');
    expect(created).toHaveLength(1);
    const userMsg = await prisma.chatMessage.findFirstOrThrow({
      where: { sessionId: w.sessionId, role: 'USER' },
    });
    expect(userMsg.checkpointId).toBe(list.body.data[0].id);
    const cp = await prisma.checkpoint.findFirstOrThrow({ where: { sessionId: w.sessionId } });
    expect(cp.conversationAnchor).toBeNull();
  });

  it('rewinds code + conversation: hides later messages, resumes the agent at the anchor', async () => {
    const w = await world();
    await send(w.owner, w.sessionId, 'First change');
    await turnDone(w.sessionId, 1);
    await send(w.owner, w.sessionId, 'Second change');
    await turnDone(w.sessionId, 2);
    const cps = (await w.owner.get(`/api/v1/sessions/${w.sessionId}/checkpoints`)).body.data;
    expect(cps.map((c: { turn: number }) => c.turn)).toEqual([1, 2]);
    const second = await prisma.checkpoint.findUniqueOrThrow({ where: { id: cps[1].id } });
    expect(second).toMatchObject({
      conversationAnchor: 'anchor-1',
      agentSessionId: 'agent-sess-1',
    });

    const res = await w.owner.post(
      `/api/v1/sessions/${w.sessionId}/checkpoints/${cps[1].id}/rewind`,
      { scope: 'both' },
    );
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.data.removedMessageIds).toHaveLength(2);
    expect(res.body.data.removedCheckpointIds).toEqual([cps[1].id]);
    const sbx = lastSandbox(ctx);
    expect(
      sbx.commands.some((c) =>
        c.cmd.includes(`read-tree -u --reset 'refs/loose/checkpoints/${cps[1].id}'`),
      ),
    ).toBe(true);
    expect(w.runner.of('rewind_conversation').at(-1)?.data).toEqual({
      anchor: 'anchor-1',
      agentSessionId: 'agent-sess-1',
    });
    const msgs = (await w.owner.get(`/api/v1/sessions/${w.sessionId}/messages`)).body.data;
    expect(msgs.map((m: { content: string }) => m.content)).not.toContain('Second change');
    expect(msgs.at(-1).role).toBe('SYSTEM');
    expect(msgs.at(-1).content).toContain('Went back to before “Second change”');
    const s = await prisma.session.findUniqueOrThrow({ where: { id: w.sessionId } });
    expect(s.resumeSessionAt).toBe('anchor-1');
    const entries = await busEvents(ctx, w.sessionId);
    expect(ofType(entries, 'rewind_complete')[0]!.message.payload).toMatchObject({ scope: 'both' });
    const audit = await prisma.auditLog.findFirst({ where: { action: 'session.rewind' } });
    expect(audit?.meta).toMatchObject({ scope: 'both', turn: 2 });

    // The next turn is turn 2 again; its completion clears the pending resume point.
    await send(w.owner, w.sessionId, 'Another try');
    await turnDone(w.sessionId, 2);
    const after = (await w.owner.get(`/api/v1/sessions/${w.sessionId}/checkpoints`)).body.data;
    expect(after.map((c: { turn: number }) => c.turn)).toEqual([1, 2]);
    expect(
      (await prisma.session.findUniqueOrThrow({ where: { id: w.sessionId } })).resumeSessionAt,
    ).toBeNull();
  });

  it('code-only rewind keeps the conversation; conversation-only keeps files', async () => {
    const w = await world();
    await send(w.owner, w.sessionId, 'Change A');
    await turnDone(w.sessionId);
    const cp = (await w.owner.get(`/api/v1/sessions/${w.sessionId}/checkpoints`)).body.data[0];
    const code = await w.owner.post(`/api/v1/sessions/${w.sessionId}/checkpoints/${cp.id}/rewind`, {
      scope: 'code',
    });
    expect(code.status).toBe(200);
    expect(code.body.data.removedMessageIds).toEqual([]);
    expect(w.runner.of('rewind_conversation')).toHaveLength(0);
    const before = lastSandbox(ctx).commands.filter((c) =>
      c.cmd.includes('read-tree -u --reset'),
    ).length;
    const conv = await w.owner.post(`/api/v1/sessions/${w.sessionId}/checkpoints/${cp.id}/rewind`, {
      scope: 'conversation',
    });
    expect(conv.status).toBe(200);
    expect(
      lastSandbox(ctx).commands.filter((c) => c.cmd.includes('read-tree -u --reset')),
    ).toHaveLength(before);
    expect(w.runner.of('rewind_conversation').at(-1)?.data).toEqual({ anchor: null });
    expect(
      (await prisma.session.findUniqueOrThrow({ where: { id: w.sessionId } })).agentSessionId,
    ).toBeNull();
  });

  it('refuses while busy, for unknown checkpoints and when the snapshot is gone; /undo works', async () => {
    const w = await world();
    let hold: FakeRunner | undefined;
    script.current = (cmd, r) => {
      if (cmd.type === 'user_message') hold = r;
    };
    await send(w.owner, w.sessionId, 'Slow change');
    await waitFor(() => hold, { label: 'turn start' });
    const cp = (await w.owner.get(`/api/v1/sessions/${w.sessionId}/checkpoints`)).body.data[0];
    expectError(
      await w.owner.post(`/api/v1/sessions/${w.sessionId}/checkpoints/${cp.id}/rewind`, {}),
      'LSE-AGT-011',
      409,
    );
    playTurn(hold!, { anchor: 'anchor-x' });
    await turnDone(w.sessionId);
    expectError(
      await w.owner.post(`/api/v1/sessions/${w.sessionId}/checkpoints/cpnope/rewind`, {}),
      'LSE-NF-001',
      404,
    );
    fake.onCommand('read-tree -u --reset', () => ({ exitCode: 1 }));
    expectError(
      await w.owner.post(`/api/v1/sessions/${w.sessionId}/checkpoints/${cp.id}/rewind`, {
        scope: 'code',
      }),
      'LSE-CONF-001',
      409,
    );
    fake.onCommand('read-tree -u --reset', () => ({ exitCode: 0 }));
    const undo = await w.owner.post(`/api/v1/sessions/${w.sessionId}/commands`, {
      command: 'undo',
    });
    expect(undo.status, JSON.stringify(undo.body)).toBe(200);
    expect(undo.body.data.kind).toBe('action');
    expect((await w.owner.get(`/api/v1/sessions/${w.sessionId}/checkpoints`)).body.data).toEqual(
      [],
    );
    expectError(
      await w.owner.post(`/api/v1/sessions/${w.sessionId}/commands`, { command: 'undo' }),
      'LSE-NF-001',
      404,
    );
  });
});

const PLAN =
  '1. Read `src/components/Header.tsx`\n2. Change the title colour to red\n3. Check the preview';

function planScript() {
  script.current = (cmd, r) => {
    if (cmd.type !== 'user_message') return;
    if (cmd.data.permissionMode === 'plan')
      playTurn(r, { text: 'Here is my plan.', plan: PLAN, anchor: `anchor-${(anchorSeq += 1)}` });
    else playTurn(r, { anchor: `anchor-${(anchorSeq += 1)}` });
  };
}

describe('plan mode', () => {
  it('plan turn → plan approval (Simple-safe), edited approval runs the plan', async () => {
    const w = await world();
    planScript();
    expect((await send(w.owner, w.sessionId, 'Make the title red', { plan: true })).status).toBe(
      202,
    );
    await turnDone(w.sessionId);
    expect(w.runner.of('user_message')[0]!.data.permissionMode).toBe('plan');
    const approval = await prisma.toolApproval.findFirstOrThrow({
      where: { sessionId: w.sessionId },
    });
    expect(approval).toMatchObject({ kind: 'plan', status: 'PENDING', tool: 'plan' });
    const entries = await busEvents(ctx, w.sessionId);
    const simple = ofType(entries, 'plan_proposed', 'simple')[0]!.message.payload as {
      plan: { steps: string[]; markdown?: string };
    };
    const pro = ofType(entries, 'plan_proposed', 'pro')[0]!.message.payload as {
      plan: { steps: string[]; markdown?: string };
    };
    expect(simple.plan.markdown).toBeUndefined();
    for (const step of simple.plan.steps) expect(leakCheck(step), step).toEqual([]);
    expect(pro.plan.markdown).toBe(PLAN);
    const planMsg = await prisma.chatMessage.findFirstOrThrow({
      where: { sessionId: w.sessionId, role: 'ASSISTANT' },
    });
    expect((planMsg.metadata as { kind: string }).kind).toBe('plan');
    expect(leakCheck(planMsg.content)).toEqual([]);
    const simpleMsgs = (await w.owner.get(`/api/v1/sessions/${w.sessionId}/messages`)).body.data;
    expect(simpleMsgs.at(-1).metadata.plan.markdown).toBeUndefined();

    const edited = `${PLAN}\n4. Also update the footer`;
    const res = await w.owner.post(`/api/v1/sessions/${w.sessionId}/approvals/${approval.id}`, {
      decision: 'approve',
      plan: edited,
    });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.data).toMatchObject({ kind: 'plan', status: 'APPROVED' });
    await turnDone(w.sessionId, 2);
    const exec = w.runner.of('user_message')[1]!.data;
    expect(exec.permissionMode).toBeUndefined();
    expect(exec.text).toContain('<approved_plan>');
    expect(exec.text).toContain('Also update the footer');
    const userMsgs = await prisma.chatMessage.findMany({
      where: { sessionId: w.sessionId, role: 'USER' },
      orderBy: { createdAt: 'asc' },
    });
    expect(userMsgs.at(-1)!.content).toBe('Approved the edited plan');
    expect(await prisma.auditLog.count({ where: { action: 'plan.decide' } })).toBe(1);
  });

  it('cancel returns to idle; a new message supersedes a pending plan', async () => {
    const w = await world();
    planScript();
    await send(w.owner, w.sessionId, 'Plan A', { plan: true });
    await turnDone(w.sessionId);
    const a1 = await prisma.toolApproval.findFirstOrThrow({ where: { sessionId: w.sessionId } });
    const res = await w.owner.post(`/api/v1/sessions/${w.sessionId}/approvals/${a1.id}`, {
      decision: 'deny',
    });
    expect(res.status).toBe(200);
    await ctx.agent.idle(w.sessionId);
    expect(w.runner.of('user_message')).toHaveLength(1);
    const sys = await prisma.chatMessage.findFirstOrThrow({
      where: { sessionId: w.sessionId, role: 'SYSTEM' },
    });
    expect(sys.content).toContain('The plan was cancelled');

    await send(w.owner, w.sessionId, 'Plan B', { plan: true });
    await turnDone(w.sessionId, 2);
    const a2 = await prisma.toolApproval.findFirstOrThrow({
      where: { sessionId: w.sessionId, status: 'PENDING' },
    });
    await send(w.owner, w.sessionId, 'Actually just change the text');
    await turnDone(w.sessionId, 3);
    expect((await prisma.toolApproval.findUniqueOrThrow({ where: { id: a2.id } })).status).toBe(
      'DENIED',
    );
    expectError(
      await w.owner.post(`/api/v1/sessions/${w.sessionId}/approvals/${a2.id}`, {
        decision: 'approve',
      }),
      'LSE-CONF-001',
      409,
    );
  });

  it('project plan mode: AUTO uses the heuristic, ALWAYS plans everything, OFF never', async () => {
    const auto = await world({ planMode: 'AUTO' });
    planScript();
    await send(auto.owner, auto.sessionId, 'Change the footer text');
    await turnDone(auto.sessionId);
    expect(auto.runner.of('user_message')[0]!.data.permissionMode).toBeUndefined();
    await send(auto.owner, auto.sessionId, 'Add a login page with password reset');
    await turnDone(auto.sessionId, 2);
    expect(auto.runner.of('user_message')[1]!.data.permissionMode).toBe('plan');
    const userMeta = await prisma.chatMessage.findFirstOrThrow({
      where: { sessionId: auto.sessionId, content: 'Add a login page with password reset' },
    });
    expect(userMeta.metadata).toMatchObject({ planMode: 'auto' });

    await resetDb();
    const always = await world({ planMode: 'ALWAYS' });
    await send(always.owner, always.sessionId, 'Change the footer text');
    await turnDone(always.sessionId);
    expect(always.runner.of('user_message')[0]!.data.permissionMode).toBe('plan');

    await resetDb();
    const off = await world({ planMode: 'OFF' });
    await send(off.owner, off.sessionId, 'Add a login page');
    await turnDone(off.sessionId);
    expect(off.runner.of('user_message')[0]!.data.permissionMode).toBeUndefined();
  });
});

describe('session notes', () => {
  it('"# note" in Pro is saved to session memory without an agent turn', async () => {
    const w = await world({ mode: 'PRO', ownerRole: 'ADMIN' });
    const res = await send(w.owner, w.sessionId, '# Use British spelling');
    expect(res.status).toBe(202);
    await ctx.agent.idle(w.sessionId);
    expect(w.runner.of('user_message')).toHaveLength(0);
    expect(w.runner.of('memory_note')[0]!.data).toEqual({ text: 'Use British spelling' });
    const notes = (await w.owner.get(`/api/v1/sessions/${w.sessionId}/notes`)).body.data.notes;
    expect(notes).toMatch(/^- Use British spelling \(/);
    const add = await w.owner.post(`/api/v1/sessions/${w.sessionId}/notes`, {
      text: 'Prefer short words',
    });
    expect(add.status).toBe(201);
    expect(add.body.data.notes.split('\n')).toHaveLength(2);
  });

  it('in Simple mode "#" is a normal message', async () => {
    const w = await world();
    await send(w.owner, w.sessionId, '# Big heading please');
    await turnDone(w.sessionId);
    expect(w.runner.of('user_message')).toHaveLength(1);
    expect(w.runner.of('memory_note')).toHaveLength(0);
  });
});
