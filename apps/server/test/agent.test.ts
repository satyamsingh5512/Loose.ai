/**
 * Phase 5: orchestrator turn flow with FakeSandboxProvider + a scripted fake runner:
 * full turn (OTL, usage, change summary), queueing, dedupe, guardrail revert, secret in
 * diff, budgets, approvals (approve/deny/expire), loop detection, crash restarts,
 * provider errors, malformed lines, interrupt, usage endpoint.
 */
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { scrubSecrets } from '@loose/shared';
import { expireApprovals } from '../src/services/agentChat.service';
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
  captureLogger,
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
const logs = captureLogger('debug');
const { app, ctx } = makeApp({ logger: logs.logger });
const fake = fakeSandbox(ctx);
const PROJECT_SECRET = 'stripe-sk-live-Secr3tValue99';

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
  runners = installFakeRunner(fake, script);
  git = new FakeGit().install(fake);
  script.current = (cmd, r) => {
    if (cmd.type === 'user_message') playTurn(r);
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
  opts: {
    budgetUsd?: number;
    project?: Parameters<typeof createReadyProject>[2];
    mode?: 'SIMPLE' | 'PRO';
  } = {},
): Promise<World> {
  const admin = await login(app, undefined, 'Ada Admin');
  const org = await createOrg(admin);
  const owner = await login(app, undefined, 'Mo Member');
  await addMember(org.id, owner.user.id, 'MEMBER');
  await linkGithub(ctx, owner.user.id);
  await addApiKey(ctx, owner.user.id);
  const project = await createReadyProject(ctx, org.id, {
    env: { STRIPE_KEY: PROJECT_SECRET },
    componentLabels: { 'src/components/Header*': 'the site header' },
    ...(opts.budgetUsd !== undefined ? { maxBudgetUsd: opts.budgetUsd } : {}),
    ...opts.project,
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

async function send(c: Client, sessionId: string, content: string, clientMessageId?: string) {
  return c.post(`/api/v1/sessions/${sessionId}/messages`, {
    content,
    ...(clientMessageId ? { clientMessageId } : {}),
  });
}

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

function ofType(entries: Awaited<ReturnType<typeof busEvents>>, type: string, audience?: string) {
  return entries.filter((e) => e.message.type === type && (!audience || e.audience === audience));
}

describe('turn flow', () => {
  it('runs a full turn: OTL per audience, tool events (Pro only), usage, change summary, history', async () => {
    const w = await world();
    git.set('src/components/Header.tsx', ' M', ['<h1>Howdy</h1>']);
    script.current = (cmd, r) => {
      if (cmd.type !== 'user_message') return;
      playTurn(r, {
        deltas: [
          'I edited `src/components/Header.tsx`',
          ' to say Howdy.\n',
          'Run `npm test` to check.',
        ],
        text: 'I edited `src/components/Header.tsx` to say Howdy.\nRun `npm test` to check.',
        tools: [
          { name: 'Read', input: { file_path: '/home/user/workspace/src/components/Header.tsx' } },
          {
            name: 'Edit',
            input: {
              file_path: '/home/user/workspace/src/components/Header.tsx',
              old_string: 'Hello',
              new_string: 'Howdy',
            },
          },
          { name: 'Bash', input: { command: 'npm test' }, output: `ok ${PROJECT_SECRET}` },
        ],
        files: ['src/components/Header.tsx'],
        usage: { in: 1000, out: 200, costUsd: 0.0057 },
      });
    };
    const res = await send(w.owner, w.sessionId, 'Change Hello to Howdy', 'c-1');
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(res.body.data.queued).toBe(false);
    await turnDone(w.sessionId);

    const um = w.runner.of('user_message');
    expect(um).toHaveLength(1);
    expect(um[0]!.data.text).toBe('Change Hello to Howdy');

    const entries = await busEvents(ctx, w.sessionId);
    // Simple audience: nothing technical, ever.
    for (const e of entries.filter((x) => x.audience !== 'pro')) {
      const p = e.message.payload as { label?: string; delta?: string; summary?: string };
      const text = p.label ?? p.delta ?? p.summary;
      if (text !== undefined) expect(leakCheck(text), text).toEqual([]);
    }
    expect(ofType(entries, 'tool_event').every((e) => e.audience === 'pro')).toBe(true);
    expect(ofType(entries, 'tool_event')).toHaveLength(6);
    const term = ofType(entries, 'terminal_output');
    expect(term).toHaveLength(1);
    expect(JSON.stringify(term[0]!.message.payload)).not.toContain(PROJECT_SECRET);
    const simpleStatus = ofType(entries, 'agent_status', 'simple').map(
      (e) => (e.message.payload as { label: string }).label,
    );
    expect(simpleStatus).toEqual(
      expect.arrayContaining([
        'Looking through the project…',
        'Updating the site header…',
        'Running checks…',
      ]),
    );
    const streamedSimple = ofType(entries, 'agent_streaming', 'simple')
      .map((e) => (e.message.payload as { delta: string }).delta)
      .join('');
    expect(streamedSimple).toContain('the site header');
    expect(streamedSimple).not.toContain('src/');
    const streamedPro = ofType(entries, 'agent_streaming', 'pro')
      .map((e) => (e.message.payload as { delta: string }).delta)
      .join('');
    expect(streamedPro).toContain('src/components/Header.tsx');

    const cs = ofType(entries, 'change_summary');
    const simpleCs = cs.find((e) => e.audience === 'simple')!.message.payload as Record<
      string,
      unknown
    >;
    const proCs = cs.find((e) => e.audience === 'pro')!.message.payload as Record<string, unknown>;
    expect(simpleCs.files).toBeUndefined();
    expect(simpleCs.risk).toBe('MEDIUM');
    expect(simpleCs.areas).toEqual(['the site header']);
    expect(simpleCs.summary).toContain('I edited the site header to say Howdy.');
    expect(proCs.files).toEqual([{ path: 'src/components/Header.tsx', status: 'modified' }]);
    expect(proCs.stats).toEqual({ additions: 1, deletions: 1 });

    const cost = ofType(entries, 'cost_update').at(-1)!.message.payload as Record<string, number>;
    expect(cost.totalCostUsd).toBeCloseTo(0.0057, 6);
    expect(cost.tokensIn).toBe(1000);
    expect(ofType(entries, 'agent_status').at(-1)!.message.payload).toMatchObject({
      state: 'idle',
    });

    const usage = await prisma.usageEvent.findMany({ where: { sessionId: w.sessionId } });
    expect(usage).toHaveLength(1);
    expect(Number(usage[0]!.costUsd)).toBeCloseTo(0.0057, 6);
    const s = await prisma.session.findUniqueOrThrow({ where: { id: w.sessionId } });
    expect(Number(s.totalCostUsd)).toBeCloseTo(0.0057, 4);
    expect(s.agentSessionId).toBe('agent-sess-1');
    expect(s.idleSince).toBeInstanceOf(Date);

    // History: Simple viewer gets translated content and no Pro metadata.
    const hist = await w.owner.get(`/api/v1/sessions/${w.sessionId}/messages`);
    expect(hist.status).toBe(200);
    expect(hist.body.data.map((m: { role: string }) => m.role)).toEqual(['USER', 'ASSISTANT']);
    const asst = hist.body.data[1];
    expect(asst.content).toContain('I edited the site header to say Howdy.');
    expect(leakCheck(asst.content)).toEqual([]);
    expect(asst.metadata).toMatchObject({
      kind: 'change_summary',
      risk: 'MEDIUM',
      areas: ['the site header'],
    });
    expect(asst.metadata.filesChanged).toBeUndefined();
    expect(asst.rawContent).toBeUndefined();
    // Admin switching to Pro sees verbatim text + file list.
    await prisma.session.update({ where: { id: w.sessionId }, data: { mode: 'PRO' } });
    const pro = await w.admin.get(`/api/v1/sessions/${w.sessionId}/messages`);
    expect(pro.body.data[1].content).toContain('src/components/Header.tsx');
    expect(pro.body.data[1].metadata.filesChanged).toEqual(['src/components/Header.tsx']);

    // Raw events persisted (scrubbed) for audit / Pro debug.
    const row = await prisma.chatMessage.findFirstOrThrow({
      where: { sessionId: w.sessionId, role: 'ASSISTANT' },
    });
    const raw = JSON.stringify(row.rawContent);
    expect(raw).toContain('tool_use');
    expect(raw).not.toContain(PROJECT_SECRET);
  });

  it('queues messages while busy and dedupes by clientMessageId', async () => {
    const w = await world();
    let release: (() => void) | undefined;
    script.current = (cmd, r) => {
      if (cmd.type !== 'user_message') return;
      if (r.of('user_message').length === 1) release = () => playTurn(r, { text: 'First done.' });
      else playTurn(r, { text: 'Second done.' });
    };
    const a = await send(w.owner, w.sessionId, 'first', 'k1');
    expect(a.body.data.queued).toBe(false);
    await waitFor(() => w.runner.of('user_message').length === 1, { label: 'first sent' });
    const b = await send(w.owner, w.sessionId, 'second', 'k2');
    expect(b.status).toBe(202);
    expect(b.body.data.queued).toBe(true);
    const dup = await send(w.owner, w.sessionId, 'second', 'k2');
    expect(dup.body.data).toMatchObject({ duplicate: true, queued: false });
    expect(dup.body.data.message.id).toBe(b.body.data.message.id);
    expect(w.runner.of('user_message')).toHaveLength(1);
    const getS = await w.owner.get(`/api/v1/sessions/${w.sessionId}`);
    expect(getS.body.data.agentState).not.toBe('idle');
    release!();
    await turnDone(w.sessionId, 2);
    expect(w.runner.of('user_message').map((c) => c.data.text)).toEqual(['first', 'second']);
    const queuedEcho = ofType(await busEvents(ctx, w.sessionId), 'chat_message').find(
      (e) => (e.message.payload as { queued?: boolean }).queued,
    );
    expect(queuedEcho).toBeDefined();
    expect(
      await prisma.chatMessage.count({ where: { sessionId: w.sessionId, role: 'USER' } }),
    ).toBe(2);
  });

  it('rejects messages when the session is not RUNNING and from non-participants', async () => {
    const w = await world();
    const other = await login(app);
    await addMember(w.orgId, other.user.id, 'MEMBER');
    expectError(await send(other, w.sessionId, 'hi'), 'LSE-ORG-002', 403);
    await prisma.session.update({ where: { id: w.sessionId }, data: { status: 'PAUSED' } });
    expectError(await send(w.owner, w.sessionId, 'hi'), 'LSE-CONF-001', 409);
  });

  it('interrupt route forwards to the runner', async () => {
    const w = await world();
    script.current = () => undefined; // never finishes on its own
    await send(w.owner, w.sessionId, 'slow please');
    await waitFor(() => w.runner.of('user_message').length === 1);
    const res = await w.owner.post(`/api/v1/sessions/${w.sessionId}/interrupt`, {});
    expect(res.status).toBe(202);
    expect(res.body.data).toEqual({ interrupted: true });
    expect(w.runner.of('interrupt')).toHaveLength(1);
    w.runner.emit('interrupted', {});
    w.runner.emit('turn_complete', { filesChanged: [], stopReason: 'interrupted' });
    await turnDone(w.sessionId);
    const msg = await prisma.chatMessage.findFirstOrThrow({
      where: { sessionId: w.sessionId, role: 'ASSISTANT' },
    });
    expect(msg.content).toBe('Stopped. Nothing was changed.');
  });
});

describe('post-turn guardrails', () => {
  it('reverts files outside the allowed/denied patterns (LSE-AGT-004) and audits', async () => {
    const w = await world({ project: { deniedFilePatterns: ['.env*', 'src/billing'] } });
    git
      .set('.env.production', '??', ['SECRET=1'])
      .set('src/billing/plan.ts', ' M')
      .set('README.md', ' M');
    script.current = (cmd, r) => {
      if (cmd.type === 'user_message')
        playTurn(r, { files: ['.env.production', 'src/billing/plan.ts', 'README.md'] });
    };
    await send(w.owner, w.sessionId, 'touch secret');
    await turnDone(w.sessionId);
    const cmds = lastSandbox(ctx).commandLines().join('\n');
    expect(cmds).toContain("rm -rf -- '.env.production'");
    expect(cmds).toContain("checkout -q HEAD -- 'src/billing/plan.ts'");
    expect([...git.files.keys()]).toEqual(['README.md']);
    const errs = ofType(await busEvents(ctx, w.sessionId), 'error').map(
      (e) => (e.message.payload as { error: { code: string } }).error.code,
    );
    expect(errs).toContain('LSE-AGT-004');
    const audit = await prisma.auditLog.findFirstOrThrow({
      where: { action: 'security.path_violation' },
    });
    expect(audit.meta).toMatchObject({ files: ['.env.production', 'src/billing/plan.ts'] });
    const asst = await prisma.chatMessage.findFirstOrThrow({
      where: { sessionId: w.sessionId, role: 'ASSISTANT' },
    });
    expect((asst.metadata as { filesChanged: string[] }).filesChanged).toEqual(['README.md']);
    expect((asst.metadata as { risk: string }).risk).toBe('LOW');
  });

  it('blocks secrets in the diff (LSE-AGT-016): reverted, audited, never echoed', async () => {
    const w = await world();
    git
      .set('src/config.ts', ' M', [`export const key = "${PROJECT_SECRET}";`])
      .set('src/keys.ts', '??', ['const k = "sk-ant-api03-abcdefghijklmnop1234";'])
      .set('src/ok.css', ' M', ['h1 { color: red }']);
    script.current = (cmd, r) => {
      if (cmd.type === 'user_message')
        playTurn(r, {
          text: 'Added the key.',
          files: ['src/config.ts', 'src/keys.ts', 'src/ok.css'],
        });
    };
    await send(w.owner, w.sessionId, 'add key');
    await turnDone(w.sessionId);
    expect([...git.files.keys()]).toEqual(['src/ok.css']);
    const entries = await busEvents(ctx, w.sessionId);
    const codes = ofType(entries, 'error').map(
      (e) => (e.message.payload as { error: { code: string } }).error.code,
    );
    expect(codes).toContain('LSE-AGT-016');
    expect(JSON.stringify(entries)).not.toContain(PROJECT_SECRET);
    const audit = await prisma.auditLog.findFirstOrThrow({
      where: { action: 'security.secret_blocked' },
    });
    expect(audit.meta).toMatchObject({ files: ['src/config.ts', 'src/keys.ts'] });
    expect(JSON.stringify(audit.meta)).not.toContain(PROJECT_SECRET);
  });
});

describe('budgets', () => {
  it('warns once at 80% and pauses at 100% with WIP (LSE-AGT-003)', async () => {
    const w = await world({ budgetUsd: 0.1 });
    script.current = (cmd, r) => {
      if (cmd.type !== 'user_message') return;
      playTurn(r, { usage: { costUsd: r.of('user_message').length === 1 ? 0.085 : 0.02 } });
    };
    await send(w.owner, w.sessionId, 'one');
    await turnDone(w.sessionId);
    let entries = await busEvents(ctx, w.sessionId);
    expect(ofType(entries, 'cost_update').at(-1)!.message.payload).toMatchObject({
      level: 'warning',
      budgetUsd: 0.1,
    });
    expect(
      await prisma.chatMessage.count({ where: { sessionId: w.sessionId, role: 'SYSTEM' } }),
    ).toBe(1);

    await send(w.owner, w.sessionId, 'two');
    await waitFor(
      async () =>
        (await prisma.session.findUniqueOrThrow({ where: { id: w.sessionId } })).status ===
        'PAUSED',
      {
        label: 'paused',
      },
    );
    await ctx.agent.idle();
    const s = await prisma.session.findUniqueOrThrow({ where: { id: w.sessionId } });
    expect(s.errorCode).toBe('LSE-AGT-003');
    expect(s.wipRef).toBe(`refs/loose/wip/${w.sessionId}`);
    entries = await busEvents(ctx, w.sessionId);
    expect(ofType(entries, 'cost_update').at(-1)!.message.payload).toMatchObject({
      level: 'exceeded',
    });
    expect(w.runner.of('shutdown')).toHaveLength(1);
    expectError(await send(w.owner, w.sessionId, 'three'), 'LSE-CONF-001', 409);
  });

  it('rejects new messages once the budget is spent', async () => {
    const w = await world({ budgetUsd: 1 });
    await prisma.session.update({ where: { id: w.sessionId }, data: { totalCostUsd: 1 } });
    expectError(await send(w.owner, w.sessionId, 'more'), 'LSE-AGT-003', 402);
  });

  it('pauses when the user monthly cap is reached (LSE-KEY-012)', async () => {
    const w = await world();
    await prisma.organization.update({
      where: { id: w.orgId },
      data: { policy: { budgets: { orgMonthlyUsd: null, userMonthlyUsd: 0.01 } } },
    });
    script.current = (cmd, r) => {
      if (cmd.type === 'user_message') playTurn(r, { usage: { costUsd: 0.02 } });
    };
    await send(w.owner, w.sessionId, 'spend');
    await waitFor(
      async () =>
        (await prisma.session.findUniqueOrThrow({ where: { id: w.sessionId } })).status ===
        'PAUSED',
    );
    await ctx.agent.idle();
    expect((await prisma.session.findUniqueOrThrow({ where: { id: w.sessionId } })).errorCode).toBe(
      'LSE-KEY-012',
    );
  });
});

describe('approvals', () => {
  function needsApproval(gate?: 'dependencies') {
    script.current = (cmd, r) => {
      if (cmd.type === 'user_message') {
        r.emit('tool_use', { id: 't1', name: 'Bash', input: { command: 'npm install left-pad' } });
        r.emit('approval_needed', {
          id: 'apr_1',
          tool: 'Bash',
          input: { command: 'npm install left-pad' },
          reason: 'dependency install',
          ...(gate ? { gate } : {}),
        });
      }
      if (cmd.type === 'approval_response') {
        r.emit('tool_result', {
          id: 't1',
          isError: cmd.data.decision === 'deny',
          summary: cmd.data.decision,
        });
        playTurn(r, { text: cmd.data.decision === 'allow' ? 'Installed.' : 'Skipped it.' });
      }
    };
  }

  it('dependency gate in a MEMBER session needs an admin; admin approves → runner allow', async () => {
    const w = await world();
    needsApproval('dependencies');
    await send(w.owner, w.sessionId, 'needs approval');
    const appr = await waitFor(() =>
      prisma.toolApproval.findFirst({ where: { sessionId: w.sessionId } }),
    );
    expect(appr).toMatchObject({
      status: 'PENDING',
      gate: 'dependencies',
      requiresAdmin: true,
      runnerRequestId: 'apr_1',
    });
    const entries = await busEvents(ctx, w.sessionId);
    const simpleReq = ofType(entries, 'approval_required', 'simple')[0]!.message.payload as {
      approval: { summary: string; tool: string; requiresAdmin: boolean };
    };
    expect(simpleReq.approval.summary).toBe('Add or change a software package the app uses');
    expect(simpleReq.approval.tool).toBe('action');
    expect(leakCheck(simpleReq.approval.summary)).toEqual([]);
    const proReq = ofType(entries, 'approval_required', 'pro')[0]!.message.payload as {
      approval: { summary: string };
    };
    expect(proReq.approval.summary).toBe('Bash: npm install left-pad');
    expect(ofType(entries, 'agent_status', 'simple').at(-1)!.message.payload).toMatchObject({
      state: 'waiting_approval',
    });

    const list = await w.owner.get(`/api/v1/sessions/${w.sessionId}/approvals`);
    expect(list.body.data).toHaveLength(1);
    const url = `/api/v1/sessions/${w.sessionId}/approvals/${appr.id}`;
    expectError(await w.owner.post(url, { decision: 'approve' }), 'LSE-ORG-002', 403);
    const ok = await w.admin.post(url, { decision: 'approve' });
    expect(ok.status, JSON.stringify(ok.body)).toBe(200);
    expect(ok.body.data.status).toBe('APPROVED');
    expect(w.runner.of('approval_response')[0]!.data).toMatchObject({
      id: 'apr_1',
      decision: 'allow',
    });
    await turnDone(w.sessionId);
    expectError(await w.admin.post(url, { decision: 'deny' }), 'LSE-CONF-001', 409);
    const resolved = ofType(await busEvents(ctx, w.sessionId), 'approval_resolved');
    expect(resolved[0]!.message.payload).toMatchObject({
      approvalId: appr.id,
      status: 'APPROVED',
      decidedByName: 'Ada Admin',
    });
    expect(
      await prisma.auditLog.count({ where: { action: 'approval.decide', target: appr.id } }),
    ).toBe(1);
  });

  it('owner can deny an ungated approval → runner deny', async () => {
    const w = await world();
    needsApproval();
    await send(w.owner, w.sessionId, 'needs approval');
    const appr = await waitFor(() =>
      prisma.toolApproval.findFirst({ where: { sessionId: w.sessionId } }),
    );
    // npm install is a dependency command → still HIGH-risk → admin required…
    expect(appr.requiresAdmin).toBe(true);
    await prisma.toolApproval.update({ where: { id: appr.id }, data: { requiresAdmin: false } });
    const res = await w.owner.post(`/api/v1/sessions/${w.sessionId}/approvals/${appr.id}`, {
      decision: 'deny',
      reason: 'not now',
    });
    expect(res.status).toBe(200);
    expect(res.body.data.status).toBe('DENIED');
    expect(w.runner.of('approval_response')[0]!.data).toMatchObject({
      decision: 'deny',
      reason: 'not now',
    });
    await turnDone(w.sessionId);
  });

  it('expires → EXPIRED, runner deny, LSE-AGT-006', async () => {
    const w = await world();
    needsApproval('dependencies');
    await send(w.owner, w.sessionId, 'needs approval');
    const appr = await waitFor(() =>
      prisma.toolApproval.findFirst({ where: { sessionId: w.sessionId } }),
    );
    expect(await expireApprovals(ctx, {}, new Date())).toEqual([]);
    const later = new Date(appr.expiresAt!.getTime() + 1000);
    expect(await expireApprovals(ctx, {}, later)).toEqual([appr.id]);
    expect((await prisma.toolApproval.findUniqueOrThrow({ where: { id: appr.id } })).status).toBe(
      'EXPIRED',
    );
    expect(w.runner.of('approval_response')[0]!.data.decision).toBe('deny');
    const entries = await busEvents(ctx, w.sessionId);
    expect(ofType(entries, 'approval_resolved')[0]!.message.payload).toMatchObject({
      status: 'EXPIRED',
    });
    expect(
      ofType(entries, 'error').some(
        (e) => (e.message.payload as { error: { code: string } }).error.code === 'LSE-AGT-006',
      ),
    ).toBe(true);
    expect(await prisma.auditLog.count({ where: { action: 'approval.expire' } })).toBe(1);
    await turnDone(w.sessionId);
  });
});

describe('runner supervision', () => {
  it('stops a looping agent after 5 identical tool calls (LSE-AGT-007)', async () => {
    const w = await world();
    script.current = (cmd, r) => {
      if (cmd.type === 'user_message') {
        for (let i = 0; i < 6; i += 1)
          r.emit('tool_use', { id: `t${i}`, name: 'Read', input: { file_path: 'a.ts' } });
      }
      if (cmd.type === 'interrupt') {
        r.emit('interrupted', {});
        r.emit('turn_complete', { filesChanged: [], stopReason: 'interrupted' });
      }
    };
    await send(w.owner, w.sessionId, 'loop');
    await turnDone(w.sessionId);
    expect(w.runner.of('interrupt')).toHaveLength(1);
    const asst = await prisma.chatMessage.findFirstOrThrow({
      where: { sessionId: w.sessionId, role: 'ASSISTANT' },
    });
    expect((asst.metadata as { errorCode: string }).errorCode).toBe('LSE-AGT-007');
  });

  it('restarts a crashed runner with resume (LSE-AGT-001) and errors the session after 3 restarts', async () => {
    const w = await world();
    script.current = (cmd, r) => {
      if (cmd.type === 'user_message') {
        r.emit('session_init', { agentSessionId: 'resume-me', model: 'claude-sonnet-4-5' });
        r.proc.exit(1);
      }
    };
    await send(w.owner, w.sessionId, 'crash');
    await waitFor(() => runners.length === 2, { label: 'restart' });
    await ctx.agent.idle();
    const cfg = JSON.parse(lastSandbox(ctx).files.get('/home/user/.loose/config.json')!);
    expect(cfg.resumeAgentSessionId).toBe('resume-me');
    const asst = await prisma.chatMessage.findFirstOrThrow({
      where: { sessionId: w.sessionId, role: 'ASSISTANT' },
    });
    expect((asst.metadata as { errorCode: string }).errorCode).toBe('LSE-AGT-001');
    for (let i = 2; i <= 4; i += 1) {
      runners.at(-1)!.proc.exit(1);
      if (i < 4) await waitFor(() => runners.length === i + 1, { label: `restart ${i}` });
    }
    await waitFor(
      async () =>
        (await prisma.session.findUniqueOrThrow({ where: { id: w.sessionId } })).status ===
        'ERRORED',
      {
        label: 'errored',
      },
    );
    await ctx.agent.idle();
    expect((await prisma.session.findUniqueOrThrow({ where: { id: w.sessionId } })).errorCode).toBe(
      'LSE-AGT-001',
    );
    expect(runners).toHaveLength(4);
  });

  it('maps runner provider errors; KEY-003 invalidates the key; malformed lines are skipped', async () => {
    const w = await world();
    script.current = (cmd, r) => {
      if (cmd.type !== 'user_message') return;
      r.raw('this is not json\n{"v":1,"type":"bogus"}\n');
      r.emit('error', {
        code: 'LSE-KEY-003',
        detail: 'invalid x-api-key sk-ant-api03-zzzzzzzzzzzz',
      });
      r.emit('turn_complete', { filesChanged: [], stopReason: 'error' });
    };
    await send(w.owner, w.sessionId, 'go');
    await turnDone(w.sessionId);
    const key = await prisma.apiKey.findFirstOrThrow({ where: { userId: w.owner.user.id } });
    expect(key.status).toBe('INVALID');
    expect(await prisma.auditLog.count({ where: { action: 'api_key.invalidated' } })).toBe(1);
    const asst = await prisma.chatMessage.findFirstOrThrow({
      where: { sessionId: w.sessionId, role: 'ASSISTANT' },
    });
    expect(asst.content).toMatch(/key/i);
    expect((asst.metadata as { errorCode: string }).errorCode).toBe('LSE-KEY-003');
    const joined = logs.lines.join('\n');
    expect(joined).toContain('LSE-AGT-010');
    expect(joined).not.toContain('this is not json');
    expect(joined).not.toContain('sk-ant-api03-zzzz');
    expect(scrubSecrets(joined)).toBe(joined);
  });
});

describe('conflicts & screenshots', () => {
  it('warns both sessions when they change the same files (LSE-SBX-014)', async () => {
    const w = await world();
    const project = await prisma.project.findFirstOrThrow({ where: { orgId: w.orgId } });
    const other = await login(app, undefined, 'Olga Other');
    await addMember(w.orgId, other.user.id, 'MEMBER');
    await linkGithub(ctx, other.user.id);
    await addApiKey(ctx, other.user.id);
    const res = await other.post('/api/v1/sessions', { projectId: project.id });
    const s2 = await settle(ctx, res.body.data.id as string);
    await waitFor(() => ctx.agent.hasRuntime(s2.id));
    git.set('src/components/Header.tsx', ' M');
    script.current = (cmd, r) => {
      if (cmd.type === 'user_message') playTurn(r, { files: ['src/components/Header.tsx'] });
    };
    await send(w.owner, w.sessionId, 'edit header');
    await turnDone(w.sessionId);
    await send(other, s2.id, 'edit header too');
    await turnDone(s2.id);
    const mine = ofType(await busEvents(ctx, w.sessionId), 'conflict_warning').at(-1)!;
    expect(mine.message.payload).toMatchObject({
      otherSessionId: s2.id,
      otherUserName: 'Olga Other',
      files: ['src/components/Header.tsx'],
      areas: ['the site header'],
    });
    const theirs = ofType(await busEvents(ctx, s2.id), 'conflict_warning').at(-1)!;
    expect(theirs.message.payload).toMatchObject({
      otherSessionId: w.sessionId,
      otherUserName: 'Mo Member',
    });
  });

  it('captures before/after screenshots as artifacts when enabled', async () => {
    const shotApp = makeApp({ env: { AGENT_SCREENSHOTS: 'true' } });
    const shotFake = fakeSandbox(shotApp.ctx);
    const png = Buffer.from('89504e470d0a1a0a', 'hex').toString('base64');
    const shotScript: { current: RunnerScript } = {
      current: (cmd, r) => {
        if (cmd.type === 'screenshot')
          r.emit('screenshot_result', {
            requestId: cmd.data.requestId,
            ok: true,
            pngBase64: png,
            width: 1280,
            height: 800,
          });
        if (cmd.type === 'user_message') playTurn(r, { files: ['src/styles/globals.css'] });
      },
    };
    const shotRunners = installFakeRunner(shotFake, shotScript);
    new FakeGit().set('src/styles/globals.css', ' M', ['h1{color:red}']).install(shotFake);
    const admin = await login(shotApp.app);
    const org = await createOrg(admin);
    await linkGithub(shotApp.ctx, admin.user.id);
    await addApiKey(shotApp.ctx, admin.user.id);
    const project = await createReadyProject(shotApp.ctx, org.id, {
      portMap: [{ name: 'web', port: 3000, public: true }],
    });
    const res = await admin.post('/api/v1/sessions', { projectId: project.id });
    const s = await settle(shotApp.ctx, res.body.data.id as string);
    expect(s.status).toBe('RUNNING');
    await waitFor(() => shotApp.ctx.agent.hasRuntime(s.id));
    await admin.post(`/api/v1/sessions/${s.id}/messages`, { content: 'make it red' });
    await waitFor(async () => (await prisma.artifact.count({ where: { sessionId: s.id } })) === 2);
    await waitFor(() =>
      prisma.chatMessage.findFirst({
        where: {
          sessionId: s.id,
          role: 'ASSISTANT',
          rawContent: { path: ['pending'], equals: false },
        },
      }),
    );
    await shotApp.ctx.agent.idle();
    expect(shotRunners[0]!.of('screenshot').map((c) => c.data)).toEqual([
      expect.objectContaining({ url: s.previewUrl, viewport: 'desktop' }),
      expect.objectContaining({ url: s.previewUrl, viewport: 'desktop' }),
    ]);
    const arts = await prisma.artifact.findMany({
      where: { sessionId: s.id },
      orderBy: { createdAt: 'asc' },
    });
    expect(arts.map((a) => (a.meta as { phase: string }).phase)).toEqual(['before', 'after']);
    const cs = (await shotApp.ctx.sessionEvents.replay(s.id, 0)).entries.find(
      (e) => e.message.type === 'change_summary',
    )!;
    expect((cs.message.payload as { screenshots: unknown[] }).screenshots).toEqual([
      { before: arts[0]!.id, after: arts[1]!.id, viewport: 'desktop' },
    ]);
    expect(shotApp.ctx.sessionEvents).not.toBe(ctx.sessionEvents);
    await shotApp.ctx.agent.shutdownAll();
  });
});

describe('GET /orgs/:orgId/usage', () => {
  it('summarizes usage by user/project/model and exports CSV (admin only)', async () => {
    const w = await world();
    script.current = (cmd, r) => {
      if (cmd.type === 'user_message') playTurn(r, { usage: { costUsd: 0.5, in: 100, out: 10 } });
    };
    await send(w.owner, w.sessionId, 'a');
    await turnDone(w.sessionId);
    await send(w.owner, w.sessionId, 'b');
    await turnDone(w.sessionId, 2);
    const res = await w.admin.get(`/api/v1/orgs/${w.orgId}/usage`);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.data).toMatchObject({
      totalCostUsd: 1,
      sessions: 1,
      tokensIn: 200,
      tokensOut: 20,
    });
    expect(res.body.data.byUser).toEqual([
      expect.objectContaining({ userId: w.owner.user.id, costUsd: 1, sessions: 1, tokensIn: 200 }),
    ]);
    expect(res.body.data.byModel).toEqual([
      expect.objectContaining({ model: 'claude-sonnet-4-5', costUsd: 1 }),
    ]);
    expect(res.body.data.byProject).toHaveLength(1);
    const csv = await w.admin.get(`/api/v1/orgs/${w.orgId}/usage?format=csv`);
    expect(csv.status).toBe(200);
    expect(csv.headers['content-type']).toContain('text/csv');
    const lines = csv.text.trim().split('\n');
    expect(lines[0]).toBe(
      'createdAt,sessionId,projectId,projectName,userId,userEmail,model,tokensIn,tokensOut,cacheRead,costUsd,subagent',
    );
    expect(lines).toHaveLength(3);
    expectError(await w.owner.get(`/api/v1/orgs/${w.orgId}/usage`), 'LSE-ORG-002', 403);
    const future = await w.admin.get(
      `/api/v1/orgs/${w.orgId}/usage?from=2030-01-01T00:00:00Z&to=2030-02-01T00:00:00Z`,
    );
    expect(future.body.data.totalCostUsd).toBe(0);
  });
});
