/** Maintenance jobs: idle pause (WIP), max duration, cleanup, orphan reconciliation, key health. */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  cleanupSandboxes,
  keyHealthCheck,
  orphanReconciliation,
  sessionIdleCheck,
  STUCK_PROVISION_MS,
} from '../src/services/sessionJobs.service';
import {
  addMember,
  anthropicReplies,
  createMswServer,
  createOrg,
  linkGithub,
  login,
  makeApp,
  onUnhandled,
  resetDb,
  testPrisma,
  type Client,
} from './helpers';
import { addApiKey, createReadyProject, fakeSandbox, settle } from './sessionHelpers';

const server = createMswServer();
const prisma = testPrisma();
const { app, ctx } = makeApp();
const fake = fakeSandbox(ctx);
const MIN = 60_000;

beforeAll(() => server.listen({ onUnhandledRequest: onUnhandled }));
afterEach(() => server.resetHandlers());
afterAll(async () => {
  await ctx.jobs.onIdle();
  server.close();
  await prisma.$disconnect();
});
beforeEach(async () => {
  await ctx.jobs.onIdle();
  fake.reset();
  await resetDb();
});

async function runningSession(policy: object = {}) {
  const owner: Client = await login(app);
  await linkGithub(ctx, owner.user.id);
  const org = await createOrg(owner);
  await prisma.organization.update({ where: { id: org.id }, data: { policy } });
  await addApiKey(ctx, owner.user.id);
  const project = await createReadyProject(ctx, org.id, { maxSessionDurationMin: 30 });
  const res = await owner.post('/api/v1/sessions', { projectId: project.id });
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  const s = await settle(ctx, res.body.data.id);
  expect(s.status).toBe('RUNNING');
  return { owner, org, project, session: s, sandbox: fake.last()! };
}

describe('session idle check', () => {
  it('keeps alive sandboxes this process holds no handle for (worker topology)', async () => {
    const { session, sandbox } = await runningSession({ idleTimeoutMin: 10 });
    // Simulate a worker that never provisioned the session / restarted since.
    const saved = ctx.sessionRuntime.get(session.id)!;
    ctx.sessionRuntime.delete(session.id);
    sandbox.timeoutMs = 1;
    try {
      const r = await sessionIdleCheck(ctx, new Date(session.idleSince!.getTime() + MIN));
      expect(r).toMatchObject({ paused: [], timedOut: [], keptAlive: 1 });
      expect(sandbox.timeoutMs).toBe(ctx.env.SANDBOX_TIMEOUT_MIN * MIN);
    } finally {
      ctx.sessionRuntime.set(saved);
    }
  });

  it('idle beyond the policy timeout → WIP pushed, sandbox killed, PAUSED', async () => {
    const { session, sandbox } = await runningSession({ idleTimeoutMin: 10 });
    // Not idle long enough yet → kept alive.
    let r = await sessionIdleCheck(ctx, new Date(session.idleSince!.getTime() + 5 * MIN));
    expect(r).toMatchObject({ paused: [], timedOut: [], keptAlive: 1 });
    expect(sandbox.timeoutMs).toBe(ctx.env.SANDBOX_TIMEOUT_MIN * MIN);

    r = await sessionIdleCheck(ctx, new Date(session.idleSince!.getTime() + 11 * MIN));
    expect(r.paused).toEqual([session.id]);
    const s = await prisma.session.findUniqueOrThrow({ where: { id: session.id } });
    expect(s).toMatchObject({
      status: 'PAUSED',
      wipRef: `refs/loose/wip/${session.id}`,
      sandboxId: null,
      endedAt: null,
    });
    expect(sandbox.killed).toBe(true);
    expect(sandbox.commandLines().some((c) => c.includes(`refs/loose/wip/${session.id}`))).toBe(
      true,
    );
    expect(ctx.sessionRuntime.get(session.id)).toBeUndefined();
    const evs = (await ctx.sessionEvents.replay(session.id, 0)).events;
    expect(evs.filter((e) => e.type === 'session_status').at(-1)?.payload).toMatchObject({
      status: 'PAUSED',
    });
    const audit = await prisma.auditLog.findFirst({
      where: { action: 'session.stop', target: session.id },
    });
    expect(audit?.meta).toMatchObject({ reason: 'idle', status: 'PAUSED', wipSaved: true });
  });

  it('never pauses a busy agent; a failed WIP push keeps the session running', async () => {
    const { session, sandbox } = await runningSession({ idleTimeoutMin: 1 });
    const later = new Date(session.idleSince!.getTime() + 5 * MIN);
    const off = ctx.sessionHooks.register({ isBusy: (id) => id === session.id });
    try {
      expect((await sessionIdleCheck(ctx, later)).paused).toEqual([]);
    } finally {
      off();
    }
    fake.onCommand(/git push/, () => ({ exitCode: 1, stderr: 'rejected' }));
    expect((await sessionIdleCheck(ctx, later)).paused).toEqual([]);
    const s = await prisma.session.findUniqueOrThrow({ where: { id: session.id } });
    expect(s.status).toBe('RUNNING');
    expect(sandbox.killed).toBe(false);
  });

  it('max session duration → WIP pushed, TIMED_OUT with LSE-SBX-009', async () => {
    const { session, sandbox } = await runningSession();
    const r = await sessionIdleCheck(ctx, new Date(session.startedAt!.getTime() + 31 * MIN));
    expect(r.timedOut).toEqual([session.id]);
    const s = await prisma.session.findUniqueOrThrow({ where: { id: session.id } });
    expect(s).toMatchObject({
      status: 'TIMED_OUT',
      errorCode: 'LSE-SBX-009',
      wipRef: `refs/loose/wip/${session.id}`,
    });
    expect(s.endedAt).toBeInstanceOf(Date);
    expect(sandbox.killed).toBe(true);
    const evs = (await ctx.sessionEvents.replay(session.id, 0)).events;
    expect(
      evs.some(
        (e) =>
          e.type === 'error' &&
          (e.payload as { error: { code: string } }).error.code === 'LSE-SBX-009',
      ),
    ).toBe(true);
    expect(evs.at(-1)?.type).toBe('session_ended');
  });
});

describe('cleanup & orphans', () => {
  it('kills sandboxes of finished sessions and orphans; keeps active and smoke-test sandboxes', async () => {
    const { session, sandbox, project } = await runningSession();
    const done = await prisma.session.create({
      data: {
        projectId: project.id,
        userId: session.userId,
        mode: 'SIMPLE',
        model: 'claude-sonnet-4-5',
        branchName: 'loose/session-done',
        status: 'COMPLETED',
      },
    });
    const finished = await fake.createFromTemplate('t', {
      timeoutMs: 1,
      metadata: { app: 'loose', sessionId: done.id },
    });
    await prisma.session.update({ where: { id: done.id }, data: { sandboxId: finished.id } });
    const orphan = await fake.createFromTemplate('t', {
      timeoutMs: 1,
      metadata: { app: 'loose', sessionId: 'cgone' },
    });
    const smoke = await fake.createFromTemplate('t', {
      timeoutMs: 1,
      metadata: { app: 'loose', kind: 'smoke-test' },
    });

    const r = await cleanupSandboxes(ctx);
    expect(r.killed.sort()).toEqual([finished.id, orphan.id].sort());
    expect(finished.killed && orphan.killed).toBe(true);
    expect(sandbox.killed).toBe(false);
    expect(smoke.killed).toBe(false);
    expect(
      (await prisma.session.findUniqueOrThrow({ where: { id: done.id } })).sandboxId,
    ).toBeNull();
  });

  it('cleanup also times out sessions beyond max duration', async () => {
    const { session } = await runningSession();
    const r = await cleanupSandboxes(ctx, new Date(session.startedAt!.getTime() + 31 * MIN));
    expect(r.timedOut).toEqual([session.id]);
  });

  it('RUNNING sessions whose sandbox vanished → ERRORED LSE-SBX-010; previous WIP is kept', async () => {
    const { session, sandbox } = await runningSession();
    await prisma.session.update({
      where: { id: session.id },
      data: { wipRef: `refs/loose/wip/${session.id}` },
    });
    sandbox.lost = true;
    const r = await orphanReconciliation(ctx);
    expect(r.errored).toEqual([session.id]);
    const s = await prisma.session.findUniqueOrThrow({ where: { id: session.id } });
    expect(s).toMatchObject({
      status: 'ERRORED',
      errorCode: 'LSE-SBX-010',
      wipRef: `refs/loose/wip/${session.id}`,
    });
    expect(sandbox.commandLines().some((c) => c.includes('git push'))).toBe(false);
    const evs = (await ctx.sessionEvents.replay(session.id, 0)).events;
    expect(evs.at(-1)?.payload).toMatchObject({ status: 'ERRORED', errorCode: 'LSE-SBX-010' });
  });

  it('after a restart (empty runtime registry) healthy sandboxes are reattached via connect()', async () => {
    const { session } = await runningSession();
    ctx.sessionRuntime.delete(session.id);
    expect((await orphanReconciliation(ctx)).errored).toEqual([]);
  });

  it('stuck provisioning: STARTING → ERRORED (LSE-SBX-002), QUEUED → re-queued', async () => {
    const { project, session } = await runningSession();
    const old = new Date(Date.now() - STUCK_PROVISION_MS - MIN);
    const mk = (status: 'STARTING' | 'QUEUED', id: string) =>
      prisma.session.create({
        data: {
          id,
          projectId: project.id,
          userId: session.userId,
          mode: 'SIMPLE',
          model: 'claude-sonnet-4-5',
          branchName: `loose/session-${id}`,
          status,
        },
      });
    await mk('STARTING', 'cstuckstarting');
    await mk('QUEUED', 'cstuckqueued');
    await prisma.$executeRaw`UPDATE "Session" SET "updatedAt" = ${old} WHERE id IN ('cstuckstarting', 'cstuckqueued')`;
    const r = await orphanReconciliation(ctx);
    expect(r.errored).toEqual(['cstuckstarting']);
    expect(r.requeued).toEqual(['cstuckqueued']);
    expect(
      (await prisma.session.findUniqueOrThrow({ where: { id: 'cstuckstarting' } })).errorCode,
    ).toBe('LSE-SBX-002');
    await ctx.jobs.onIdle();
    expect((await prisma.session.findUniqueOrThrow({ where: { id: 'cstuckqueued' } })).status).toBe(
      'RUNNING',
    );
  });
});

describe('key health check', () => {
  it('marks rejected keys INVALID (audited) and leaves valid ones ACTIVE', async () => {
    const a = await login(app);
    const b = await login(app);
    const org = await createOrg(a);
    await addMember(org.id, b.user.id, 'MEMBER');
    const ka = await addApiKey(ctx, a.user.id);
    server.use(anthropicReplies(401, { type: 'error', error: { type: 'authentication_error' } }));
    let r = await keyHealthCheck(ctx);
    expect(r).toEqual({ checked: 1, invalidated: [ka.id] });
    expect((await prisma.apiKey.findUniqueOrThrow({ where: { id: ka.id } })).status).toBe(
      'INVALID',
    );
    const audit = await prisma.auditLog.findFirst({
      where: { action: 'api_key.invalidated', target: ka.id },
    });
    expect(audit?.meta).toMatchObject({ userId: a.user.id, source: 'key_health_check' });
    expect(JSON.stringify(audit)).not.toContain('sk-ant-api03');

    const kb = await addApiKey(ctx, b.user.id);
    server.use(anthropicReplies(200, { data: [] }));
    r = await keyHealthCheck(ctx);
    expect(r).toEqual({ checked: 1, invalidated: [] });
    expect((await prisma.apiKey.findUniqueOrThrow({ where: { id: kb.id } })).status).toBe('ACTIVE');
    // Transient provider errors don't change status.
    server.use(anthropicReplies(529, {}));
    expect((await keyHealthCheck(ctx)).invalidated).toEqual([]);
  });
});
