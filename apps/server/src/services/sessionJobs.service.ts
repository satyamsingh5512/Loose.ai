/**
 * Periodic maintenance jobs (spec §13.2 cleanup, §16.5 orphan reconciliation).
 * Each is a plain async function (called directly by tests) and is registered as a
 * repeatable job in `buildContext` / `src/worker.ts`.
 */
import { ACTIVE_SESSION_STATUSES, parseOrgPolicy, type SessionStatus } from '@loose/shared';
import type { AppContext } from '../context';
import { HARDENING_SCHEDULES, PLATFORM_SCHEDULES } from '../lib/jobs';
import { expireApprovals } from './agentChat.service';
import { decryptApiKey } from './apiKey.service';
import { getOrConnectSandbox, provisionSession, stopSession } from './sessionLifecycle.service';
import { runTemplateBuild } from './template.service';

const MINUTE = 60_000;
/** STARTING sessions older than this (and not provisioning in this process) are stuck. */
export const STUCK_PROVISION_MS = 30 * MINUTE;

export const MAINTENANCE_SCHEDULES = [
  { queue: 'session-idle-check', everyMs: MINUTE },
  { queue: 'cleanup-sandboxes', everyMs: 5 * MINUTE },
  { queue: 'orphan-reconciliation', everyMs: 5 * MINUTE },
  { queue: 'key-health-check', everyMs: 24 * 60 * MINUTE },
  { queue: 'usage-rollup', everyMs: 60 * MINUTE },
  { queue: 'approval-expiry', everyMs: MINUTE },
  ...PLATFORM_SCHEDULES,
  ...HARDENING_SCHEDULES,
] as const;

export interface IdleCheckResult {
  paused: string[];
  timedOut: string[];
  keptAlive: number;
}

/** Idle → PAUSED (WIP pushed), over max duration → TIMED_OUT (LSE-SBX-009), else keep-alive. */
export async function sessionIdleCheck(
  ctx: AppContext,
  now = new Date(),
): Promise<IdleCheckResult> {
  const out: IdleCheckResult = { paused: [], timedOut: [], keptAlive: 0 };
  const running = await ctx.prisma.session.findMany({
    where: { status: 'RUNNING' },
    include: {
      project: { select: { maxSessionDurationMin: true, org: { select: { policy: true } } } },
    },
    take: 500,
  });
  for (const s of running) {
    const policy = parseOrgPolicy(s.project.org.policy);
    const started = (s.startedAt ?? s.createdAt).getTime();
    if (now.getTime() - started >= s.project.maxSessionDurationMin * MINUTE) {
      if (
        await stopSession(ctx, s.id, {
          to: 'TIMED_OUT',
          reason: 'timeout',
          errorCode: 'LSE-SBX-009',
          pushWip: true,
        })
      ) {
        out.timedOut.push(s.id);
      }
      continue;
    }
    const idleMs = s.idleSince ? now.getTime() - s.idleSince.getTime() : 0;
    if (s.idleSince && !ctx.sessionHooks.isBusy(s.id) && idleMs >= policy.idleTimeoutMin * MINUTE) {
      if (
        await stopSession(ctx, s.id, {
          to: 'PAUSED',
          reason: 'idle',
          pushWip: true,
          requireWip: true,
        })
      ) {
        out.paused.push(s.id);
        continue;
      }
    }
    // Keep-alive for EVERY running session: use this process' live handle when it has
    // one, else reattach via the provider. The production worker holds no handles (and
    // loses its registry on restart), so relying on the registry alone would let the
    // provider's sandbox timeout kill long sessions and lose their uncommitted work.
    const sandbox = await getOrConnectSandbox(ctx, s);
    if (sandbox) {
      await sandbox
        .setTimeout(ctx.env.SANDBOX_TIMEOUT_MIN * MINUTE)
        .then(() => (out.keptAlive += 1))
        .catch((err: unknown) => ctx.logger.warn({ err, sessionId: s.id }, 'keep-alive failed'));
    }
  }
  return out;
}

export interface CleanupResult {
  killed: string[];
  timedOut: string[];
}

const TERMINAL_OR_PAUSED: SessionStatus[] = ['COMPLETED', 'ERRORED', 'TIMED_OUT', 'PAUSED'];

/** Every 5 min: kill sandboxes of finished sessions, orphans, and sessions past max duration. */
export async function cleanupSandboxes(ctx: AppContext, now = new Date()): Promise<CleanupResult> {
  const killed: string[] = [];
  // 1) finished sessions that still reference a sandbox
  const finished = await ctx.prisma.session.findMany({
    where: { status: { in: TERMINAL_OR_PAUSED }, sandboxId: { not: null } },
    select: { id: true, sandboxId: true },
    take: 500,
  });
  for (const s of finished) {
    await ctx.sandbox.kill(s.sandboxId!).catch(() => false);
    ctx.sessionRuntime.delete(s.id);
    await ctx.prisma.session.update({ where: { id: s.id }, data: { sandboxId: null } });
    killed.push(s.sandboxId!);
  }
  // 2) sandboxes the provider still runs but no active session owns
  const live = await ctx.sandbox.list().catch((err: unknown) => {
    ctx.logger.warn({ err }, 'sandbox list failed');
    return [];
  });
  const sessionIds = live.map((l) => l.metadata.sessionId).filter((x): x is string => !!x);
  const active = new Set(
    (
      await ctx.prisma.session.findMany({
        where: { id: { in: sessionIds }, status: { in: [...ACTIVE_SESSION_STATUSES] } },
        select: { sandboxId: true },
      })
    ).map((s) => s.sandboxId),
  );
  for (const sbx of live) {
    if (sbx.metadata.kind === 'smoke-test') continue; // owned by the running smoke test
    if (sbx.metadata.sessionId && active.has(sbx.id)) continue;
    if (await ctx.sandbox.kill(sbx.id).catch(() => false)) killed.push(sbx.id);
  }
  // 3) over max duration (normally caught by the idle check every minute)
  const { timedOut } = await sessionIdleCheck(ctx, now);
  return { killed: [...new Set(killed)], timedOut };
}

export interface OrphanResult {
  errored: string[];
  requeued: string[];
}

/** RUNNING sessions whose sandbox is gone → ERRORED (LSE-SBX-010); stuck provisioning → ERRORED / re-queued. */
export async function orphanReconciliation(
  ctx: AppContext,
  now = new Date(),
): Promise<OrphanResult> {
  const out: OrphanResult = { errored: [], requeued: [] };
  const running = await ctx.prisma.session.findMany({ where: { status: 'RUNNING' }, take: 500 });
  for (const s of running) {
    const sandbox = await getOrConnectSandbox(ctx, s);
    const alive = sandbox ? await sandbox.isRunning().catch(() => false) : false;
    if (alive) continue;
    // Sandbox gone: nothing left to snapshot; keep any earlier WIP ref.
    if (
      await stopSession(ctx, s.id, {
        to: 'ERRORED',
        reason: 'lost',
        errorCode: 'LSE-SBX-010',
        pushWip: false,
      })
    ) {
      out.errored.push(s.id);
    }
  }
  const stuck = await ctx.prisma.session.findMany({
    where: {
      status: { in: ['STARTING', 'QUEUED'] },
      updatedAt: { lt: new Date(now.getTime() - STUCK_PROVISION_MS) },
    },
    take: 200,
  });
  for (const s of stuck) {
    if (s.status === 'QUEUED') {
      await ctx.jobs.enqueue(
        'session-provision',
        { sessionId: s.id },
        { jobId: `provision:${s.id}` },
      );
      out.requeued.push(s.id);
    } else if (
      await stopSession(ctx, s.id, {
        to: 'ERRORED',
        reason: 'error',
        errorCode: 'LSE-SBX-002',
        pushWip: false,
        from: ['STARTING'],
      })
    ) {
      out.errored.push(s.id);
    }
  }
  return out;
}

/** Nightly: revalidate ACTIVE keys; definitively rejected keys become INVALID (audited). */
export async function keyHealthCheck(
  ctx: AppContext,
): Promise<{ checked: number; invalidated: string[] }> {
  const keys = await ctx.prisma.apiKey.findMany({
    where: { status: 'ACTIVE', provider: 'anthropic' },
    take: 1000,
  });
  const invalidated: string[] = [];
  for (const k of keys) {
    let result;
    try {
      result = await ctx.providers.anthropic.validateKey(await decryptApiKey(ctx, k));
    } catch (err) {
      ctx.logger.warn({ err, keyId: k.id }, 'key health check failed');
      continue;
    }
    if (result.ok) {
      await ctx.prisma.apiKey.update({
        where: { id: k.id },
        data: { lastValidatedAt: new Date() },
      });
    } else if (result.reason === 'invalid') {
      await ctx.prisma.apiKey.update({
        where: { id: k.id },
        data: { status: 'INVALID', lastValidatedAt: new Date() },
      });
      await ctx.audit.record({
        orgId: k.orgId,
        actorId: null,
        action: 'api_key.invalidated',
        target: k.id,
        meta: { userId: k.userId, last4: k.last4, source: 'key_health_check' },
      });
      invalidated.push(k.id);
    }
  }
  return { checked: keys.length, invalidated };
}

/** Placeholder aggregator (usage is computed on read from UsageEvent rows for now). */
export async function usageRollup(_ctx: AppContext): Promise<void> {}

/** Wire queue handlers (called from buildContext). */
export function registerJobHandlers(ctx: AppContext) {
  ctx.jobs.register('template-builds', (d) =>
    runTemplateBuild(ctx, d as { projectId: string; buildId: string }),
  );
  ctx.jobs.register('session-provision', (d) => provisionSession(ctx, d as { sessionId: string }));
  ctx.jobs.register('session-idle-check', async () => void (await sessionIdleCheck(ctx)));
  ctx.jobs.register('cleanup-sandboxes', async () => void (await cleanupSandboxes(ctx)));
  ctx.jobs.register('orphan-reconciliation', async () => void (await orphanReconciliation(ctx)));
  ctx.jobs.register('key-health-check', async () => void (await keyHealthCheck(ctx)));
  ctx.jobs.register('usage-rollup', () => usageRollup(ctx));
  ctx.jobs.register(
    'approval-expiry',
    async (d) => void (await expireApprovals(ctx, d as { approvalId?: string })),
  );
}
