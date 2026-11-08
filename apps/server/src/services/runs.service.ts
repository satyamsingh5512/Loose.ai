/**
 * Headless runs (spec §8.15, §10.6; Phase 9) — OWNED BY W1.
 *
 * A run = prompt → agent session → optional pull request, driven without a browser:
 *
 *   createRun   preflight + `startSession` (BYOK key, budgets, concurrency, template) → Run row
 *   driver      PROVISIONING → (session ready) send the prompt once → RUNNING
 *               ⇄ WAITING_APPROVAL (tool/plan approvals, decided via the sessions API)
 *               → turn completed → CREATING_PR (when `createPr` and files changed) → SUCCEEDED
 *   failures    blocking turn errors / session errored, timed out or ended → FAILED with the
 *               catalog code; cancel → CANCELLED
 *
 * Every transition is a DB compare-and-set (`updateMany` on the expected status), so several
 * drivers (API reconcile, a trigger worker) can never both create the PR or both finalize. Every
 * terminal transition emits the internal `run.completed` platform event (W4 posts results back).
 *
 * The driver hosts the agent runner in its own process (same as a WS-served session); with several
 * API instances a run is driven by the instance that created it, and `runs-reconcile` re-attaches
 * orphans (Phase 10 will move this to a dedicated runner service).
 */
import type { Prisma, Project, Run, Session } from '@prisma/client';
import {
  chatMessageDtoSchema,
  hasRoleAtLeast,
  isAdminRole,
  isTerminalRunStatus,
  runClientMessageId,
  runDtoSchema,
  runOptionsSchema,
  toSimpleChatMessage,
  type ListRunsQuery,
  type Mode,
  type RunDto,
  type RunOptions,
  type RunSource,
  type RunStatus,
  type ServerMessage,
} from '@loose/shared';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';
import { sessionWebUrl, type TurnCompletedData } from '../lib/events/platformEvents';
import { deliverableFor } from '../lib/events/sessionEventBus';
import { pageArgs, toPage, type Page } from '../lib/pagination';
import { assertScopes } from '../middleware/requireScope';
import type { PlatformRole } from '../platform/register';
import { createPr } from './delivery.service';
import { withAttachments } from './orchestrator.service';
import {
  activeKeyFor,
  findExceededBudget,
  membershipFor,
  startSession,
  stopSession,
  type Caller,
} from './sessionLifecycle.service';

export interface CreateRunInput {
  projectId: string;
  prompt: string;
  options: RunOptions;
  source: RunSource;
  triggerId?: string;
  externalRef?: Record<string, unknown>;
  metadata?: Record<string, string>;
}

export type RunStreamEvent =
  | { kind: 'status'; run: RunDto }
  | { kind: 'event'; message: ServerMessage }
  | { kind: 'end'; run: RunDto };

type RunWithRefs = Run & {
  project: { name: string };
  session: Pick<Session, 'totalCostUsd'> | null;
};

const runInclude = {
  project: { select: { name: true } },
  session: { select: { totalCostUsd: true } },
} as const;

/** Statuses a driver may still move out of. */
const ACTIVE_RUN_STATUSES: RunStatus[] = [
  'QUEUED',
  'PROVISIONING',
  'RUNNING',
  'WAITING_APPROVAL',
  'CREATING_PR',
];
const TERMINAL: RunStatus[] = ['SUCCEEDED', 'FAILED', 'CANCELLED'];

/** Driver safety net: re-evaluate the run this often even without events. */
const DRIVER_POLL_MS = 5_000;
/** Without a local `session.started` (provisioned by a worker), host the runner after this. */
const READY_GRACE_MS = 3_000;
/** A run still active after this long is failed by the reconcile job (LSE-SBX-009). */
export const RUN_MAX_AGE_MS = 24 * 60 * 60 * 1000;
/** A run stuck in CREATING_PR this long lost its driver mid-PR: fail it instead of waiting. */
export const RUN_PR_STALE_MS = 10 * 60 * 1000;
const MAX_SUMMARY_CHARS = 20_000;

// ---- DTO ----------------------------------------------------------------------------------

function toRunDto(ctx: AppContext, r: RunWithRefs): RunDto {
  const live = !isTerminalRunStatus(r.status) && r.session !== null;
  return runDtoSchema.parse({
    id: r.id,
    orgId: r.orgId,
    projectId: r.projectId,
    projectName: r.project.name,
    userId: r.userId,
    sessionId: r.sessionId,
    sessionUrl: r.sessionId ? sessionWebUrl(ctx, r.sessionId) : null,
    status: r.status,
    source: r.source,
    prompt: r.prompt,
    options: runOptionsSchema.parse(r.options ?? {}),
    metadata: r.metadata ?? {},
    triggerId: r.triggerId,
    summary: r.summary,
    filesChanged: r.filesChanged,
    prUrl: r.prUrl,
    prNumber: r.prNumber,
    errorCode: r.errorCode,
    // While running, show the live session cost; the run keeps its own total once finished.
    costUsd: Number(live ? r.session!.totalCostUsd : r.costUsd),
    createdAt: r.createdAt,
    startedAt: r.startedAt,
    endedAt: r.endedAt,
  });
}

async function loadRunDto(ctx: AppContext, runId: string): Promise<RunDto | null> {
  const row = await ctx.prisma.run.findUnique({ where: { id: runId }, include: runInclude });
  return row ? toRunDto(ctx, row) : null;
}

// ---- per-context state: drivers + in-process status streams --------------------------------

type StreamListener = (e: RunStreamEvent) => void;

interface RunsState {
  drivers: Map<string, RunDriver>;
  bySession: Map<string, RunDriver>;
  streams: Map<string, Set<StreamListener>>;
  /** Sessions whose runner came up in this process (a driver may be created after the event). */
  started: Set<string>;
}

const states = new WeakMap<AppContext, RunsState>();

function stateOf(ctx: AppContext): RunsState {
  let s = states.get(ctx);
  if (!s) {
    s = { drivers: new Map(), bySession: new Map(), streams: new Map(), started: new Set() };
    states.set(ctx, s);
  }
  return s;
}

function broadcast(ctx: AppContext, runId: string, e: RunStreamEvent): void {
  for (const l of stateOf(ctx).streams.get(runId) ?? []) {
    try {
      l(e);
    } catch (err) {
      ctx.logger.warn({ err, runId }, 'run stream listener failed');
    }
  }
}

/** Push the current run state to in-process subscribers (and `end` once terminal). */
async function publishRun(ctx: AppContext, runId: string): Promise<RunDto | null> {
  const dto = await loadRunDto(ctx, runId);
  if (!dto) return null;
  broadcast(ctx, runId, { kind: 'status', run: dto });
  if (isTerminalRunStatus(dto.status)) broadcast(ctx, runId, { kind: 'end', run: dto });
  return dto;
}

/**
 * Subscribe to a run's progress. `status` / `end` come from the process that drives the run (SSE
 * additionally polls the DB, so other instances stay correct); `event`s are the session's
 * `ServerMessage`s filtered for the run's mode (pass `{events:false}` to skip them).
 */
export function subscribeRun(
  ctx: AppContext,
  runId: string,
  listener: (e: RunStreamEvent) => void,
  opts: { events?: boolean } = {},
): () => void {
  const st = stateOf(ctx);
  let set = st.streams.get(runId);
  if (!set) {
    set = new Set();
    st.streams.set(runId, set);
  }
  set.add(listener);
  let closed = false;
  let off: (() => void) | undefined;
  if (opts.events !== false) {
    void (async () => {
      const r = await ctx.prisma.run.findUnique({
        where: { id: runId },
        select: { sessionId: true, session: { select: { mode: true } } },
      });
      if (closed || !r?.sessionId) return;
      const mode: Mode = r.session?.mode ?? 'PRO';
      off = ctx.sessionEvents.subscribe(r.sessionId, (message, audience) => {
        const m = deliverableFor({ message, audience }, mode);
        if (m) listener({ kind: 'event', message: m });
      });
    })().catch((err: unknown) => ctx.logger.warn({ err, runId }, 'run event subscribe failed'));
  }
  return () => {
    closed = true;
    off?.();
    set.delete(listener);
    if (set.size === 0 && st.streams.get(runId) === set) st.streams.delete(runId);
  };
}

// ---- access -------------------------------------------------------------------------------

async function loadRunFor(
  ctx: AppContext,
  caller: Caller,
  runId: string,
  need: 'read' | 'write',
): Promise<RunWithRefs> {
  assertScopes(caller, need === 'read' ? 'runs:read' : 'runs:write');
  const row = await ctx.prisma.run.findUnique({ where: { id: runId }, include: runInclude });
  const membership = row ? await membershipFor(ctx, caller, row.orgId) : null;
  if (!row || !membership) throw new AppError('LSE-NF-001', { devMessage: 'Run not found' });
  if (row.userId !== caller.user.id && !isAdminRole(membership.role)) {
    throw new AppError('LSE-ORG-002', {
      devMessage: 'Only the run owner or an org admin can access this run',
    });
  }
  return row;
}

// ---- project resolution ---------------------------------------------------------------------

/**
 * Find the project of a run request: by id, or by `project` = id | name | `owner/repo`. API tokens
 * are bound to one org; cookie callers search every org they belong to (or the given `orgId`).
 */
export async function resolveRunProject(
  ctx: AppContext,
  caller: Caller,
  ref: { projectId?: string; project?: string; orgId?: string },
): Promise<Project> {
  const notFound = () => new AppError('LSE-NF-001', { devMessage: 'Project not found' });
  if (ref.projectId) {
    const p = await ctx.prisma.project.findUnique({ where: { id: ref.projectId } });
    if (!p || !(await membershipFor(ctx, caller, p.orgId))) throw notFound();
    if (ref.orgId && ref.orgId !== p.orgId) throw notFound();
    return p;
  }
  const needle = (ref.project ?? '').trim();
  if (!needle) throw notFound();

  let orgIds: string[];
  if (caller.apiToken) {
    if (ref.orgId && ref.orgId !== caller.apiToken.orgId) {
      throw new AppError('LSE-ORG-001', { devMessage: 'API token is scoped to a different org' });
    }
    orgIds = [caller.apiToken.orgId];
  } else if (ref.orgId) {
    if (!(await membershipFor(ctx, caller, ref.orgId))) throw new AppError('LSE-ORG-001');
    orgIds = [ref.orgId];
  } else {
    const rows = await ctx.prisma.orgMember.findMany({
      where: { userId: caller.user.id },
      select: { orgId: true },
    });
    orgIds = rows.map((r) => r.orgId);
  }
  const candidates = await ctx.prisma.project.findMany({
    where: {
      orgId: { in: orgIds },
      OR: [
        { id: needle },
        { githubRepoFullName: { equals: needle, mode: 'insensitive' } },
        { name: { equals: needle, mode: 'insensitive' } },
      ],
    },
    orderBy: { createdAt: 'asc' },
    take: 10,
  });
  // An exact id or repo match beats a name match.
  const exact = candidates.filter(
    (p) => p.id === needle || p.githubRepoFullName.toLowerCase() === needle.toLowerCase(),
  );
  const pool = exact.length > 0 ? exact : candidates;
  if (pool.length === 0) throw notFound();
  if (pool.length > 1) {
    throw new AppError('LSE-VAL-001', {
      devMessage: `"${needle}" matches ${pool.length} projects; pass projectId (and orgId)`,
      fields: { project: ['Matches more than one project; use the project id'] },
    });
  }
  return pool[0]!;
}

// ---- create ---------------------------------------------------------------------------------

export async function createRun(
  ctx: AppContext,
  caller: Caller,
  input: CreateRunInput,
): Promise<RunDto> {
  assertScopes(caller, 'runs:write');
  const project = await ctx.prisma.project.findUnique({ where: { id: input.projectId } });
  const membership = project ? await membershipFor(ctx, caller, project.orgId) : null;
  if (!project || !membership)
    throw new AppError('LSE-NF-001', { devMessage: 'Project not found' });
  if (!hasRoleAtLeast(membership.role, 'MEMBER')) {
    throw new AppError('LSE-ORG-002', { devMessage: 'Viewers cannot start runs' });
  }

  // Preflight errors (key, budgets, concurrency, template…) surface as-is; no Run row is kept.
  // `runs:write` was checked above, so the session start runs without the token's session scope.
  const owner: Caller = { user: caller.user, ip: caller.ip };
  const session = await startSession(
    ctx,
    owner,
    {
      projectId: project.id,
      ...(input.options.mode ? { mode: input.options.mode } : {}),
      ...(input.options.model ? { model: input.options.model } : {}),
    },
    input.options.branch ? { baseBranch: input.options.branch } : {},
  );

  let row: RunWithRefs;
  try {
    row = await ctx.prisma.run.create({
      data: {
        orgId: project.orgId,
        projectId: project.id,
        userId: caller.user.id,
        sessionId: session.id,
        apiTokenId: caller.apiToken?.id ?? null,
        triggerId: input.triggerId ?? null,
        source: input.source,
        status: 'PROVISIONING',
        prompt: input.prompt,
        options: input.options as unknown as Prisma.InputJsonValue,
        metadata: (input.metadata ?? {}) as Prisma.InputJsonValue,
        ...(input.externalRef ? { externalRef: input.externalRef as Prisma.InputJsonValue } : {}),
      },
      include: runInclude,
    });
  } catch (err) {
    // The session exists but nothing will ever drive it: release it.
    ctx.logger.error({ err, sessionId: session.id }, 'could not record the run');
    void stopSession(ctx, session.id, { to: 'PAUSED', reason: 'stopped', pushWip: false }).catch(
      () => undefined,
    );
    throw err;
  }
  await ctx.audit.record({
    orgId: project.orgId,
    actorId: caller.user.id,
    action: 'run.create',
    target: row.id,
    meta: {
      projectId: project.id,
      sessionId: session.id,
      source: input.source,
      createPr: input.options.createPr,
      via: caller.apiToken ? 'token' : 'session',
      ...(input.triggerId ? { triggerId: input.triggerId } : {}),
    },
    ip: caller.ip,
  });
  ensureDriver(ctx, row, true);
  return toRunDto(ctx, row);
}

// ---- read / list / cancel ----------------------------------------------------------------------

export async function getRun(ctx: AppContext, caller: Caller, runId: string): Promise<RunDto> {
  return toRunDto(ctx, await loadRunFor(ctx, caller, runId, 'read'));
}

/**
 * Members see their own runs, admins every run of the org. API tokens only reach their own org;
 * cookie callers see all their orgs (narrow with `?orgId`).
 */
export async function listRuns(
  ctx: AppContext,
  caller: Caller,
  q: ListRunsQuery,
): Promise<Page<RunDto>> {
  assertScopes(caller, 'runs:read');
  let orgIds: string[];
  if (caller.apiToken) {
    if (q.orgId && q.orgId !== caller.apiToken.orgId) {
      throw new AppError('LSE-ORG-001', { devMessage: 'API token is scoped to a different org' });
    }
    orgIds = [caller.apiToken.orgId];
  } else {
    orgIds = (
      await ctx.prisma.orgMember.findMany({
        where: { userId: caller.user.id, ...(q.orgId ? { orgId: q.orgId } : {}) },
        select: { orgId: true },
      })
    ).map((m) => m.orgId);
    if (q.orgId && orgIds.length === 0) throw new AppError('LSE-ORG-001');
  }
  const memberships = await ctx.prisma.orgMember.findMany({
    where: { userId: caller.user.id, orgId: { in: orgIds } },
  });
  const scopes: Prisma.RunWhereInput[] = memberships.map((m) =>
    isAdminRole(m.role) ? { orgId: m.orgId } : { orgId: m.orgId, userId: caller.user.id },
  );
  if (scopes.length === 0) return { data: [], nextCursor: null };
  const rows = await ctx.prisma.run.findMany({
    where: {
      OR: scopes,
      ...(q.status ? { status: q.status } : {}),
      ...(q.projectId ? { projectId: q.projectId } : {}),
      ...(q.triggerId ? { triggerId: q.triggerId } : {}),
    },
    include: runInclude,
    orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
    ...pageArgs({ limit: q.limit, ...(q.cursor ? { cursor: q.cursor } : {}) }),
  });
  return toPage(rows, q.limit, (r) => toRunDto(ctx, r));
}

export async function cancelRun(ctx: AppContext, caller: Caller, runId: string): Promise<RunDto> {
  const run = await loadRunFor(ctx, caller, runId, 'write');
  if (isTerminalRunStatus(run.status)) {
    throw new AppError('LSE-CONF-001', { devMessage: `The run is already ${run.status}` });
  }
  // Claim first so a driver racing with us cannot also finalize or open a PR.
  const done = await finishRun(ctx, run.id, ACTIVE_RUN_STATUSES, { status: 'CANCELLED' }, 'pause', {
    interruptAs: { user: caller.user, ip: caller.ip },
  });
  if (!done) throw new AppError('LSE-CONF-001', { devMessage: 'The run just finished' });
  await ctx.audit.record({
    orgId: run.orgId,
    actorId: caller.user.id,
    action: 'run.cancel',
    target: run.id,
    meta: { from: run.status, sessionId: run.sessionId },
    ip: caller.ip,
  });
  return done;
}

// ---- finishing (shared by the driver, cancel and reconcile) ---------------------------------------

interface FinishPatch {
  status: Extract<RunStatus, 'SUCCEEDED' | 'FAILED' | 'CANCELLED'>;
  errorCode?: string | null;
  summary?: string | null;
  prUrl?: string | null;
  prNumber?: number | null;
  filesChanged?: string[];
}

/**
 * Move a run to a terminal status exactly once (compare-and-set on `from`), then — outside the
 * claim — release the session, notify streams and emit `run.completed`. Returns the final DTO, or
 * null when someone else already finished the run.
 */
async function finishRun(
  ctx: AppContext,
  runId: string,
  from: RunStatus[],
  patch: FinishPatch,
  session: 'pause' | 'keep',
  opts: { interruptAs?: Caller } = {},
): Promise<RunDto | null> {
  const run = await ctx.prisma.run.findUnique({
    where: { id: runId },
    include: { session: { select: { totalCostUsd: true, status: true } } },
  });
  if (!run || !from.includes(run.status)) return null;
  const claimed = await ctx.prisma.run.updateMany({
    where: { id: runId, status: { in: from } },
    data: {
      status: patch.status,
      endedAt: new Date(),
      costUsd: run.session?.totalCostUsd ?? run.costUsd,
      ...(patch.errorCode !== undefined ? { errorCode: patch.errorCode } : {}),
      ...(patch.summary !== undefined ? { summary: patch.summary } : {}),
      ...(patch.prUrl !== undefined ? { prUrl: patch.prUrl } : {}),
      ...(patch.prNumber !== undefined ? { prNumber: patch.prNumber } : {}),
      ...(patch.filesChanged !== undefined ? { filesChanged: patch.filesChanged } : {}),
    },
  });
  if (claimed.count === 0) return null;

  if (session === 'pause' && run.sessionId) {
    if (opts.interruptAs && run.session?.status === 'RUNNING') {
      await ctx.agent.interrupt(opts.interruptAs, run.sessionId).catch(() => undefined);
    }
    // Keep the work: snapshot to the WIP ref and pause (Resume continues from there).
    await stopSession(ctx, run.sessionId, {
      to: 'PAUSED',
      reason: 'stopped',
      pushWip: true,
      ...(opts.interruptAs ? { actorId: opts.interruptAs.user.id } : {}),
    }).catch((err: unknown) =>
      ctx.logger.warn({ err, runId, sessionId: run.sessionId }, 'could not pause the run session'),
    );
  }

  const dto = await publishRun(ctx, runId);
  const final = await ctx.prisma.run.findUniqueOrThrow({ where: { id: runId } });
  await ctx.platformEvents.emit('run.completed', final.orgId, {
    runId,
    sessionId: final.sessionId,
    projectId: final.projectId,
    triggerId: final.triggerId,
    status: final.status,
    prUrl: final.prUrl,
    prNumber: final.prNumber,
    errorCode: final.errorCode,
    summary: final.summary,
    externalRef:
      final.externalRef &&
      typeof final.externalRef === 'object' &&
      !Array.isArray(final.externalRef)
        ? (final.externalRef as Record<string, unknown>)
        : null,
  });
  stateOf(ctx).drivers.get(runId)?.dispose();
  return dto;
}

function errorCodeOf(err: unknown, fallback = 'LSE-SYS-001'): string {
  return err instanceof AppError ? err.code : fallback;
}

// ---- the driver -------------------------------------------------------------------------------

class RunDriver {
  #chain: Promise<void> = Promise.resolve();
  #unsubscribe: (() => void) | undefined;
  #timer: NodeJS.Timeout | undefined;
  #disposed = false;
  /** `session.started` was observed in this process: the runner is up and may be prompted. */
  #ready = false;

  constructor(
    private readonly ctx: AppContext,
    readonly runId: string,
    readonly sessionId: string,
    /** Hosts the runner and sends the prompt (false = only settle runs whose session ended). */
    private readonly host: boolean,
  ) {
    this.#ready = stateOf(ctx).started.has(sessionId);
  }

  start(): void {
    if (this.host) {
      this.#unsubscribe = this.ctx.sessionEvents.subscribe(this.sessionId, (m) => {
        if (
          m.type === 'session_status' ||
          m.type === 'session_ended' ||
          m.type === 'approval_required' ||
          m.type === 'plan_proposed' ||
          m.type === 'approval_resolved'
        ) {
          this.kick();
        }
      });
      this.#timer = setInterval(() => this.kick(), DRIVER_POLL_MS);
      this.#timer.unref();
    }
    this.kick();
  }

  markReady(): void {
    this.#ready = true;
    this.kick();
  }

  kick(): Promise<void> {
    return this.#enqueue(() => this.#tick());
  }

  onTurn(data: TurnCompletedData): Promise<void> {
    return this.#enqueue(() => this.#handleTurn(data));
  }

  /** Resolves once everything queued so far has run (tests). */
  idle(): Promise<void> {
    return this.#chain;
  }

  dispose(): void {
    if (this.#disposed) return;
    this.#disposed = true;
    this.#unsubscribe?.();
    if (this.#timer) clearInterval(this.#timer);
    const st = stateOf(this.ctx);
    if (st.drivers.get(this.runId) === this) st.drivers.delete(this.runId);
    if (st.bySession.get(this.sessionId) === this) st.bySession.delete(this.sessionId);
    st.started.delete(this.sessionId);
  }

  #enqueue(fn: () => Promise<void>): Promise<void> {
    this.#chain = this.#chain.then(fn).catch((err: unknown) => {
      this.ctx.logger.warn({ err, runId: this.runId }, 'run driver step failed');
    });
    return this.#chain;
  }

  async #setStatus(from: RunStatus[], to: RunStatus): Promise<boolean> {
    const r = await this.ctx.prisma.run.updateMany({
      where: { id: this.runId, status: { in: from } },
      data: { status: to, ...(to === 'RUNNING' ? { startedAt: new Date() } : {}) },
    });
    if (r.count > 0) await publishRun(this.ctx, this.runId);
    return r.count > 0;
  }

  /** Evaluate the run against its session and move it forward. Idempotent. */
  async #tick(): Promise<void> {
    if (this.#disposed) return;
    const run = await this.ctx.prisma.run.findUnique({
      where: { id: this.runId },
      include: { session: true },
    });
    if (!run || isTerminalRunStatus(run.status)) return this.dispose();
    const s = run.session;
    if (!s) {
      await finishRun(
        this.ctx,
        run.id,
        ACTIVE_RUN_STATUSES,
        {
          status: 'FAILED',
          errorCode: 'LSE-NF-001',
        },
        'keep',
      );
      return;
    }
    switch (s.status) {
      case 'QUEUED':
      case 'STARTING':
        if (run.status === 'QUEUED') await this.#setStatus(['QUEUED'], 'PROVISIONING');
        return;
      case 'RUNNING':
        if (!this.host) return;
        if (run.status === 'QUEUED' || run.status === 'PROVISIONING') {
          if (!this.#ready && !this.#provisionedElsewhere(s)) return;
          await this.#start(run);
        } else if (run.status === 'RUNNING' || run.status === 'WAITING_APPROVAL') {
          await this.#syncApproval(run);
        }
        return;
      case 'STOPPING':
        return;
      default:
        // PAUSED / COMPLETED / ERRORED / TIMED_OUT while the run is unfinished.
        // (CREATING_PR ends its own session; the PR flow settles the run.)
        if (run.status !== 'CREATING_PR') await this.#sessionEnded(run, s);
    }
  }

  /** RUNNING for a while with no local runtime: a worker provisioned it; attach lazily. */
  #provisionedElsewhere(s: Session): boolean {
    if (this.ctx.agent.hasRuntime(s.id)) return false;
    const since = (s.startedAt ?? s.updatedAt).getTime();
    return Date.now() - since >= READY_GRACE_MS;
  }

  async #start(run: Run): Promise<void> {
    if (!(await this.#setStatus(['QUEUED', 'PROVISIONING'], 'RUNNING'))) return;
    try {
      const user = await this.ctx.prisma.user.findUniqueOrThrow({ where: { id: run.userId } });
      // Idempotent through the clientMessageId: a second driver cannot send the prompt twice.
      await this.ctx.agent.sendMessage({ user }, this.sessionId, {
        content: run.prompt,
        clientMessageId: runClientMessageId(run.id),
      });
    } catch (err) {
      await finishRun(
        this.ctx,
        run.id,
        ACTIVE_RUN_STATUSES,
        {
          status: 'FAILED',
          errorCode: errorCodeOf(err, 'LSE-AGT-001'),
        },
        'pause',
      );
    }
  }

  /** Pending tool/plan approvals ⇒ WAITING_APPROVAL; all decided ⇒ back to RUNNING. */
  async #syncApproval(run: Run): Promise<void> {
    const pending = await this.ctx.prisma.toolApproval.count({
      where: { sessionId: this.sessionId, status: 'PENDING' },
    });
    if (pending > 0 && run.status === 'RUNNING')
      await this.#setStatus(['RUNNING'], 'WAITING_APPROVAL');
    else if (pending === 0 && run.status === 'WAITING_APPROVAL') {
      await this.#setStatus(['WAITING_APPROVAL'], 'RUNNING');
    }
  }

  async #sessionEnded(run: Run, s: Session): Promise<void> {
    const all = ACTIVE_RUN_STATUSES;
    switch (s.status) {
      case 'ERRORED':
      case 'TIMED_OUT':
        await finishRun(
          this.ctx,
          run.id,
          all,
          {
            status: 'FAILED',
            errorCode: s.errorCode ?? (s.status === 'TIMED_OUT' ? 'LSE-SBX-009' : 'LSE-AGT-001'),
          },
          'keep',
        );
        return;
      case 'PAUSED':
        // Paused with an error (budget…) failed; paused by a person means they stopped the run.
        await finishRun(
          this.ctx,
          run.id,
          all,
          s.errorCode ? { status: 'FAILED', errorCode: s.errorCode } : { status: 'CANCELLED' },
          'keep',
        );
        return;
      case 'COMPLETED':
        // Someone delivered (or discarded) the session from the UI.
        await finishRun(
          this.ctx,
          run.id,
          all,
          s.outcome === 'DISCARDED' || !s.outcome
            ? { status: 'CANCELLED' }
            : {
                status: 'SUCCEEDED',
                prUrl: s.prUrl,
                prNumber: s.prNumber,
              },
          'keep',
        );
        return;
      default:
    }
  }

  async #summaryOf(messageId: string, mode: Mode): Promise<string | null> {
    try {
      const row = await this.ctx.prisma.chatMessage.findUnique({ where: { id: messageId } });
      if (!row) return null;
      const raw =
        row.rawContent && typeof row.rawContent === 'object' && !Array.isArray(row.rawContent)
          ? (row.rawContent as Record<string, unknown>)
          : null;
      const proText = typeof raw?.proText === 'string' ? raw.proText : undefined;
      const dto = chatMessageDtoSchema.parse({
        ...row,
        content: mode === 'PRO' && proText ? proText : row.content,
        metadata: withAttachments(row.metadata, row.attachments),
      });
      const text = (mode === 'PRO' ? dto : toSimpleChatMessage(dto)).content.trim();
      return text ? text.slice(0, MAX_SUMMARY_CHARS) : null;
    } catch (err) {
      this.ctx.logger.warn({ err, runId: this.runId }, 'could not read the run summary');
      return null;
    }
  }

  /**
   * The orchestrator pauses a session asynchronously once a budget is used up, so a turn can
   * complete "successfully" a moment before the stop lands. Decide from the numbers instead of
   * racing it: a run whose session budget or monthly cap is exhausted cannot continue (no PR).
   */
  async #exhaustedBudget(): Promise<'LSE-AGT-003' | 'LSE-KEY-012' | null> {
    try {
      const s = await this.ctx.prisma.session.findUniqueOrThrow({
        where: { id: this.sessionId },
        include: { project: { include: { org: true } } },
      });
      const budget = Number(s.budgetUsd ?? 0);
      if (budget > 0 && Number(s.totalCostUsd) >= budget) return 'LSE-AGT-003';
      const key = await activeKeyFor(this.ctx, s.userId);
      return (await findExceededBudget(this.ctx, s.project.org, s.userId, key))
        ? 'LSE-KEY-012'
        : null;
    } catch {
      return null;
    }
  }

  async #handleTurn(data: TurnCompletedData): Promise<void> {
    const run = await this.ctx.prisma.run.findUnique({
      where: { id: this.runId },
      include: { session: { select: { mode: true } } },
    });
    if (!run || (run.status !== 'RUNNING' && run.status !== 'WAITING_APPROVAL')) return;
    const live: RunStatus[] = ['RUNNING', 'WAITING_APPROVAL'];

    if (data.planPending) {
      await this.#setStatus(['RUNNING'], 'WAITING_APPROVAL');
      return;
    }
    if (data.errorCode) {
      await finishRun(
        this.ctx,
        run.id,
        live,
        { status: 'FAILED', errorCode: data.errorCode },
        'pause',
      );
      return;
    }
    if (data.interrupted) {
      await finishRun(this.ctx, run.id, live, { status: 'CANCELLED' }, 'pause');
      return;
    }

    const exhausted = await this.#exhaustedBudget();
    if (exhausted) {
      await finishRun(
        this.ctx,
        run.id,
        live,
        { status: 'FAILED', errorCode: exhausted, filesChanged: data.filesChanged },
        'pause',
      );
      return;
    }

    const options = runOptionsSchema.parse(run.options ?? {});
    const summary = await this.#summaryOf(data.messageId, run.session?.mode ?? 'PRO');
    const files = data.filesChanged;

    if (!options.createPr || files.length === 0) {
      // Nothing to submit: keep the work on the WIP ref and pause the session.
      await finishRun(
        this.ctx,
        run.id,
        live,
        { status: 'SUCCEEDED', summary, filesChanged: files },
        'pause',
      );
      return;
    }

    // Claim the PR step: only one driver may open the pull request.
    const claimed = await this.ctx.prisma.run.updateMany({
      where: { id: run.id, status: { in: live } },
      data: { status: 'CREATING_PR', summary, filesChanged: files },
    });
    if (claimed.count === 0) return;
    await publishRun(this.ctx, run.id);
    try {
      const user = await this.ctx.prisma.user.findUniqueOrThrow({ where: { id: run.userId } });
      const res = await createPr(this.ctx, { user }, this.sessionId, {
        draft: options.draft,
        ...(options.prTitle ? { title: options.prTitle } : {}),
        ...(options.prNotes ? { notes: options.prNotes } : {}),
      });
      await finishRun(
        this.ctx,
        run.id,
        ['CREATING_PR'],
        {
          status: 'SUCCEEDED',
          prUrl: res.prUrl,
          prNumber: res.prNumber,
        },
        'keep',
      );
    } catch (err) {
      if (err instanceof AppError && err.code === 'LSE-GH-008') {
        // Nothing new to submit (or a PR already exists): the run still did its job.
        await finishRun(this.ctx, run.id, ['CREATING_PR'], { status: 'SUCCEEDED' }, 'pause');
        return;
      }
      await finishRun(
        this.ctx,
        run.id,
        ['CREATING_PR'],
        {
          status: 'FAILED',
          errorCode: errorCodeOf(err),
        },
        'pause',
      );
    }
  }
}

function ensureDriver(
  ctx: AppContext,
  run: Pick<Run, 'id' | 'sessionId'>,
  host: boolean,
): RunDriver | null {
  if (!run.sessionId) return null;
  const st = stateOf(ctx);
  const existing = st.drivers.get(run.id);
  if (existing) {
    void existing.kick();
    return existing;
  }
  const d = new RunDriver(ctx, run.id, run.sessionId, host);
  st.drivers.set(run.id, d);
  st.bySession.set(run.sessionId, d);
  d.start();
  return d;
}

/** Wait until the in-process driver of a run has processed everything queued (tests, tooling). */
export async function runDriverIdle(ctx: AppContext, runId: string): Promise<void> {
  await stateOf(ctx).drivers.get(runId)?.idle();
}

// ---- reconcile + registration ----------------------------------------------------------------------

/**
 * Re-attach drivers for unfinished runs (API boot / every minute) and fail runs that outlived
 * {@link RUN_MAX_AGE_MS}. Workers only settle runs whose session already ended.
 */
export async function reconcileRuns(
  ctx: AppContext,
  role: PlatformRole = ctx.platformRole,
  now: Date = new Date(),
): Promise<{ attached: number; failedStale: number }> {
  const rows = await ctx.prisma.run.findMany({
    where: { status: { in: ACTIVE_RUN_STATUSES } },
    orderBy: { createdAt: 'asc' },
    take: 200,
  });
  let attached = 0;
  let failedStale = 0;
  for (const r of rows) {
    if (now.getTime() - r.createdAt.getTime() > RUN_MAX_AGE_MS) {
      const done = await finishRun(
        ctx,
        r.id,
        ACTIVE_RUN_STATUSES,
        {
          status: 'FAILED',
          errorCode: 'LSE-SBX-009',
        },
        'pause',
      );
      if (done) failedStale += 1;
      continue;
    }
    if (
      r.status === 'CREATING_PR' &&
      !stateOf(ctx).drivers.has(r.id) &&
      now.getTime() - r.updatedAt.getTime() > RUN_PR_STALE_MS
    ) {
      const done = await finishRun(
        ctx,
        r.id,
        ['CREATING_PR'],
        { status: 'FAILED', errorCode: 'LSE-SYS-001' },
        'pause',
      );
      if (done) failedStale += 1;
      continue;
    }
    if (role === 'api') {
      if (!stateOf(ctx).drivers.has(r.id)) attached += 1;
      ensureDriver(ctx, r, true);
    } else if (r.sessionId) {
      // Settle-only: a throw-away driver that never hosts the runner.
      const d = new RunDriver(ctx, r.id, r.sessionId, false);
      await d.kick();
      d.dispose();
    }
  }
  return { attached, failedStale };
}

/** Subscribe the driver to platform events and register the reconcile job. */
export function registerRunsService(ctx: AppContext, role: PlatformRole): void {
  const st = stateOf(ctx);
  ctx.jobs.register('runs-reconcile', async () => {
    await reconcileRuns(ctx, role);
  });
  ctx.platformEvents.on('session.started', async (e) => {
    const id = e.data.session.id;
    st.started.add(id);
    // Bounded: only sessions that become runs are ever consumed.
    if (st.started.size > 1000) st.started.delete(st.started.values().next().value as string);
    st.bySession.get(id)?.markReady();
    // A run cancelled while its session was still provisioning must not keep a live sandbox.
    const run = await ctx.prisma.run.findUnique({
      where: { sessionId: id },
      select: { status: true },
    });
    if (run && TERMINAL.includes(run.status) && run.status !== 'SUCCEEDED') {
      void stopSession(ctx, id, { to: 'PAUSED', reason: 'stopped', pushWip: true }).catch(
        () => undefined,
      );
    }
  });
  ctx.platformEvents.on('session.turn_completed', (e) => {
    // Detached: the bus awaits listeners and the turn flow must not wait for the PR.
    void st.bySession.get(e.data.sessionId)?.onTurn(e.data);
  });
  const onEnd = (e: { data: { session: { id: string } } }) => {
    void st.bySession.get(e.data.session.id)?.kick();
  };
  ctx.platformEvents.on('session.errored', onEnd);
  ctx.platformEvents.on('session.completed', onEnd);
  // Re-attach drivers of runs that were in flight when this API process (re)started.
  if (role === 'api' && ctx.env.NODE_ENV !== 'test') {
    const t = setTimeout(() => {
      reconcileRuns(ctx, role).catch((err: unknown) =>
        ctx.logger.warn({ err }, 'run reconcile on boot failed'),
      );
    }, 2_000);
    t.unref();
  }
}
