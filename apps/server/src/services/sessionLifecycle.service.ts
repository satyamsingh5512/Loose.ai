/**
 * Agent session lifecycle (spec §7.3, §10.5, §13.2, §16.5; Phase 4).
 * Named `sessionLifecycle` to avoid clashing with the auth `SessionService`.
 *
 * POST /sessions → preflight → Session QUEUED → `session-provision` job:
 *   STARTING → sandbox → clone → branch (GH-004 suffix retry) → .env with public
 *   URLs + runner config.json → services → startup commands → health check →
 *   RUNNING (+ `SessionHookRegistry.ready`, where the orchestrator starts the runner).
 * Every step publishes `session_status` on the SessionEventBus. Failures → ERRORED
 * with the step's LSE code. Pause/timeout/loss snapshot work to `refs/loose/wip/<id>`
 * first ("never lose the user's work").
 */
import { randomBytes } from 'node:crypto';
import type {
  ApiToken,
  AuthSession,
  Organization,
  OrgMember,
  Prisma,
  Project,
  Session,
  User,
} from '@prisma/client';
import {
  ACTIVE_SESSION_STATUSES,
  API_PREFIX,
  artifactDtoSchema,
  buildErrorEnvelope,
  DEFAULT_MAX_TURNS,
  DEFAULT_MODEL,
  getErrorDefinition,
  hasRoleAtLeast,
  isAdminRole,
  isRecoverableSessionStatus,
  parseOrgPolicy,
  resolveModelId,
  sessionBranchName,
  sessionDtoSchema,
  serializeRunnerConfig,
  wipRefName,
  approvalGatesSchema,
  commandPolicySchema,
  type ArtifactDto,
  type ArtifactKind,
  type ErrorCode,
  type Mode,
  type OrgSessionsQuery,
  type RunnerConfig,
  type HookEvent,
  type HookFailMode,
  type RunnerHookInput,
  type RunnerMcpServerInput,
  type RunnerSubagentInput,
  type SessionParticipantRole,
  type ShareRole,
  type Viewport,
  type SessionDto,
  type SessionStatus,
  type SessionStep,
  type StartSessionBody,
} from '@loose/shared';
import type { AppContext } from '../context';
import { BASE_SYSTEM_PROMPT } from '../lib/agentPrompt';
import { AppError } from '../lib/errors';
import { emitBudgetExceeded, emitSessionEvent } from '../lib/events/platformEvents';
import { pageArgs, toPage, type Page } from '../lib/pagination';
import type { SandboxHandle } from '../lib/sandbox';
import { enforceOrgAccess, orgAccessSubjectFromCaller } from './identity/accessPolicy';
import { decryptProjectEnv } from './project.service';
import { forkSession } from './fork.service';
import { prepareRunnerConfig } from './runnerConfig.service';
import { resolveGitAccess } from './gitAccess.service';
import { runnerLaunchFor, type SessionRuntime, type StopReason } from './sessionRuntime';
import { isTemplateOutdated, sandboxCreateError } from './template.service';
import {
  cloneRepo,
  createSessionBranch,
  firstPublicPort,
  pushWip,
  resolveSessionEnv,
  restoreBranch,
  restoreWip,
  runStartupCommands,
  secretValuesOf,
  startServices,
  StepFailure,
  waitForHealthy,
  writeEnvFile,
  type WorkspaceContext,
} from './workspace.service';

export interface Caller {
  user: User;
  apiToken?: ApiToken | undefined;
  ip?: string | undefined;
  /** Cookie session of the request (Phase 10: 2FA / SSO checks in enforceOrgAccess). */
  authSession?: AuthSession | undefined;
}

export type SessionRow = Session & {
  project: Pick<Project, 'name' | 'orgId' | 'maxSessionDurationMin'>;
  user: Pick<User, 'name' | 'email'>;
  /** Phase 9: participant who took control (shared sessions, spec §8.18). */
  controller?: Pick<User, 'name' | 'email'> | null;
};

export const sessionInclude = {
  project: { select: { name: true, orgId: true, maxSessionDurationMin: true } },
  user: { select: { name: true, email: true } },
  controller: { select: { name: true, email: true } },
} as const;

const ACTIVE = [...ACTIVE_SESSION_STATUSES] as SessionStatus[];

const ID_ALPHABET = '0123456789abcdefghijklmnopqrstuvwxyz';
/**
 * A `Session.wipRef` with this prefix means "restore by checking out that remote branch"
 * (resume of a delivered session, fork of a stopped one) instead of a WIP snapshot.
 */
export const REMOTE_BRANCH_REF_PREFIX = 'refs/heads/';

/** cuid-like id (so the branch name is known before insert). */
export function newId(): string {
  const bytes = randomBytes(24);
  let out = 'c';
  for (const b of bytes) out += ID_ALPHABET[b % 36];
  return out;
}

export function toSessionDto(ctx: AppContext, s: SessionRow, access?: SessionAccess): SessionDto {
  return sessionDtoSchema.parse({
    ...s,
    projectName: s.project.name,
    orgId: s.project.orgId,
    userName: s.user.name ?? s.user.email,
    controllerName: s.controller ? (s.controller.name ?? s.controller.email) : null,
    maxSessionDurationMin: s.project.maxSessionDurationMin,
    budgetUsd: s.budgetUsd,
    ...(access ? { access: { role: access.participantRole, canAct: access.canAct } } : {}),
    ...(s.status === 'RUNNING' ? { agentState: ctx.sessionHooks.agentState(s.id) ?? 'idle' } : {}),
  });
}

// ---- access ------------------------------------------------------------------------------

const TOKEN_SCOPES = { read: 'sessions:read', write: 'sessions:write' } as const;

export function assertTokenScope(caller: Caller, need: 'read' | 'write') {
  const t = caller.apiToken;
  if (t && !t.scopes.includes(TOKEN_SCOPES[need])) {
    throw new AppError('LSE-ORG-002', { devMessage: `API token lacks ${TOKEN_SCOPES[need]}` });
  }
}

export async function membershipFor(
  ctx: AppContext,
  caller: Caller,
  orgId: string,
): Promise<OrgMember | null> {
  if (caller.apiToken && caller.apiToken.orgId !== orgId) return null;
  const membership = await ctx.prisma.orgMember.findUnique({
    where: { userId_orgId: { userId: caller.user.id, orgId } },
  });
  // Phase 10 (W1): IP allowlist / SSO / admin 2FA for session, run and WS access.
  if (membership)
    await enforceOrgAccess(ctx, orgAccessSubjectFromCaller(caller), orgId, membership);
  return membership;
}

export interface SessionAccess {
  session: SessionRow;
  /**
   * The caller's org membership as it applies to THIS session. A collaborator invited as
   * `VIEWER` (spec §8.18) gets a copy with `role: 'VIEWER'`, so every existing write check
   * (`role === 'VIEWER'`) denies them without further changes.
   */
  membership: OrgMember;
  isOwner: boolean;
  isAdmin: boolean;
  /** Set when the caller takes part through a share rather than ownership / org admin. */
  collaboratorRole: ShareRole | null;
  /** How the caller takes part (presence, SessionDto.access). */
  participantRole: SessionParticipantRole;
  /** Another participant has taken control: write actions must fail with LSE-AGT-017. */
  controlledByOther: boolean;
  /** The caller may send messages, decide approvals and deliver. */
  canAct: boolean;
}

function sessionAccessOf(
  session: SessionRow,
  membership: OrgMember,
  userId: string,
  opts: { isOwner: boolean; isAdmin: boolean; collaboratorRole: ShareRole | null },
): SessionAccess {
  const { isOwner, isAdmin, collaboratorRole } = opts;
  const viewerOnly = !isOwner && !isAdmin && collaboratorRole === 'VIEWER';
  const effective: OrgMember =
    viewerOnly && membership.role !== 'VIEWER' ? { ...membership, role: 'VIEWER' } : membership;
  const participantRole: SessionParticipantRole = isOwner
    ? 'owner'
    : isAdmin
      ? 'admin'
      : collaboratorRole === 'CO_EDITOR'
        ? 'co_editor'
        : 'viewer';
  const controlledByOther = session.controllerId !== null && session.controllerId !== userId;
  return {
    session,
    membership: effective,
    isOwner,
    isAdmin,
    collaboratorRole,
    participantRole,
    controlledByOther,
    canAct: effective.role !== 'VIEWER' && !controlledByOther,
  };
}

/**
 * Load a session for a participant: the owner, an org ADMIN+, or a user the session was
 * shared with (spec §8.18). Sessions in orgs the caller doesn't belong to are reported as
 * not found (tenant isolation).
 */
export async function loadSessionForParticipant(
  ctx: AppContext,
  caller: Caller,
  sessionId: string,
): Promise<SessionAccess> {
  const session = await ctx.prisma.session.findUnique({
    where: { id: sessionId },
    include: sessionInclude,
  });
  const membership = session ? await membershipFor(ctx, caller, session.project.orgId) : null;
  if (!session || !membership)
    throw new AppError('LSE-NF-001', { devMessage: 'Session not found' });
  const isOwner = session.userId === caller.user.id;
  const isAdmin = isAdminRole(membership.role);
  const share =
    isOwner || isAdmin
      ? null
      : await ctx.prisma.sessionCollaborator.findUnique({
          where: { sessionId_userId: { sessionId: session.id, userId: caller.user.id } },
        });
  if (!isOwner && !isAdmin && !share) {
    throw new AppError('LSE-ORG-002', {
      devMessage:
        'Only the session owner, an org admin or an invited collaborator can access this session',
    });
  }
  return sessionAccessOf(session, membership, caller.user.id, {
    isOwner,
    isAdmin,
    collaboratorRole: share?.role ?? null,
  });
}

/** Viewers (org VIEWERs and VIEWER collaborators) may watch but never change anything. */
export function assertNotViewer(access: SessionAccess, what = 'act in sessions'): void {
  if (access.membership.role === 'VIEWER') {
    throw new AppError('LSE-ORG-002', { devMessage: `Viewers cannot ${what}` });
  }
}

/**
 * Gate for everything that changes a session (spec §8.18): viewers are refused, and while
 * another participant holds control the action is refused with LSE-AGT-017.
 */
export function assertCanAct(access: SessionAccess, what = 'act in sessions'): void {
  assertNotViewer(access, what);
  if (access.controlledByOther) {
    throw new AppError('LSE-AGT-017', {
      devMessage: 'Another participant has taken control of this session',
    });
  }
}

// ---- preflight ---------------------------------------------------------------------------

function startOfMonthUtc(now = new Date()): Date {
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
}

async function monthlySpend(ctx: AppContext, where: Prisma.UsageEventWhereInput): Promise<number> {
  const agg = await ctx.prisma.usageEvent.aggregate({
    where: { ...where, createdAt: { gte: startOfMonthUtc() } },
    _sum: { costUsd: true },
  });
  return Number(agg._sum.costUsd ?? 0);
}

export async function activeKeyFor(ctx: AppContext, userId: string) {
  const keys = await ctx.prisma.apiKey.findMany({
    where: { userId, orgId: null, provider: 'anthropic' },
    orderBy: { createdAt: 'desc' },
  });
  const active = keys.find((k) => k.status === 'ACTIVE');
  if (active) return active;
  if (keys.some((k) => k.status === 'INVALID')) {
    throw new AppError('LSE-KEY-003', { devMessage: 'The stored API key failed validation' });
  }
  throw new AppError('LSE-KEY-001', { devMessage: 'No active Anthropic API key' });
}

function resolveMode(
  requested: Mode | undefined,
  user: User,
  membership: OrgMember,
  org: Organization,
): Mode {
  const policy = parseOrgPolicy(org.policy);
  const locked =
    membership.lockedMode ??
    (membership.role === 'MEMBER' || membership.role === 'VIEWER'
      ? policy.lockedModes[membership.role]
      : undefined);
  return locked ?? requested ?? user.preferredMode;
}

/** Which monthly cap is used up (spec §8.19). */
export type MonthlyBudgetScope = 'org' | 'user' | 'key';

export interface ExceededBudget {
  scope: MonthlyBudgetScope;
  spentUsd: number;
  budgetUsd: number;
}

const BUDGET_DEV_MESSAGES: Record<MonthlyBudgetScope, string> = {
  org: 'Organization monthly budget reached',
  user: 'Your monthly budget in this organization is used up',
  key: 'The monthly limit set on your API key is reached',
};

export function budgetExceededError(scope: MonthlyBudgetScope): AppError {
  return new AppError('LSE-KEY-012', { devMessage: BUDGET_DEV_MESSAGES[scope] });
}

/** The first monthly cap (org → user → key) that is used up, or null. */
export async function findExceededBudget(
  ctx: AppContext,
  org: Organization,
  userId: string,
  key: { monthlyLimitUsd: Prisma.Decimal | null },
): Promise<ExceededBudget | null> {
  const policy = parseOrgPolicy(org.policy);
  const { orgMonthlyUsd, userMonthlyUsd } = policy.budgets;
  if (orgMonthlyUsd !== null) {
    const spent = await monthlySpend(ctx, { orgId: org.id });
    if (spent >= orgMonthlyUsd) return { scope: 'org', spentUsd: spent, budgetUsd: orgMonthlyUsd };
  }
  if (userMonthlyUsd !== null) {
    const spent = await monthlySpend(ctx, { orgId: org.id, userId });
    if (spent >= userMonthlyUsd)
      return { scope: 'user', spentUsd: spent, budgetUsd: userMonthlyUsd };
  }
  if (key.monthlyLimitUsd !== null) {
    const spent = await monthlySpend(ctx, { userId });
    const limit = Number(key.monthlyLimitUsd);
    if (spent >= limit) return { scope: 'key', spentUsd: spent, budgetUsd: limit };
  }
  return null;
}

export async function assertBudgets(
  ctx: AppContext,
  org: Organization,
  userId: string,
  key: { monthlyLimitUsd: Prisma.Decimal | null },
) {
  const hit = await findExceededBudget(ctx, org, userId, key);
  if (hit) throw budgetExceededError(hit.scope);
}

/** Counted inside a transaction holding the org advisory lock (no over-admission races). */
async function assertConcurrency(
  tx: Prisma.TransactionClient,
  org: Organization,
  userId: string,
  excludeSessionId?: string,
) {
  const policy = parseOrgPolicy(org.policy);
  await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext(${`sessions:${org.id}`}))::text`;
  const base: Prisma.SessionWhereInput = {
    project: { orgId: org.id },
    status: { in: ACTIVE },
    ...(excludeSessionId ? { id: { not: excludeSessionId } } : {}),
  };
  const mine = await tx.session.count({ where: { ...base, userId } });
  if (mine >= policy.maxConcurrentSessionsPerUser) {
    throw new AppError('LSE-SBX-011', {
      devMessage: `At most ${policy.maxConcurrentSessionsPerUser} active sessions per user`,
    });
  }
  const all = await tx.session.count({ where: base });
  if (all >= policy.maxConcurrentSessionsPerOrg) {
    throw new AppError('LSE-RATE-002', {
      devMessage: `At most ${policy.maxConcurrentSessionsPerOrg} active sessions per organization`,
    });
  }
}

/**
 * Internal start options (Phase 9). Not part of the public `POST /sessions` body:
 * headless runs pass `baseBranch`; forks pass the lineage and the snapshot to restore.
 */
export interface StartSessionExtras {
  /** Clone from / open the PR against this branch instead of the project default. */
  baseBranch?: string | null;
  parentSessionId?: string;
  forkedFromCheckpointId?: string;
  /** Snapshot ref on the remote (`refs/loose/wip/<id>` style) restored on first provision. */
  wipRef?: string;
  /** Initial session notes (forks copy the parent's). */
  notes?: string;
}

export async function startSession(
  ctx: AppContext,
  caller: Caller,
  body: StartSessionBody,
  extras: StartSessionExtras = {},
): Promise<SessionDto> {
  assertTokenScope(caller, 'write');
  // `POST /sessions {forkFrom}` is the same operation as `POST /sessions/:id/fork` (spec §10.5).
  if (body.forkFrom) {
    return forkSession(ctx, caller, body.forkFrom, {
      ...(body.checkpointId ? { checkpointId: body.checkpointId } : {}),
      ...(body.mode ? { mode: body.mode } : {}),
      ...(body.model ? { model: body.model } : {}),
    });
  }
  const project = await ctx.prisma.project.findUnique({
    where: { id: body.projectId },
    include: { org: true },
  });
  const membership = project ? await membershipFor(ctx, caller, project.orgId) : null;
  if (!project || !membership)
    throw new AppError('LSE-NF-001', { devMessage: 'Project not found' });
  if (!hasRoleAtLeast(membership.role, 'MEMBER')) {
    throw new AppError('LSE-ORG-002', { devMessage: 'Viewers cannot start sessions' });
  }
  const org = project.org;
  // Blue/green: any previously READY template keeps the project usable during a rebuild.
  if (!project.e2bTemplateId) {
    throw new AppError('LSE-TPL-001', {
      devMessage: `Template status is ${project.templateStatus}`,
    });
  }
  const templateOutdated = isTemplateOutdated(project);
  if (templateOutdated) {
    ctx.logger.info(
      { projectId: project.id, code: 'LSE-TPL-008' },
      'template is outdated (services changed)',
    );
  }
  const key = await activeKeyFor(ctx, caller.user.id);
  const model = resolveModelId(body.model ?? project.defaultModel ?? DEFAULT_MODEL);
  if (!model)
    throw new AppError('LSE-KEY-013', {
      devMessage: `Unknown model ${body.model ?? project.defaultModel}`,
    });
  const mode = resolveMode(body.mode, caller.user, membership, org);
  const exceeded = await findExceededBudget(ctx, org, caller.user.id, key);
  if (exceeded) {
    await emitBudgetExceeded(ctx, org.id, {
      scope: exceeded.scope,
      errorCode: 'LSE-KEY-012',
      action: 'blocked',
      userId: caller.user.id,
      projectId: project.id,
      sessionId: null,
      spentUsd: exceeded.spentUsd,
      budgetUsd: exceeded.budgetUsd,
    });
    throw budgetExceededError(exceeded.scope);
  }
  // Fail before queueing when nobody can clone the repo.
  await resolveGitAccess(ctx, {
    org,
    userId: caller.user.id,
    repoFullName: project.githubRepoFullName,
  }).catch((err: unknown) => {
    if (err instanceof AppError && err.code === 'LSE-GH-001') throw err;
  });

  const id = newId();
  const session = await ctx.prisma.$transaction(async (tx) => {
    await assertConcurrency(tx, org, caller.user.id);
    return tx.session.create({
      data: {
        id,
        projectId: project.id,
        userId: caller.user.id,
        mode,
        model,
        branchName: sessionBranchName(id),
        status: 'QUEUED',
        budgetUsd: project.maxBudgetUsd,
        baseBranch: extras.baseBranch ?? null,
        parentSessionId: extras.parentSessionId ?? null,
        forkedFromCheckpointId: extras.forkedFromCheckpointId ?? null,
        wipRef: extras.wipRef ?? null,
        ...(extras.notes !== undefined ? { notes: extras.notes } : {}),
      },
      include: sessionInclude,
    });
  });
  await ctx.audit.record({
    orgId: org.id,
    actorId: caller.user.id,
    action: 'session.start',
    target: session.id,
    meta: { projectId: project.id, mode, model },
    ip: caller.ip,
  });
  await publishStatus(ctx, session.id, 'QUEUED', undefined, 'Waiting for a workspace…', 0);
  if (templateOutdated) await publishError(ctx, session.id, 'LSE-TPL-008');
  await warnOtherActiveSessions(ctx, session);
  await ctx.jobs.enqueue(
    'session-provision',
    { sessionId: session.id },
    { jobId: `provision:${session.id}` },
  );
  return toSessionDto(ctx, session);
}

/** §8.14: tell the new session about other active sessions on the same project. */
async function warnOtherActiveSessions(ctx: AppContext, s: SessionRow) {
  const others = await ctx.prisma.session.findMany({
    where: { projectId: s.projectId, status: { in: ACTIVE }, id: { not: s.id } },
    include: { user: { select: { name: true, email: true } } },
    take: 5,
  });
  for (const o of others) {
    await ctx.sessionEvents.publish(s.id, 'conflict_warning', {
      otherSessionId: o.id,
      otherUserName: o.user.name ?? o.user.email,
      code: 'LSE-SBX-014',
      files: [],
      areas: [],
    });
  }
}

// ---- events ------------------------------------------------------------------------------

const STEP_PROGRESS: Record<SessionStep, [number, string]> = {
  provisioning: [0.05, 'Starting your workspace…'],
  cloning: [0.15, 'Copying the project…'],
  branching: [0.25, 'Preparing a safe copy for your changes…'],
  writing_env: [0.35, 'Configuring the app…'],
  syncing: [0.4, 'Loading project settings…'],
  starting_services: [0.45, 'Starting databases and services…'],
  installing: [0.55, 'Installing what the app needs…'],
  starting_app: [0.7, 'Starting the app…'],
  health_check: [0.85, 'Waiting for the app to respond…'],
  ready: [1, 'Ready'],
  stopping: [1, 'Stopping…'],
};

async function publishStatus(
  ctx: AppContext,
  sessionId: string,
  status: SessionStatus,
  step: SessionStep | undefined,
  message?: string,
  progress?: number,
) {
  const [p, m] = step ? STEP_PROGRESS[step] : [progress, message ?? status];
  try {
    await ctx.sessionEvents.publish(sessionId, 'session_status', {
      status,
      ...(step ? { step } : {}),
      ...(p !== undefined ? { progress: p } : {}),
      message: message ?? m ?? status,
    });
  } catch (err) {
    ctx.logger.warn({ err, sessionId }, 'failed to publish session_status');
  }
}

async function publishError(ctx: AppContext, sessionId: string, code: ErrorCode) {
  const def = getErrorDefinition(code);
  // devMessage is intentionally omitted: events also reach Simple-mode viewers.
  const { error } = buildErrorEnvelope(code, { requestId: `sess_${sessionId}` });
  await ctx.sessionEvents
    .publish(sessionId, 'error', { error, recoverable: def.recoverable && !def.fatal })
    .catch((err: unknown) => ctx.logger.warn({ err, sessionId }, 'failed to publish error'));
}

async function publishEnded(
  ctx: AppContext,
  s: Pick<Session, 'id' | 'status' | 'outcome' | 'prUrl' | 'errorCode'>,
) {
  await ctx.sessionEvents
    .publish(s.id, 'session_ended', {
      status: s.status,
      outcome: s.outcome,
      prUrl: s.prUrl,
      errorCode: s.errorCode,
    })
    .catch((err: unknown) =>
      ctx.logger.warn({ err, sessionId: s.id }, 'failed to publish session_ended'),
    );
}

// ---- provisioning ------------------------------------------------------------------------

/** Phase 7 inputs of the runner config (memory layers, skills, MCP). */
export interface RunnerConfigExtras {
  userMemory?: string | null;
  pluginDir?: string;
  skills?: string[];
  mcpServers?: RunnerMcpServerInput[];
  /** Subagents offered to the agent (spec §8.8). */
  subagents?: RunnerSubagentInput[];
  /** Hooks the runner evaluates itself (command / local built-in handlers; §8.9). */
  hooks?: RunnerHookInput[];
  /** Events for which the runner must ask the server (`hook_request`). */
  serverHookEvents?: HookEvent[];
  serverHookTimeoutMs?: number;
  serverHookFailMode?: HookFailMode;
}

const RUNNER_REPO_MEMORY = new Set(['prefer_loose', 'prefer_repo', 'ignore']);
const VIEWPORTS = new Set<string>(['desktop', 'tablet', 'mobile']);

/** Viewports for after-turn screenshots (spec §8.12), always including `desktop`. */
export function screenshotViewportsOf(project: Pick<Project, 'screenshotViewports'>): Viewport[] {
  const list = project.screenshotViewports.filter((v): v is Viewport => VIEWPORTS.has(v));
  return list.length ? [...new Set(list)] : ['desktop'];
}

export function buildRunnerConfig(
  ctx: AppContext,
  s: Session,
  project: Project,
  org: Organization,
  sandbox: SandboxHandle,
  extras: RunnerConfigExtras = {},
): RunnerConfig {
  const policy = parseOrgPolicy(org.policy);
  return JSON.parse(
    serializeRunnerConfig({
      v: 1,
      sessionId: s.id,
      workspaceDir: sandbox.paths.workspace,
      model: s.model,
      permissionMode: 'default',
      maxTurns: DEFAULT_MAX_TURNS,
      maxBudgetUsd: Math.min(1000, Math.max(0.01, Number(s.budgetUsd ?? project.maxBudgetUsd))),
      systemPrompt: {
        base: BASE_SYSTEM_PROMPT,
        projectContext: project.contextInstructions,
        looseMd: project.looseMd ?? '',
        orgMemory: org.memory ?? '',
        userMemory: extras.userMemory ?? '',
        sessionNotes: s.notes,
      },
      allowedFilePatterns: project.allowedFilePatterns,
      deniedFilePatterns: project.deniedFilePatterns,
      commandPolicy: commandPolicySchema.parse(project.commandPolicy ?? {}),
      approvalGates: approvalGatesSchema.parse(project.approvalGates ?? {}),
      networkAllowlist: project.networkAllowlist,
      approvalTimeoutMs: policy.approvalTimeoutMin * 60_000,
      ...(s.agentSessionId ? { resumeAgentSessionId: s.agentSessionId } : {}),
      ...(s.agentSessionId && s.resumeSessionAt ? { resumeSessionAt: s.resumeSessionAt } : {}),
      repoMemory: (RUNNER_REPO_MEMORY.has(project.repoMemory)
        ? project.repoMemory
        : 'prefer_loose') as RunnerConfig['repoMemory'],
      ...(extras.pluginDir ? { pluginDir: extras.pluginDir } : {}),
      skills: extras.skills ?? [],
      mcpServers: extras.mcpServers ?? [],
      subagents: extras.subagents ?? [],
      hooks: extras.hooks ?? [],
      serverHookEvents: extras.serverHookEvents ?? [],
      ...(extras.serverHookTimeoutMs !== undefined
        ? { serverHookTimeoutMs: extras.serverHookTimeoutMs }
        : {}),
      ...(extras.serverHookFailMode !== undefined
        ? { serverHookFailMode: extras.serverHookFailMode }
        : {}),
      autoCompactPercent: project.autoCompactPercent,
      screenshotViewports: screenshotViewportsOf(project),
      mock: ctx.env.RUNNER_MOCK,
    }),
  ) as RunnerConfig;
}

function sandboxTimeoutMs(ctx: AppContext) {
  return ctx.env.SANDBOX_TIMEOUT_MIN * 60_000;
}

/** Job handler for `session-provision`. Idempotent: only acts on QUEUED sessions. */
export async function provisionSession(
  ctx: AppContext,
  data: { sessionId: string },
): Promise<void> {
  const s = await ctx.prisma.session.findUnique({
    where: { id: data.sessionId },
    include: { project: { include: { org: true } } },
  });
  if (!s || s.status !== 'QUEUED') return;
  // A never-started session with a snapshot is a fork (restore, but not a "recover").
  const firstStart = s.startedAt === null;
  const claimed = await ctx.prisma.session.updateMany({
    where: { id: s.id, status: 'QUEUED' },
    data: { status: 'STARTING', startedAt: new Date(), errorCode: null, endedAt: null },
  });
  if (claimed.count === 0) return;
  // Phase 9: `baseBranch` (headless runs, PR-comment fixes) replaces the default branch.
  const project = s.baseBranch ? { ...s.project, defaultBranch: s.baseBranch } : s.project;
  const org = project.org;
  const restoring = s.wipRef !== null;
  const recovering = restoring && !firstStart;
  let sandbox: SandboxHandle | undefined;
  const stillStarting = async (data: Prisma.SessionUpdateManyMutationInput = {}) => {
    const r = await ctx.prisma.session.updateMany({
      where: { id: s.id, status: 'STARTING' },
      data,
    });
    if (r.count === 0)
      throw new StepFailure(
        'create_sandbox',
        new AppError('LSE-SBX-002', { devMessage: 'Session was stopped during provisioning' }),
      );
  };

  try {
    if (!project.e2bTemplateId) {
      throw new StepFailure(
        'create_sandbox',
        new AppError('LSE-TPL-001', { devMessage: 'Project has no template' }),
      );
    }
    await publishStatus(ctx, s.id, 'STARTING', 'provisioning');
    try {
      sandbox = await ctx.sandbox.createFromTemplate(project.e2bTemplateId, {
        timeoutMs: sandboxTimeoutMs(ctx),
        metadata: { app: 'loose', sessionId: s.id, projectId: project.id, orgId: org.id },
      });
    } catch (err) {
      throw new StepFailure('create_sandbox', sandboxCreateError(err));
    }
    await stillStarting({ sandboxId: sandbox.id });

    const projectEnv = await decryptProjectEnv(ctx, project);
    const secrets = secretValuesOf(projectEnv);
    const w: WorkspaceContext = {
      ctx,
      sandbox,
      project,
      secrets,
      reporter: { log: (line) => ctx.logger.debug({ sessionId: s.id, line }, 'provision') },
    };

    await publishStatus(ctx, s.id, 'STARTING', 'cloning');
    const access = await resolveGitAccess(ctx, {
      org,
      userId: s.userId,
      repoFullName: project.githubRepoFullName,
    }).catch((err: unknown) => {
      throw new StepFailure(
        'clone',
        err instanceof AppError ? err : new AppError('LSE-SBX-003', { cause: err }),
      );
    });
    await cloneRepo(w, access);

    await publishStatus(ctx, s.id, 'STARTING', 'branching');
    if (restoring && s.wipRef) {
      // A `refs/heads/…` snapshot is a resume/fork from a pushed branch: check out that
      // branch tip (commits stay committed). Everything else is a WIP snapshot.
      if (s.wipRef.startsWith(REMOTE_BRANCH_REF_PREFIX)) {
        await restoreBranch(
          w,
          access,
          s.wipRef.slice(REMOTE_BRANCH_REF_PREFIX.length),
          s.branchName,
        );
      } else {
        await restoreWip(w, access, s.wipRef, s.branchName);
      }
    } else {
      const branch = await createSessionBranch(w, access, s.branchName);
      if (branch !== s.branchName) await stillStarting({ branchName: branch });
    }

    await publishStatus(ctx, s.id, 'STARTING', 'writing_env');
    const vars = resolveSessionEnv(project, sandbox, projectEnv);
    await writeEnvFile(w, vars);
    await publishStatus(ctx, s.id, 'STARTING', 'syncing');
    const fresh = await ctx.prisma.session.findUniqueOrThrow({ where: { id: s.id } });
    const { config: runnerConfig } = await prepareRunnerConfig(ctx, fresh, sandbox);

    await publishStatus(ctx, s.id, 'STARTING', 'starting_services');
    await startServices(w);
    const { appProcesses } = await runStartupCommands(w, vars, async (phase) => {
      await publishStatus(ctx, s.id, 'STARTING', phase);
    });

    await publishStatus(ctx, s.id, 'STARTING', 'health_check');
    await waitForHealthy(w, appProcesses);

    const front = firstPublicPort(project);
    const previewUrl = front ? sandbox.getUrl(front.port) : null;
    const runtime: SessionRuntime = {
      sessionId: s.id,
      sandbox,
      appProcesses,
      extensions: new Map(),
    };
    ctx.sessionRuntime.set(runtime);
    await stillStarting({ status: 'RUNNING', previewUrl, idleSince: new Date() });
    const running = await ctx.prisma.session.findUniqueOrThrow({ where: { id: s.id } });
    await publishStatus(ctx, s.id, 'RUNNING', 'ready');
    if (previewUrl) {
      await ctx.sessionEvents
        .publish(s.id, 'preview_updated', { url: previewUrl, reason: 'ready' })
        .catch(() => undefined);
    }
    if (recovering) {
      await ctx.audit.record({
        orgId: org.id,
        actorId: s.userId,
        action: 'session.recover',
        target: s.id,
        meta: { restoredFrom: s.wipRef },
      });
    }
    try {
      await ctx.sessionHooks.ready({
        session: running,
        project,
        runtime,
        runnerConfig,
        runnerLaunch: runnerLaunchFor(sandbox, ctx.env.RUNNER_MOCK),
        recovered: recovering,
      });
      await emitSessionEvent(ctx, 'session.started', s.id, { resumed: recovering });
    } catch (err) {
      const appErr = err instanceof AppError ? err : new AppError('LSE-AGT-001', { cause: err });
      await stopSession(ctx, s.id, {
        to: 'ERRORED',
        reason: 'error',
        errorCode: appErr.code,
        pushWip: true,
        from: ['RUNNING'],
      });
    }
  } catch (err) {
    await failProvisioning(ctx, s.id, sandbox, err);
  }
}

async function failProvisioning(
  ctx: AppContext,
  sessionId: string,
  sandbox: SandboxHandle | undefined,
  err: unknown,
) {
  const appErr =
    err instanceof StepFailure
      ? err.error
      : err instanceof AppError
        ? err
        : new AppError('LSE-SBX-002', { cause: err });
  ctx.logger.warn(
    {
      sessionId,
      code: appErr.code,
      step: err instanceof StepFailure ? err.step : undefined,
      devMessage: appErr.devMessage,
    },
    'session provisioning failed',
  );
  ctx.sessionRuntime.delete(sessionId);
  if (sandbox) await sandbox.kill().catch(() => undefined);
  const r = await ctx.prisma.session.updateMany({
    where: { id: sessionId, status: { in: ['STARTING', 'QUEUED'] } },
    data: { status: 'ERRORED', errorCode: appErr.code, endedAt: new Date(), sandboxId: null },
  });
  if (r.count === 0) return;
  await publishError(ctx, sessionId, appErr.code);
  await publishStatus(
    ctx,
    sessionId,
    'ERRORED',
    undefined,
    getErrorDefinition(appErr.code).userMessage,
  );
  const s = await ctx.prisma.session.findUnique({ where: { id: sessionId } });
  if (s) await publishEnded(ctx, s);
  await emitSessionEvent(ctx, 'session.errored', sessionId);
}

// ---- stop / pause / timeout --------------------------------------------------------------

export interface StopOptions {
  to: Extract<SessionStatus, 'PAUSED' | 'TIMED_OUT' | 'ERRORED' | 'COMPLETED'>;
  reason: StopReason;
  errorCode?: ErrorCode;
  /** Snapshot work to the WIP ref before killing the sandbox. */
  pushWip: boolean;
  /** Abort (leave the session running) when the WIP push fails. */
  requireWip?: boolean;
  /** Statuses this transition may start from (default RUNNING). */
  from?: SessionStatus[];
  actorId?: string;
}

/** Live handle from this process' registry, else reattach via the provider. */
export async function getOrConnectSandbox(ctx: AppContext, s: Pick<Session, 'id' | 'sandboxId'>) {
  const rt = ctx.sessionRuntime.get(s.id);
  if (rt) return rt.sandbox;
  if (!s.sandboxId) return null;
  try {
    return await ctx.sandbox.connect(s.sandboxId);
  } catch {
    return null;
  }
}

/**
 * Stop a session's sandbox and move it to `to`. Returns false when the session was
 * not in a `from` status or (with requireWip) the WIP push failed.
 */
export async function stopSession(
  ctx: AppContext,
  sessionId: string,
  opts: StopOptions,
): Promise<boolean> {
  const from = opts.from ?? ['RUNNING'];
  const s = await ctx.prisma.session.findUnique({
    where: { id: sessionId },
    include: { project: { include: { org: true } } },
  });
  if (!s || !from.includes(s.status)) return false;
  const claimed = await ctx.prisma.session.updateMany({
    where: { id: s.id, status: { in: from } },
    data: { status: 'STOPPING' },
  });
  if (claimed.count === 0) return false;
  await publishStatus(ctx, s.id, 'STOPPING', 'stopping');

  const runtime = ctx.sessionRuntime.get(s.id);
  const sandbox = await getOrConnectSandbox(ctx, s);
  await ctx.sessionHooks.stopping(s.id, opts.reason, runtime, (err) =>
    ctx.logger.warn({ err, sessionId: s.id }, 'onSessionStopping hook failed'),
  );

  let wipRef = s.wipRef;
  if (opts.pushWip && sandbox && (await sandbox.isRunning())) {
    let ok = false;
    try {
      const access = await resolveGitAccess(ctx, {
        org: s.project.org,
        userId: s.userId,
        repoFullName: s.project.githubRepoFullName,
      });
      const env = await decryptProjectEnv(ctx, s.project);
      ok = await pushWip(
        {
          ctx,
          sandbox,
          project: s.project,
          secrets: secretValuesOf(env),
          reporter: { log: () => undefined },
        },
        access,
        wipRefName(s.id),
      );
    } catch (err) {
      ctx.logger.warn({ err, sessionId: s.id }, 'WIP push failed');
    }
    if (ok) wipRef = wipRefName(s.id);
    else if (opts.requireWip) {
      await ctx.prisma.session.updateMany({
        where: { id: s.id, status: 'STOPPING' },
        data: { status: s.status },
      });
      await publishStatus(ctx, s.id, s.status, undefined, 'Still running');
      return false;
    }
  }

  if (sandbox)
    await sandbox
      .kill()
      .catch((err: unknown) => ctx.logger.warn({ err, sessionId: s.id }, 'sandbox kill failed'));
  else if (s.sandboxId) await ctx.sandbox.kill(s.sandboxId).catch(() => false);
  ctx.sessionRuntime.delete(s.id);

  const ended = opts.to !== 'PAUSED';
  const updated = await ctx.prisma.session.update({
    where: { id: s.id },
    data: {
      status: opts.to,
      sandboxId: null,
      runnerPid: null,
      idleSince: null,
      wipRef,
      ...(opts.errorCode ? { errorCode: opts.errorCode } : {}),
      ...(ended ? { endedAt: new Date() } : {}),
    },
  });
  if (opts.errorCode) await publishError(ctx, s.id, opts.errorCode);
  await publishStatus(
    ctx,
    s.id,
    opts.to,
    undefined,
    opts.to === 'PAUSED'
      ? 'Paused — your work is saved'
      : opts.errorCode
        ? getErrorDefinition(opts.errorCode).userMessage
        : 'Session ended',
  );
  await publishEnded(ctx, updated);
  if (opts.to === 'COMPLETED') await emitSessionEvent(ctx, 'session.completed', s.id);
  else if (opts.to === 'ERRORED' || opts.to === 'TIMED_OUT')
    await emitSessionEvent(ctx, 'session.errored', s.id);
  await ctx.audit.record({
    orgId: s.project.orgId,
    actorId: opts.actorId ?? null,
    action: 'session.stop',
    target: s.id,
    meta: {
      reason: opts.reason,
      status: opts.to,
      wipSaved: wipRef !== null,
      errorCode: opts.errorCode ?? null,
    },
  });
  return true;
}

// ---- recover -----------------------------------------------------------------------------

export interface RequeueOptions {
  /**
   * Snapshot restored on the next provision. `refs/heads/<branch>` checks that branch out
   * at its tip; anything else is treated as a WIP snapshot. Omit to keep the current ref.
   */
  wipRef?: string;
  /** Simple-mode progress text for the QUEUED status event. */
  message?: string;
}

/**
 * Put a stopped session back in the provisioning queue (recover, spec §8.13; resume, §8.14).
 * Re-runs the preflight the session's OWNER would face (key, monthly budgets, concurrency)
 * because the session keeps running on their key, and hands control back to them.
 */
export async function requeueSession(
  ctx: AppContext,
  session: SessionRow,
  opts: RequeueOptions = {},
): Promise<SessionDto> {
  const project = await ctx.prisma.project.findUniqueOrThrow({
    where: { id: session.projectId },
    include: { org: true },
  });
  if (!project.e2bTemplateId) throw new AppError('LSE-TPL-001');
  // The session keeps running on its owner's key and budget.
  const key = await activeKeyFor(ctx, session.userId);
  await assertBudgets(ctx, project.org, session.userId, key);
  if (session.sandboxId) await ctx.sandbox.kill(session.sandboxId).catch(() => false);
  await ctx.prisma.$transaction(async (tx) => {
    await assertConcurrency(tx, project.org, session.userId, session.id);
    const r = await tx.session.updateMany({
      where: { id: session.id, status: session.status },
      data: {
        status: 'QUEUED',
        errorCode: null,
        endedAt: null,
        sandboxId: null,
        previewUrl: null,
        runnerPid: null,
        // A restarted session is driven by its owner again (spec §8.18).
        controllerId: null,
        controlTakenAt: null,
        ...(opts.wipRef !== undefined ? { wipRef: opts.wipRef } : {}),
      },
    });
    if (r.count === 0)
      throw new AppError('LSE-CONF-001', { devMessage: 'Session changed while restarting' });
  });
  await publishStatus(
    ctx,
    session.id,
    'QUEUED',
    undefined,
    opts.message ?? 'Restoring your workspace…',
    0,
  );
  await ctx.jobs.enqueue(
    'session-provision',
    { sessionId: session.id },
    { jobId: `provision:${session.id}:${Date.now()}` },
  );
  const fresh = await ctx.prisma.session.findUniqueOrThrow({
    where: { id: session.id },
    include: sessionInclude,
  });
  return toSessionDto(ctx, fresh);
}

export async function recoverSession(
  ctx: AppContext,
  caller: Caller,
  sessionId: string,
): Promise<SessionDto> {
  assertTokenScope(caller, 'write');
  const access = await loadSessionForParticipant(ctx, caller, sessionId);
  assertNotViewer(access, 'restart sessions');
  if (!isRecoverableSessionStatus(access.session.status)) {
    throw new AppError('LSE-CONF-001', {
      devMessage: `Cannot recover a ${access.session.status} session`,
    });
  }
  return requeueSession(ctx, access.session);
}

// ---- queries -----------------------------------------------------------------------------

export async function getSession(
  ctx: AppContext,
  caller: Caller,
  sessionId: string,
): Promise<SessionDto> {
  assertTokenScope(caller, 'read');
  const access = await loadSessionForParticipant(ctx, caller, sessionId);
  return toSessionDto(ctx, access.session, access);
}

/** Members see their own sessions; admins see everyone's (with optional filters). */
export async function listOrgSessions(
  ctx: AppContext,
  orgId: string,
  membership: OrgMember,
  q: OrgSessionsQuery,
): Promise<Page<SessionDto>> {
  const admin = isAdminRole(membership.role);
  const where: Prisma.SessionWhereInput = {
    project: { orgId },
    ...(admin ? (q.userId ? { userId: q.userId } : {}) : { userId: membership.userId }),
    ...(q.status ? { status: q.status } : {}),
    ...(q.projectId ? { projectId: q.projectId } : {}),
    ...(q.outcome ? { outcome: q.outcome } : {}),
  };
  const rows = await ctx.prisma.session.findMany({
    where,
    include: sessionInclude,
    orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
    ...pageArgs(q),
  });
  return toPage(rows, q.limit, (r) => toSessionDto(ctx, r));
}

/** Active sessions on a project (dashboard / conflict awareness). Others' preview URLs are hidden. */
export async function listActiveProjectSessions(
  ctx: AppContext,
  orgId: string,
  projectId: string,
  membership: OrgMember,
): Promise<SessionDto[]> {
  const project = await ctx.prisma.project.findFirst({ where: { id: projectId, orgId } });
  if (!project) throw new AppError('LSE-NF-001', { devMessage: 'Project not found in this org' });
  const rows = await ctx.prisma.session.findMany({
    where: { projectId, status: { in: ACTIVE } },
    include: sessionInclude,
    orderBy: { createdAt: 'desc' },
    take: 100,
  });
  const admin = isAdminRole(membership.role);
  return rows.map((r) => {
    const dto = toSessionDto(ctx, r);
    return admin || r.userId === membership.userId
      ? dto
      : { ...dto, previewUrl: null, prUrl: null };
  });
}

// ---- artifacts ---------------------------------------------------------------------------

export function artifactContentUrl(sessionId: string, artifactId: string): string {
  return `${API_PREFIX}/sessions/${sessionId}/artifacts/${artifactId}/content`;
}

function toArtifactDto(a: {
  id: string;
  sessionId: string;
  kind: string;
  meta: Prisma.JsonValue;
  createdAt: Date;
}): ArtifactDto {
  return artifactDtoSchema.parse({
    id: a.id,
    kind: a.kind,
    url: artifactContentUrl(a.sessionId, a.id),
    meta: a.meta && typeof a.meta === 'object' && !Array.isArray(a.meta) ? a.meta : null,
    createdAt: a.createdAt,
  });
}

const EXT: Record<string, string> = {
  'image/png': 'png',
  'image/jpeg': 'jpg',
  'image/webp': 'webp',
  'image/gif': 'gif',
  'application/pdf': 'pdf',
  'text/plain': 'txt',
  'application/json': 'json',
  'text/x-diff': 'diff',
};

/** EXTENSION POINT: persist an artifact (screenshot, log, diff) for a session. */
export async function saveArtifact(
  ctx: AppContext,
  input: {
    sessionId: string;
    kind: ArtifactKind;
    data: Uint8Array | string;
    contentType: string;
    meta?: Record<string, unknown>;
  },
): Promise<ArtifactDto> {
  const id = newId();
  const key = `sessions/${input.sessionId}/${id}.${EXT[input.contentType] ?? 'bin'}`;
  const { bytes } = await ctx.storage.put(key, input.data);
  const row = await ctx.prisma.artifact.create({
    data: {
      id,
      sessionId: input.sessionId,
      kind: input.kind,
      url: artifactContentUrl(input.sessionId, id),
      storageKey: key,
      contentType: input.contentType,
      bytes,
      meta: (input.meta ?? {}) as Prisma.InputJsonValue,
    },
  });
  return toArtifactDto(row);
}

export async function listArtifacts(
  ctx: AppContext,
  caller: Caller,
  sessionId: string,
): Promise<ArtifactDto[]> {
  assertTokenScope(caller, 'read');
  const { session } = await loadSessionForParticipant(ctx, caller, sessionId);
  const rows = await ctx.prisma.artifact.findMany({
    where: { sessionId: session.id },
    orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
    take: 500,
  });
  return rows.map(toArtifactDto);
}

export async function openArtifact(
  ctx: AppContext,
  caller: Caller,
  sessionId: string,
  artifactId: string,
) {
  assertTokenScope(caller, 'read');
  const { session } = await loadSessionForParticipant(ctx, caller, sessionId);
  const row = await ctx.prisma.artifact.findFirst({
    where: { id: artifactId, sessionId: session.id },
  });
  const obj = row?.storageKey ? await ctx.storage.get(row.storageKey) : null;
  if (!row || !obj) throw new AppError('LSE-NF-001', { devMessage: 'Artifact not found' });
  return { row, obj };
}
