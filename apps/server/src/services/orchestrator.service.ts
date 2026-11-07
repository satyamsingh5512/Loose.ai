/**
 * Agent orchestrator (spec §8.2, §11 "Standard Turn Flow", §15, §16.5; Phases 5–6).
 *
 * One `AgentRuntime` per RUNNING session held by THIS process: it starts the runner
 * (`node /sandbox-agent/runner/dist/cli.js`, stdin kept open) inside the sandbox, feeds it
 * NDJSON commands and turns its NDJSON events into WS events through the Output
 * Translation Layer, with policy checks, usage/budget accounting, approvals, post-turn
 * guardrails (path patterns + secret detection with auto-revert), risk labels, change
 * summaries and screenshots.
 *
 * Process model: the runner lives in the process that owns the session's WebSocket
 * traffic (the API process). When provisioning ran elsewhere (worker) or after an API
 * restart, the runtime is attached lazily (`ensureRuntime`) on the first WS join / message.
 * Multi-instance deployments need session affinity (sticky routing by session id).
 *
 * Phase 7: a checkpoint before every turn (code snapshot + conversation anchor) with
 * rewind (code / conversation / both), plan-mode turns that end in a plan approval,
 * session notes, MCP servers (secret env, status) and skills via the runner config.
 */
import type { ApiKey, Organization, Prisma, Project, Role, Session } from '@prisma/client';
import {
  appendSessionNote,
  assessRisk,
  buildErrorEnvelope,
  buildPlanApprovalPrompt,
  chatMessageDtoSchema,
  classifyCommand,
  computeCostUsd,
  CONTEXT_WARNING_PERCENT,
  costLevel,
  diffStats,
  elementLabel,
  encodeRunnerCommand,
  gateForFile,
  getErrorDefinition,
  inspectResultDtoSchema,
  isAdminRole,
  isPathAllowed,
  isSimpleContextUpdate,
  LOOP_DETECTION_THRESHOLD,
  makeRunnerCommand,
  MAX_RUNNER_RESTARTS,
  MIN_EXTRA_SECRET_LENGTH,
  normalizeWorkspacePath,
  parseOrgPolicy,
  parseRunnerLine,
  parseQuickNote,
  planSteps,
  remainingBudgetUsd,
  resolveModelId,
  riskForChange,
  scrubSecrets,
  scrubSecretsDeep,
  shouldAutoPlan,
  toolApprovalDtoSchema,
  toSimpleChatMessage,
  type AgentPermissionMode,
  type AgentState,
  type ApprovalGate,
  type ChatMessageDto,
  type ChatAttachment,
  type ChatMessageMetadata,
  type ContextUsageDto,
  type ErrorCode,
  type HookPayload,
  type InspectBody,
  type InspectResultDto,
  type Mode,
  type RewindResultDto,
  type RewindScope,
  type RiskLevel,
  type RunnerCommandInput,
  type RunnerEvent,
  type RunnerEventData,
  type SendMessageBody,
  type ServerMessageType,
  type ServerPayloadInput,
  type ToolApprovalDto,
  type Viewport,
  type BudgetScope,
} from '@loose/shared';
import type { AppContext } from '../context';
import { SessionOwnerLease } from '../lib/events/cluster';
import type { EventAudience } from '../lib/events/sessionEventBus';
import { AppError } from '../lib/errors';
import { emitBudgetExceeded, emitTurnCompleted } from '../lib/events/platformEvents';
import { sleep } from '../lib/resilience';
import type { BackgroundProcess, SandboxHandle } from '../lib/sandbox';
import { decryptApiKey } from './apiKey.service';
import { viewerMode } from './agentChat.service';
import {
  createCheckpoint,
  deleteCheckpointRefs,
  hideFrom,
  restoreWorkspace,
  toCheckpointDto,
} from './checkpoint.service';
import { recordMcpStatuses } from './extensions.service';
import { elementPromptContext, loadRunnerAttachments } from './attachments.service';
import {
  evaluateServerHooks,
  blockedPaths,
  isServerHandled,
  runLifecycleHooks,
  type ResolvedHook,
} from './hooks.service';
import {
  addedLines,
  gitStatus,
  parseUnifiedDiff,
  revertPaths,
  statusKind,
  workingDiff,
  type StatusEntry,
} from './gitWorkspace.service';
import { decryptProjectEnv } from './project.service';
import {
  activeKeyFor,
  assertBudgets,
  assertCanAct,
  assertTokenScope,
  findExceededBudget,
  getOrConnectSandbox,
  loadSessionForParticipant,
  newId,
  saveArtifact,
  stopSession,
  type Caller,
  type SessionAccess,
} from './sessionLifecycle.service';
import {
  runnerLaunchFor,
  type RunnerLaunch,
  type SessionReadyContext,
  type StopReason,
} from './sessionRuntime';
import {
  defaultTranslator,
  type Streamer,
  type TranslationContext,
  type Translator,
} from './translation';
import { prepareRunnerConfig } from './runnerConfig.service';
import { secretValuesOf } from './workspace.service';

const RUNTIME_KEY = 'agent';
const SCREENSHOT_TIMEOUT_MS = 30_000;
const RUNNER_SHUTDOWN_GRACE_MS = 5_000;
const RAW_FLUSH_EVERY = 25;
const MAX_RAW_EVENTS = 500;
const STDERR_LOG_MAX = 500;

// ---- runtime state ---------------------------------------------------------------------

interface QueuedMessage {
  /** USER ChatMessage id. */
  id: string;
  /** Text for the agent (may differ from what the chat shows, e.g. commands). */
  content: string;
  /** Checkpoint label (default: `content`). */
  label?: string;
  plan?: boolean;
  allowedTools?: string[];
  model?: string;
  attachments?: ChatAttachment[];
}

/** A user turn submitted by chat, a slash command or a plan approval. */
export interface TurnRequest {
  /** What the chat shows as the USER message. */
  content: string;
  /** Sent to the agent (default: `content`). */
  agentText?: string;
  clientMessageId?: string;
  attachments?: ChatAttachment[];
  /** Run in plan mode (`manual` = asked for, `auto` = heuristic / project setting). */
  plan?: 'manual' | 'auto';
  allowedTools?: string[];
  model?: string;
  /** Slash command / quick action that produced the turn. */
  command?: string;
  label?: string;
}

interface ToolCall {
  name: string;
  input: Record<string, unknown>;
  startedAt: number;
}

interface Turn {
  userMessageId: string;
  /** Id of the ASSISTANT ChatMessage (also the `agent_streaming.messageId`). */
  assistantId: string;
  startedAt: number;
  raw: unknown[];
  rawRowCreated: boolean;
  texts: string[];
  deltaText: string;
  streamers: { simple: Streamer; pro: Streamer };
  toolsUsed: Set<string>;
  /** Subagents the turn delegated to (`usage.subagent`, `Task` tool calls). */
  subagents: Set<string>;
  commands: string[];
  tools: Map<string, ToolCall>;
  lastToolKey?: string;
  repeat: number;
  loopStopped: boolean;
  hasErrors: boolean;
  interrupted: boolean;
  errorCode?: ErrorCode;
  done: boolean;
  /** Plan-mode turn. */
  plan: boolean;
  /** Plan proposed by the agent (plan_proposed). */
  planText?: string;
  /** Conversation anchor reported by turn_complete. */
  anchor?: string;
}

interface ProjectInfo {
  project: Project;
  org: Organization;
  ownerRole: Role;
  /** Exact values redacted from every output (all project env values ≥ 6 chars). */
  scrubValues: string[];
  /** Values that must never be committed (secret-flagged env vars + the API key). */
  diffSecrets: string[];
  tctx: TranslationContext;
}

interface AgentRuntime {
  sessionId: string;
  userId: string;
  userName: string;
  sandbox: SandboxHandle;
  launch: RunnerLaunch;
  info: ProjectInfo;
  runner?: BackgroundProcess;
  lineBuf: string;
  chain: Promise<void>;
  busy: boolean;
  state: AgentState;
  queue: QueuedMessage[];
  turn: Turn | null;
  restarts: number;
  lastErrorCode?: ErrorCode;
  warned: boolean;
  stopping: boolean;
  budgetStopping: boolean;
  previewUrl: string | null;
  /** Per-viewport before/after screenshots of the running turn (spec §8.12). */
  beforeShots: Map<Viewport, string>;
  lastAfterShots: Map<Viewport, string>;
  screenshotViewports: Viewport[];
  shots: Map<string, (r: RunnerEventData<'screenshot_result'>) => void>;
  /** In-flight `inspect` requests (click-to-select). */
  inspects: Map<string, (r: RunnerEventData<'inspect_result'>) => void>;
  /** Hooks that apply to this session (org + project + plugins; spec §8.9). */
  hooks: ResolvedHook[];
  /** MCP secrets for the runner process env (never on disk). */
  mcpEnv: Record<string, string>;
  /** MCP server name → McpServer id. */
  mcpIds: Map<string, string>;
  /** MCP servers already reported as failing (LSE-MCP-001/002 once per runtime). */
  mcpWarned: Set<string>;
  /** Conversation anchor after the last turn (`undefined` = look it up, `null` = none). */
  lastAnchor?: string | null;
  agentSessionId: string | null;
  /** A rewind / clear is in progress (no new turns). */
  rewinding: boolean;
}

export interface SendMessageResult {
  message: ChatMessageDto;
  queued: boolean;
  duplicate?: boolean;
}

function errorPayload(code: ErrorCode, sessionId: string) {
  const def = getErrorDefinition(code);
  const { error } = buildErrorEnvelope(code, { requestId: `sess_${sessionId}` });
  // `recoverable` here = the session can continue.
  return { error, recoverable: !def.fatal };
}

/** Errors that end the turn's useful work (shown as the turn outcome). */
const BLOCKING_RUNNER_ERRORS = new Set<string>([
  'LSE-AGT-001',
  'LSE-AGT-002',
  'LSE-AGT-003',
  'LSE-AGT-008',
  'LSE-KEY-002',
  'LSE-KEY-003',
  'LSE-KEY-004',
  'LSE-KEY-005',
  'LSE-KEY-006',
  'LSE-KEY-007',
]);

function stableKey(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v) ?? 'null';
  if (Array.isArray(v)) return `[${v.map(stableKey).join(',')}]`;
  return `{${Object.keys(v as Record<string, unknown>)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${stableKey((v as Record<string, unknown>)[k])}`)
    .join(',')}}`;
}

const SIMPLE_IDLE = 'Ready for your next request';

export class Orchestrator {
  readonly #runtimes = new Map<string, AgentRuntime>();
  readonly #attaching = new Map<string, Promise<AgentRuntime | null>>();
  readonly #background = new Set<Promise<unknown>>();
  readonly #ownerLease: SessionOwnerLease;
  #installed = false;

  constructor(
    private readonly ctx: AppContext,
    readonly translator: Translator = defaultTranslator,
  ) {
    this.#ownerLease = new SessionOwnerLease(ctx.redis, ctx.instanceId, ctx.logger);
  }

  /** Register lifecycle hooks (API process only). */
  install(): void {
    if (this.#installed) return;
    this.#installed = true;
    this.ctx.sessionHooks.register({
      onSessionReady: (c) => this.onReady(c),
      onSessionStopping: (id, reason) => this.onStopping(id, reason),
      isBusy: (id) => this.isBusy(id),
      agentState: (id) => this.#runtimes.get(id)?.state,
    });
  }

  isBusy(sessionId: string): boolean {
    const rt = this.#runtimes.get(sessionId);
    return !!rt && (rt.busy || rt.queue.length > 0);
  }

  hasRuntime(sessionId: string): boolean {
    return this.#runtimes.has(sessionId);
  }

  /** Test/ops helper: wait for in-flight event handling and background stops. */
  async idle(sessionId?: string): Promise<void> {
    for (let i = 0; i < 100; i += 1) {
      const rts = sessionId
        ? [this.#runtimes.get(sessionId)].filter((r): r is AgentRuntime => !!r)
        : [...this.#runtimes.values()];
      const chains = rts.map((r) => r.chain);
      const bg = [...this.#background];
      await Promise.allSettled([...chains, ...bg]);
      const changed = rts.some((r, k) => r.chain !== chains[k]);
      if (!changed && this.#background.size === 0) return;
    }
  }

  #track<T>(p: Promise<T>): void {
    this.#background.add(p);
    void p
      .catch((err: unknown) => this.ctx.logger.warn({ err }, 'orchestrator background task failed'))
      .finally(() => this.#background.delete(p));
  }

  // ---- publishing ------------------------------------------------------------------------

  async #publish<T extends ServerMessageType>(
    sessionId: string,
    type: T,
    payload: ServerPayloadInput<T>,
    audience: EventAudience = 'all',
  ) {
    try {
      await this.ctx.sessionEvents.publish(sessionId, type, payload, { audience });
    } catch (err) {
      this.ctx.logger.warn({ err, sessionId, type }, 'failed to publish session event');
    }
  }

  /** Publish mode-specific variants (one shared entry when they're identical). */
  async #publishModes<T extends ServerMessageType>(
    sessionId: string,
    type: T,
    simple: ServerPayloadInput<T>,
    pro: ServerPayloadInput<T>,
  ) {
    if (stableKey(simple) === stableKey(pro)) return this.#publish(sessionId, type, simple);
    await this.#publish(sessionId, type, simple, 'simple');
    await this.#publish(sessionId, type, pro, 'pro');
  }

  async #status(rt: AgentRuntime, state: AgentState, simple: string, pro = simple) {
    rt.state = state;
    await this.#publishModes(
      rt.sessionId,
      'agent_status',
      { state, label: simple },
      { state, label: pro },
    );
  }

  async #error(sessionId: string, code: ErrorCode) {
    await this.#publish(sessionId, 'error', errorPayload(code, sessionId));
  }

  // ---- runtime lifecycle -------------------------------------------------------------------

  async #projectInfo(session: Session, apiKey: string | null): Promise<ProjectInfo> {
    const project = await this.ctx.prisma.project.findUniqueOrThrow({
      where: { id: session.projectId },
      include: { org: true },
    });
    const owner = await this.ctx.prisma.orgMember.findUnique({
      where: { userId_orgId: { userId: session.userId, orgId: project.orgId } },
    });
    const env = await decryptProjectEnv(this.ctx, project);
    const meta = Array.isArray(project.envVarMeta)
      ? (project.envVarMeta as { name?: string; secret?: boolean }[])
      : [];
    const secretNames = new Set(meta.filter((m) => m?.secret && m.name).map((m) => m.name!));
    const diffSecrets = Object.entries(env)
      .filter(([k, v]) => secretNames.has(k) && v.length >= 6)
      .map(([, v]) => v);
    if (apiKey) diffSecrets.push(apiKey);
    const scrubValues = [...secretValuesOf(env), ...(apiKey ? [apiKey] : [])];
    const labels =
      project.componentLabels && typeof project.componentLabels === 'object'
        ? (project.componentLabels as Record<string, string>)
        : null;
    const { org, ...p } = project;
    return {
      project: p as Project,
      org,
      ownerRole: owner?.role ?? 'MEMBER',
      scrubValues,
      diffSecrets,
      tctx: { componentLabels: labels, secrets: scrubValues },
    };
  }

  async #ownerKey(userId: string): Promise<{ row: ApiKey; key: string | null }> {
    const row = await activeKeyFor(this.ctx, userId);
    // Mock runners never call Anthropic: the key stays out of their environment.
    return { row, key: this.ctx.env.RUNNER_MOCK ? null : await decryptApiKey(this.ctx, row) };
  }

  async #createRuntime(
    session: Session,
    sandbox: SandboxHandle,
    launch: RunnerLaunch,
  ): Promise<AgentRuntime> {
    const { key } = await this.#ownerKey(session.userId);
    const info = await this.#projectInfo(session, key);
    info.tctx.workspaceDir = sandbox.paths.workspace;
    const user = await this.ctx.prisma.user.findUnique({ where: { id: session.userId } });
    const rt: AgentRuntime = {
      sessionId: session.id,
      userId: session.userId,
      userName: user?.name ?? user?.email ?? 'Someone',
      sandbox,
      launch,
      info,
      lineBuf: '',
      chain: Promise.resolve(),
      busy: false,
      state: 'idle',
      queue: [],
      turn: null,
      restarts: 0,
      warned: false,
      stopping: false,
      budgetStopping: false,
      previewUrl: session.previewUrl,
      beforeShots: new Map(),
      lastAfterShots: new Map(),
      screenshotViewports: ['desktop'],
      shots: new Map(),
      inspects: new Map(),
      hooks: [],
      mcpEnv: {},
      mcpIds: new Map(),
      mcpWarned: new Set(),
      agentSessionId: session.agentSessionId,
      rewinding: false,
    };
    this.#runtimes.set(session.id, rt);
    try {
      await this.#writeConfig(session, sandbox, launch, rt);
    } catch (err) {
      this.#runtimes.delete(session.id);
      throw err;
    }
    await this.#spawn(rt, key);
    return rt;
  }

  /** `onSessionReady` hook: the sandbox is healthy → start the runner. */
  async onReady(c: SessionReadyContext): Promise<void> {
    if (this.#runtimes.has(c.session.id)) return;
    c.runtime.extensions.set(RUNTIME_KEY, true);
    const rt = await this.#createRuntime(c.session, c.runtime.sandbox, c.runnerLaunch);
    await this.#ownerLease.claim(c.session.id);
    // SessionStart webhooks / notifications are the server's job (spec §8.9).
    this.#track(
      this.#lifecycleHooks(rt, 'SessionStart', `A session started on ${c.project.name}`, {
        projectName: c.project.name,
        recovered: c.recovered,
      }),
    );
  }

  /** Run the server-owned hooks of a lifecycle event and report them in Pro. */
  async #lifecycleHooks(
    rt: AgentRuntime,
    event: 'SessionStart' | 'SessionEnd' | 'Notification',
    message: string,
    context?: Record<string, unknown>,
  ) {
    const results = await runLifecycleHooks(this.ctx, {
      sessionId: rt.sessionId,
      orgId: rt.info.org.id,
      projectId: rt.info.project.id,
      event,
      message,
      ...(context ? { context } : {}),
    });
    for (const r of results) await this.#publishHookEvent(rt.sessionId, r);
  }

  /** Attach to a RUNNING session provisioned by another process / before a restart. */
  async ensureRuntime(sessionId: string): Promise<AgentRuntime | null> {
    const existing = this.#runtimes.get(sessionId);
    if (existing) return existing;
    const inflight = this.#attaching.get(sessionId);
    if (inflight) return inflight;
    const p = (async () => {
      const s = await this.ctx.prisma.session.findUnique({ where: { id: sessionId } });
      if (!s || s.status !== 'RUNNING') return null;
      const sandbox = await getOrConnectSandbox(this.ctx, s);
      if (!sandbox || !(await sandbox.isRunning().catch(() => false))) return null;
      let runtime = this.ctx.sessionRuntime.get(s.id);
      if (!runtime) {
        runtime = { sessionId: s.id, sandbox, appProcesses: [], extensions: new Map() };
        this.ctx.sessionRuntime.set(runtime);
      }
      runtime.extensions.set(RUNTIME_KEY, true);
      // A runner left over from a previous API process would compete for the workspace.
      if (s.runnerPid && sandbox.kind === 'e2b') {
        await sandbox.run(`kill ${Number(s.runnerPid)} 2>/dev/null || true`).catch(() => undefined);
      }
      const launch = runnerLaunchFor(sandbox, this.ctx.env.RUNNER_MOCK);
      const attached = await this.#createRuntime(s, sandbox, launch);
      await this.#ownerLease.claim(s.id);
      return attached;
    })()
      .catch((err: unknown) => {
        this.ctx.logger.warn({ err, sessionId }, 'could not attach agent runtime');
        return null;
      })
      .finally(() => this.#attaching.delete(sessionId));
    this.#attaching.set(sessionId, p);
    return p;
  }

  /**
   * Rewrite config.json (resume id/anchor, remaining budget, memory, skills, MCP) before
   * a (re)start and keep the MCP secret env for the process.
   */
  async #writeConfig(s: Session, sandbox: SandboxHandle, launch: RunnerLaunch, rt: AgentRuntime) {
    const prepared = await prepareRunnerConfig(this.ctx, s, sandbox, {
      configPath: launch.configPath,
      capToRemainingBudget: true,
    });
    rt.mcpEnv = prepared.mcpEnv;
    rt.mcpIds = prepared.mcpIds;
    rt.hooks = prepared.extensions.hooks;
    rt.screenshotViewports = prepared.config.screenshotViewports;
    for (const v of Object.values(prepared.mcpEnv)) {
      if (v.length < MIN_EXTRA_SECRET_LENGTH) continue;
      if (!rt.info.scrubValues.includes(v)) rt.info.scrubValues.push(v);
      if (!rt.info.diffSecrets.includes(v)) rt.info.diffSecrets.push(v);
    }
    if (prepared.extensions.skippedSkills.length) await this.#error(s.id, 'LSE-AGT-015');
  }

  async #spawn(rt: AgentRuntime, apiKey: string | null): Promise<void> {
    const envs: Record<string, string> = { ...rt.launch.envs, ...rt.mcpEnv };
    if (apiKey) envs.ANTHROPIC_API_KEY = apiKey;
    rt.lineBuf = '';
    const proc = await rt.sandbox.runBackground(rt.launch.command, {
      cwd: rt.launch.cwd,
      envs,
      stdin: true,
      onStdout: (chunk) => this.#onStdout(rt, chunk),
      onStderr: (chunk) =>
        this.ctx.logger.debug(
          {
            sessionId: rt.sessionId,
            stderr: scrubSecrets(chunk, rt.info.scrubValues).slice(0, STDERR_LOG_MAX),
          },
          'runner stderr',
        ),
    });
    rt.runner = proc;
    await this.ctx.prisma.session
      .update({ where: { id: rt.sessionId }, data: { runnerPid: proc.pid > 0 ? proc.pid : null } })
      .catch(() => undefined);
    void proc.wait().then((r) => this.#onExit(rt, proc, r.exitCode));
  }

  #onStdout(rt: AgentRuntime, chunk: string) {
    rt.lineBuf += chunk;
    let i = rt.lineBuf.indexOf('\n');
    while (i >= 0) {
      const line = rt.lineBuf.slice(0, i);
      rt.lineBuf = rt.lineBuf.slice(i + 1);
      i = rt.lineBuf.indexOf('\n');
      if (!line.trim()) continue;
      const parsed = parseRunnerLine(line);
      if (!parsed.ok) {
        // Never log the line itself (it may contain secrets or user code).
        this.ctx.logger.warn(
          { sessionId: rt.sessionId, code: 'LSE-AGT-010', kind: parsed.error.kind },
          'malformed runner line skipped',
        );
        continue;
      }
      const ev = parsed.event;
      if (ev.type === 'screenshot_result') {
        // Answered out of band: the turn finaliser awaits these.
        rt.shots.get(ev.data.requestId)?.(ev.data);
        rt.shots.delete(ev.data.requestId);
        continue;
      }
      if (ev.type === 'inspect_result') {
        rt.inspects.get(ev.data.requestId)?.(ev.data);
        rt.inspects.delete(ev.data.requestId);
        continue;
      }
      rt.chain = rt.chain
        .then(() => this.#handle(rt, ev))
        .catch((err: unknown) =>
          this.ctx.logger.error(
            { err, sessionId: rt.sessionId, type: ev.type },
            'runner event handling failed',
          ),
        );
    }
  }

  async #send(rt: AgentRuntime, cmd: RunnerCommandInput): Promise<boolean> {
    if (!rt.runner || rt.runner.exitCode !== undefined) return false;
    try {
      await rt.runner.sendStdin(encodeRunnerCommand(cmd));
      return true;
    } catch (err) {
      this.ctx.logger.warn({ err, sessionId: rt.sessionId }, 'runner stdin write failed');
      return false;
    }
  }

  async #onExit(rt: AgentRuntime, proc: BackgroundProcess, code: number) {
    if (rt.runner !== proc) return;
    rt.runner = undefined;
    for (const resolve of rt.shots.values())
      resolve({ requestId: '', ok: false, error: 'runner exited' });
    rt.shots.clear();
    if (rt.stopping || this.#runtimes.get(rt.sessionId) !== rt) return;
    await rt.chain;
    // The sandbox may have been stopped by another process (the production worker runs
    // idle/timeout/orphan stops and cannot reach this runner): the runner then dies with
    // it. That is not a crash — drop the runtime instead of erroring/restarting.
    const current = await this.ctx.prisma.session
      .findUnique({ where: { id: rt.sessionId }, select: { status: true } })
      .catch(() => null);
    if (current?.status !== 'RUNNING') {
      await this.onStopping(rt.sessionId, 'stopped').catch(() => undefined);
      this.ctx.sessionRuntime.delete(rt.sessionId);
      this.ctx.logger.info(
        { sessionId: rt.sessionId, status: current?.status ?? 'missing' },
        'runner exited after the session stopped elsewhere',
      );
      return;
    }
    this.ctx.logger.warn({ sessionId: rt.sessionId, exitCode: code }, 'runner exited unexpectedly');
    if (rt.turn && !rt.turn.done) {
      rt.turn.errorCode ??= 'LSE-AGT-001';
      await this.#finishTurn(rt, { filesChanged: [], stopReason: 'error' }).catch((err: unknown) =>
        this.ctx.logger.warn({ err, sessionId: rt.sessionId }, 'finishing crashed turn failed'),
      );
    }
    const badConfig = code === 2;
    if (badConfig || rt.restarts >= MAX_RUNNER_RESTARTS) {
      const errorCode: ErrorCode = badConfig ? (rt.lastErrorCode ?? 'LSE-AGT-001') : 'LSE-AGT-001';
      this.#track(
        stopSession(this.ctx, rt.sessionId, {
          to: 'ERRORED',
          reason: 'error',
          errorCode,
          pushWip: true,
        }),
      );
      return;
    }
    rt.restarts += 1;
    await this.#error(rt.sessionId, 'LSE-AGT-001');
    try {
      const s = await this.ctx.prisma.session.findUniqueOrThrow({ where: { id: rt.sessionId } });
      if (s.status !== 'RUNNING') return;
      await this.#writeConfig(s, rt.sandbox, rt.launch, rt);
      const { key } = await this.#ownerKey(rt.userId);
      await this.#spawn(rt, key);
      this.#drain(rt);
    } catch (err) {
      this.ctx.logger.warn({ err, sessionId: rt.sessionId }, 'runner restart failed');
      this.#track(
        stopSession(this.ctx, rt.sessionId, {
          to: 'ERRORED',
          reason: 'error',
          errorCode: err instanceof AppError ? err.code : 'LSE-AGT-001',
          pushWip: true,
        }),
      );
    }
  }

  /** `onSessionStopping` hook: shut the runner down (pending approvals expire). */
  async onStopping(sessionId: string, reason: StopReason): Promise<void> {
    const rt = this.#runtimes.get(sessionId);
    if (!rt) return;
    rt.stopping = true;
    this.#runtimes.delete(sessionId);
    await this.#ownerLease.release(sessionId);
    await this.#lifecycleHooks(rt, 'SessionEnd', `The session ended (${reason})`, {
      reason,
    }).catch(() => undefined);
    const proc = rt.runner;
    if (proc && proc.exitCode === undefined) {
      if (rt.busy) await this.#send(rt, makeRunnerCommand('interrupt', {}));
      await this.#send(rt, makeRunnerCommand('shutdown', {}));
      await Promise.race([proc.wait(), sleep(RUNNER_SHUTDOWN_GRACE_MS)]);
      if (proc.exitCode === undefined) await proc.kill().catch(() => undefined);
    }
    rt.runner = undefined;
    for (const resolve of rt.shots.values())
      resolve({ requestId: '', ok: false, error: 'stopping' });
    rt.shots.clear();
    for (const resolve of rt.inspects.values())
      resolve({ requestId: '', ok: false, error: 'stopping' });
    rt.inspects.clear();
    const pending = await this.ctx.prisma.toolApproval.updateMany({
      where: { sessionId, status: 'PENDING' },
      data: { status: 'EXPIRED', decidedAt: new Date() },
    });
    if (pending.count)
      this.ctx.logger.info(
        { sessionId, count: pending.count },
        'expired pending approvals on stop',
      );
    rt.state = 'idle';
  }

  /** Graceful shutdown of the API process: stop all runners (sandboxes keep running). */
  async shutdownAll(): Promise<void> {
    await Promise.allSettled(
      [...this.#runtimes.keys()].map((id) => this.onStopping(id, 'stopped')),
    );
    await this.#ownerLease.close();
  }

  // ---- inbound user actions --------------------------------------------------------------

  async #access(caller: Caller, sessionId: string, need: 'read' | 'write'): Promise<SessionAccess> {
    assertTokenScope(caller, need);
    const access = await loadSessionForParticipant(this.ctx, caller, sessionId);
    if (need === 'write') assertCanAct(access, 'act in sessions');
    return access;
  }

  #requireRunning(s: Session) {
    if (s.status !== 'RUNNING') {
      throw new AppError('LSE-CONF-001', { devMessage: `Session is ${s.status}, not RUNNING` });
    }
  }

  async #runtimeFor(s: Session): Promise<AgentRuntime> {
    const rt = await this.ensureRuntime(s.id);
    if (!rt)
      throw new AppError('LSE-SBX-010', { devMessage: 'The session sandbox is not reachable' });
    return rt;
  }

  /** Chat turn entry point (WS `chat_message` and `POST /sessions/:id/messages`). */
  async sendMessage(
    caller: Caller,
    sessionId: string,
    body: SendMessageBody,
  ): Promise<SendMessageResult> {
    const access = await this.#access(caller, sessionId, 'write');
    const { session } = access;
    if (body.clientMessageId) {
      const dup = await this.ctx.prisma.chatMessage.findUnique({
        where: { sessionId_clientMessageId: { sessionId, clientMessageId: body.clientMessageId } },
      });
      if (dup) return { message: this.#dto(dup), queued: false, duplicate: true };
    }
    this.#requireRunning(session);
    // `# note` quick-add (Pro): saved to session memory, no agent turn.
    const note = parseQuickNote(body.content);
    if (note !== null) {
      const org = await this.ctx.prisma.organization.findUniqueOrThrow({
        where: { id: session.project.orgId },
      });
      if (viewerMode(session, access.membership, org) === 'PRO') {
        return this.#quickNote(sessionId, body, note);
      }
    }
    const project = await this.ctx.prisma.project.findUniqueOrThrow({
      where: { id: session.projectId },
      select: { planMode: true },
    });
    let plan: TurnRequest['plan'];
    if (body.plan) plan = 'manual';
    else if (project.planMode === 'ALWAYS') plan = 'auto';
    else if (project.planMode === 'AUTO' && shouldAutoPlan(body.content).plan) plan = 'auto';
    return this.#submit(session, {
      content: body.content,
      ...(body.clientMessageId ? { clientMessageId: body.clientMessageId } : {}),
      ...(body.attachments ? { attachments: body.attachments } : {}),
      ...(plan ? { plan } : {}),
    });
  }

  /** Start (or queue) a turn for an already authorised caller (commands, plan approvals). */
  async submitTurn(sessionId: string, req: TurnRequest): Promise<SendMessageResult> {
    const session = await this.ctx.prisma.session.findUniqueOrThrow({
      where: { id: sessionId },
      include: { project: { select: { orgId: true } } },
    });
    this.#requireRunning(session);
    return this.#submit(session, req);
  }

  async #submit(
    session: Session & { project: { orgId: string } },
    req: TurnRequest,
  ): Promise<SendMessageResult> {
    const sessionId = session.id;
    const budget = Number(session.budgetUsd ?? 0);
    if (budget > 0 && Number(session.totalCostUsd) >= budget) {
      throw new AppError('LSE-AGT-003', { devMessage: 'Session budget is used up' });
    }
    const org = await this.ctx.prisma.organization.findUniqueOrThrow({
      where: { id: session.project.orgId },
    });
    const key = await activeKeyFor(this.ctx, session.userId);
    await assertBudgets(this.ctx, org, session.userId, key);
    const rt = await this.#runtimeFor(session);
    if (rt.rewinding) throw new AppError('LSE-AGT-011', { devMessage: 'A rewind is in progress' });
    // UserPromptSubmit hooks are enforced by the SERVER before the turn exists.
    const agentText = await this.#userPromptHooks(rt, req);
    const queued = rt.busy || rt.queue.length > 0;
    const metadata: ChatMessageMetadata = {
      kind: 'text',
      ...(queued ? { queued: true } : {}),
      ...(req.plan ? { planMode: req.plan } : {}),
      ...(req.command ? { command: req.command } : {}),
    };
    let row;
    try {
      row = await this.ctx.prisma.chatMessage.create({
        data: {
          id: newId(),
          sessionId,
          role: 'USER',
          content: req.content,
          clientMessageId: req.clientMessageId ?? null,
          ...(req.attachments ? { attachments: req.attachments as Prisma.InputJsonValue } : {}),
          metadata: metadata as Prisma.InputJsonValue,
        },
      });
    } catch (err) {
      // Concurrent duplicate (unique sessionId+clientMessageId).
      if ((err as { code?: string }).code === 'P2002' && req.clientMessageId) {
        const dup = await this.ctx.prisma.chatMessage.findUniqueOrThrow({
          where: {
            sessionId_clientMessageId: { sessionId, clientMessageId: req.clientMessageId },
          },
        });
        return { message: this.#dto(dup), queued: false, duplicate: true };
      }
      throw err;
    }
    // A new request replaces a plan that is still waiting for approval.
    await this.#supersedePlans(sessionId);
    const message = this.#dto(row);
    // Element attachments carry a CSS selector, which Simple viewers never see.
    await this.#publishModes(
      sessionId,
      'chat_message',
      { message: toSimpleChatMessage(message), ...(queued ? { queued: true } : {}) },
      { message, ...(queued ? { queued: true } : {}) },
    );
    rt.queue.push({
      id: row.id,
      content: agentText ?? req.agentText ?? row.content,
      ...(req.label ? { label: req.label } : {}),
      ...(req.plan ? { plan: true } : {}),
      ...(req.allowedTools?.length ? { allowedTools: req.allowedTools } : {}),
      ...(req.model ? { model: req.model } : {}),
      ...(req.attachments?.length ? { attachments: req.attachments } : {}),
    });
    this.#drain(rt);
    return { message, queued };
  }

  /**
   * `UserPromptSubmit` (spec §8.9): the server evaluates its own hooks before a turn is
   * created — `deny` rejects the message (LSE-AGT-005), `modify` rewrites the prompt the
   * agent sees (the chat still shows what the user typed).
   */
  async #userPromptHooks(rt: AgentRuntime, req: TurnRequest): Promise<string | undefined> {
    if (!rt.hooks.some((h) => h.event === 'UserPromptSubmit' && isServerHandled(h))) {
      return undefined;
    }
    const prompt = req.agentText ?? req.content;
    const payload: HookPayload = {
      event: 'UserPromptSubmit',
      sessionId: rt.sessionId,
      projectId: rt.info.project.id,
      orgId: rt.info.org.id,
      cwd: rt.sandbox.paths.workspace,
      prompt,
      ts: new Date().toISOString(),
    };
    const { decision, results } = await evaluateServerHooks(this.ctx, {
      hooks: rt.hooks,
      payload,
      orgId: rt.info.org.id,
      sessionId: rt.sessionId,
    });
    for (const r of results) await this.#publishHookEvent(rt.sessionId, r);
    if (decision.decision === 'deny') {
      throw new AppError('LSE-AGT-005', {
        devMessage: decision.reason ?? 'A project hook denied this message',
        ...(decision.reason ? { userMessage: decision.reason } : {}),
      });
    }
    if (decision.decision === 'modify' && decision.updatedPrompt) return decision.updatedPrompt;
    return undefined;
  }

  async #publishHookEvent(
    sessionId: string,
    r: {
      hookId: string;
      name: string;
      event: HookPayload['event'];
      handler: 'command' | 'builtin' | 'http';
      decision: { decision: string; reason?: string | undefined };
      errorCode?: ErrorCode | undefined;
    },
    toolName?: string,
  ) {
    await this.#publish(
      sessionId,
      'hook_event',
      {
        hookId: r.hookId,
        name: r.name,
        event: r.event,
        decision: r.decision.decision as 'allow' | 'deny' | 'ask' | 'modify',
        ...(r.decision.reason ? { reason: r.decision.reason } : {}),
        ...(toolName ? { toolName } : {}),
        handler: r.handler,
        ...(r.errorCode ? { errorCode: r.errorCode } : {}),
      },
      'pro',
    );
  }

  async #supersedePlans(sessionId: string) {
    const pending = await this.ctx.prisma.toolApproval.findMany({
      where: { sessionId, kind: 'plan', status: 'PENDING' },
      select: { id: true },
    });
    for (const p of pending) {
      const r = await this.ctx.prisma.toolApproval.updateMany({
        where: { id: p.id, status: 'PENDING' },
        data: { status: 'DENIED', decidedAt: new Date(), reason: 'Replaced by a new request' },
      });
      if (r.count) {
        await this.#publish(sessionId, 'approval_resolved', { approvalId: p.id, status: 'DENIED' });
      }
    }
  }

  async #quickNote(
    sessionId: string,
    body: SendMessageBody,
    note: string,
  ): Promise<SendMessageResult> {
    const row = await this.ctx.prisma.chatMessage.create({
      data: {
        id: newId(),
        sessionId,
        role: 'USER',
        content: body.content,
        clientMessageId: body.clientMessageId ?? null,
        metadata: { kind: 'text', command: 'note' },
      },
    });
    const message = this.#dto(row);
    await this.#publish(sessionId, 'chat_message', { message });
    await this.addNote(sessionId, note);
    return { message, queued: false };
  }

  /** Append a session note (memory) and hand it to the running agent. */
  async addNote(sessionId: string, note: string): Promise<string> {
    const s = await this.ctx.prisma.session.findUniqueOrThrow({ where: { id: sessionId } });
    const notes = appendSessionNote(s.notes, note);
    await this.ctx.prisma.session.update({ where: { id: sessionId }, data: { notes } });
    const rt = this.#runtimes.get(sessionId);
    if (rt) await this.#send(rt, makeRunnerCommand('memory_note', { text: note }));
    await this.systemMessage(sessionId, `Noted for this session: ${note}`);
    return notes;
  }

  /** Start the next queued turn when idle (synchronous busy check → no double start). */
  #drain(rt: AgentRuntime) {
    if (rt.busy || rt.stopping || !rt.runner) return;
    const next = rt.queue.shift();
    if (!next) return;
    rt.busy = true;
    this.#track(
      this.#startTurn(rt, next).catch(async (err: unknown) => {
        this.ctx.logger.warn({ err, sessionId: rt.sessionId }, 'could not start turn');
        rt.busy = false;
        rt.turn = null;
        await this.#error(rt.sessionId, 'LSE-AGT-001');
      }),
    );
  }

  #newTurn(rt: AgentRuntime, userMessageId: string, plan = false): Turn {
    return {
      plan,
      userMessageId,
      assistantId: newId(),
      startedAt: Date.now(),
      raw: [],
      rawRowCreated: false,
      texts: [],
      deltaText: '',
      streamers: {
        simple: this.translator.streamer('SIMPLE', rt.info.tctx),
        pro: this.translator.streamer('PRO', rt.info.tctx),
      },
      toolsUsed: new Set(),
      subagents: new Set(),
      commands: [],
      tools: new Map(),
      repeat: 0,
      loopStopped: false,
      hasErrors: false,
      interrupted: false,
      done: false,
    };
  }

  async #startTurn(rt: AgentRuntime, msg: QueuedMessage) {
    rt.turn = this.#newTurn(rt, msg.id, msg.plan === true);
    rt.lastErrorCode = undefined;
    await this.ctx.prisma.session.update({
      where: { id: rt.sessionId },
      data: { idleSince: null },
    });
    await this.#status(
      rt,
      'thinking',
      msg.plan ? 'Working out a plan…' : 'Thinking…',
      msg.plan ? 'Planning (read-only)…' : 'Thinking…',
    );
    await this.#checkpoint(rt, msg).catch((err: unknown) =>
      this.ctx.logger.warn({ err, sessionId: rt.sessionId }, 'checkpoint failed'),
    );
    for (const viewport of rt.screenshotViewports) {
      if (rt.lastAfterShots.has(viewport) || rt.beforeShots.has(viewport)) continue;
      const shot = await this.#screenshot(rt, 'before', msg.id, viewport);
      if (shot) rt.beforeShots.set(viewport, shot);
    }
    const attachments = msg.attachments?.length
      ? await loadRunnerAttachments(this.ctx, rt.sessionId, msg.attachments).catch(
          (err: unknown) => {
            this.ctx.logger.warn(
              { err, sessionId: rt.sessionId },
              'could not load message attachments',
            );
            return [];
          },
        )
      : [];
    const elementContext = msg.attachments?.length ? elementPromptContext(msg.attachments) : '';
    const permissionMode: AgentPermissionMode | undefined = msg.plan ? 'plan' : undefined;
    const ok = await this.#send(
      rt,
      makeRunnerCommand('user_message', {
        messageId: msg.id,
        text: elementContext ? `${msg.content}\n\n${elementContext}` : msg.content,
        ...(attachments.length ? { attachments } : {}),
        ...(permissionMode ? { permissionMode } : {}),
        ...(msg.allowedTools?.length ? { allowedTools: msg.allowedTools } : {}),
        ...(msg.model ? { model: msg.model } : {}),
      }),
    );
    if (!ok) throw new AppError('LSE-AGT-001', { devMessage: 'runner is not accepting input' });
  }

  /** Anchor after the latest (non-rewound) turn: memory first, else the DB. */
  async #currentAnchor(rt: AgentRuntime): Promise<string | null> {
    if (rt.lastAnchor !== undefined) return rt.lastAnchor;
    const s = await this.ctx.prisma.session.findUnique({
      where: { id: rt.sessionId },
      select: { resumeSessionAt: true },
    });
    if (s?.resumeSessionAt) return (rt.lastAnchor = s.resumeSessionAt);
    const last = await this.ctx.prisma.chatMessage.findFirst({
      where: { sessionId: rt.sessionId, role: 'ASSISTANT', rewoundAt: null },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      select: { rawContent: true },
    });
    const raw = last?.rawContent as { conversationAnchor?: unknown } | null | undefined;
    rt.lastAnchor = typeof raw?.conversationAnchor === 'string' ? raw.conversationAnchor : null;
    return rt.lastAnchor;
  }

  async #checkpoint(rt: AgentRuntime, msg: QueuedMessage) {
    const anchor = await this.#currentAnchor(rt);
    const row = await createCheckpoint(
      this.ctx,
      rt.sandbox,
      {
        sessionId: rt.sessionId,
        messageId: msg.id,
        label: msg.label ?? msg.content,
        conversationAnchor: anchor,
        agentSessionId: anchor ? rt.agentSessionId : null,
      },
      newId(),
    );
    await this.#publish(rt.sessionId, 'checkpoint_created', { checkpoint: toCheckpointDto(row) });
  }

  async interrupt(caller: Caller, sessionId: string): Promise<{ interrupted: boolean }> {
    const { session } = await this.#access(caller, sessionId, 'write');
    this.#requireRunning(session);
    const rt = this.#runtimes.get(sessionId);
    if (!rt?.busy) return { interrupted: false };
    if (rt.turn) rt.turn.interrupted = true;
    await this.#status(rt, 'finishing', 'Stopping…');
    return { interrupted: await this.#send(rt, makeRunnerCommand('interrupt', {})) };
  }

  /** WS `stop_session`: interrupt + snapshot work → PAUSED (no delivery). */
  async stop(caller: Caller, sessionId: string): Promise<void> {
    const { session } = await this.#access(caller, sessionId, 'write');
    this.#requireRunning(session);
    const ok = await stopSession(this.ctx, sessionId, {
      to: 'PAUSED',
      reason: 'stopped',
      pushWip: true,
      actorId: caller.user.id,
    });
    if (!ok) throw new AppError('LSE-CONF-001', { devMessage: 'Session changed while stopping' });
  }

  async setMode(caller: Caller, sessionId: string, mode: Mode): Promise<Mode> {
    const { session, membership } = await this.#access(caller, sessionId, 'write');
    const org = await this.ctx.prisma.organization.findUniqueOrThrow({
      where: { id: session.project.orgId },
    });
    const policy = parseOrgPolicy(org.policy);
    const owner = await this.ctx.prisma.orgMember.findUnique({
      where: { userId_orgId: { userId: session.userId, orgId: org.id } },
    });
    const lockedFor = (m: typeof membership | null) =>
      m?.lockedMode ??
      (m && (m.role === 'MEMBER' || m.role === 'VIEWER') ? policy.lockedModes[m.role] : undefined);
    const locked = lockedFor(membership) ?? lockedFor(owner);
    if (locked && locked !== mode) {
      throw new AppError('LSE-ORG-009', { devMessage: `Mode is locked to ${locked}` });
    }
    await this.ctx.prisma.session.update({ where: { id: sessionId }, data: { mode } });
    if (session.status === 'RUNNING') {
      await this.#publish(sessionId, 'session_status', {
        status: 'RUNNING',
        message: mode === 'PRO' ? 'Switched to Pro mode' : 'Switched to Simple mode',
      });
    }
    return mode;
  }

  async setModel(caller: Caller, sessionId: string, model: string): Promise<string> {
    const { session } = await this.#access(caller, sessionId, 'write');
    const id = resolveModelId(model);
    if (!id) throw new AppError('LSE-KEY-013', { devMessage: `Unknown model ${model}` });
    await this.ctx.prisma.session.update({ where: { id: sessionId }, data: { model: id } });
    const rt = this.#runtimes.get(session.id);
    if (rt) await this.#send(rt, makeRunnerCommand('set_model', { model: id }));
    return id;
  }

  // ---- checkpoints & rewind (Phase 7) -------------------------------------------------------

  #requireIdle(rt: AgentRuntime) {
    if (rt.busy || rt.queue.length > 0 || rt.rewinding) {
      throw new AppError('LSE-AGT-011', {
        devMessage: 'Wait for the agent to finish before rewinding',
      });
    }
  }

  /** `POST /sessions/:id/checkpoints/:cid/rewind`, WS `rewind`, `/undo`. */
  async rewind(
    caller: Caller,
    sessionId: string,
    checkpointId: string,
    scope: RewindScope,
  ): Promise<RewindResultDto> {
    const { session } = await this.#access(caller, sessionId, 'write');
    this.#requireRunning(session);
    const rt = await this.#runtimeFor(session);
    this.#requireIdle(rt);
    const cp = await this.ctx.prisma.checkpoint.findFirst({
      where: { id: checkpointId, sessionId, rewoundAt: null },
    });
    if (!cp) throw new AppError('LSE-NF-001', { devMessage: 'Checkpoint not found' });
    const code = scope === 'code' || scope === 'both';
    const conversation = scope === 'conversation' || scope === 'both';
    if (code && !cp.hasCode) {
      throw new AppError('LSE-CONF-001', {
        devMessage: 'This checkpoint has no code snapshot',
        userMessage: "This point can't be restored any more.",
      });
    }
    if (conversation && cp.turn > 1 && !cp.conversationAnchor) {
      throw new AppError('LSE-CONF-001', {
        devMessage: 'The conversation position of this checkpoint is unknown',
        userMessage:
          "The conversation can't be rewound to this point. Try restoring the files only.",
      });
    }
    rt.rewinding = true;
    try {
      if (code && !(await restoreWorkspace(rt.sandbox, cp.gitRef))) {
        throw new AppError('LSE-CONF-001', {
          devMessage: `Checkpoint snapshot ${cp.gitRef} is not available in this workspace`,
          userMessage: "This point can't be restored any more (the workspace was restarted).",
        });
      }
      let removed = { messageIds: [] as string[], checkpointIds: [] as string[] };
      if (conversation) {
        removed = await hideFrom(this.ctx, cp);
        await deleteCheckpointRefs(rt.sandbox, removed.checkpointIds);
        const anchor = cp.conversationAnchor;
        const agentSessionId = anchor ? (cp.agentSessionId ?? rt.agentSessionId) : null;
        await this.ctx.prisma.session.update({
          where: { id: sessionId },
          data: { agentSessionId, resumeSessionAt: anchor },
        });
        rt.agentSessionId = agentSessionId;
        rt.lastAnchor = anchor;
        await this.#send(
          rt,
          makeRunnerCommand('rewind_conversation', {
            anchor,
            ...(anchor && agentSessionId ? { agentSessionId } : {}),
          }),
        );
        const expired = await this.ctx.prisma.toolApproval.findMany({
          where: { sessionId, status: 'PENDING' },
          select: { id: true },
        });
        if (expired.length) {
          await this.ctx.prisma.toolApproval.updateMany({
            where: { id: { in: expired.map((e) => e.id) } },
            data: { status: 'EXPIRED', decidedAt: new Date() },
          });
          for (const e of expired)
            await this.#publish(sessionId, 'approval_resolved', {
              approvalId: e.id,
              status: 'EXPIRED',
            });
        }
      }
      const hasChanges = (await gitStatus(rt.sandbox).catch(() => [])).length > 0;
      if (code) {
        rt.lastAfterShots.clear();
        rt.beforeShots.clear();
        if (rt.previewUrl)
          await this.#publish(sessionId, 'preview_updated', {
            url: rt.previewUrl,
            reason: 'rewind',
          });
      }
      const result: RewindResultDto = {
        checkpointId: cp.id,
        scope,
        removedMessageIds: removed.messageIds,
        removedCheckpointIds: removed.checkpointIds,
        hasChanges,
      };
      await this.#publish(sessionId, 'rewind_complete', result);
      const label = cp.label ? `“${cp.label}”` : 'that request';
      await this.systemMessage(
        sessionId,
        scope === 'code'
          ? `Restored your project to how it was before ${label}. The conversation is unchanged.`
          : scope === 'conversation'
            ? `Rewound the conversation to before ${label}. Your project files are unchanged.`
            : `Went back to before ${label}.`,
      );
      await this.ctx.audit.record({
        orgId: rt.info.org.id,
        actorId: caller.user.id,
        action: 'session.rewind',
        target: sessionId,
        meta: {
          checkpointId: cp.id,
          scope,
          turn: cp.turn,
          removedMessages: removed.messageIds.length,
        },
        ip: caller.ip,
      });
      await this.#status(rt, 'idle', SIMPLE_IDLE, 'Idle');
      return result;
    } finally {
      rt.rewinding = false;
    }
  }

  /** `/undo`: rewind code + conversation to before the latest turn. */
  async undoLast(caller: Caller, sessionId: string): Promise<RewindResultDto> {
    await this.#access(caller, sessionId, 'write');
    const cp = await this.ctx.prisma.checkpoint.findFirst({
      where: { sessionId, rewoundAt: null, hasCode: true },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
    });
    if (!cp)
      throw new AppError('LSE-NF-001', {
        devMessage: 'No checkpoint to undo to',
        userMessage: 'There is nothing to undo yet.',
      });
    return this.rewind(caller, sessionId, cp.id, 'both');
  }

  /** `/clear`: fresh agent conversation; files and chat history are kept. */
  async clearConversation(caller: Caller, sessionId: string): Promise<void> {
    const { session } = await this.#access(caller, sessionId, 'write');
    this.#requireRunning(session);
    const rt = await this.#runtimeFor(session);
    this.#requireIdle(rt);
    await this.ctx.prisma.session.update({
      where: { id: sessionId },
      data: { agentSessionId: null, resumeSessionAt: null },
    });
    rt.agentSessionId = null;
    rt.lastAnchor = null;
    await this.#send(rt, makeRunnerCommand('rewind_conversation', { anchor: null }));
    await this.systemMessage(
      sessionId,
      'Started a fresh conversation. Your changes are kept; the AI no longer remembers earlier messages.',
    );
  }

  /** True when a runtime exists and no turn is running or queued. */
  isIdle(sessionId: string): boolean {
    const rt = this.#runtimes.get(sessionId);
    return !!rt && !rt.busy && rt.queue.length === 0 && !rt.rewinding;
  }

  /** Live workspace of a RUNNING session (commands, review diff). */
  async sandboxFor(sessionId: string): Promise<SandboxHandle> {
    const s = await this.ctx.prisma.session.findUniqueOrThrow({ where: { id: sessionId } });
    this.#requireRunning(s);
    return (await this.#runtimeFor(s)).sandbox;
  }

  /** Secret values to scrub from anything derived from the workspace. */
  scrubValuesFor(sessionId: string): string[] {
    return this.#runtimes.get(sessionId)?.info.scrubValues ?? [];
  }

  /** Send an approval decision to the runner (approvals service). */
  async sendApprovalResponse(
    sessionId: string,
    runnerRequestId: string,
    allow: boolean,
    reason?: string,
  ) {
    const rt = this.#runtimes.get(sessionId);
    if (!rt) return false;
    const ok = await this.#send(
      rt,
      makeRunnerCommand('approval_response', {
        id: runnerRequestId,
        decision: allow ? 'allow' : 'deny',
        ...(reason ? { reason: reason.slice(0, 2000) } : {}),
      }),
    );
    if (ok && rt.busy)
      await this.#status(rt, 'thinking', allow ? 'Continuing…' : 'Trying another way…');
    return ok;
  }

  // ---- runner events -----------------------------------------------------------------------

  async #flushRaw(rt: AgentRuntime, turn: Turn, final = false) {
    const raw = turn.raw.slice(-MAX_RAW_EVENTS);
    if (!final && turn.raw.length % RAW_FLUSH_EVERY !== 0 && turn.rawRowCreated) return;
    const rawContent = { pending: !final, events: raw } as Prisma.InputJsonValue;
    if (!turn.rawRowCreated) {
      turn.rawRowCreated = true;
      await this.ctx.prisma.chatMessage.create({
        data: {
          id: turn.assistantId,
          sessionId: rt.sessionId,
          role: 'ASSISTANT',
          content: '',
          rawContent,
          metadata: { kind: 'text' },
        },
      });
    } else if (!final) {
      await this.ctx.prisma.chatMessage.update({
        where: { id: turn.assistantId },
        data: { rawContent },
      });
    }
  }

  async #handle(rt: AgentRuntime, ev: RunnerEvent): Promise<void> {
    if (rt.stopping) return;
    const turn = rt.turn;
    if (turn && !turn.done && ev.type !== 'log') {
      turn.raw.push(
        scrubSecretsDeep(
          { type: ev.type, seq: ev.seq, ts: ev.ts, data: ev.data },
          rt.info.scrubValues,
        ),
      );
      await this.#flushRaw(rt, turn).catch((err: unknown) =>
        this.ctx.logger.warn({ err, sessionId: rt.sessionId }, 'raw event flush failed'),
      );
    }
    const tctx = rt.info.tctx;
    switch (ev.type) {
      case 'ready':
        this.ctx.logger.info({ sessionId: rt.sessionId, ...ev.data }, 'runner ready');
        return;
      case 'session_init':
        rt.agentSessionId = ev.data.agentSessionId;
        await this.ctx.prisma.session.update({
          where: { id: rt.sessionId },
          data: { agentSessionId: ev.data.agentSessionId },
        });
        return;
      case 'plan_proposed':
        if (turn && turn.plan && !turn.planText) turn.planText = ev.data.plan;
        return;
      case 'mcp_status':
        await this.#mcpStatus(rt, ev.data);
        return;
      case 'conversation_rewound':
        this.ctx.logger.info(
          { sessionId: rt.sessionId, anchor: ev.data.anchor },
          'agent conversation rewound',
        );
        return;
      case 'log':
        this.ctx.logger.debug(
          {
            sessionId: rt.sessionId,
            level: ev.data.level,
            msg: scrubSecrets(ev.data.message, rt.info.scrubValues).slice(0, 500),
          },
          'runner log',
        );
        return;
      case 'assistant_text_delta': {
        if (!turn) return;
        turn.deltaText += ev.data.text;
        const simple = turn.streamers.simple.push(ev.data.text);
        const pro = turn.streamers.pro.push(ev.data.text);
        if (simple)
          await this.#publish(
            rt.sessionId,
            'agent_streaming',
            { messageId: turn.assistantId, delta: simple },
            'simple',
          );
        if (pro)
          await this.#publish(
            rt.sessionId,
            'agent_streaming',
            { messageId: turn.assistantId, delta: pro },
            'pro',
          );
        return;
      }
      case 'assistant_text': {
        if (!turn) return;
        turn.texts.push(ev.data.text);
        return;
      }
      case 'tool_use': {
        if (!turn) return;
        const { id, name, input } = ev.data;
        turn.tools.set(id, { name, input, startedAt: Date.now() });
        turn.toolsUsed.add(name);
        // `Task` is the SDK's delegation tool: remember which subagent ran (spec §8.8).
        if (name === 'Task') {
          const sub = input.subagent_type ?? input.subagentType ?? input.description;
          if (typeof sub === 'string' && sub.trim()) turn.subagents.add(sub.trim().slice(0, 100));
        }
        if (name === 'Bash' && typeof input.command === 'string') turn.commands.push(input.command);
        const key = `${name}:${stableKey(input)}`;
        turn.repeat = key === turn.lastToolKey ? turn.repeat + 1 : 1;
        turn.lastToolKey = key;
        const simple = this.translator.toolStatus({ name, input }, 'SIMPLE', tctx);
        const pro = this.translator.toolStatus({ name, input }, 'PRO', tctx);
        rt.state = simple.state;
        await this.#publish(rt.sessionId, 'agent_status', simple, 'simple');
        await this.#publish(rt.sessionId, 'agent_status', pro, 'pro');
        await this.#publish(
          rt.sessionId,
          'tool_event',
          { id, name, phase: 'start', input: scrubSecretsDeep(input, rt.info.scrubValues) },
          'pro',
        );
        if (turn.repeat >= LOOP_DETECTION_THRESHOLD && !turn.loopStopped) {
          turn.loopStopped = true;
          turn.errorCode = 'LSE-AGT-007';
          turn.interrupted = true;
          this.ctx.logger.warn(
            { sessionId: rt.sessionId, code: 'LSE-AGT-007', tool: name },
            'agent loop detected',
          );
          await this.#send(rt, makeRunnerCommand('interrupt', {}));
          await this.#error(rt.sessionId, 'LSE-AGT-007');
        }
        return;
      }
      case 'tool_result': {
        if (!turn) return;
        const call = turn.tools.get(ev.data.id);
        const summary = scrubSecrets(ev.data.summary, rt.info.scrubValues);
        await this.#publish(
          rt.sessionId,
          'tool_event',
          {
            id: ev.data.id,
            name: call?.name ?? 'tool',
            phase: 'end',
            isError: ev.data.isError,
            summary,
            ...(call ? { durationMs: Math.max(0, Date.now() - call.startedAt) } : {}),
          },
          'pro',
        );
        if (call?.name === 'Bash' && ev.data.output) {
          await this.#publish(
            rt.sessionId,
            'terminal_output',
            { toolId: ev.data.id, chunk: scrubSecrets(ev.data.output, rt.info.scrubValues) },
            'pro',
          );
        }
        if (ev.data.isError) {
          turn.hasErrors = true;
          const s = this.translator.toolErrorStatus('SIMPLE', summary, tctx);
          const p = this.translator.toolErrorStatus('PRO', summary, tctx);
          rt.state = s.state;
          await this.#publish(rt.sessionId, 'agent_status', s, 'simple');
          await this.#publish(rt.sessionId, 'agent_status', p, 'pro');
        }
        return;
      }
      case 'approval_needed':
        await this.#approvalNeeded(rt, ev.data);
        return;
      case 'hook_request':
        await this.#hookRequest(rt, ev.data);
        return;
      case 'hook_result':
        await this.#hookResult(rt, ev.data);
        return;
      case 'context_usage':
        await this.#contextUsage(rt, ev.data);
        return;
      case 'usage':
        await this.#usage(rt, ev.data);
        return;
      case 'interrupted':
        if (turn) turn.interrupted = true;
        return;
      case 'error':
        await this.#runnerError(rt, ev.data);
        return;
      case 'turn_complete':
        if (turn && ev.data.conversationAnchor) turn.anchor = ev.data.conversationAnchor;
        await this.#finishTurn(rt, ev.data);
        return;
      case 'screenshot_result':
        return;
      case 'inspect_result':
        return;
    }
  }

  // ---- hooks (spec §8.9) ----------------------------------------------------------------------

  /**
   * The runner hit an event the SERVER owns (webhook / Slack handlers): run them, audit
   * every decision and answer with `hook_response`. Failures become fail-open/closed
   * decisions and are reported as LSE-AGT-014.
   */
  async #hookRequest(rt: AgentRuntime, data: RunnerEventData<'hook_request'>) {
    const payload: HookPayload = {
      ...data.payload,
      sessionId: rt.sessionId,
      projectId: rt.info.project.id,
      orgId: rt.info.org.id,
    };
    const hooks = data.hookId ? rt.hooks.filter((h) => h.id === data.hookId) : rt.hooks;
    const { decision, results } = await evaluateServerHooks(this.ctx, {
      hooks,
      payload,
      orgId: rt.info.org.id,
      sessionId: rt.sessionId,
    });
    for (const r of results) await this.#publishHookEvent(rt.sessionId, r, payload.toolName);
    if (results.some((r) => r.errorCode)) await this.#error(rt.sessionId, 'LSE-AGT-014');
    if (decision.decision === 'deny') {
      if (rt.turn) rt.turn.hasErrors = true;
      await this.#error(rt.sessionId, 'LSE-AGT-005');
    }
    await this.#send(
      rt,
      makeRunnerCommand('hook_response', {
        id: data.id,
        decision: decision.decision,
        ...(decision.reason ? { reason: decision.reason.slice(0, 2000) } : {}),
        ...(decision.updatedInput ? { updatedInput: decision.updatedInput } : {}),
        ...(decision.updatedPrompt ? { updatedPrompt: decision.updatedPrompt } : {}),
      }),
    );
  }

  /** A hook the runner evaluated itself: audit it and show it in the Pro timeline. */
  async #hookResult(rt: AgentRuntime, data: RunnerEventData<'hook_result'>) {
    const hook = rt.hooks.find((h) => h.id === data.hookId);
    await this.#publishHookEvent(
      rt.sessionId,
      {
        hookId: data.hookId,
        name: hook?.name ?? data.hookId,
        event: data.event,
        handler: data.handler,
        decision: {
          decision: data.decision,
          ...(data.reason ? { reason: data.reason } : {}),
        },
        ...(data.errorCode ? { errorCode: data.errorCode as ErrorCode } : {}),
      },
      data.toolName,
    );
    await this.ctx.audit
      .record({
        orgId: rt.info.org.id,
        actorId: null,
        action: 'hook.decision',
        target: data.hookId,
        meta: {
          sessionId: rt.sessionId,
          name: hook?.name ?? null,
          event: data.event,
          handler: data.handler,
          decision: data.decision,
          ...(data.action ? { action: data.action } : {}),
          ...(data.toolName ? { toolName: data.toolName } : {}),
          ...(data.reason
            ? { reason: scrubSecrets(data.reason, rt.info.scrubValues).slice(0, 500) }
            : {}),
          ...(data.errorCode ? { errorCode: data.errorCode } : {}),
          ...(data.durationMs !== undefined ? { durationMs: data.durationMs } : {}),
          source: 'runner',
        },
      })
      .catch(() => undefined);
    if (!hook?.pluginName && data.hookId) {
      await this.ctx.prisma.hook
        .updateMany({
          where: { id: data.hookId },
          data: {
            lastDecision: data.decision,
            lastError: data.errorCode ? `${data.errorCode}` : null,
            lastRunAt: new Date(),
          },
        })
        .catch(() => undefined);
    }
    if (data.errorCode) await this.#error(rt.sessionId, 'LSE-AGT-014');
    else if (data.decision === 'deny') await this.#error(rt.sessionId, 'LSE-AGT-005');
  }

  // ---- context management (spec §8.11) --------------------------------------------------------

  /**
   * Context window usage. Pro viewers always see it; Simple viewers only at / above the
   * warning threshold or when the conversation was compacted.
   */
  async #contextUsage(rt: AgentRuntime, data: RunnerEventData<'context_usage'>) {
    const payload: ContextUsageDto = {
      percent: data.percent,
      usedTokens: data.usedTokens,
      contextWindow: data.contextWindow,
      ...(data.compacted
        ? { event: 'compacted' as const }
        : data.percent >= CONTEXT_WARNING_PERCENT
          ? { event: 'warning' as const }
          : {}),
      ...(data.trigger ? { trigger: data.trigger } : {}),
    };
    await this.#publish(rt.sessionId, 'context_update', payload, 'pro');
    if (isSimpleContextUpdate(payload)) {
      await this.#publish(rt.sessionId, 'context_update', payload, 'simple');
    }
    if (data.compacted) {
      await this.#systemMessage(
        rt,
        'The conversation got long, so I summarised the earlier part. Your files are untouched.',
      );
    }
  }

  async #runnerError(rt: AgentRuntime, data: RunnerEventData<'error'>) {
    const code = data.code as ErrorCode;
    rt.lastErrorCode = code;
    this.ctx.logger.warn(
      {
        sessionId: rt.sessionId,
        code,
        fatal: data.fatal ?? false,
        detail: scrubSecrets(data.detail ?? '', rt.info.scrubValues).slice(0, 300),
      },
      'runner error',
    );
    if (rt.turn) {
      rt.turn.hasErrors = true;
      if (BLOCKING_RUNNER_ERRORS.has(code)) rt.turn.errorCode ??= code;
    }
    if (code === 'LSE-KEY-003') {
      const key = await this.ctx.prisma.apiKey.findFirst({
        where: { userId: rt.userId, orgId: null, provider: 'anthropic', status: 'ACTIVE' },
        orderBy: { createdAt: 'desc' },
      });
      if (key) {
        await this.ctx.prisma.apiKey.update({ where: { id: key.id }, data: { status: 'INVALID' } });
        await this.ctx.audit.record({
          orgId: rt.info.org.id,
          actorId: null,
          action: 'api_key.invalidated',
          target: key.id,
          meta: {
            userId: rt.userId,
            last4: key.last4,
            source: 'agent_runtime',
            sessionId: rt.sessionId,
          },
        });
      }
    }
    try {
      getErrorDefinition(code);
    } catch {
      await this.#error(rt.sessionId, 'LSE-AGT-001');
      return;
    }
    await this.#error(rt.sessionId, code);
  }

  // ---- usage & budgets ---------------------------------------------------------------------

  async #usage(rt: AgentRuntime, u: RunnerEventData<'usage'>) {
    if (u.subagent && rt.turn) rt.turn.subagents.add(u.subagent);
    const computed = computeCostUsd(u.model, {
      in: u.in,
      out: u.out,
      cacheRead: u.cacheRead,
      ...(u.cacheWrite !== undefined ? { cacheWrite: u.cacheWrite } : {}),
    });
    const cost = u.costUsd > 0 ? u.costUsd : computed;
    if (u.costUsd > 0 && computed > 0 && Math.abs(u.costUsd - computed) / computed > 0.05) {
      this.ctx.logger.warn(
        {
          sessionId: rt.sessionId,
          model: u.model,
          runnerCostUsd: u.costUsd,
          computedCostUsd: computed,
        },
        'runner-reported cost differs from the price table by more than 5%',
      );
    }
    const [, s] = await this.ctx.prisma.$transaction([
      this.ctx.prisma.usageEvent.create({
        data: {
          sessionId: rt.sessionId,
          orgId: rt.info.org.id,
          userId: rt.userId,
          model: u.model,
          tokensIn: u.in,
          tokensOut: u.out,
          cacheRead: u.cacheRead,
          costUsd: cost,
          subagent: u.subagent ?? null,
        },
      }),
      this.ctx.prisma.session.update({
        where: { id: rt.sessionId },
        data: {
          totalCostUsd: { increment: cost },
          totalTokensIn: { increment: u.in },
          totalTokensOut: { increment: u.out },
          cacheReadTokens: { increment: u.cacheRead },
        },
      }),
    ]);
    const total = Number(s.totalCostUsd);
    const budget = s.budgetUsd === null ? null : Number(s.budgetUsd);
    const level = costLevel(total, budget);
    await this.#publish(rt.sessionId, 'cost_update', {
      totalCostUsd: total,
      budgetUsd: budget ?? 0,
      remainingUsd: remainingBudgetUsd(total, budget) ?? 0,
      tokensIn: Number(s.totalTokensIn),
      tokensOut: Number(s.totalTokensOut),
      cacheRead: Number(s.cacheReadTokens),
      level,
    });
    if (level === 'warning' && !rt.warned) {
      rt.warned = true;
      await this.#systemMessage(rt, 'Heads up: this session has used 80% of its budget.');
    }
    if (level === 'exceeded') {
      this.#budgetStop(rt, 'LSE-AGT-003', {
        scope: 'session',
        spentUsd: total,
        budgetUsd: budget,
      });
      return;
    }
    try {
      // Fresh org row: the policy (caps) may have changed during the session.
      const org = await this.ctx.prisma.organization.findUniqueOrThrow({
        where: { id: rt.info.org.id },
      });
      rt.info.org = org;
      const key = await activeKeyFor(this.ctx, rt.userId);
      const hit = await findExceededBudget(this.ctx, org, rt.userId, key);
      if (hit) this.#budgetStop(rt, 'LSE-KEY-012', hit);
    } catch {
      // No usable key / DB hiccup: not a budget stop (the next turn's preflight decides).
    }
  }

  /** Hard stop at 100 %: interrupt, push WIP, PAUSED (spec §8.19). */
  #budgetStop(
    rt: AgentRuntime,
    code: ErrorCode,
    budget: { scope: BudgetScope; spentUsd: number | null; budgetUsd: number | null },
  ) {
    if (rt.budgetStopping) return;
    rt.budgetStopping = true;
    this.ctx.logger.info({ sessionId: rt.sessionId, code }, 'budget reached; pausing session');
    this.#track(
      (async () => {
        await emitBudgetExceeded(this.ctx, rt.info.org.id, {
          ...budget,
          errorCode: code,
          action: 'paused',
          userId: rt.userId,
          projectId: rt.info.project.id,
          sessionId: rt.sessionId,
        });
        if (rt.busy) await this.#send(rt, makeRunnerCommand('interrupt', {}));
        await stopSession(this.ctx, rt.sessionId, {
          to: 'PAUSED',
          reason: 'budget',
          errorCode: code,
          pushWip: true,
        });
      })(),
    );
  }

  async #systemMessage(rt: AgentRuntime, content: string) {
    await this.systemMessage(rt.sessionId, content);
  }

  /** Persist + broadcast a SYSTEM chat message (same text for every viewer). */
  async systemMessage(
    sessionId: string,
    content: string,
    metadata: ChatMessageMetadata = { kind: 'system' },
  ): Promise<ChatMessageDto> {
    const row = await this.ctx.prisma.chatMessage.create({
      data: {
        id: newId(),
        sessionId,
        role: 'SYSTEM',
        content,
        metadata: metadata as Prisma.InputJsonValue,
      },
    });
    const message = this.#dto(row);
    await this.#publish(sessionId, 'chat_message', { message });
    return message;
  }

  // ---- approvals -----------------------------------------------------------------------------

  #highRiskAction(rt: AgentRuntime, tool: string, input: Record<string, unknown>): boolean {
    if (tool === 'Bash' && typeof input.command === 'string') {
      const c = classifyCommand(input.command);
      return (
        c.category === 'destructive' || c.category === 'dependencies' || c.category === 'migrations'
      );
    }
    const path = typeof input.file_path === 'string' ? input.file_path : undefined;
    if (!path) return false;
    const rel = normalizeWorkspacePath(path, rt.sandbox.paths.workspace) ?? path;
    return gateForFile(rel) !== undefined || assessRisk({ files: [rel] }).level === 'HIGH';
  }

  async #approvalNeeded(rt: AgentRuntime, a: RunnerEventData<'approval_needed'>) {
    const org = await this.ctx.prisma.organization.findUniqueOrThrow({
      where: { id: rt.info.org.id },
    });
    rt.info.org = org;
    const policy = parseOrgPolicy(org.policy);
    const gate = (a.gate ?? null) as ApprovalGate | null;
    const requiresAdmin =
      !isAdminRole(rt.info.ownerRole) &&
      (gate === 'dependencies' ||
        gate === 'migrations' ||
        this.#highRiskAction(rt, a.tool, a.input));
    const tctx = rt.info.tctx;
    const simple = this.translator.approvalText(
      { tool: a.tool, input: a.input, gate, reason: a.reason },
      'SIMPLE',
      tctx,
    );
    const pro = this.translator.approvalText(
      { tool: a.tool, input: a.input, gate, reason: a.reason },
      'PRO',
      tctx,
    );
    const expiresAt = new Date(Date.now() + policy.approvalTimeoutMin * 60_000);
    const row = await this.ctx.prisma.toolApproval.create({
      data: {
        id: newId(),
        sessionId: rt.sessionId,
        tool: a.tool,
        input: scrubSecretsDeep(a.input, rt.info.scrubValues) as Prisma.InputJsonValue,
        status: 'PENDING',
        gate,
        summary: simple.summary,
        reason: pro.reason,
        runnerRequestId: a.id,
        requiresAdmin,
        expiresAt,
      },
    });
    const simpleDto = approvalDto(row, 'SIMPLE', this.translator, tctx);
    const proDto = approvalDto(row, 'PRO', this.translator, tctx);
    await this.#publish(rt.sessionId, 'approval_required', { approval: simpleDto }, 'simple');
    await this.#publish(rt.sessionId, 'approval_required', { approval: proDto }, 'pro');
    await this.#status(
      rt,
      'waiting_approval',
      requiresAdmin ? 'Waiting for an admin to approve…' : 'Waiting for your OK…',
      `Waiting for approval: ${pro.summary}`,
    );
    await this.ctx.jobs.enqueue(
      'approval-expiry',
      { approvalId: row.id },
      { jobId: `approval-expiry:${row.id}`, delayMs: expiresAt.getTime() - Date.now() + 1000 },
    );
  }

  // ---- turn completion -----------------------------------------------------------------------

  async #screenshot(
    rt: AgentRuntime,
    phase: 'before' | 'after',
    messageId: string,
    viewport: Viewport = 'desktop',
  ): Promise<string | undefined> {
    if (!this.ctx.env.AGENT_SCREENSHOTS || !rt.previewUrl || !rt.runner) return undefined;
    const requestId = newId();
    const result = await new Promise<RunnerEventData<'screenshot_result'>>((resolve) => {
      const timer = setTimeout(() => {
        rt.shots.delete(requestId);
        resolve({ requestId, ok: false, error: 'timeout' });
      }, SCREENSHOT_TIMEOUT_MS);
      timer.unref();
      rt.shots.set(requestId, (r) => {
        clearTimeout(timer);
        resolve(r);
      });
      void this.#send(
        rt,
        makeRunnerCommand('screenshot', { requestId, url: rt.previewUrl!, viewport }),
      ).then((ok) => {
        if (!ok) rt.shots.get(requestId)?.({ requestId, ok: false, error: 'runner unavailable' });
      });
    });
    if (!result.ok || !result.pngBase64) return undefined;
    const artifact = await saveArtifact(this.ctx, {
      sessionId: rt.sessionId,
      kind: 'screenshot',
      data: Buffer.from(result.pngBase64, 'base64'),
      contentType: 'image/png',
      meta: {
        viewport,
        phase,
        messageId,
        ...(result.width ? { width: result.width } : {}),
        ...(result.height ? { height: result.height } : {}),
      },
    });
    return artifact.id;
  }

  /**
   * `POST /sessions/:id/inspect` (spec §8.12): find the element at a point of the
   * preview. The CSS selector is Pro-only; Simple viewers get the label.
   */
  async inspect(caller: Caller, sessionId: string, body: InspectBody): Promise<InspectResultDto> {
    const { session, membership } = await this.#access(caller, sessionId, 'write');
    this.#requireRunning(session);
    const rt = await this.#runtimeFor(session);
    if (!rt.previewUrl) {
      throw new AppError('LSE-CONF-001', {
        devMessage: 'The session has no preview to inspect',
        userMessage: 'The preview is not ready yet. Try again in a moment.',
      });
    }
    const org = await this.ctx.prisma.organization.findUniqueOrThrow({
      where: { id: session.project.orgId },
    });
    const pro = viewerMode(session, membership, org) === 'PRO';
    const requestId = newId();
    const result = await new Promise<RunnerEventData<'inspect_result'>>((resolve) => {
      const timer = setTimeout(() => {
        rt.inspects.delete(requestId);
        resolve({ requestId, ok: false, error: 'timeout' });
      }, SCREENSHOT_TIMEOUT_MS);
      timer.unref();
      rt.inspects.set(requestId, (r) => {
        clearTimeout(timer);
        resolve(r);
      });
      void this.#send(
        rt,
        makeRunnerCommand('inspect', {
          requestId,
          url: rt.previewUrl!,
          x: body.x,
          y: body.y,
          viewport: body.viewport,
        }),
      ).then((ok) => {
        if (!ok)
          rt.inspects.get(requestId)?.({ requestId, ok: false, error: 'runner unavailable' });
      });
    });
    const label = elementLabel(result.tagName, result.text);
    if (!result.ok) {
      return inspectResultDtoSchema.parse({
        ok: false,
        selector: null,
        label,
        tagName: null,
        artifactId: null,
        rect: null,
        error: {
          code: 'LSE-AGT-001',
          message: scrubSecrets(result.error ?? 'The preview could not be inspected.').slice(
            0,
            200,
          ),
        },
      });
    }
    let artifactId: string | null = null;
    if (result.pngBase64) {
      const artifact = await saveArtifact(this.ctx, {
        sessionId: rt.sessionId,
        kind: 'element',
        data: Buffer.from(result.pngBase64, 'base64'),
        contentType: 'image/png',
        meta: {
          viewport: body.viewport,
          label,
          ...(result.tagName ? { tagName: result.tagName } : {}),
          ...(result.rect ? { rect: result.rect } : {}),
        },
      }).catch((err: unknown) => {
        this.ctx.logger.warn({ err, sessionId }, 'could not store the element crop');
        return null;
      });
      artifactId = artifact?.id ?? null;
    }
    return inspectResultDtoSchema.parse({
      ok: true,
      selector: pro ? (result.selector ?? null) : null,
      label,
      tagName: result.tagName ?? null,
      artifactId,
      rect: result.rect ?? null,
      error: null,
    });
  }

  /** Post-turn guardrails: path patterns + secrets in the diff (auto-revert). */
  async #guardrails(rt: AgentRuntime, turn: Turn): Promise<StatusEntry[]> {
    const { project } = rt.info;
    let status = await gitStatus(rt.sandbox);
    const patterns = { allowed: project.allowedFilePatterns, denied: project.deniedFilePatterns };
    const violations = status.filter(
      (e) =>
        !isPathAllowed(e.path, patterns) ||
        (e.origPath !== undefined && !isPathAllowed(e.origPath, patterns)),
    );
    if (violations.length) {
      const reverted = await revertPaths(rt.sandbox, violations);
      turn.hasErrors = true;
      this.ctx.logger.warn(
        { sessionId: rt.sessionId, code: 'LSE-AGT-004', count: reverted.length },
        'reverted off-limits changes',
      );
      await this.ctx.audit.record({
        orgId: rt.info.org.id,
        actorId: null,
        action: 'security.path_violation',
        target: rt.sessionId,
        meta: { files: reverted.slice(0, 50), projectId: project.id },
      });
      await this.#error(rt.sessionId, 'LSE-AGT-004');
      status = await gitStatus(rt.sandbox);
    }
    // The server re-validates `block_paths` hooks against the real git status: a hook
    // that the runner skipped (or that was added mid-session) still cannot be bypassed.
    status = await this.#revalidateBlockPaths(rt, turn, status);
    if (!status.length) return status;
    const files = parseUnifiedDiff(await workingDiff(rt.sandbox));
    const offending = files.filter((f) =>
      addedLines(f.patch).some((l) => scrubSecrets(l, rt.info.diffSecrets) !== l),
    );
    if (offending.length) {
      const paths = new Set(offending.map((f) => f.path));
      const reverted = await revertPaths(
        rt.sandbox,
        status.filter((e) => paths.has(e.path)),
      );
      turn.hasErrors = true;
      this.ctx.logger.warn(
        { sessionId: rt.sessionId, code: 'LSE-AGT-016', count: reverted.length },
        'reverted files containing secrets',
      );
      await this.ctx.audit.record({
        orgId: rt.info.org.id,
        actorId: null,
        action: 'security.secret_blocked',
        target: rt.sessionId,
        meta: { files: reverted.slice(0, 50), projectId: project.id, alert: 'admins' },
      });
      await this.#error(rt.sessionId, 'LSE-AGT-016');
      status = await gitStatus(rt.sandbox);
    }
    return status;
  }

  /**
   * Server-side enforcement of `block_paths` hooks (Phase 8 exit criterion): revert
   * anything the hooks forbid, report LSE-AGT-004 and audit it.
   */
  async #revalidateBlockPaths(
    rt: AgentRuntime,
    turn: Turn,
    status: StatusEntry[],
  ): Promise<StatusEntry[]> {
    if (!status.length) return status;
    const paths = status.flatMap((e) => [e.path, ...(e.origPath ? [e.origPath] : [])]);
    const blocked = blockedPaths(rt.hooks, paths);
    if (!blocked) return status;
    const offending = new Set(blocked.paths);
    const entries = status.filter(
      (e) => offending.has(e.path) || (e.origPath !== undefined && offending.has(e.origPath)),
    );
    const reverted = await revertPaths(rt.sandbox, entries);
    turn.hasErrors = true;
    this.ctx.logger.warn(
      {
        sessionId: rt.sessionId,
        code: 'LSE-AGT-004',
        hookId: blocked.hook.id,
        count: reverted.length,
      },
      'reverted changes blocked by a hook',
    );
    await this.ctx.audit
      .record({
        orgId: rt.info.org.id,
        actorId: null,
        action: 'hook.decision',
        target: blocked.hook.id,
        meta: {
          sessionId: rt.sessionId,
          name: blocked.hook.name,
          event: 'PostToolUse',
          handler: 'builtin',
          action: 'block_paths',
          decision: 'deny',
          reason: blocked.reason.slice(0, 500),
          files: reverted.slice(0, 50),
          source: 'post_turn',
        },
      })
      .catch(() => undefined);
    await this.#publishHookEvent(rt.sessionId, {
      hookId: blocked.hook.id,
      name: blocked.hook.name,
      event: 'PostToolUse',
      handler: 'builtin',
      decision: { decision: 'deny', reason: blocked.reason },
    });
    await this.#error(rt.sessionId, 'LSE-AGT-004');
    return gitStatus(rt.sandbox);
  }

  async #finishTurn(rt: AgentRuntime, data: RunnerEventData<'turn_complete'>) {
    const turn = rt.turn;
    if (!turn || turn.done) return;
    turn.done = true;
    if (data.stopReason === 'interrupted') turn.interrupted = true;
    if (data.stopReason === 'error' && !turn.errorCode && rt.lastErrorCode) {
      if (BLOCKING_RUNNER_ERRORS.has(rt.lastErrorCode)) turn.errorCode = rt.lastErrorCode;
    }
    if (data.stopReason === 'max_turns') turn.errorCode ??= 'LSE-AGT-002';
    if (data.stopReason === 'budget') turn.errorCode ??= 'LSE-AGT-003';
    const tctx = rt.info.tctx;
    const sid = rt.sessionId;
    /** Files the turn changed (for the platform `session.turn_completed` event). */
    let emittedFiles: string[] = [];
    try {
      // Rest of the streamed text.
      const s = turn.streamers.simple.flush();
      const p = turn.streamers.pro.flush();
      if (s)
        await this.#publish(
          sid,
          'agent_streaming',
          { messageId: turn.assistantId, delta: s },
          'simple',
        );
      if (p)
        await this.#publish(
          sid,
          'agent_streaming',
          { messageId: turn.assistantId, delta: p },
          'pro',
        );
      await this.#status(rt, 'finishing', 'Wrapping up…');

      let status: StatusEntry[] = [];
      try {
        status = await this.#guardrails(rt, turn);
      } catch (err) {
        this.ctx.logger.warn({ err, sessionId: sid }, 'post-turn validation failed');
      }
      const byPath = new Map(status.map((e) => [e.path, e]));
      const ws = rt.sandbox.paths.workspace;
      const turnFiles = [
        ...new Set(
          data.filesChanged
            .map((f) => normalizeWorkspacePath(f, ws))
            .filter((f): f is string => !!f && byPath.has(f)),
        ),
      ];
      const diffFiles = turnFiles.length
        ? parseUnifiedDiff(await workingDiff(rt.sandbox).catch(() => '')).filter((f) =>
            turnFiles.includes(f.path),
          )
        : [];
      emittedFiles = turnFiles;
      const deleted = turnFiles.filter((f) => statusKind(byPath.get(f)!) === 'deleted');
      const changed = turnFiles.filter((f) => !deleted.includes(f));
      const risk: RiskLevel | undefined = turnFiles.length
        ? riskForChange({ files: changed, deletedFiles: deleted, commands: turn.commands })
        : undefined;
      const areas = this.translator.areas(turnFiles, tctx);

      const afterShots = new Map<Viewport, string>();
      if (turnFiles.length) {
        for (const viewport of rt.screenshotViewports) {
          const shot = await this.#screenshot(rt, 'after', turn.assistantId, viewport);
          if (shot) afterShots.set(viewport, shot);
        }
      }
      const beforeShots = new Map(rt.beforeShots);
      for (const [viewport, shot] of rt.lastAfterShots) beforeShots.set(viewport, shot);
      for (const [viewport, shot] of afterShots) rt.lastAfterShots.set(viewport, shot);

      const text = turn.texts.length ? turn.texts.join('\n\n') : turn.deltaText;
      if (turn.anchor) {
        rt.lastAnchor = turn.anchor;
        await this.ctx.prisma.session
          .updateMany({
            where: { id: sid, resumeSessionAt: { not: null } },
            data: { resumeSessionAt: null },
          })
          .catch(() => undefined);
      }
      if (turn.plan && turn.planText && !turn.errorCode && !turn.interrupted && !turnFiles.length) {
        await this.#finishPlan(rt, turn, turn.planText);
        return;
      }
      const summaryInput = {
        text,
        files: turnFiles,
        interrupted: turn.interrupted,
        ...(turn.errorCode
          ? {
              errorCode: turn.errorCode,
              errorUserMessage: getErrorDefinition(turn.errorCode).userMessage,
            }
          : {}),
      };
      const simpleText = this.translator.changeSummary(summaryInput, 'SIMPLE', tctx);
      const proText = this.translator.changeSummary(summaryInput, 'PRO', tctx);
      const kind: ChatMessageMetadata['kind'] = turnFiles.length
        ? 'change_summary'
        : turn.errorCode
          ? 'error'
          : 'text';
      const metadata: ChatMessageMetadata = {
        kind,
        ...(risk ? { risk } : {}),
        areas,
        filesChanged: turnFiles,
        toolsUsed: [...turn.toolsUsed],
        hasErrors: turn.hasErrors,
        ...(turn.subagents.size ? { subagents: [...turn.subagents].slice(0, 20) } : {}),
        ...(turn.errorCode ? { errorCode: turn.errorCode } : {}),
      };
      const rawContent = {
        pending: false,
        events: turn.raw.slice(-MAX_RAW_EVENTS),
        proText,
        ...(turn.anchor ? { conversationAnchor: turn.anchor } : {}),
      } as Prisma.InputJsonValue;
      const row = await this.ctx.prisma.chatMessage.upsert({
        where: { id: turn.assistantId },
        create: {
          id: turn.assistantId,
          sessionId: sid,
          role: 'ASSISTANT',
          content: simpleText,
          rawContent,
          metadata: metadata as Prisma.InputJsonValue,
        },
        update: { content: simpleText, rawContent, metadata: metadata as Prisma.InputJsonValue },
      });
      const simpleMsg = this.#dto(row);
      const proMsg = { ...simpleMsg, content: proText };
      await this.#publish(sid, 'chat_message', { message: simpleMsg }, 'simple');
      await this.#publish(sid, 'chat_message', { message: proMsg }, 'pro');

      if (turnFiles.length && risk) {
        const viewports = [
          ...new Set<Viewport>([...afterShots.keys(), ...beforeShots.keys()]),
        ].sort();
        const screenshots = viewports
          .map((viewport) => ({
            ...(beforeShots.get(viewport) ? { before: beforeShots.get(viewport)! } : {}),
            ...(afterShots.get(viewport) ? { after: afterShots.get(viewport)! } : {}),
            viewport,
          }))
          .filter((s) => s.before || s.after);
        const base = {
          messageId: turn.assistantId,
          areas,
          risk,
          stats: diffStats(diffFiles),
          screenshots,
        };
        await this.#publish(sid, 'change_summary', { ...base, summary: simpleText }, 'simple');
        await this.#publish(
          sid,
          'change_summary',
          {
            ...base,
            summary: proText,
            files: turnFiles.map((f) => ({ path: f, status: statusKind(byPath.get(f)!) })),
          },
          'pro',
        );
        if (rt.previewUrl)
          await this.#publish(sid, 'preview_updated', { url: rt.previewUrl, reason: 'change' });
        await this.#conflicts(rt, turnFiles);
      }
    } finally {
      rt.turn = null;
      rt.busy = false;
      await this.ctx.prisma.session
        .updateMany({ where: { id: sid, status: 'RUNNING' }, data: { idleSince: new Date() } })
        .catch(() => undefined);
      const planPending = !!(turn.plan && turn.planText && rt.state === 'waiting_approval');
      if (!rt.stopping) {
        if (rt.queue.length) this.#drain(rt);
        else if (planPending) {
          // Keep "waiting for the plan" until it is approved / cancelled.
        } else await this.#status(rt, 'idle', SIMPLE_IDLE, 'Idle');
      }
      // Phase 9: headless runs / triggers react to the end of a turn (never throws).
      await emitTurnCompleted(this.ctx, rt.info.org.id, {
        sessionId: sid,
        projectId: rt.info.project.id,
        userId: rt.userId,
        messageId: turn.assistantId,
        filesChanged: emittedFiles,
        errorCode: turn.errorCode ?? null,
        interrupted: turn.interrupted,
        planPending,
      });
    }
  }

  /** Plan-mode turn → plan message + plan approval (approve / edit / cancel). */
  async #finishPlan(rt: AgentRuntime, turn: Turn, markdown: string) {
    const sid = rt.sessionId;
    const tctx = rt.info.tctx;
    const plan = scrubSecrets(markdown, rt.info.scrubValues);
    const proSteps = planSteps(plan);
    const simpleSteps = proSteps
      .map((step) => this.translator.assistantText(step, 'SIMPLE', tctx).trim())
      .filter(Boolean);
    const intro = "Here's my plan. Nothing has been changed yet.";
    const simpleText = [
      intro,
      ...simpleSteps.map((x) => `- ${x}`),
      '',
      'Approve it to start, or tell me what to change.',
    ].join('\n');
    const proText = `${intro}\n\n${plan}`;
    const org = await this.ctx.prisma.organization.findUniqueOrThrow({
      where: { id: rt.info.org.id },
    });
    const policy = parseOrgPolicy(org.policy);
    const approval = await this.ctx.prisma.toolApproval.create({
      data: {
        id: newId(),
        sessionId: sid,
        tool: 'plan',
        kind: 'plan',
        input: { plan, steps: simpleSteps } as Prisma.InputJsonValue,
        status: 'PENDING',
        summary: 'Review the plan',
        reason: '',
        messageId: turn.assistantId,
        requiresAdmin: false,
        expiresAt: new Date(Date.now() + policy.approvalTimeoutMin * 60_000),
      },
    });
    const metadata: ChatMessageMetadata = {
      kind: 'plan',
      toolsUsed: [...turn.toolsUsed],
      hasErrors: turn.hasErrors,
      ...(turn.subagents.size ? { subagents: [...turn.subagents].slice(0, 20) } : {}),
      plan: { approvalId: approval.id, steps: simpleSteps, markdown: plan },
    };
    const rawContent = {
      pending: false,
      events: turn.raw.slice(-MAX_RAW_EVENTS),
      proText,
      ...(turn.anchor ? { conversationAnchor: turn.anchor } : {}),
    } as Prisma.InputJsonValue;
    const row = await this.ctx.prisma.chatMessage.upsert({
      where: { id: turn.assistantId },
      create: {
        id: turn.assistantId,
        sessionId: sid,
        role: 'ASSISTANT',
        content: simpleText,
        rawContent,
        metadata: metadata as Prisma.InputJsonValue,
      },
      update: { content: simpleText, rawContent, metadata: metadata as Prisma.InputJsonValue },
    });
    const msg = this.#dto(row);
    await this.#publish(sid, 'chat_message', { message: msg }, 'simple');
    await this.#publish(sid, 'chat_message', { message: { ...msg, content: proText } }, 'pro');
    await this.#publish(
      sid,
      'plan_proposed',
      {
        approval: approvalDto(approval, 'SIMPLE', this.translator, tctx),
        messageId: turn.assistantId,
        plan: { steps: simpleSteps },
      },
      'simple',
    );
    await this.#publish(
      sid,
      'plan_proposed',
      {
        approval: approvalDto(approval, 'PRO', this.translator, tctx),
        messageId: turn.assistantId,
        plan: { steps: proSteps, markdown: plan },
      },
      'pro',
    );
    await this.ctx.jobs.enqueue(
      'approval-expiry',
      { approvalId: approval.id },
      {
        jobId: `approval-expiry:${approval.id}`,
        delayMs: approval.expiresAt!.getTime() - Date.now() + 1000,
      },
    );
    await this.#status(
      rt,
      'waiting_approval',
      'Waiting for you to approve the plan…',
      'Plan ready for review',
    );
  }

  /**
   * Plan decision (approvals service): approve starts a turn executing the (edited) plan;
   * cancel returns to idle (LSE-AGT-012).
   */
  async onPlanDecision(
    sessionId: string,
    approval: { id: string; input: Prisma.JsonValue },
    decision: { approve: boolean; plan?: string; edited: boolean },
  ) {
    const rt = this.#runtimes.get(sessionId);
    if (!decision.approve) {
      if (rt && !rt.busy) await this.#status(rt, 'idle', SIMPLE_IDLE, 'Idle');
      await this.systemMessage(sessionId, getErrorDefinition('LSE-AGT-012').userMessage, {
        kind: 'system',
        errorCode: 'LSE-AGT-012',
      });
      return;
    }
    const input = (approval.input ?? {}) as { plan?: unknown };
    const plan = decision.plan ?? (typeof input.plan === 'string' ? input.plan : '');
    await this.submitTurn(sessionId, {
      content: decision.edited ? 'Approved the edited plan' : 'Approved the plan',
      agentText: buildPlanApprovalPrompt(plan),
      command: 'plan-approved',
      label: 'Carry out the approved plan',
    });
  }

  async #mcpStatus(rt: AgentRuntime, data: RunnerEventData<'mcp_status'>) {
    const servers = data.servers.map((x) => ({
      name: x.name,
      status: x.status,
      ...(x.error ? { error: scrubSecrets(x.error, rt.info.scrubValues).slice(0, 500) } : {}),
      ...(x.tools ? { toolCount: x.tools.length } : {}),
    }));
    await this.#publish(rt.sessionId, 'mcp_status', { servers }, 'pro');
    await recordMcpStatuses(
      this.ctx,
      rt.mcpIds,
      data.servers.map((x) => ({
        name: x.name,
        status: x.status,
        ...(x.error ? { error: scrubSecrets(x.error, rt.info.scrubValues) } : {}),
        ...(x.tools ? { tools: x.tools } : {}),
      })),
    );
    for (const x of data.servers) {
      if (x.status !== 'failed' && x.status !== 'needs_auth') continue;
      if (rt.mcpWarned.has(x.name)) continue;
      rt.mcpWarned.add(x.name);
      const code: ErrorCode = x.status === 'needs_auth' ? 'LSE-MCP-002' : 'LSE-MCP-001';
      this.ctx.logger.warn(
        { sessionId: rt.sessionId, code, server: x.name },
        'MCP server unavailable',
      );
      await this.#publish(rt.sessionId, 'error', {
        ...errorPayload(code, rt.sessionId),
        recoverable: true,
      });
    }
  }

  /** §8.14: overlap with other RUNNING sessions on the same project (LSE-SBX-014). */
  async #conflicts(rt: AgentRuntime, files: string[]) {
    const others = await this.ctx.prisma.session.findMany({
      where: { projectId: rt.info.project.id, status: 'RUNNING', id: { not: rt.sessionId } },
      include: { user: { select: { name: true, email: true } } },
      take: 20,
    });
    for (const o of others) {
      const msgs = await this.ctx.prisma.chatMessage.findMany({
        where: { sessionId: o.id, role: 'ASSISTANT', rewoundAt: null },
        select: { metadata: true },
        orderBy: { createdAt: 'desc' },
        take: 50,
      });
      const theirs = new Set(
        msgs.flatMap((m) => {
          const f = (m.metadata as ChatMessageMetadata | null)?.filesChanged;
          return Array.isArray(f) ? f : [];
        }),
      );
      const overlap = files.filter((f) => theirs.has(f));
      if (!overlap.length) continue;
      const areas = this.translator.areas(overlap, rt.info.tctx);
      this.ctx.logger.info(
        { sessionId: rt.sessionId, otherSessionId: o.id, code: 'LSE-SBX-014' },
        'conflicting edits',
      );
      await this.#publish(rt.sessionId, 'conflict_warning', {
        otherSessionId: o.id,
        otherUserName: o.user.name ?? o.user.email,
        code: 'LSE-SBX-014',
        files: overlap,
        areas,
      });
      await this.#publish(o.id, 'conflict_warning', {
        otherSessionId: rt.sessionId,
        otherUserName: rt.userName,
        code: 'LSE-SBX-014',
        files: overlap,
        areas,
      });
    }
  }

  // ---- DTOs ----------------------------------------------------------------------------------

  #dto(row: {
    id: string;
    sessionId: string;
    role: string;
    content: string;
    clientMessageId: string | null;
    metadata: Prisma.JsonValue;
    attachments?: Prisma.JsonValue;
    createdAt: Date;
  }): ChatMessageDto {
    return chatMessageDtoSchema.parse({
      ...row,
      metadata: withAttachments(row.metadata, row.attachments),
    });
  }
}

/**
 * Attachments live in their own column; the DTO carries them inside `metadata` (spec §8.12),
 * so the two are merged when a row is rendered.
 */
export function withAttachments(
  metadata: Prisma.JsonValue,
  attachments: Prisma.JsonValue | undefined,
): Record<string, unknown> | null {
  const meta =
    metadata && typeof metadata === 'object' && !Array.isArray(metadata)
      ? (metadata as Record<string, unknown>)
      : null;
  if (!Array.isArray(attachments) || attachments.length === 0) return meta;
  return { ...(meta ?? {}), attachments };
}

export function approvalDto(
  row: {
    id: string;
    sessionId: string;
    tool: string;
    input: Prisma.JsonValue;
    status: string;
    gate: string | null;
    summary: string | null;
    reason: string | null;
    requiresAdmin: boolean;
    createdAt: Date;
    expiresAt: Date | null;
    decidedAt: Date | null;
    kind?: string;
  },
  mode: Mode,
  translator: Translator = defaultTranslator,
  tctx: TranslationContext = { secrets: [] },
): ToolApprovalDto {
  const input =
    row.input && typeof row.input === 'object' && !Array.isArray(row.input)
      ? (row.input as Record<string, unknown>)
      : {};
  if (row.kind === 'plan') {
    const markdown = typeof input.plan === 'string' ? input.plan : '';
    const steps = Array.isArray(input.steps)
      ? input.steps.filter((x): x is string => typeof x === 'string')
      : [];
    return toolApprovalDtoSchema.parse({
      id: row.id,
      sessionId: row.sessionId,
      tool: 'plan',
      kind: 'plan',
      summary: mode === 'PRO' ? 'Review the plan' : "Here's the plan — approve it to start",
      reason: '',
      gate: null,
      status: row.status,
      createdAt: row.createdAt,
      expiresAt: row.expiresAt,
      decidedAt: row.decidedAt,
      requiresAdmin: false,
      plan: mode === 'PRO' ? { steps: planSteps(markdown), markdown } : { steps },
    });
  }
  const texts = translator.approvalText(
    {
      tool: row.tool,
      input,
      gate: (row.gate ?? null) as ApprovalGate | null,
      reason: row.reason ?? '',
    },
    mode,
    tctx,
  );
  return toolApprovalDtoSchema.parse({
    id: row.id,
    sessionId: row.sessionId,
    tool: mode === 'PRO' ? row.tool : 'action',
    summary: texts.summary,
    reason: texts.reason,
    gate: row.gate,
    status: row.status,
    createdAt: row.createdAt,
    expiresAt: row.expiresAt,
    decidedAt: row.decidedAt,
    requiresAdmin: row.requiresAdmin,
  });
}
