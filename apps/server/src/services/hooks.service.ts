/**
 * Hooks (spec §8.9; Phase 8) — deterministic policy automation. **The server is the
 * source of truth**: it owns every handler that talks to the outside world (`http`
 * webhooks, `notify_slack`), evaluates `UserPromptSubmit` itself before a turn starts,
 * answers the runner's `hook_request` for the events it owns, and re-validates
 * `block_paths` against the git status after every turn.
 *
 * `command` and `builtin` handlers that only touch the workspace are evaluated inside
 * the sandbox by the runner (it reports them back as `hook_result` for the audit log).
 *
 * Secrets (webhook HMAC secret, Slack webhook URL) live envelope-encrypted in
 * `Hook.secretEnc` and are never returned by the API.
 */
import { createHmac, timingSafeEqual } from 'node:crypto';
import type { Hook, Organization, Prisma } from '@prisma/client';
import {
  defaultHookFailMode,
  evaluateBuiltinHook,
  hookDecisionSchema,
  hookDtoSchema,
  hookFailureDecision,
  hookMatcherMatches,
  hookSamplePayload,
  hookTestResultDtoSchema,
  HOOK_EVENT_HEADER,
  HOOK_RECIPES,
  HOOK_SIGNATURE_HEADER,
  isToolHookEvent,
  MAX_HOOKS_PER_EVENT,
  mergeHookDecisions,
  scrubSecrets,
  validateHookDefinition,
  type CreateHookBody,
  type ErrorCode,
  type ExtensionListQuery,
  type HookBuiltinConfig,
  type HookDecision,
  type HookDto,
  type HookEvent,
  type HookFailMode,
  type HookHandler,
  type HookHandlerDto,
  type HookPayload,
  type HookTestBody,
  type HookTestResultDto,
  type RunnerHookInput,
  type UpdateHookBody,
} from '@loose/shared';
import type { AppContext } from '../context';
import { safeFetch } from '../lib/net/safeFetch';
import { AppError } from '../lib/errors';
import {
  assertAdmin,
  assertNameFree,
  assertProjectInOrg,
  assertPublicUrl,
  isRecord,
  json,
  type ExtActor,
} from './extensionsCommon';
import { resolvePluginContents, type ResolvedPluginHook } from './plugins.service';

/** Decrypted handler secrets (never leave the server). */
interface HookSecrets {
  secret?: string;
  webhookUrl?: string;
}

export interface ResolvedHook {
  id: string;
  name: string;
  scope: 'ORG' | 'PROJECT';
  event: HookEvent;
  matcher: string | null;
  handler: HookHandler;
  failMode: HookFailMode;
  timeoutSec: number;
  /** Set for hooks contributed by an installed plugin (no database row). */
  pluginName?: string | undefined;
  secrets: HookSecrets;
}

export type HookHandlerKind = HookHandler['type'];

export interface HookRunResult {
  hookId: string;
  name: string;
  event: HookEvent;
  handler: HookHandlerKind;
  decision: HookDecision;
  durationMs: number;
  /** HTTP status of a webhook handler. */
  status?: number | undefined;
  /** Set when the hook could not run (fail open / closed was applied). */
  errorCode?: ErrorCode | undefined;
}

/** Test transport is intentionally injected; all non-test hook traffic is DNS-pinned. */
function outboundFetch(ctx: AppContext, url: string | URL, init: Parameters<typeof safeFetch>[2]) {
  return ctx.env.NODE_ENV === 'test' ? ctx.fetch(url, init) : safeFetch(ctx, url, init);
}

const HOOK_FETCH_MAX_BYTES = 64 * 1024;

// ---- storage helpers -------------------------------------------------------------------------

function handlerOf(v: Prisma.JsonValue): HookHandler | null {
  if (!isRecord(v)) return null;
  const type = v.type;
  if (type === 'command') {
    return typeof v.command === 'string' ? { type: 'command', command: v.command } : null;
  }
  if (type === 'http') {
    return typeof v.url === 'string' ? { type: 'http', url: v.url } : null;
  }
  if (type === 'builtin') {
    const action = v.action;
    if (typeof action !== 'string') return null;
    return {
      type: 'builtin',
      action: action as HookHandler extends { action: infer A } ? A : never,
      config: (isRecord(v.config) ? v.config : {}) as HookBuiltinConfig,
    } as HookHandler;
  }
  return null;
}

/** Split a handler into the part stored as JSON and the secrets stored encrypted. */
function splitHandler(handler: HookHandler): { stored: HookHandler; secrets: HookSecrets } {
  if (handler.type === 'http') {
    const { secret, ...rest } = handler;
    return { stored: rest, secrets: secret ? { secret } : {} };
  }
  if (handler.type === 'builtin') {
    const { webhookUrl, ...config } = handler.config;
    return {
      stored: { ...handler, config },
      secrets: webhookUrl ? { webhookUrl } : {},
    };
  }
  return { stored: handler, secrets: {} };
}

async function encryptSecrets(
  ctx: AppContext,
  s: HookSecrets,
): Promise<Uint8Array<ArrayBuffer> | null> {
  if (!s.secret && !s.webhookUrl) return null;
  return ctx.crypto.encryptPacked(JSON.stringify(s), 'generic');
}

async function decryptSecrets(
  ctx: AppContext,
  row: Pick<Hook, 'id' | 'secretEnc'>,
): Promise<HookSecrets> {
  if (!row.secretEnc) return {};
  try {
    const raw = JSON.parse(
      await ctx.crypto.decryptPackedString(row.secretEnc, 'generic'),
    ) as HookSecrets;
    return {
      ...(typeof raw.secret === 'string' ? { secret: raw.secret } : {}),
      ...(typeof raw.webhookUrl === 'string' ? { webhookUrl: raw.webhookUrl } : {}),
    };
  } catch (err) {
    ctx.logger.warn({ err, hookId: row.id }, 'could not decrypt hook secrets');
    return {};
  }
}

function handlerDto(handler: HookHandler, hasSecret: boolean): HookHandlerDto {
  if (handler.type === 'http') return { type: 'http', url: handler.url, hasSecret };
  if (handler.type === 'builtin') {
    const { webhookUrl: _w, ...config } = handler.config;
    return {
      type: 'builtin',
      action: handler.action,
      config: { ...config, ...(hasSecret ? { hasWebhookUrl: true } : {}) },
    };
  }
  return { type: 'command', command: handler.command };
}

/**
 * The stored handler with its write-only secrets replaced by placeholders, so that validating
 * a saved hook still passes (`notify_slack` cannot validate without a `webhookUrl`, and the
 * real values only live in `secretEnc`). Never stored or returned.
 */
const STORED_SECRET_PLACEHOLDER = '********';
const STORED_SLACK_URL_PLACEHOLDER = 'https://hooks.slack.com/stored';

function handlerForValidation(row: Pick<Hook, 'handler' | 'secretEnc'>): HookHandler | null {
  const handler = handlerOf(row.handler);
  if (!handler || row.secretEnc === null) return handler;
  if (handler.type === 'http') return { ...handler, secret: STORED_SECRET_PLACEHOLDER };
  if (handler.type === 'builtin' && handler.action === 'notify_slack') {
    return { ...handler, config: { ...handler.config, webhookUrl: STORED_SLACK_URL_PLACEHOLDER } };
  }
  return handler;
}

export function hookToDto(row: Hook): HookDto {
  const handler = handlerOf(row.handler);
  const forValidation = handlerForValidation(row);
  const warnings = forValidation
    ? validateHookDefinition({
        event: row.event,
        matcher: row.matcher,
        handler: forValidation,
        failMode: row.failMode,
        timeoutSec: row.timeoutSec,
      }).warnings
    : ['This hook definition is not valid any more'];
  return hookDtoSchema.parse({
    id: row.id,
    scope: row.scope,
    orgId: row.orgId,
    projectId: row.projectId,
    name: row.name,
    event: row.event,
    matcher: row.matcher,
    handler: handler
      ? handlerDto(handler, row.secretEnc !== null)
      : { type: 'command', command: '' },
    failMode: row.failMode,
    timeoutSec: row.timeoutSec,
    enabled: row.enabled,
    recipe: row.recipe,
    pluginName: null,
    warnings,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  });
}

/** DTO for a hook that only exists inside an installed plugin manifest. */
export function pluginHookToDto(h: ResolvedPluginHook): HookDto {
  const { stored } = splitHandler(h.handler);
  return hookDtoSchema.parse({
    id: h.id,
    scope: 'PROJECT',
    orgId: null,
    projectId: null,
    name: h.name,
    event: h.event,
    matcher: h.matcher ?? null,
    handler: handlerDto(stored, false),
    failMode: h.failMode ?? defaultHookFailMode(h.event),
    timeoutSec: h.timeoutSec ?? 10,
    enabled: true,
    recipe: null,
    pluginName: h.pluginName,
    warnings: [],
    createdAt: new Date(0),
    updatedAt: new Date(0),
  });
}

function validateOrThrow(input: {
  event: string;
  matcher?: string | null | undefined;
  handler: unknown;
  failMode?: string | undefined;
  timeoutSec?: number | undefined;
}): HookHandler {
  const v = validateHookDefinition(input);
  if (!v.ok || !v.handler) {
    const first = v.issues[0];
    throw new AppError('LSE-EXT-006', {
      devMessage: first?.message ?? 'Invalid hook',
      fields: {
        ...(v.issues.length
          ? { handler: v.issues.map((i) => (i.path ? `${i.path}: ${i.message}` : i.message)) }
          : {}),
      },
    });
  }
  return v.handler;
}

// ---- CRUD ------------------------------------------------------------------------------------

export async function listHooks(
  ctx: AppContext,
  org: Organization,
  _actor: ExtActor,
  q: ExtensionListQuery,
): Promise<HookDto[]> {
  const rows = await ctx.prisma.hook.findMany({
    where: {
      orgId: org.id,
      OR: [
        { scope: 'ORG' },
        { scope: 'PROJECT', ...(q.projectId ? { projectId: q.projectId } : {}) },
      ],
    },
    orderBy: [{ scope: 'asc' }, { event: 'asc' }, { name: 'asc' }],
  });
  const dtos = rows.map(hookToDto);
  if (!q.projectId) return dtos;
  const plugins = await resolvePluginContents(ctx, q.projectId);
  return [...dtos, ...plugins.hooks.map(pluginHookToDto)];
}

async function loadHook(ctx: AppContext, orgId: string, id: string) {
  const row = await ctx.prisma.hook.findFirst({ where: { id, orgId } });
  if (!row) throw new AppError('LSE-NF-001', { devMessage: 'Hook not found' });
  return row;
}

export async function getHook(
  ctx: AppContext,
  org: Organization,
  _actor: ExtActor,
  id: string,
): Promise<HookDto> {
  return hookToDto(await loadHook(ctx, org.id, id));
}

async function assertHookBudget(
  ctx: AppContext,
  orgId: string,
  event: HookEvent,
  exceptId?: string,
) {
  const count = await ctx.prisma.hook.count({ where: { orgId, event, enabled: true } });
  const self = exceptId
    ? await ctx.prisma.hook.count({ where: { id: exceptId, orgId, event, enabled: true } })
    : 0;
  if (count - self >= MAX_HOOKS_PER_EVENT) {
    throw new AppError('LSE-EXT-006', {
      devMessage: `At most ${MAX_HOOKS_PER_EVENT} enabled hooks per event`,
      fields: { event: [`At most ${MAX_HOOKS_PER_EVENT} hooks can run on ${event}`] },
    });
  }
}

export async function createHook(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  body: CreateHookBody,
): Promise<HookDto> {
  assertAdmin(actor, 'hooks');
  await assertProjectInOrg(ctx, org.id, body.projectId);
  const handler = validateOrThrow({
    event: body.event,
    ...(body.matcher !== undefined ? { matcher: body.matcher } : {}),
    handler: body.handler,
    ...(body.failMode !== undefined ? { failMode: body.failMode } : {}),
    ...(body.timeoutSec !== undefined ? { timeoutSec: body.timeoutSec } : {}),
  });
  await assertHookBudget(ctx, org.id, body.event);
  const ids = {
    scope: body.scope,
    orgId: org.id,
    projectId: body.scope === 'PROJECT' ? (body.projectId ?? null) : null,
    userId: null,
  };
  await assertNameFree(
    (where) =>
      ctx.prisma.hook.findFirst({
        where: {
          scope: where.scope,
          orgId: where.orgId,
          projectId: where.projectId,
          name: where.name,
        },
        select: { id: true },
      }),
    ids,
    body.name,
  );
  const { stored, secrets } = splitHandler(handler);
  const row = await ctx.prisma.hook.create({
    data: {
      scope: body.scope,
      orgId: org.id,
      projectId: ids.projectId,
      name: body.name,
      event: body.event,
      matcher: body.matcher ?? null,
      handler: json(stored),
      failMode: body.failMode ?? defaultHookFailMode(body.event),
      timeoutSec: body.timeoutSec ?? 10,
      recipe: body.recipe ?? null,
      secretEnc: await encryptSecrets(ctx, secrets),
      enabled: body.enabled,
    },
  });
  await ctx.audit.record({
    orgId: org.id,
    actorId: actor.userId,
    action: 'hook.create',
    target: row.id,
    // Handler type / action only — never the URL secret or the Slack webhook.
    meta: {
      name: row.name,
      scope: row.scope,
      event: row.event,
      handler: handler.type,
      ...(handler.type === 'builtin' ? { action: handler.action } : {}),
      failMode: row.failMode,
      ...(row.recipe ? { recipe: row.recipe } : {}),
    },
    ip: actor.ip,
  });
  return hookToDto(row);
}

export async function updateHook(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  id: string,
  body: UpdateHookBody,
): Promise<HookDto> {
  assertAdmin(actor, 'hooks');
  const row = await loadHook(ctx, org.id, id);
  const event = body.event ?? (row.event as HookEvent);
  const handler = validateOrThrow({
    event,
    matcher: body.matcher !== undefined ? body.matcher : row.matcher,
    handler: body.handler ?? handlerForValidation(row),
    failMode: body.failMode ?? row.failMode,
    timeoutSec: body.timeoutSec ?? row.timeoutSec,
  });
  if (body.name !== undefined && body.name !== row.name) {
    await assertNameFree(
      (where) =>
        ctx.prisma.hook.findFirst({
          where: {
            scope: where.scope,
            orgId: where.orgId,
            projectId: where.projectId,
            name: where.name,
          },
          select: { id: true },
        }),
      {
        scope: row.scope as 'ORG' | 'PROJECT',
        orgId: org.id,
        projectId: row.projectId,
        userId: null,
      },
      body.name,
      row.id,
    );
  }
  if ((body.event !== undefined && body.event !== row.event) || body.enabled === true) {
    await assertHookBudget(ctx, org.id, event, row.id);
  }
  const data: Prisma.HookUpdateInput = {};
  if (body.name !== undefined) data.name = body.name;
  if (body.event !== undefined) data.event = body.event;
  if (body.matcher !== undefined) data.matcher = body.matcher;
  if (body.failMode !== undefined) data.failMode = body.failMode;
  if (body.timeoutSec !== undefined) data.timeoutSec = body.timeoutSec;
  if (body.enabled !== undefined) data.enabled = body.enabled;
  if (body.handler !== undefined) {
    const { stored, secrets } = splitHandler(handler);
    data.handler = json(stored);
    // Secrets are write-only: an update that re-sends the handler without them keeps the
    // stored value, as long as the handler (and built-in action) did not change.
    const prev = handlerOf(row.handler);
    const sameHandler =
      prev !== null &&
      prev.type === handler.type &&
      (handler.type !== 'builtin' || prev.type !== 'builtin' || prev.action === handler.action);
    const keepSecrets =
      row.secretEnc !== null && sameHandler && !secrets.secret && !secrets.webhookUrl;
    if (!keepSecrets) data.secretEnc = await encryptSecrets(ctx, secrets);
    data.lastDecision = null;
    data.lastError = null;
  }
  const updated = await ctx.prisma.hook.update({ where: { id: row.id }, data });
  await ctx.audit.record({
    orgId: org.id,
    actorId: actor.userId,
    action: 'hook.update',
    target: row.id,
    meta: { name: updated.name, event: updated.event, fields: Object.keys(body) },
    ip: actor.ip,
  });
  return hookToDto(updated);
}

export async function deleteHook(ctx: AppContext, org: Organization, actor: ExtActor, id: string) {
  assertAdmin(actor, 'hooks');
  const row = await loadHook(ctx, org.id, id);
  await ctx.prisma.hook.delete({ where: { id: row.id } });
  await ctx.audit.record({
    orgId: org.id,
    actorId: actor.userId,
    action: 'hook.delete',
    target: row.id,
    meta: { name: row.name, event: row.event, scope: row.scope },
    ip: actor.ip,
  });
}

export function hookRecipes() {
  return HOOK_RECIPES;
}

// ---- webhook invocation ----------------------------------------------------------------------

/** `sha256=<hex>` over the exact request body (spec §8.9, §8.15 signature scheme). */
export function hookSignature(secret: string, body: string): string {
  return `sha256=${createHmac('sha256', secret).update(body, 'utf8').digest('hex')}`;
}

/** Constant-time check — exported so tests (and future inbound hooks) can reuse it. */
export function verifyHookSignature(secret: string, body: string, signature: string): boolean {
  const expected = Buffer.from(hookSignature(secret, body), 'utf8');
  const given = Buffer.from(signature, 'utf8');
  return expected.length === given.length && timingSafeEqual(expected, given);
}

interface WebhookOutcome {
  decision: HookDecision | null;
  status: number;
  error?: string;
}

async function callWebhook(
  ctx: AppContext,
  hook: ResolvedHook,
  url: URL,
  payload: HookPayload,
): Promise<WebhookOutcome> {
  const body = JSON.stringify(payload);
  const res = await outboundFetch(ctx, url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      [HOOK_EVENT_HEADER]: hook.event,
      ...(hook.secrets.secret
        ? { [HOOK_SIGNATURE_HEADER]: hookSignature(hook.secrets.secret, body) }
        : {}),
    },
    body,
    redirect: 'manual',
    signal: AbortSignal.timeout(hook.timeoutSec * 1000),
  });
  if (!res.ok) {
    await res.body?.cancel().catch(() => undefined);
    return { decision: null, status: res.status, error: `HTTP ${res.status}` };
  }
  const text = (await res.text()).slice(0, HOOK_FETCH_MAX_BYTES).trim();
  if (!text) return { decision: { decision: 'allow' }, status: res.status };
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    // A 2xx without a decision body is informational only.
    return { decision: { decision: 'allow' }, status: res.status };
  }
  const decision = hookDecisionSchema.safeParse(parsed);
  return decision.success
    ? { decision: decision.data, status: res.status }
    : { decision: null, status: res.status, error: 'the response is not a valid hook decision' };
}

async function postSlack(ctx: AppContext, hook: ResolvedHook, payload: HookPayload) {
  const url = await assertPublicUrl(hook.secrets.webhookUrl ?? '', 'LSE-EXT-006');
  const template =
    hook.handler.type === 'builtin' ? (hook.handler.config.text ?? '{message}') : '{message}';
  const text = template
    .replace(/\{event\}/g, payload.event)
    .replace(/\{session\}/g, payload.sessionId)
    .replace(/\{summary\}/g, payload.message ?? '')
    .replace(/\{message\}/g, payload.message ?? payload.event);
  const res = await outboundFetch(ctx, url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text: text.slice(0, 2000) }),
    redirect: 'manual',
    signal: AbortSignal.timeout(hook.timeoutSec * 1000),
  });
  await res.body?.cancel().catch(() => undefined);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.status;
}

/** Handlers only the server may run (they leave the sandbox). */
export function isServerHandled(hook: { handler: HookHandler }): boolean {
  return (
    hook.handler.type === 'http' ||
    (hook.handler.type === 'builtin' && hook.handler.action === 'notify_slack')
  );
}

async function recordOutcome(ctx: AppContext, hook: ResolvedHook, r: HookRunResult) {
  if (hook.pluginName) return;
  await ctx.prisma.hook
    .update({
      where: { id: hook.id },
      data: {
        lastDecision: r.decision.decision,
        lastError: r.errorCode
          ? `${r.errorCode}: ${(r.decision.reason ?? '').slice(0, 500)}`
          : null,
        lastRunAt: new Date(),
      },
    })
    .catch(() => undefined);
}

/** Run one server-owned hook. Never throws: failures become fail-open/closed decisions. */
export async function runServerHook(
  ctx: AppContext,
  hook: ResolvedHook,
  payload: HookPayload,
): Promise<HookRunResult> {
  const started = Date.now();
  const base = {
    hookId: hook.id,
    name: hook.name,
    event: hook.event,
    handler: hook.handler.type,
  } as const;
  try {
    if (hook.handler.type === 'http') {
      const url = await assertPublicUrl(hook.handler.url, 'LSE-EXT-006');
      const out = await callWebhook(ctx, hook, url, payload);
      const result: HookRunResult = out.decision
        ? { ...base, decision: out.decision, durationMs: Date.now() - started, status: out.status }
        : {
            ...base,
            decision: hookFailureDecision(hook.failMode, out.error ?? 'the webhook failed'),
            durationMs: Date.now() - started,
            status: out.status,
            errorCode: 'LSE-AGT-014',
          };
      await recordOutcome(ctx, hook, result);
      return result;
    }
    if (hook.handler.type === 'builtin' && hook.handler.action === 'notify_slack') {
      const status = await postSlack(ctx, hook, payload);
      const result: HookRunResult = {
        ...base,
        decision: { decision: 'allow' },
        durationMs: Date.now() - started,
        status,
      };
      await recordOutcome(ctx, hook, result);
      return result;
    }
    // Local handlers are evaluated in-process (post-turn re-validation, hook test).
    if (hook.handler.type === 'builtin') {
      const decision =
        evaluateBuiltinHook({
          action: hook.handler.action,
          config: hook.handler.config,
          payload,
        }) ?? ({ decision: 'allow' } as HookDecision);
      return { ...base, decision, durationMs: Date.now() - started };
    }
    return { ...base, decision: { decision: 'allow' }, durationMs: Date.now() - started };
  } catch (err) {
    const timeout = (err as Error).name === 'TimeoutError' || (err as Error).name === 'AbortError';
    const detail = timeout
      ? 'it did not answer in time'
      : scrubSecrets(String((err as Error).message ?? err)).slice(0, 200);
    const result: HookRunResult = {
      ...base,
      decision: hookFailureDecision(hook.failMode, detail),
      durationMs: Date.now() - started,
      errorCode: 'LSE-AGT-014',
    };
    await recordOutcome(ctx, hook, result);
    ctx.logger.warn(
      { hookId: hook.id, event: hook.event, code: 'LSE-AGT-014', detail },
      'hook failed',
    );
    return result;
  }
}

export interface HookEvaluation {
  decision: HookDecision;
  results: HookRunResult[];
}

/**
 * Run every server-owned hook that matches `payload.event` (and the tool name for tool
 * events), merge the decisions (deny > ask > modify > allow) and audit each one.
 */
export async function evaluateServerHooks(
  ctx: AppContext,
  input: {
    hooks: readonly ResolvedHook[];
    payload: HookPayload;
    orgId: string;
    sessionId: string;
  },
): Promise<HookEvaluation> {
  const matching = input.hooks.filter(
    (h) =>
      h.event === input.payload.event &&
      isServerHandled(h) &&
      (!isToolHookEvent(h.event) || hookMatcherMatches(h.matcher, input.payload.toolName ?? '')),
  );
  const results: HookRunResult[] = [];
  for (const hook of matching.slice(0, MAX_HOOKS_PER_EVENT)) {
    const r = await runServerHook(ctx, hook, input.payload);
    results.push(r);
    await ctx.audit
      .record({
        orgId: input.orgId,
        actorId: null,
        action: 'hook.decision',
        target: hook.id,
        meta: {
          sessionId: input.sessionId,
          name: hook.name,
          event: hook.event,
          handler: r.handler,
          decision: r.decision.decision,
          ...(r.decision.reason ? { reason: r.decision.reason.slice(0, 500) } : {}),
          ...(input.payload.toolName ? { toolName: input.payload.toolName } : {}),
          ...(hook.pluginName ? { plugin: hook.pluginName } : {}),
          ...(r.errorCode ? { errorCode: r.errorCode } : {}),
          durationMs: r.durationMs,
        },
      })
      .catch(() => undefined);
  }
  return { decision: mergeHookDecisions(results.map((r) => r.decision)), results };
}

// ---- hook test (`POST /orgs/:orgId/hooks/:id/test`) -------------------------------------------

export async function testHook(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  id: string,
  body: HookTestBody,
): Promise<HookTestResultDto> {
  assertAdmin(actor, 'hooks');
  const row = await loadHook(ctx, org.id, id);
  const handler = handlerOf(row.handler);
  if (!handler) throw new AppError('LSE-EXT-006', { devMessage: 'Stored handler is invalid' });
  const payload: HookPayload = body.payload ?? hookSamplePayload(row.event as HookEvent);
  const hook: ResolvedHook = {
    id: row.id,
    name: row.name,
    scope: row.scope as 'ORG' | 'PROJECT',
    event: row.event as HookEvent,
    matcher: row.matcher,
    handler,
    failMode: row.failMode as HookFailMode,
    timeoutSec: row.timeoutSec,
    secrets: await decryptSecrets(ctx, row),
  };
  let result: HookTestResultDto;
  if (handler.type === 'command') {
    result = hookTestResultDtoSchema.parse({
      ok: true,
      decision: null,
      latencyMs: null,
      error: null,
      note: 'Command hooks run inside the session sandbox; this test cannot execute them here.',
      payload,
    });
  } else {
    // The SSRF guard must reject outright here (not as a fail-open decision), so the
    // admin sees the real problem while editing the hook.
    if (handler.type === 'http') await assertPublicUrl(handler.url, 'LSE-EXT-006');
    if (handler.type === 'builtin' && handler.action === 'notify_slack') {
      await assertPublicUrl(hook.secrets.webhookUrl ?? '', 'LSE-EXT-006');
    }
    const r = await runServerHook(ctx, hook, payload);
    result = hookTestResultDtoSchema.parse({
      ok: !r.errorCode,
      decision: r.decision,
      latencyMs: r.durationMs,
      status: r.status ?? null,
      error: r.errorCode
        ? { code: r.errorCode, message: r.decision.reason ?? 'The hook could not run.' }
        : null,
      note: null,
      payload,
    });
  }
  await ctx.audit.record({
    orgId: org.id,
    actorId: actor.userId,
    action: 'hook.test',
    target: row.id,
    meta: {
      name: row.name,
      event: row.event,
      handler: handler.type,
      decision: result.decision?.decision ?? null,
      ok: result.ok,
    },
    ip: actor.ip,
  });
  return result;
}

// ---- session resolution ----------------------------------------------------------------------

/** Org + project hooks of a project (enabled only), plus the hooks of its plugins. */
export async function resolveHooks(
  ctx: AppContext,
  input: { orgId: string; projectId: string; pluginHooks?: readonly ResolvedPluginHook[] },
): Promise<ResolvedHook[]> {
  const rows = await ctx.prisma.hook.findMany({
    where: {
      orgId: input.orgId,
      enabled: true,
      OR: [{ scope: 'ORG' }, { scope: 'PROJECT', projectId: input.projectId }],
    },
    orderBy: [{ scope: 'asc' }, { createdAt: 'asc' }],
  });
  const out: ResolvedHook[] = [];
  for (const row of rows) {
    const handler = handlerOf(row.handler);
    if (!handler) {
      ctx.logger.warn({ hookId: row.id, code: 'LSE-EXT-006' }, 'skipping invalid hook');
      continue;
    }
    out.push({
      id: row.id,
      name: row.name,
      scope: row.scope as 'ORG' | 'PROJECT',
      event: row.event as HookEvent,
      matcher: row.matcher,
      handler,
      failMode: row.failMode as HookFailMode,
      timeoutSec: row.timeoutSec,
      secrets: await decryptSecrets(ctx, row),
    });
  }
  for (const h of input.pluginHooks ?? []) {
    const v = validateHookDefinition({
      event: h.event,
      ...(h.matcher !== undefined ? { matcher: h.matcher } : {}),
      handler: h.handler,
    });
    if (!v.ok || !v.handler) continue;
    const { stored, secrets } = splitHandler(v.handler);
    out.push({
      id: h.id,
      name: h.name,
      scope: 'PROJECT',
      event: h.event,
      matcher: h.matcher ?? null,
      handler: stored,
      failMode: h.failMode ?? defaultHookFailMode(h.event),
      timeoutSec: h.timeoutSec ?? 10,
      pluginName: h.pluginName,
      secrets,
    });
  }
  return out;
}

/** Hooks the runner evaluates itself (`command` + local `builtin` handlers). */
export function runnerHooksOf(hooks: readonly ResolvedHook[]): RunnerHookInput[] {
  return hooks
    .filter((h) => !isServerHandled(h))
    .map((h) => ({
      id: h.id,
      name: h.name,
      event: h.event,
      ...(h.matcher ? { matcher: h.matcher } : {}),
      handler: h.handler as RunnerHookInput['handler'],
      failMode: h.failMode,
      timeoutSec: h.timeoutSec,
    }));
}

/** Events for which the runner must ask the server (`hook_request`). */
export function serverHookEventsOf(hooks: readonly ResolvedHook[]): HookEvent[] {
  return [...new Set(hooks.filter(isServerHandled).map((h) => h.event))];
}

/** Longest timeout among the server-owned hooks (what the runner should wait). */
export function serverHookTimeoutMs(hooks: readonly ResolvedHook[], fallbackSec = 10): number {
  const owned = hooks.filter(isServerHandled);
  const sec = owned.length ? Math.max(...owned.map((h) => h.timeoutSec)) : fallbackSec;
  // Leave the runner a little slack over the server's own per-hook timeout.
  return Math.min(60_000, sec * 1000 + 2_000);
}

/** A deny by any server-owned hook stops the turn → the strictest fail mode wins. */
export function serverHookFailMode(hooks: readonly ResolvedHook[]): HookFailMode {
  return hooks.filter(isServerHandled).some((h) => h.failMode === 'closed') ? 'closed' : 'open';
}

/** `block_paths` hooks, used to re-validate the workspace after a turn (LSE-AGT-004). */
export function blockPathHooks(hooks: readonly ResolvedHook[]): ResolvedHook[] {
  return hooks.filter((h) => h.handler.type === 'builtin' && h.handler.action === 'block_paths');
}

/**
 * Which of `paths` a `block_paths` hook forbids (same evaluation as in the runner).
 * Returns the offending paths and the reason of the first hook that denied.
 */
export function blockedPaths(
  hooks: readonly ResolvedHook[],
  paths: readonly string[],
): { paths: string[]; hook: ResolvedHook; reason: string } | null {
  for (const hook of blockPathHooks(hooks)) {
    if (hook.handler.type !== 'builtin') continue;
    const hits = paths.filter((p) => {
      const d = evaluateBuiltinHook({
        action: 'block_paths',
        config: hook.handler.type === 'builtin' ? hook.handler.config : {},
        payload: { event: 'PreToolUse', sessionId: 'revalidate', filePaths: [p] },
        filePaths: [p],
      });
      return d?.decision === 'deny';
    });
    if (hits.length) {
      const d = evaluateBuiltinHook({
        action: 'block_paths',
        config: hook.handler.config,
        payload: { event: 'PreToolUse', sessionId: 'revalidate', filePaths: hits },
        filePaths: hits,
      });
      return { paths: hits, hook, reason: d?.reason ?? 'Those files are off-limits' };
    }
  }
  return null;
}

/**
 * Fire the server-owned hooks of a lifecycle event (SessionStart / SessionEnd /
 * Notification). Never throws and never blocks the caller's result.
 */
export async function runLifecycleHooks(
  ctx: AppContext,
  input: {
    sessionId: string;
    orgId: string;
    projectId: string;
    event: HookEvent;
    message?: string | undefined;
    context?: Record<string, unknown> | undefined;
  },
): Promise<HookRunResult[]> {
  try {
    const plugins = await resolvePluginContents(ctx, input.projectId);
    const hooks = await resolveHooks(ctx, {
      orgId: input.orgId,
      projectId: input.projectId,
      pluginHooks: plugins.hooks,
    });
    if (!hooks.some((h) => h.event === input.event && isServerHandled(h))) return [];
    const payload: HookPayload = {
      event: input.event,
      sessionId: input.sessionId,
      projectId: input.projectId,
      orgId: input.orgId,
      ...(input.message ? { message: input.message } : {}),
      ...(input.context ? { context: input.context } : {}),
      ts: new Date().toISOString(),
    };
    const { results } = await evaluateServerHooks(ctx, {
      hooks,
      payload,
      orgId: input.orgId,
      sessionId: input.sessionId,
    });
    return results;
  } catch (err) {
    ctx.logger.warn(
      { err, sessionId: input.sessionId, event: input.event, code: 'LSE-AGT-014' },
      'lifecycle hooks failed',
    );
    return [];
  }
}
