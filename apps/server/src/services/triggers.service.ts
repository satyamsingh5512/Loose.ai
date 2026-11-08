/**
 * Automation triggers (spec §8.15; Phase 9) — OWNED BY W4.
 *
 * - Admin CRUD for org triggers (`routes/triggers.ts`).
 * - `fireTrigger` (the common "a trigger wants to run" path) lives in `triggers/fire.ts` to
 *   avoid an import cycle with the per-kind inbound handlers, which this module dispatches to.
 * - Inbound dispatch: `services/triggers/{github,slack,linear,jira,schedule}.ts`.
 */
import type { Prisma, Trigger } from '@prisma/client';
import {
  DEFAULT_TRIGGER_PROMPTS,
  hasRoleAtLeast,
  MAX_TRIGGERS_PER_ORG,
  nextCronRun,
  parseTriggerConfig,
  triggerDtoSchema,
  type CreateTriggerBody,
  type FireTriggerBody,
  type ListTriggersQuery,
  type PaginationQuery,
  type RunDto,
  type RunSource,
  type TriggerDto,
  type TriggerKind,
  type UpdateTriggerBody,
} from '@loose/shared';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';
import type { Page } from '../lib/pagination';
import type { PlatformRole } from '../platform/register';
import { listRuns } from './runs.service';
import { fireTrigger } from './triggers/fire';
import {
  isWebhookTriggerKind,
  triggerWebhookSecret,
  triggerWebhookToken,
} from './triggers/webhookAuth';
import { handleGithubTriggerFire, postGithubRunResult } from './triggers/github';
import { scheduleTick as runScheduleTick } from './triggers/schedule';
import { postSlackRunResult } from './triggers/slack';

export { fireTrigger, type FireTriggerInput } from './triggers/fire';

export interface TriggerActor {
  userId: string;
  ip?: string | undefined;
}

type TriggerRow = Trigger & { project: { name: string }; runAs: { name: string | null } | null };

const triggerInclude = {
  project: { select: { name: true } },
  runAs: { select: { name: true } },
} as const;

/**
 * P10-SEC-007: Linear/Jira webhooks are addressed per trigger — the path carries an
 * unguessable per-trigger token and the body is verified with that trigger's own derived
 * secret, so one tenant can never fire another tenant's trigger.
 */
const inboundWebhookUrl = (
  ctx: AppContext,
  kind: TriggerKind,
  triggerId: string,
): string | null => {
  const base = ctx.env.API_URL.replace(/\/+$/, '');
  if (kind === 'SLACK_COMMAND') return `${base}/api/v1/integrations/slack/commands`;
  if (isWebhookTriggerKind(kind)) {
    const token = triggerWebhookToken(ctx.env.SESSION_SECRET, kind, triggerId);
    const path = kind === 'LINEAR' ? 'linear/webhook' : 'jira/webhook';
    return `${base}/api/v1/integrations/${path}/${token}`;
  }
  return null;
};

/** The secret the admin configures in Linear/Jira for this trigger (admin-only DTO field). */
const inboundWebhookSecret = (
  ctx: AppContext,
  kind: TriggerKind,
  triggerId: string,
): string | null =>
  isWebhookTriggerKind(kind) ? triggerWebhookSecret(ctx.env.SESSION_SECRET, kind, triggerId) : null;

const isConfigured = (ctx: AppContext, kind: TriggerKind): boolean => {
  if (kind === 'SLACK_COMMAND') return !!ctx.env.SLACK_SIGNING_SECRET;
  // LINEAR/JIRA carry their own per-trigger secret (derived) — nothing global to configure.
  return true; // GitHub (uses GITHUB_WEBHOOK_SECRET, already required for the repo link) and SCHEDULE
};

export function toTriggerDto(ctx: AppContext, t: TriggerRow): TriggerDto {
  return triggerDtoSchema.parse({
    id: t.id,
    orgId: t.orgId,
    projectId: t.projectId,
    projectName: t.project.name,
    kind: t.kind,
    name: t.name,
    enabled: t.enabled,
    config: (t.config ?? {}) as Record<string, unknown>,
    promptTemplate: t.promptTemplate,
    runAsUserId: t.runAsUserId,
    runAsUserName: t.runAs?.name ?? null,
    createPr: t.createPr,
    mode: t.mode,
    model: t.model,
    nextRunAt: t.nextRunAt,
    lastFiredAt: t.lastFiredAt,
    lastRunId: t.lastRunId,
    lastError: t.lastError,
    webhookUrl: inboundWebhookUrl(ctx, t.kind, t.id),
    webhookSecret: inboundWebhookSecret(ctx, t.kind, t.id),
    configured: isConfigured(ctx, t.kind),
    createdAt: t.createdAt,
    updatedAt: t.updatedAt,
  });
}

async function loadTrigger(ctx: AppContext, orgId: string, id: string): Promise<TriggerRow> {
  const row = await ctx.prisma.trigger.findFirst({
    where: { id, orgId },
    include: triggerInclude,
  });
  if (!row) throw new AppError('LSE-NF-001', { devMessage: 'Trigger not found' });
  return row;
}

// ---- admin CRUD -----------------------------------------------------------------------------

export async function listTriggers(
  ctx: AppContext,
  orgId: string,
  q: ListTriggersQuery,
): Promise<Page<TriggerDto>> {
  const rows = await ctx.prisma.trigger.findMany({
    where: { orgId, ...(q.projectId ? { projectId: q.projectId } : {}) },
    include: triggerInclude,
    orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
  });
  return { data: rows.map((r) => toTriggerDto(ctx, r)), nextCursor: null };
}

export async function getTrigger(ctx: AppContext, orgId: string, id: string): Promise<TriggerDto> {
  return toTriggerDto(ctx, await loadTrigger(ctx, orgId, id));
}

async function assertProjectInOrg(ctx: AppContext, orgId: string, projectId: string) {
  const p = await ctx.prisma.project.findFirst({ where: { id: projectId, orgId } });
  if (!p) throw new AppError('LSE-NF-001', { devMessage: 'Project not found' });
  return p;
}

/** `runAsUserId` defaults to the creator and must be a MEMBER+ of the org. */
async function resolveRunAsUser(
  ctx: AppContext,
  orgId: string,
  actor: TriggerActor,
  runAsUserId: string | undefined,
): Promise<string> {
  const userId = runAsUserId ?? actor.userId;
  const membership = await ctx.prisma.orgMember.findUnique({
    where: { userId_orgId: { userId, orgId } },
  });
  if (!membership || !hasRoleAtLeast(membership.role, 'MEMBER')) {
    throw new AppError('LSE-VAL-001', {
      devMessage: 'runAsUserId must be a MEMBER or higher of the organization',
      fields: { runAsUserId: ['Must be an org member'] },
    });
  }
  return userId;
}

function nextRunAtFor(config: { cron: string; timezone: string }, after = new Date()): Date | null {
  return nextCronRun(config.cron, after, config.timezone);
}

export async function createTrigger(
  ctx: AppContext,
  orgId: string,
  actor: TriggerActor,
  body: CreateTriggerBody,
): Promise<TriggerDto> {
  if ((await ctx.prisma.trigger.count({ where: { orgId } })) >= MAX_TRIGGERS_PER_ORG) {
    throw new AppError('LSE-ORG-009', {
      devMessage: `An organization can have at most ${MAX_TRIGGERS_PER_ORG} triggers`,
    });
  }
  await assertProjectInOrg(ctx, orgId, body.projectId);
  const runAsUserId = await resolveRunAsUser(ctx, orgId, actor, body.runAsUserId);
  const promptTemplate = body.promptTemplate || DEFAULT_TRIGGER_PROMPTS[body.kind];
  const nextRunAt =
    body.kind === 'SCHEDULE' && body.enabled
      ? nextRunAtFor(body.config as { cron: string; timezone: string })
      : null;
  const row = await ctx.prisma.trigger.create({
    data: {
      orgId,
      projectId: body.projectId,
      kind: body.kind,
      name: body.name,
      enabled: body.enabled,
      config: body.config as Prisma.InputJsonValue,
      promptTemplate,
      runAsUserId,
      createPr: body.createPr,
      mode: body.mode,
      model: body.model ?? null,
      nextRunAt,
      createdById: actor.userId,
    },
    include: triggerInclude,
  });
  await ctx.audit.record({
    orgId,
    actorId: actor.userId,
    action: 'trigger.create',
    target: row.id,
    meta: { kind: row.kind, name: row.name, projectId: row.projectId },
    ip: actor.ip,
  });
  return toTriggerDto(ctx, row);
}

export async function updateTrigger(
  ctx: AppContext,
  orgId: string,
  id: string,
  actor: TriggerActor,
  body: UpdateTriggerBody,
): Promise<TriggerDto> {
  const before = await loadTrigger(ctx, orgId, id);
  const runAsUserId =
    body.runAsUserId !== undefined
      ? await resolveRunAsUser(ctx, orgId, actor, body.runAsUserId)
      : undefined;
  const config = body.config
    ? (() => {
        const parsed = parseTriggerConfig(before.kind, body.config);
        if (!parsed) {
          throw new AppError('LSE-VAL-001', {
            devMessage: `Invalid config for a ${before.kind} trigger`,
            fields: { config: ['Does not match this trigger kind'] },
          });
        }
        return parsed;
      })()
    : undefined;
  const enabled = body.enabled ?? before.enabled;
  const nextRunAt =
    before.kind === 'SCHEDULE'
      ? enabled
        ? nextRunAtFor(
            (config ?? (before.config as { cron: string; timezone: string })) as {
              cron: string;
              timezone: string;
            },
          )
        : null
      : undefined;
  const row = await ctx.prisma.trigger.update({
    where: { id: before.id },
    data: {
      ...(body.name !== undefined ? { name: body.name } : {}),
      ...(body.enabled !== undefined ? { enabled: body.enabled } : {}),
      ...(body.promptTemplate !== undefined ? { promptTemplate: body.promptTemplate } : {}),
      ...(runAsUserId !== undefined ? { runAsUserId } : {}),
      ...(body.createPr !== undefined ? { createPr: body.createPr } : {}),
      ...(body.mode !== undefined ? { mode: body.mode } : {}),
      ...(body.model !== undefined ? { model: body.model } : {}),
      ...(config !== undefined ? { config: config as Prisma.InputJsonValue } : {}),
      ...(nextRunAt !== undefined ? { nextRunAt } : {}),
    },
    include: triggerInclude,
  });
  await ctx.audit.record({
    orgId,
    actorId: actor.userId,
    action: 'trigger.update',
    target: row.id,
    meta: { changed: Object.keys(body) },
    ip: actor.ip,
  });
  return toTriggerDto(ctx, row);
}

export async function deleteTrigger(
  ctx: AppContext,
  orgId: string,
  id: string,
  actor: TriggerActor,
): Promise<void> {
  const row = await loadTrigger(ctx, orgId, id);
  await ctx.prisma.trigger.delete({ where: { id: row.id } });
  await ctx.audit.record({
    orgId,
    actorId: actor.userId,
    action: 'trigger.delete',
    target: row.id,
    meta: { kind: row.kind, name: row.name },
    ip: actor.ip,
  });
}

export async function listTriggerRuns(
  ctx: AppContext,
  orgId: string,
  id: string,
  actor: TriggerActor,
  q: PaginationQuery,
): Promise<Page<RunDto>> {
  const trigger = await loadTrigger(ctx, orgId, id);
  const user = await ctx.prisma.user.findUniqueOrThrow({ where: { id: actor.userId } });
  // The caller is already known to be an org ADMIN (route guard); listRuns scopes admins to
  // the whole org, so filtering by triggerId here is exactly the trigger's run history.
  return listRuns(ctx, { user, ip: actor.ip }, { ...q, orgId, triggerId: trigger.id });
}

function manualSourceFor(kind: TriggerKind): RunSource {
  switch (kind) {
    case 'GITHUB_ISSUE_LABEL':
      return 'GITHUB_ISSUE';
    case 'GITHUB_PR_COMMENT':
      return 'GITHUB_COMMENT';
    case 'SLACK_COMMAND':
      return 'SLACK';
    case 'LINEAR':
      return 'LINEAR';
    case 'JIRA':
      return 'JIRA';
    case 'SCHEDULE':
      return 'SCHEDULE';
  }
}

export async function fireTriggerManually(
  ctx: AppContext,
  orgId: string,
  id: string,
  _actor: TriggerActor,
  body: FireTriggerBody,
): Promise<{ runId: string | null; duplicate: boolean }> {
  const trigger = await loadTrigger(ctx, orgId, id);
  if (!trigger.enabled) {
    throw new AppError('LSE-CONF-001', { devMessage: 'The trigger is disabled' });
  }
  return fireTrigger(ctx, trigger.id, {
    dedupeKey: `manual:${Date.now()}:${Math.random().toString(36).slice(2)}`,
    vars: { text: body.text ?? '', title: body.text ?? '' },
    source: manualSourceFor(trigger.kind),
  });
}

// ---- inbound dispatch ---------------------------------------------------------------------

/** Inbound GitHub `issues` / `issue_comment` events. Returns whether a trigger matched. */
export async function handleGithubTriggerEvent(
  ctx: AppContext,
  event: string,
  deliveryId: string | undefined,
  payload: unknown,
): Promise<boolean> {
  return handleGithubTriggerFire(ctx, event, deliveryId, payload);
}

export async function scheduleTick(
  ctx: AppContext,
  now: Date = new Date(),
): Promise<{ fired: string[] }> {
  return runScheduleTick(ctx, now);
}

// ---- job registration + run.completed post-back --------------------------------------------

interface RunCompletedData {
  runId: string;
  triggerId: string | null;
  status: string;
  prUrl: string | null;
  errorCode: string | null;
  summary: string | null;
  externalRef: Record<string, unknown> | null;
}

/** Post the run's outcome back to the origin (GitHub issue/PR comment, Slack response_url). */
async function postRunCompletion(ctx: AppContext, data: RunCompletedData): Promise<void> {
  if (!data.triggerId) return;
  const trigger = await ctx.prisma.trigger.findUnique({ where: { id: data.triggerId } });
  if (!trigger) return;
  if (trigger.kind === 'GITHUB_ISSUE_LABEL' || trigger.kind === 'GITHUB_PR_COMMENT') {
    await postGithubRunResult(ctx, trigger, data);
  } else if (trigger.kind === 'SLACK_COMMAND') {
    await postSlackRunResult(ctx, trigger, data);
  }
}

/** `trigger-fire` jobs, the schedule tick and `run.completed` post-backs. */
export function registerTriggerHandlers(ctx: AppContext, _role: PlatformRole): void {
  ctx.jobs.register('trigger-fire', async (data) => {
    const triggerId = typeof data.triggerId === 'string' ? data.triggerId : '';
    const dedupeKey = typeof data.dedupeKey === 'string' ? data.dedupeKey : '';
    if (!triggerId || !dedupeKey) return;
    const vars = (data.vars ?? {}) as Record<string, string>;
    const source = (data.source ?? 'API') as RunSource;
    const externalRef = data.externalRef as Record<string, unknown> | undefined;
    const overrideOptions = data.overrideOptions as
      Parameters<typeof fireTrigger>[2]['overrideOptions'] | undefined;
    await fireTrigger(ctx, triggerId, {
      dedupeKey,
      vars,
      source,
      ...(externalRef ? { externalRef } : {}),
      ...(overrideOptions ? { overrideOptions } : {}),
    });
  });
  ctx.jobs.register('trigger-schedule-tick', async () => {
    await runScheduleTick(ctx);
  });
  ctx.platformEvents.on('run.completed', (e) => {
    void postRunCompletion(ctx, e.data).catch((err: unknown) =>
      ctx.logger.warn({ err }, 'trigger post-back failed'),
    );
  });
}
