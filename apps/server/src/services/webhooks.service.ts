/**
 * Outbound webhooks (spec §8.15, §10.2; Phase 9) — OWNED BY W1.
 *
 * - Admin CRUD for org webhooks (secret shown once on create / rotate, stored envelope-encrypted).
 * - A subscriber on the platform event bus turns each webhook event into one `WebhookDelivery`
 *   per active, subscribed webhook (unique `(webhookId, eventId)`) and enqueues `webhook-delivery`.
 * - One attempt = HMAC-SHA256 signed POST (`x-loose-signature: sha256=…` over `<ts>.<body>`),
 *   SSRF-guarded on every attempt (DNS rebinding), redirects never followed, 10 s timeout.
 *   Failures retry with exponential backoff (shared schedule, ±10 % jitter, 6 attempts), a 410
 *   Gone switches the webhook off, and 20 consecutive failed deliveries auto-disable it.
 * - `webhook-sweep` (every minute) re-enqueues overdue deliveries and prunes old rows.
 */
import { createHmac, randomBytes } from 'node:crypto';
import type { Prisma, Webhook, WebhookDelivery } from '@prisma/client';
import {
  createWebhookResponseSchema,
  MAX_WEBHOOKS_PER_ORG,
  scrubSecrets,
  WEBHOOK_DELIVERY_HEADER,
  WEBHOOK_DELIVERY_RETENTION_DAYS,
  WEBHOOK_EVENT_HEADER,
  WEBHOOK_EVENT_TYPES,
  WEBHOOK_MAX_ATTEMPTS,
  WEBHOOK_MAX_CONSECUTIVE_FAILURES,
  WEBHOOK_PING_EVENT,
  WEBHOOK_RESPONSE_SNIPPET_BYTES,
  WEBHOOK_SECRET_BYTES,
  WEBHOOK_SECRET_PREFIX,
  WEBHOOK_SIGNATURE_HEADER,
  WEBHOOK_TIMEOUT_MS,
  WEBHOOK_TIMESTAMP_HEADER,
  WEBHOOK_USER_AGENT,
  webhookDeliveryDtoSchema,
  webhookDtoSchema,
  webhookPayloadSchema,
  webhookRetryDelayMs,
  webhookSignedPayload,
  type CreateWebhookBody,
  type CreateWebhookResponse,
  type ListWebhookDeliveriesQuery,
  type PaginationQuery,
  type UpdateWebhookBody,
  type WebhookDeliveryDto,
  type WebhookDto,
  type WebhookEventType,
} from '@loose/shared';
import type { AppContext } from '../context';
import type { AnyPlatformEvent } from '../lib/events/platformEvents';
import { AppError } from '../lib/errors';
import { safeFetch } from '../lib/net/safeFetch';
import { pageArgs, toPage, type Page } from '../lib/pagination';
import type { PlatformRole } from '../platform/register';
import { assertPublicUrl } from './extensionsCommon';

export interface WebhookActor {
  userId: string | null;
  ip?: string | undefined;
}

/** A claimed attempt is leased for this long; a crashed worker's delivery is swept afterwards. */
const ATTEMPT_LEASE_MS = WEBHOOK_TIMEOUT_MS * 2 + 5_000;
/** A delayed retry job may fire slightly before the stored `nextAttemptAt`. */
const CLAIM_SLACK_MS = 5_000;

/** Test transport is injected; production delivery always uses the pinned SSRF transport. */
function outboundFetch(ctx: AppContext, url: string | URL, init: Parameters<typeof safeFetch>[2]) {
  return ctx.env.NODE_ENV === 'test' ? ctx.fetch(url, init) : safeFetch(ctx, url, init);
}
/** Sweep: a PENDING delivery this far past due had its job lost. */
const SWEEP_GRACE_MS = 30_000;

const isWebhookEvent = (t: string): t is WebhookEventType =>
  (WEBHOOK_EVENT_TYPES as readonly string[]).includes(t);

// ---- signing ------------------------------------------------------------------------------

/** `sha256=<hex HMAC-SHA256(secret, "<timestamp>.<body>")>` — the `x-loose-signature` value. */
export function signWebhook(secret: string, timestamp: number, body: string): string {
  const mac = createHmac('sha256', secret)
    .update(webhookSignedPayload(timestamp, body))
    .digest('hex');
  return `sha256=${mac}`;
}

function newWebhookSecret(): string {
  return `${WEBHOOK_SECRET_PREFIX}${randomBytes(WEBHOOK_SECRET_BYTES).toString('base64url')}`;
}

// ---- DTOs ---------------------------------------------------------------------------------

export function toWebhookDto(w: Webhook): WebhookDto {
  return webhookDtoSchema.parse({
    id: w.id,
    orgId: w.orgId,
    name: w.name,
    url: w.url,
    events: w.events,
    active: w.active,
    failureCount: w.failureCount,
    lastDeliveryAt: w.lastDeliveryAt,
    lastStatus: w.lastStatus,
    disabledAt: w.disabledAt,
    createdAt: w.createdAt,
    updatedAt: w.updatedAt,
  });
}

export function toDeliveryDto(d: WebhookDelivery, withPayload = false): WebhookDeliveryDto {
  return webhookDeliveryDtoSchema.parse({
    id: d.id,
    webhookId: d.webhookId,
    eventId: d.eventId,
    event: d.event,
    status: d.status,
    attempts: d.attempts,
    nextAttemptAt: d.nextAttemptAt,
    responseStatus: d.responseStatus,
    responseSnippet: d.responseSnippet,
    error: d.error,
    durationMs: d.durationMs,
    deliveredAt: d.deliveredAt,
    createdAt: d.createdAt,
    ...(withPayload ? { payload: d.payload } : {}),
  });
}

// ---- admin CRUD ---------------------------------------------------------------------------

/** Same SSRF guard as server hooks, plus https-only in production. */
async function assertWebhookUrl(ctx: AppContext, raw: string): Promise<URL> {
  const url = await assertPublicUrl(raw, 'LSE-VAL-001');
  if (ctx.env.NODE_ENV === 'production' && url.protocol !== 'https:') {
    throw new AppError('LSE-VAL-001', {
      devMessage: 'Webhook URLs must use https in production',
      fields: { url: ['Use an https:// address'] },
    });
  }
  return url;
}

async function loadWebhook(ctx: AppContext, orgId: string, id: string): Promise<Webhook> {
  const row = await ctx.prisma.webhook.findFirst({ where: { id, orgId } });
  if (!row) throw new AppError('LSE-NF-001', { devMessage: 'Webhook not found' });
  return row;
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return '';
  }
}

export async function listWebhooks(ctx: AppContext, orgId: string): Promise<Page<WebhookDto>> {
  const rows = await ctx.prisma.webhook.findMany({
    where: { orgId },
    orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
  });
  return { data: rows.map(toWebhookDto), nextCursor: null };
}

export async function getWebhook(ctx: AppContext, orgId: string, id: string): Promise<WebhookDto> {
  return toWebhookDto(await loadWebhook(ctx, orgId, id));
}

export async function createWebhook(
  ctx: AppContext,
  orgId: string,
  actor: WebhookActor,
  body: CreateWebhookBody,
): Promise<CreateWebhookResponse> {
  if ((await ctx.prisma.webhook.count({ where: { orgId } })) >= MAX_WEBHOOKS_PER_ORG) {
    throw new AppError('LSE-ORG-009', {
      devMessage: `An organization can have at most ${MAX_WEBHOOKS_PER_ORG} webhooks`,
    });
  }
  await assertWebhookUrl(ctx, body.url);
  const secret = newWebhookSecret();
  const row = await ctx.prisma.webhook.create({
    data: {
      orgId,
      name: body.name,
      url: body.url,
      events: body.events,
      active: body.active,
      secretEnc: await ctx.crypto.encryptPacked(secret, 'generic'),
      createdById: actor.userId,
    },
  });
  await ctx.audit.record({
    orgId,
    actorId: actor.userId,
    action: 'webhook.create',
    target: row.id,
    meta: { name: row.name, host: hostOf(row.url), events: row.events },
    ip: actor.ip,
  });
  return createWebhookResponseSchema.parse({ ...toWebhookDto(row), secret });
}

export async function updateWebhook(
  ctx: AppContext,
  orgId: string,
  id: string,
  actor: WebhookActor,
  body: UpdateWebhookBody,
): Promise<WebhookDto> {
  const before = await loadWebhook(ctx, orgId, id);
  if (body.url !== undefined && body.url !== before.url) await assertWebhookUrl(ctx, body.url);
  const reEnable = body.active === true && !before.active;
  const row = await ctx.prisma.webhook.update({
    where: { id: before.id },
    data: {
      ...(body.name !== undefined ? { name: body.name } : {}),
      ...(body.url !== undefined ? { url: body.url } : {}),
      ...(body.events !== undefined ? { events: body.events } : {}),
      ...(body.active !== undefined ? { active: body.active } : {}),
      // Switching it back on clears the auto-disable bookkeeping.
      ...(reEnable ? { disabledAt: null, failureCount: 0 } : {}),
    },
  });
  await ctx.audit.record({
    orgId,
    actorId: actor.userId,
    action: 'webhook.update',
    target: row.id,
    meta: {
      changed: Object.keys(body),
      ...(body.events ? { events: body.events } : {}),
      ...(body.active !== undefined ? { active: body.active } : {}),
    },
    ip: actor.ip,
  });
  return toWebhookDto(row);
}

export async function deleteWebhook(
  ctx: AppContext,
  orgId: string,
  id: string,
  actor: WebhookActor,
): Promise<void> {
  const row = await loadWebhook(ctx, orgId, id);
  await ctx.prisma.webhook.delete({ where: { id: row.id } });
  await ctx.audit.record({
    orgId,
    actorId: actor.userId,
    action: 'webhook.delete',
    target: row.id,
    meta: { name: row.name, host: hostOf(row.url) },
    ip: actor.ip,
  });
}

export async function rotateWebhookSecret(
  ctx: AppContext,
  orgId: string,
  id: string,
  actor: WebhookActor,
): Promise<{ secret: string }> {
  const row = await loadWebhook(ctx, orgId, id);
  const secret = newWebhookSecret();
  await ctx.prisma.webhook.update({
    where: { id: row.id },
    data: { secretEnc: await ctx.crypto.encryptPacked(secret, 'generic') },
  });
  await ctx.audit.record({
    orgId,
    actorId: actor.userId,
    action: 'webhook.rotate_secret',
    target: row.id,
    ip: actor.ip,
  });
  return { secret };
}

export async function listDeliveries(
  ctx: AppContext,
  orgId: string,
  webhookId: string,
  q: ListWebhookDeliveriesQuery,
): Promise<Page<WebhookDeliveryDto>> {
  await loadWebhook(ctx, orgId, webhookId);
  const page: PaginationQuery = { limit: q.limit, ...(q.cursor ? { cursor: q.cursor } : {}) };
  const rows = await ctx.prisma.webhookDelivery.findMany({
    where: { webhookId, ...(q.status ? { status: q.status } : {}) },
    orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
    ...pageArgs(page),
  });
  return toPage(rows, q.limit, (d) => toDeliveryDto(d));
}

export async function getDelivery(
  ctx: AppContext,
  orgId: string,
  webhookId: string,
  deliveryId: string,
): Promise<WebhookDeliveryDto> {
  await loadWebhook(ctx, orgId, webhookId);
  const row = await ctx.prisma.webhookDelivery.findFirst({ where: { id: deliveryId, webhookId } });
  if (!row) throw new AppError('LSE-NF-001', { devMessage: 'Delivery not found' });
  return toDeliveryDto(row, true);
}

/** Send one `webhook.ping` right now (no retries); the result is logged like any delivery. */
export async function testWebhook(
  ctx: AppContext,
  orgId: string,
  id: string,
  actor: WebhookActor,
): Promise<WebhookDeliveryDto> {
  const webhook = await loadWebhook(ctx, orgId, id);
  const eventId = `evt_ping_${randomBytes(8).toString('hex')}`;
  const payload = {
    id: eventId,
    type: WEBHOOK_PING_EVENT,
    createdAt: new Date().toISOString(),
    orgId,
    data: { webhookId: webhook.id },
  };
  const row = await ctx.prisma.webhookDelivery.create({
    data: {
      webhookId: webhook.id,
      orgId,
      eventId,
      event: WEBHOOK_PING_EVENT,
      payload: payload as Prisma.InputJsonValue,
      status: 'PENDING',
      attempts: 1,
    },
  });
  const outcome = await sendDelivery(ctx, webhook, row);
  const settled = await settleOutcome(ctx, webhook, row, 1, outcome, { retry: false, ping: true });
  await ctx.audit.record({
    orgId,
    actorId: actor.userId,
    action: 'webhook.test',
    target: webhook.id,
    meta: { deliveryId: row.id, ok: outcome.ok, status: outcome.status },
    ip: actor.ip,
  });
  return toDeliveryDto(settled);
}

/** Reset a finished delivery to PENDING and send it again (same event id / delivery id). */
export async function redeliver(
  ctx: AppContext,
  orgId: string,
  webhookId: string,
  deliveryId: string,
  actor: WebhookActor,
): Promise<WebhookDeliveryDto> {
  const webhook = await loadWebhook(ctx, orgId, webhookId);
  const d = await ctx.prisma.webhookDelivery.findFirst({ where: { id: deliveryId, webhookId } });
  if (!d) throw new AppError('LSE-NF-001', { devMessage: 'Delivery not found' });
  if (!webhook.active) {
    throw new AppError('LSE-CONF-001', {
      devMessage: 'The webhook is disabled; re-enable it before redelivering',
    });
  }
  const reset = await ctx.prisma.webhookDelivery.updateMany({
    where: { id: d.id, status: { not: 'PENDING' } },
    data: {
      status: 'PENDING',
      attempts: 0,
      nextAttemptAt: new Date(),
      error: null,
      responseStatus: null,
      responseSnippet: null,
      durationMs: null,
      deliveredAt: null,
    },
  });
  if (reset.count === 0) {
    throw new AppError('LSE-CONF-001', { devMessage: 'The delivery is still in progress' });
  }
  await ctx.audit.record({
    orgId,
    actorId: actor.userId,
    action: 'webhook.test',
    target: webhook.id,
    meta: { kind: 'redeliver', deliveryId: d.id, event: d.event },
    ip: actor.ip,
  });
  await ctx.jobs.enqueue(
    'webhook-delivery',
    { deliveryId: d.id },
    { jobId: `wh:${d.id}:redeliver:${Date.now()}` },
  );
  return toDeliveryDto(await ctx.prisma.webhookDelivery.findUniqueOrThrow({ where: { id: d.id } }));
}

// ---- fan-out ------------------------------------------------------------------------------

/**
 * Persist one delivery per subscribed webhook and enqueue it. Quick by design (the event bus
 * awaits listeners): no network calls here.
 */
async function fanOut(ctx: AppContext, e: AnyPlatformEvent): Promise<void> {
  if (!isWebhookEvent(e.type)) return;
  const body = { id: e.id, type: e.type, createdAt: e.occurredAt, orgId: e.orgId, data: e.data };
  const parsed = webhookPayloadSchema.safeParse(body);
  if (!parsed.success) {
    ctx.logger.warn(
      { event: e.type, eventId: e.id, issues: parsed.error.issues.length },
      'webhook payload does not match the shared contract; not delivered',
    );
    return;
  }
  const hooks = await ctx.prisma.webhook.findMany({
    where: { orgId: e.orgId, active: true, events: { has: e.type } },
    select: { id: true },
  });
  for (const h of hooks) {
    try {
      const row = await ctx.prisma.webhookDelivery.create({
        data: {
          webhookId: h.id,
          orgId: e.orgId,
          eventId: e.id,
          event: e.type,
          payload: parsed.data as Prisma.InputJsonValue,
          status: 'PENDING',
          nextAttemptAt: new Date(),
        },
      });
      await ctx.jobs.enqueue(
        'webhook-delivery',
        { deliveryId: row.id },
        { jobId: `wh:${row.id}:0` },
      );
    } catch (err) {
      // Unique (webhookId, eventId): already fanned out.
      if ((err as { code?: string }).code === 'P2002') continue;
      ctx.logger.warn({ err, webhookId: h.id, eventId: e.id }, 'could not queue webhook delivery');
    }
  }
}

// ---- delivery -----------------------------------------------------------------------------

interface Outcome {
  ok: boolean;
  status: number | null;
  snippet: string | null;
  error: string | null;
  durationMs: number;
}

/** First `max` bytes of the response body, scrubbed and safe for a text column. */
async function readSnippet(res: Response, max = WEBHOOK_RESPONSE_SNIPPET_BYTES): Promise<string> {
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (total < max) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      total += value.length;
    }
  } catch {
    /* an interrupted body is not a delivery failure by itself */
  } finally {
    await reader.cancel().catch(() => undefined);
  }
  return scrubSecrets(Buffer.concat(chunks).subarray(0, max).toString('utf8'))
    .replaceAll('\0', '')
    .slice(0, max);
}

/** One signed POST. Never throws: every failure becomes an `Outcome`. */
async function sendDelivery(
  ctx: AppContext,
  webhook: Webhook,
  delivery: Pick<WebhookDelivery, 'id' | 'event' | 'payload'>,
): Promise<Outcome> {
  const started = Date.now();
  const fail = (error: string, status: number | null = null, snippet: string | null = null) => ({
    ok: false,
    status,
    snippet,
    error,
    durationMs: Date.now() - started,
  });
  try {
    // Re-checked on every attempt (DNS rebinding and production HTTPS); a blocked target is recorded,
    // not sent.
    let url: URL;
    try {
      url = await assertWebhookUrl(ctx, webhook.url);
    } catch {
      return fail('Blocked: the URL does not point to an allowed public address');
    }
    const secret = await ctx.crypto.decryptPackedString(webhook.secretEnc, 'generic');
    const body = JSON.stringify(delivery.payload);
    const timestamp = Math.floor(Date.now() / 1000);
    const res = await outboundFetch(ctx, url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': WEBHOOK_USER_AGENT,
        [WEBHOOK_EVENT_HEADER]: delivery.event,
        [WEBHOOK_DELIVERY_HEADER]: delivery.id,
        [WEBHOOK_TIMESTAMP_HEADER]: String(timestamp),
        [WEBHOOK_SIGNATURE_HEADER]: signWebhook(secret, timestamp, body),
      },
      body,
      redirect: 'manual',
      signal: AbortSignal.timeout(WEBHOOK_TIMEOUT_MS),
    });
    const snippet = await readSnippet(res);
    const durationMs = Date.now() - started;
    if (res.status >= 200 && res.status < 300) {
      return { ok: true, status: res.status, snippet, error: null, durationMs };
    }
    const error =
      res.status >= 300 && res.status < 400
        ? `Redirects are not followed (HTTP ${res.status})`
        : `HTTP ${res.status}`;
    return { ok: false, status: res.status, snippet, error, durationMs };
  } catch (err) {
    const name = (err as Error).name;
    if (name === 'TimeoutError' || name === 'AbortError') {
      return fail(`Timed out after ${WEBHOOK_TIMEOUT_MS / 1000}s`);
    }
    return fail(
      `Request failed: ${scrubSecrets(String((err as Error).message ?? err)).slice(0, 300)}`,
    );
  }
}

async function deactivate(
  ctx: AppContext,
  webhook: Webhook,
  reason: 'consecutive_failures' | 'gone',
  failures: number,
): Promise<void> {
  const r = await ctx.prisma.webhook.updateMany({
    where: { id: webhook.id, active: true },
    data: { active: false, disabledAt: new Date() },
  });
  if (r.count === 0) return;
  await ctx.audit.record({
    orgId: webhook.orgId,
    actorId: null,
    action: 'webhook.disabled',
    target: webhook.id,
    meta: { reason, failures, host: hostOf(webhook.url) },
  });
}

/** Record an attempt's result; schedule the next attempt when retries are left. */
async function settleOutcome(
  ctx: AppContext,
  webhook: Webhook,
  delivery: WebhookDelivery,
  attempt: number,
  outcome: Outcome,
  opts: { retry: boolean; ping?: boolean },
): Promise<WebhookDelivery> {
  const now = new Date();
  const common = {
    attempts: attempt,
    responseStatus: outcome.status,
    responseSnippet: outcome.snippet,
    durationMs: outcome.durationMs,
  };
  if (outcome.ok) {
    const row = await ctx.prisma.webhookDelivery.update({
      where: { id: delivery.id },
      data: { ...common, status: 'SUCCEEDED', error: null, nextAttemptAt: null, deliveredAt: now },
    });
    await ctx.prisma.webhook.update({
      where: { id: webhook.id },
      data: {
        lastDeliveryAt: now,
        lastStatus: 'succeeded',
        // A ping proves reachability but must not hide real failures.
        ...(opts.ping ? {} : { failureCount: 0 }),
      },
    });
    return row;
  }

  const gone = outcome.status === 410;
  const delay = opts.retry && !gone ? webhookRetryDelayMs(attempt) : null;
  if (delay !== null) {
    const next = new Date(now.getTime() + delay);
    const row = await ctx.prisma.webhookDelivery.update({
      where: { id: delivery.id },
      data: { ...common, status: 'PENDING', error: outcome.error, nextAttemptAt: next },
    });
    await ctx.prisma.webhook.update({
      where: { id: webhook.id },
      data: { lastDeliveryAt: now, lastStatus: 'failed' },
    });
    await ctx.jobs.enqueue(
      'webhook-delivery',
      { deliveryId: delivery.id },
      { jobId: `wh:${delivery.id}:${attempt}`, delayMs: delay },
    );
    return row;
  }

  // Final failure (retries exhausted, 410 Gone, or a one-shot ping).
  const row = await ctx.prisma.webhookDelivery.update({
    where: { id: delivery.id },
    data: { ...common, status: 'FAILED', error: outcome.error, nextAttemptAt: null },
  });
  if (opts.ping) {
    await ctx.prisma.webhook.update({
      where: { id: webhook.id },
      data: { lastDeliveryAt: now, lastStatus: 'failed' },
    });
    return row;
  }
  const updated = await ctx.prisma.webhook.update({
    where: { id: webhook.id },
    data: { lastDeliveryAt: now, lastStatus: 'failed', failureCount: { increment: 1 } },
  });
  if (gone) await deactivate(ctx, updated, 'gone', updated.failureCount);
  else if (updated.failureCount >= WEBHOOK_MAX_CONSECUTIVE_FAILURES) {
    await deactivate(ctx, updated, 'consecutive_failures', updated.failureCount);
  }
  return row;
}

/** One delivery attempt (the `webhook-delivery` job). Safe to call repeatedly / concurrently. */
export async function deliverWebhook(ctx: AppContext, deliveryId: string): Promise<void> {
  const d = await ctx.prisma.webhookDelivery.findUnique({
    where: { id: deliveryId },
    include: { webhook: true },
  });
  if (!d || d.status !== 'PENDING') return;
  const { webhook, ...delivery } = d;
  if (!webhook.active) {
    await ctx.prisma.webhookDelivery.update({
      where: { id: d.id },
      data: { status: 'FAILED', error: 'The webhook is disabled', nextAttemptAt: null },
    });
    return;
  }
  // Claim the attempt (optimistic on `attempts`) and lease it so a crash is swept later.
  const attempt = d.attempts + 1;
  const claimed = await ctx.prisma.webhookDelivery.updateMany({
    where: {
      id: d.id,
      status: 'PENDING',
      attempts: d.attempts,
      OR: [
        { nextAttemptAt: null },
        { nextAttemptAt: { lte: new Date(Date.now() + CLAIM_SLACK_MS) } },
      ],
    },
    data: { attempts: attempt, nextAttemptAt: new Date(Date.now() + ATTEMPT_LEASE_MS) },
  });
  if (claimed.count === 0) return;
  const outcome = await sendDelivery(ctx, webhook, delivery);
  await settleOutcome(ctx, webhook, { ...delivery, attempts: attempt }, attempt, outcome, {
    retry: attempt < WEBHOOK_MAX_ATTEMPTS,
  });
}

/** Re-enqueue overdue deliveries (lost jobs) and prune finished rows past retention. */
export async function webhookSweep(
  ctx: AppContext,
  now: Date = new Date(),
): Promise<{ requeued: number; pruned: number }> {
  const overdue = await ctx.prisma.webhookDelivery.findMany({
    where: {
      status: 'PENDING',
      OR: [
        { nextAttemptAt: { lte: new Date(now.getTime() - SWEEP_GRACE_MS) } },
        { nextAttemptAt: null, createdAt: { lte: new Date(now.getTime() - SWEEP_GRACE_MS) } },
      ],
    },
    select: { id: true, attempts: true },
    take: 500,
    orderBy: { createdAt: 'asc' },
  });
  for (const d of overdue) {
    await ctx.jobs.enqueue(
      'webhook-delivery',
      { deliveryId: d.id },
      { jobId: `wh:${d.id}:sweep:${now.getTime()}` },
    );
  }
  const cutoff = new Date(now.getTime() - WEBHOOK_DELIVERY_RETENTION_DAYS * 86_400_000);
  const pruned = await ctx.prisma.webhookDelivery.deleteMany({
    where: { status: { not: 'PENDING' }, createdAt: { lt: cutoff } },
  });
  return { requeued: overdue.length, pruned: pruned.count };
}

/** Subscribe to platform events and register the `webhook-delivery` / `webhook-sweep` jobs. */
export function registerWebhookDelivery(ctx: AppContext, _role: PlatformRole): void {
  ctx.jobs.register('webhook-delivery', async (data) => {
    const id = typeof data.deliveryId === 'string' ? data.deliveryId : '';
    if (id) await deliverWebhook(ctx, id);
  });
  ctx.jobs.register('webhook-sweep', async () => {
    await webhookSweep(ctx);
  });
  ctx.platformEvents.onAny((e) => fanOut(ctx, e));
}
