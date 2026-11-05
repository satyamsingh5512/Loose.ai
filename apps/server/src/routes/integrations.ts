/**
 * Inbound integration endpoints (Slack slash command, Linear and Jira webhooks; spec §8.15) —
 * OWNED BY W4. Mounted by app.ts at `/api/v1/integrations` BEFORE cookies, the JSON parser and
 * CSRF: each route parses its own raw body (signatures are computed over the exact bytes).
 * Missing secret env var → 503 LSE-SYS-007; bad signature → 401 LSE-AUTH-009.
 *
 * P10-SEC-007: Linear and Jira are addressed per trigger
 * (`/integrations/{linear,jira}/webhook/<triggerId>.<mac>`) and verified with that trigger's
 * own derived secret (`services/triggers/webhookAuth.ts`). The old org-agnostic paths that
 * verified a global `LINEAR_WEBHOOK_SECRET` / `JIRA_WEBHOOK_SECRET` and then scanned every
 * tenant's triggers are gone (401 LSE-AUTH-009).
 */
import express, { Router } from 'express';
import type { Trigger } from '@prisma/client';
import { INTEGRATION_PATHS } from '@loose/shared';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';
import { handleJiraEvent, verifyJiraSignature } from '../services/triggers/jira';
import { handleLinearEvent, verifyLinearSignature } from '../services/triggers/linear';
import {
  findSlackTrigger,
  handleSlackCommand,
  parseSlackForm,
  verifySlackSignature,
} from '../services/triggers/slack';
import {
  parseTriggerWebhookToken,
  triggerWebhookSecret,
  type WebhookTriggerKind,
} from '../services/triggers/webhookAuth';

const RAW_BODY_LIMIT = '1mb';

/** `INTEGRATION_PATHS` are relative to `API_PREFIX`; this router is mounted at
 * `${API_PREFIX}/integrations`, so strip that segment for the in-router path. */
const relativePath = (p: string): string => p.replace(/^\/integrations/, '');

/**
 * Resolves the one trigger a tokenised webhook request may fire, together with its own
 * signing secret. An unknown/forged token is indistinguishable from a bad signature
 * (401 LSE-AUTH-009) so the endpoint does not reveal which triggers exist.
 */
async function authenticatedTrigger(
  ctx: AppContext,
  kind: WebhookTriggerKind,
  token: string | undefined,
): Promise<{ trigger: Trigger; secret: string }> {
  const triggerId = parseTriggerWebhookToken(ctx.env.SESSION_SECRET, kind, token);
  const trigger = triggerId
    ? await ctx.prisma.trigger.findFirst({ where: { id: triggerId, kind } })
    : null;
  if (!trigger) {
    throw new AppError('LSE-AUTH-009', { devMessage: 'Unknown webhook trigger token' });
  }
  return { trigger, secret: triggerWebhookSecret(ctx.env.SESSION_SECRET, kind, trigger.id) };
}

export function integrationsRouter(ctx: AppContext): Router {
  const r = Router();
  const raw = express.raw({ type: () => true, limit: RAW_BODY_LIMIT });

  r.post(relativePath(INTEGRATION_PATHS.slack), raw, async (req, res) => {
    const secret = ctx.env.SLACK_SIGNING_SECRET;
    if (!secret) {
      throw new AppError('LSE-SYS-007', { devMessage: 'SLACK_SIGNING_SECRET is not configured' });
    }
    const rawBody = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '';
    const timestamp = req.get('x-slack-request-timestamp');
    const ok = verifySlackSignature(secret, timestamp, req.get('x-slack-signature'), rawBody);
    if (!ok) throw new AppError('LSE-AUTH-009', { devMessage: 'x-slack-signature mismatch' });

    const payload = parseSlackForm(rawBody, timestamp);
    const trigger = await findSlackTrigger(ctx, payload);
    if (!trigger) {
      res.json({
        response_type: 'ephemeral',
        text: 'No loose.ai trigger is configured for this Slack workspace/channel.',
      });
      return;
    }
    // Enqueue a durable trigger-fire job (fast), then ack within Slack's 3s window; the run's
    // result is posted to response_url on run.completed (triggers.service postRunCompletion).
    const queued = await handleSlackCommand(ctx, trigger, payload);
    res.json({
      response_type: 'ephemeral',
      text: queued ? 'Working on it…' : 'Usage: /loose <what you want changed>',
    });
  });

  r.post(`${relativePath(INTEGRATION_PATHS.linear)}/:token`, raw, async (req, res) => {
    const { trigger, secret } = await authenticatedTrigger(ctx, 'LINEAR', req.params.token);
    const rawBody = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
    if (!verifyLinearSignature(secret, rawBody, req.get('linear-signature'))) {
      throw new AppError('LSE-AUTH-009', { devMessage: 'linear-signature mismatch' });
    }
    let payload: unknown;
    try {
      payload = JSON.parse(rawBody.toString('utf8'));
    } catch {
      res.status(202).json({ data: { handled: false } });
      return;
    }
    const handled = await handleLinearEvent(ctx, payload, trigger);
    res.status(202).json({ data: { handled } });
  });

  r.post(`${relativePath(INTEGRATION_PATHS.jira)}/:token`, raw, async (req, res) => {
    const { trigger, secret } = await authenticatedTrigger(ctx, 'JIRA', req.params.token);
    const rawBody = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
    if (!verifyJiraSignature(secret, rawBody, req.get('x-hub-signature'))) {
      throw new AppError('LSE-AUTH-009', { devMessage: 'x-hub-signature mismatch' });
    }
    let payload: unknown;
    try {
      payload = JSON.parse(rawBody.toString('utf8'));
    } catch {
      res.status(202).json({ data: { handled: false } });
      return;
    }
    const handled = await handleJiraEvent(ctx, payload, trigger);
    res.status(202).json({ data: { handled } });
  });

  // The pre-Phase-10 global endpoints are no longer accepted: without a trigger token the
  // request cannot be bound to one organization (P10-SEC-007).
  for (const path of [INTEGRATION_PATHS.linear, INTEGRATION_PATHS.jira]) {
    r.post(relativePath(path), raw, () => {
      throw new AppError('LSE-AUTH-009', {
        devMessage: 'This endpoint requires the trigger-specific webhook URL',
      });
    });
  }

  r.use(() => {
    throw new AppError('LSE-SYS-007', { devMessage: 'Unknown integration endpoint' });
  });

  return r;
}
