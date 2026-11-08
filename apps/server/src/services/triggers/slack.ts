/**
 * Slack slash command trigger (spec §8.15). `POST /integrations/slack/commands` is mounted
 * on a raw body (routes/integrations.ts) because the signature covers the exact bytes.
 * Slack requires an ack within 3s: we enqueue a durable `trigger-fire` job and reply immediately
 * with an ephemeral "working on it" message; the final result is POSTed to `response_url`.
 */
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import {
  INTEGRATION_SIGNATURE_TOLERANCE_SEC,
  parseTriggerConfig,
  type RunSource,
} from '@loose/shared';
import type { Trigger } from '@prisma/client';
import type { AppContext } from '../../context';

export interface SlackCommandPayload {
  teamId: string;
  channelId: string;
  text: string;
  userName: string;
  responseUrl: string;
  command: string;
  /** Slack's unique invocation id, when present. */
  triggerId: string;
  /** Stable fallback identity for retries of the exact signed request. */
  requestKey: string;
}

/** `v0=<hex HMAC-SHA256(signingSecret, "v0:<timestamp>:<rawBody>")>`, ±5 min. */
export function verifySlackSignature(
  signingSecret: string,
  timestampHeader: string | undefined,
  signatureHeader: string | undefined,
  rawBody: string,
  now = Date.now(),
): boolean {
  if (!timestampHeader || !signatureHeader?.startsWith('v0=')) return false;
  const ts = Number(timestampHeader);
  if (!Number.isFinite(ts) || Math.abs(now / 1000 - ts) > INTEGRATION_SIGNATURE_TOLERANCE_SEC) {
    return false;
  }
  const base = `v0:${timestampHeader}:${rawBody}`;
  const expected = `v0=${createHmac('sha256', signingSecret).update(base).digest('hex')}`;
  const a = Buffer.from(signatureHeader);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

export function parseSlackForm(rawBody: string, timestampHeader = ''): SlackCommandPayload {
  const params = new URLSearchParams(rawBody);
  return {
    teamId: params.get('team_id') ?? '',
    channelId: params.get('channel_id') ?? '',
    text: params.get('text') ?? '',
    userName: params.get('user_name') ?? '',
    responseUrl: params.get('response_url') ?? '',
    command: params.get('command') ?? '',
    triggerId: params.get('trigger_id') ?? '',
    requestKey: timestampHeader
      ? createHash('sha256').update(`v0:${timestampHeader}:${rawBody}`).digest('hex')
      : '',
  };
}

/** Find the enabled trigger matching this team (and channel, if the trigger restricts it). */
export async function findSlackTrigger(
  ctx: AppContext,
  payload: SlackCommandPayload,
): Promise<Trigger | null> {
  const triggers = await ctx.prisma.trigger.findMany({
    where: { kind: 'SLACK_COMMAND', enabled: true },
  });
  for (const trigger of triggers) {
    const cfg = parseTriggerConfig('SLACK_COMMAND', trigger.config);
    if (!cfg || cfg.teamId !== payload.teamId) continue;
    if (cfg.channelIds?.length && !cfg.channelIds.includes(payload.channelId)) continue;
    return trigger;
  }
  return null;
}

/**
 * Enqueue a durable `trigger-fire` job (the same path as the GitHub triggers), deduping Slack
 * retries by its invocation id or the signed request bytes. Enqueueing is fast, so the route can
 * await it and still ack within Slack's 3s window; the job survives an API restart and is
 * tracked by the job runner (tests await `ctx.jobs.onIdle()`). Returns false for empty text.
 */
export async function handleSlackCommand(
  ctx: AppContext,
  trigger: Trigger,
  payload: SlackCommandPayload,
): Promise<boolean> {
  if (!payload.text.trim()) return false;
  const invocationId =
    payload.triggerId ||
    payload.requestKey ||
    createHash('sha256')
      .update(
        `${payload.teamId}\0${payload.channelId}\0${payload.userName}\0${payload.command}\0${payload.text}`,
      )
      .digest('hex');
  const dedupeKey = `slack:${invocationId}`;
  await ctx.jobs.enqueue(
    'trigger-fire',
    {
      triggerId: trigger.id,
      dedupeKey,
      vars: { text: payload.text, title: payload.text },
      source: 'SLACK' satisfies RunSource,
      externalRef: {
        responseUrl: payload.responseUrl,
        channelId: payload.channelId,
        userName: payload.userName,
      },
    },
    { jobId: `trigger-fire:${trigger.id}:${dedupeKey}` },
  );
  return true;
}

interface RunCompletedData {
  status: string;
  prUrl: string | null;
  errorCode: string | null;
  summary: string | null;
  externalRef: Record<string, unknown> | null;
}

function resultText(data: RunCompletedData): string {
  if (data.status === 'SUCCEEDED' && data.prUrl) return `Done — pull request: ${data.prUrl}`;
  if (data.status === 'SUCCEEDED') return data.summary ?? 'Done.';
  if (data.status === 'CANCELLED') return 'Cancelled.';
  return `Failed (${data.errorCode ?? 'error'}).`;
}

/** POST the final result to the stored `response_url` (must be a Slack hooks URL). */
export async function postSlackRunResult(
  ctx: AppContext,
  _trigger: Trigger,
  data: RunCompletedData,
): Promise<void> {
  const responseUrl = data.externalRef?.responseUrl;
  if (typeof responseUrl !== 'string' || !responseUrl.startsWith('https://hooks.slack.com/')) {
    return;
  }
  await ctx.fetch(responseUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ response_type: 'in_channel', text: resultText(data) }),
  });
}
