/**
 * Jira webhook trigger (spec §8.15). `POST /integrations/jira/webhook` is mounted on a raw
 * body (routes/integrations.ts): `x-hub-signature: sha256=<hex>` over the exact bytes, same
 * scheme as the GitHub webhook.
 */
import { createHmac, timingSafeEqual } from 'node:crypto';
import { parseTriggerConfig, type RunSource } from '@loose/shared';
import type { Trigger } from '@prisma/client';
import type { AppContext } from '../../context';
import { fireTrigger } from './fire';

export function verifyJiraSignature(
  secret: string,
  rawBody: Buffer,
  header: string | undefined,
): boolean {
  if (!header?.startsWith('sha256=')) return false;
  const expected = createHmac('sha256', secret).update(rawBody).digest('hex');
  const a = Buffer.from(header.slice('sha256='.length), 'hex');
  const b = Buffer.from(expected, 'hex');
  return a.length === b.length && a.length > 0 && timingSafeEqual(a, b);
}

interface JiraWebhookPayload {
  webhookEvent?: string; // 'jira:issue_created' | 'jira:issue_updated'
  issue?: {
    key?: string;
    self?: string;
    fields?: {
      summary?: string;
      description?: string | null;
      project?: { key?: string };
      labels?: string[];
    };
  };
}

function issueUrl(issue: NonNullable<JiraWebhookPayload['issue']>): string {
  if (!issue.self) return '';
  try {
    const u = new URL(issue.self);
    return `${u.protocol}//${u.host}/browse/${issue.key ?? ''}`;
  } catch {
    return '';
  }
}

/**
 * Fire the (already authenticated) trigger when the configured label is present on the issue.
 *
 * P10-SEC-007: only the trigger named by the unguessable per-trigger path token — whose own
 * derived secret signed this body — is considered; the handler no longer scans every
 * organization's Jira triggers for a matching project key.
 */
export async function handleJiraEvent(
  ctx: AppContext,
  payload: unknown,
  trigger: Trigger,
): Promise<boolean> {
  const p = payload as JiraWebhookPayload;
  if (
    !['jira:issue_created', 'jira:issue_updated'].includes(p.webhookEvent ?? '') ||
    !p.issue?.key
  ) {
    return false;
  }
  if (trigger.kind !== 'JIRA' || !trigger.enabled) return false;
  const labels = p.issue.fields?.labels ?? [];
  const cfg = parseTriggerConfig('JIRA', trigger.config);
  if (!cfg) return false;
  if (cfg.projectKey && cfg.projectKey !== p.issue.fields?.project?.key) return false;
  if (!labels.includes(cfg.label)) return false;
  const dedupeKey = `jira:${p.issue.key}:${cfg.label}`;
  const r = await fireTrigger(ctx, trigger.id, {
    dedupeKey,
    vars: {
      title: p.issue.fields?.summary ?? '',
      body: p.issue.fields?.description ?? '',
      number: p.issue.key,
      url: issueUrl(p.issue),
    },
    source: 'JIRA' satisfies RunSource,
    externalRef: { issueKey: p.issue.key },
  });
  return !!(r.runId || r.duplicate);
}
