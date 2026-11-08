/**
 * Linear webhook trigger (spec §8.15). `POST /integrations/linear/webhook` is mounted on a
 * raw body (routes/integrations.ts): the `linear-signature` header is a hex HMAC-SHA256 of
 * the exact bytes Linear sent.
 */
import { createHmac, timingSafeEqual } from 'node:crypto';
import { parseTriggerConfig, type RunSource } from '@loose/shared';
import type { Trigger } from '@prisma/client';
import type { AppContext } from '../../context';
import { fireTrigger } from './fire';

export function verifyLinearSignature(
  secret: string,
  rawBody: Buffer,
  header: string | undefined,
): boolean {
  if (!header) return false;
  const expected = createHmac('sha256', secret).update(rawBody).digest('hex');
  const a = Buffer.from(header, 'hex');
  const b = Buffer.from(expected, 'hex');
  return a.length === b.length && a.length > 0 && timingSafeEqual(a, b);
}

interface LinearIssuePayload {
  action?: string; // 'create' | 'update' | ...
  type?: string; // 'Issue'
  data?: {
    id?: string;
    identifier?: string;
    title?: string;
    description?: string | null;
    url?: string;
    team?: { id?: string };
    labels?: { nodes?: { name?: string }[] };
    labelIds?: string[];
  };
  updatedFrom?: { labelIds?: string[] };
}

function labelNames(data: LinearIssuePayload['data']): string[] {
  return (data?.labels?.nodes ?? []).map((l) => l.name ?? '').filter(Boolean);
}

/**
 * Fire the (already authenticated) trigger when the configured label is present on the issue.
 *
 * P10-SEC-007: the trigger is resolved from the unguessable per-trigger path token and its own
 * derived secret verified the body, so no global scan over other organizations' triggers
 * happens any more — a tenant can only ever fire the trigger whose URL/secret it holds.
 */
export async function handleLinearEvent(
  ctx: AppContext,
  payload: unknown,
  trigger: Trigger,
): Promise<boolean> {
  const p = payload as LinearIssuePayload;
  if (p.type !== 'Issue' || !['create', 'update'].includes(p.action ?? '') || !p.data?.id) {
    return false;
  }
  if (trigger.kind !== 'LINEAR' || !trigger.enabled) return false;
  const names = labelNames(p.data);
  const cfg = parseTriggerConfig('LINEAR', trigger.config);
  if (!cfg) return false;
  if (cfg.teamId && cfg.teamId !== p.data.team?.id) return false;
  if (!names.includes(cfg.label)) return false;
  const dedupeKey = `linear:${p.data.id}:${cfg.label}`;
  const r = await fireTrigger(ctx, trigger.id, {
    dedupeKey,
    vars: {
      title: p.data.title ?? '',
      body: p.data.description ?? '',
      number: p.data.identifier ?? '',
      url: p.data.url ?? '',
    },
    source: 'LINEAR' satisfies RunSource,
    externalRef: { issueId: p.data.id },
  });
  return !!(r.runId || r.duplicate);
}
