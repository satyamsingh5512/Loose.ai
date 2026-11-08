/**
 * Per-trigger inbound webhook credentials (P10-SEC-007).
 *
 * Linear and Jira used to share one global `LINEAR_WEBHOOK_SECRET` / `JIRA_WEBHOOK_SECRET`,
 * and the handlers then scanned **every** enabled trigger of **every** organization for a
 * matching team/project. A tenant that knows the shared secret could therefore sign a body
 * carrying another tenant's team/project id and fire that tenant's trigger under its
 * `runAsUser`. Instead, each trigger now has:
 *
 * - an unguessable path token — `<triggerId>.<base64url(HMAC)>` — so the inbound request
 *   names exactly one trigger and the request is bound to the organization that owns it, and
 * - its own signing secret, derived per trigger, so one tenant's secret cannot sign a request
 *   for another tenant's trigger.
 *
 * Both are derived from `SESSION_SECRET` with HKDF-SHA256 (no new storage, no new env var,
 * deterministic so the UI can show the URL/secret again). The token MAC covers the trigger
 * kind, so a Linear URL cannot be replayed against the Jira endpoint.
 */
import { createHmac, hkdfSync, timingSafeEqual } from 'node:crypto';
import type { TriggerKind } from '@loose/shared';

const TOKEN_SALT = 'loose-trigger-webhook-token';
const SECRET_SALT = 'loose-trigger-webhook-secret';
const INFO = 'v1';
const KEY_BYTES = 32;
/** Trigger kinds with a per-trigger inbound webhook URL. */
export type WebhookTriggerKind = Extract<TriggerKind, 'LINEAR' | 'JIRA'>;

function key(secret: string, salt: string): Buffer {
  return Buffer.from(hkdfSync('sha256', secret, salt, INFO, KEY_BYTES) as ArrayBuffer);
}

function tokenMac(secret: string, kind: WebhookTriggerKind, triggerId: string): string {
  return createHmac('sha256', key(secret, TOKEN_SALT))
    .update(`${kind}:${triggerId}`)
    .digest('base64url');
}

/** `<triggerId>.<mac>` — the path segment of the trigger's inbound webhook URL. */
export function triggerWebhookToken(
  secret: string,
  kind: WebhookTriggerKind,
  triggerId: string,
): string {
  return `${triggerId}.${tokenMac(secret, kind, triggerId)}`;
}

/** The trigger id of a valid token for `kind`, or null (unknown/forged/foreign-kind token). */
export function parseTriggerWebhookToken(
  secret: string,
  kind: WebhookTriggerKind,
  token: string | undefined,
): string | null {
  if (!token || token.length > 256) return null;
  const dot = token.indexOf('.');
  if (dot <= 0 || dot === token.length - 1) return null;
  const triggerId = token.slice(0, dot);
  const provided = Buffer.from(token.slice(dot + 1), 'base64url');
  const expected = Buffer.from(tokenMac(secret, kind, triggerId), 'base64url');
  if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) return null;
  return triggerId;
}

/** The signing secret the tenant configures in Linear/Jira for this trigger (hex). */
export function triggerWebhookSecret(
  secret: string,
  kind: WebhookTriggerKind,
  triggerId: string,
): string {
  return createHmac('sha256', key(secret, SECRET_SALT))
    .update(`${kind}:${triggerId}`)
    .digest('hex');
}

export function isWebhookTriggerKind(kind: TriggerKind): kind is WebhookTriggerKind {
  return kind === 'LINEAR' || kind === 'JIRA';
}
