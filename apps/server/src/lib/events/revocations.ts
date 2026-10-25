/**
 * Credential revocation bus (P10-SEC-003).
 *
 * WebSockets authenticate once at upgrade, so logout / "sign out everywhere" / deleting a PAT
 * / deleting the account used to leave an already-established socket fully usable. Revoking
 * code publishes a revocation event here; every API instance closes the matching sockets with
 * close code 4401 (`WS_CLOSE_CODES.UNAUTHORIZED`, error `LSE-WS-001`).
 *
 * - Publishers (`services/session.service.ts`, `services/token.service.ts`, …) call the
 *   module-level helpers; they do not need an `AppContext`. Every registered bus (one per
 *   process that serves WebSockets) receives the event locally and, if Redis is wired, relays
 *   it to the other instances on the `revoke` channel.
 * - The wire format is an authenticated cluster envelope (`envelope.ts`): an unsigned, stale
 *   or forged revocation is dropped, so Redis write access cannot be used to mass-disconnect
 *   users either.
 * - Expiry needs no event: the gateway also re-validates credentials periodically and before
 *   every state-changing command.
 * - REAUDIT-006: org policy changes (SSO connection replaced/removed, enforce-SSO, admin 2FA,
 *   IP allowlist, verified domains, member removal / role change) publish a `policy_changed`
 *   event scoped to an org (optionally one user) after the change committed. Every instance then
 *   drops its cached org security config and immediately re-validates the matching sockets
 *   against the live credential + org access policy (close 4401 / 4403, or 1013 on errors).
 */
import type { Logger } from '../logger';
import type { Redis } from '../redis';
import {
  deriveClusterKey,
  signClusterMessage,
  verifyClusterMessage,
  CLUSTER_MESSAGE_MAX_AGE_MS,
} from './envelope';

export const REVOCATION_CHANNEL = 'revoke';

export type RevocationReason =
  | 'logout'
  | 'session_revoked'
  | 'token_revoked'
  | 'account_deleted'
  | 'mfa_changed'
  | 'policy_changed';

export interface RevocationEvent {
  reason: RevocationReason;
  /** Owner of the revoked credentials, when known. */
  userId?: string;
  /** `AuthSession.id` values (= sha256 of the cookie token). */
  authSessionIds?: string[];
  apiTokenIds?: string[];
  /** Every credential of `userId` (sign out everywhere / account deletion). */
  allForUser?: boolean;
  /**
   * `policy_changed` only: the org whose access policy / membership changed. Sockets joined to
   * one of its sessions, or authenticated by one of its PATs (limited to `userId` when set), are
   * re-validated rather than closed unconditionally.
   */
  orgId?: string;
}

export type RevocationListener = (event: RevocationEvent) => void;

const asIds = (value: unknown): string[] | undefined => {
  if (!Array.isArray(value)) return undefined;
  const ids = value.filter((v): v is string => typeof v === 'string' && v.length > 0);
  return ids.length ? ids : undefined;
};

const REASONS: readonly RevocationReason[] = [
  'logout',
  'session_revoked',
  'token_revoked',
  'account_deleted',
  'mfa_changed',
  'policy_changed',
];

/** Shape-check a payload that arrived over the wire (it is signed, but still parsed). */
export function parseRevocationEvent(payload: unknown): RevocationEvent | null {
  if (!payload || typeof payload !== 'object') return null;
  const p = payload as Record<string, unknown>;
  const reason = REASONS.find((r) => r === p.reason);
  if (!reason) return null;
  const event: RevocationEvent = { reason };
  if (typeof p.userId === 'string' && p.userId) event.userId = p.userId;
  const sessions = asIds(p.authSessionIds);
  if (sessions) event.authSessionIds = sessions;
  const tokens = asIds(p.apiTokenIds);
  if (tokens) event.apiTokenIds = tokens;
  if (p.allForUser === true) event.allForUser = true;
  if (reason === 'policy_changed' && typeof p.orgId === 'string' && p.orgId) event.orgId = p.orgId;
  if (
    !event.authSessionIds &&
    !event.apiTokenIds &&
    !(event.allForUser && event.userId) &&
    !event.orgId
  ) {
    return null; // nothing identifiable to revoke
  }
  return event;
}

/** True when `credentials` are hit by `event`. */
export function revocationMatches(
  event: RevocationEvent,
  credentials: {
    userId: string;
    authSessionId?: string | undefined;
    apiTokenId?: string | undefined;
  },
): boolean {
  if (event.allForUser && event.userId === credentials.userId) return true;
  if (credentials.authSessionId && event.authSessionIds?.includes(credentials.authSessionId)) {
    return true;
  }
  if (credentials.apiTokenId && event.apiTokenIds?.includes(credentials.apiTokenId)) return true;
  return false;
}

/** REAUDIT-006: true when a `policy_changed` event requires re-validating this socket. */
export function policyChangeMatches(
  event: RevocationEvent,
  socket: { userId: string; orgIds: (string | undefined)[] },
): boolean {
  if (event.reason !== 'policy_changed' || !event.orgId) return false;
  if (event.userId && event.userId !== socket.userId) return false;
  return socket.orgIds.includes(event.orgId);
}

export interface RevocationBusDeps {
  redis: Redis | null;
  instanceId: string;
  logger: Logger;
  /** `SESSION_SECRET`; without it cross-instance relay is disabled (local delivery only). */
  secret?: string | undefined;
}

export class RevocationBus {
  readonly #listeners = new Set<RevocationListener>();
  readonly #key: Buffer | null;
  #sub?: Redis;
  #subscribed?: Promise<void>;

  constructor(private readonly deps: RevocationBusDeps) {
    this.#key = deps.secret ? deriveClusterKey(deps.secret) : null;
  }

  subscribe(listener: RevocationListener): () => void {
    this.#listeners.add(listener);
    if (this.deps.redis && this.#key && !this.#sub) {
      const sub = this.deps.redis.duplicate();
      sub.on('error', (err) =>
        this.deps.logger.warn({ err: { message: err.message } }, 'revocation subscriber error'),
      );
      sub.on('message', (channel: string, raw: string) => {
        if (channel !== REVOCATION_CHANNEL) return;
        const verified = verifyClusterMessage<unknown>(this.#key, raw, {
          channel: REVOCATION_CHANNEL,
          maxAgeMs: CLUSTER_MESSAGE_MAX_AGE_MS,
        });
        if (!verified) {
          this.deps.logger.warn({ channel, reason: 'bad_signature' }, 'cluster message rejected');
          return;
        }
        // Our own publishes were already delivered locally.
        if (verified.instanceId === this.deps.instanceId) return;
        const event = parseRevocationEvent(verified.payload);
        if (event) this.#notify(event);
      });
      this.#sub = sub;
      this.#subscribed = sub
        .subscribe(REVOCATION_CHANNEL)
        .then(() => undefined)
        .catch((err: unknown) => {
          this.deps.logger.warn({ err }, 'revocation subscribe failed');
        });
    }
    return () => this.#listeners.delete(listener);
  }

  /** Resolves once this bus' Redis SUBSCRIBE is live (tests). */
  async ready(): Promise<void> {
    await this.#subscribed;
  }

  async publish(event: RevocationEvent): Promise<void> {
    this.#notify(event);
    if (!this.deps.redis || !this.#key) return;
    const raw = signClusterMessage(this.#key, {
      instanceId: this.deps.instanceId,
      channel: REVOCATION_CHANNEL,
      payload: event,
    });
    await this.deps.redis
      .publish(REVOCATION_CHANNEL, raw)
      .catch((err: unknown) =>
        this.deps.logger.warn({ err, reason: event.reason }, 'revocation publish failed'),
      );
  }

  async close(): Promise<void> {
    this.#listeners.clear();
    await this.#sub?.quit().catch(() => undefined);
    this.#sub = undefined;
    this.#subscribed = undefined;
  }

  #notify(event: RevocationEvent) {
    for (const l of this.#listeners) {
      try {
        l(event);
      } catch {
        /* a broken listener must not break revocation */
      }
    }
  }
}

// ---- process-wide registry ------------------------------------------------------------------

const buses = new Set<RevocationBus>();

/** Registers a bus (the WS gateway does this); returns the unregister function. */
export function registerRevocationBus(bus: RevocationBus): () => void {
  buses.add(bus);
  return () => {
    buses.delete(bus);
  };
}

export function revocationBusCount(): number {
  return buses.size;
}

/** Publishes to every bus in this process. Never throws (revocation must not fail a request). */
export async function publishRevocation(event: RevocationEvent): Promise<void> {
  await Promise.all([...buses].map((b) => b.publish(event).catch(() => undefined)));
}

/** Cookie sessions were invalidated (logout, session delete, rotation, MFA change). */
export async function publishSessionRevoked(
  authSessionIds: string[],
  opts: { userId?: string | undefined; reason?: RevocationReason } = {},
): Promise<void> {
  const ids = authSessionIds.filter((id) => typeof id === 'string' && id.length > 0);
  if (!ids.length) return;
  await publishRevocation({
    reason: opts.reason ?? 'session_revoked',
    authSessionIds: ids,
    ...(opts.userId ? { userId: opts.userId } : {}),
  });
}

/** Personal API tokens were deleted/revoked. */
export async function publishTokenRevoked(
  apiTokenIds: string[],
  opts: { userId?: string | undefined; reason?: RevocationReason } = {},
): Promise<void> {
  const ids = apiTokenIds.filter((id) => typeof id === 'string' && id.length > 0);
  if (!ids.length) return;
  await publishRevocation({
    reason: opts.reason ?? 'token_revoked',
    apiTokenIds: ids,
    ...(opts.userId ? { userId: opts.userId } : {}),
  });
}

/** Every credential of a user (sign out everywhere, account deletion, 2FA reset). */
export async function publishUserRevoked(
  userId: string,
  reason: RevocationReason = 'logout',
): Promise<void> {
  if (!userId) return;
  await publishRevocation({ reason, userId, allForUser: true });
}

/**
 * REAUDIT-006: an org's access policy or a membership changed (call AFTER the transaction
 * committed). Every instance re-validates the org's live sockets (`userId` limits it to one
 * member). Never throws.
 */
export async function publishPolicyChanged(
  orgId: string,
  opts: { userId?: string | undefined } = {},
): Promise<void> {
  if (!orgId) return;
  await publishRevocation({
    reason: 'policy_changed',
    orgId,
    ...(opts.userId ? { userId: opts.userId } : {}),
  });
}
