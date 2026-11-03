import type { Redis } from '../redis';
import type { Logger } from '../logger';
import { deriveClusterKey, signClusterMessage, verifyClusterMessage } from './envelope';

export interface PresenceEntry {
  id: string;
  name: string | null;
  avatarUrl: string | null;
  role?: 'owner' | 'admin' | 'co_editor' | 'viewer';
  mode: 'SIMPLE' | 'PRO';
  controller: boolean;
}

function parseEntry(payload: unknown): PresenceEntry | null {
  if (!payload || typeof payload !== 'object') return null;
  const p = payload as Record<string, unknown>;
  if (typeof p.id !== 'string' || !p.id) return null;
  if (p.mode !== 'SIMPLE' && p.mode !== 'PRO') return null;
  const role = p.role;
  return {
    id: p.id,
    name: typeof p.name === 'string' ? p.name : null,
    avatarUrl: typeof p.avatarUrl === 'string' ? p.avatarUrl : null,
    ...(role === 'owner' || role === 'admin' || role === 'co_editor' || role === 'viewer'
      ? { role }
      : {}),
    mode: p.mode,
    controller: p.controller === true,
  };
}

/**
 * Redis-backed presence lease. Redis is optional, so local/test behavior remains deterministic.
 *
 * P10-SEC-004: both the stored hash entries and the "changed" notifications are authenticated
 * cluster envelopes (HMAC over the body, bound to the presence channel); entries that are not
 * signed with the deployment's key are ignored, so Redis write access cannot inject fake
 * participants or names into another tenant's session.
 */
export class ClusterPresence {
  readonly #local = new Map<string, Map<string, PresenceEntry>>();
  readonly #listeners = new Map<string, Set<() => void>>();
  readonly #mac: Buffer | null;
  #sub?: Redis;
  #subscribed?: Promise<void>;
  constructor(
    private readonly redis: Redis | null,
    private readonly instanceId: string,
    private readonly logger: Logger,
    secret?: string | undefined,
  ) {
    this.#mac = secret ? deriveClusterKey(secret) : null;
  }
  #field(connId: string) {
    return `${this.instanceId}:${connId}`;
  }
  #key(sessionId: string) {
    return `presence:${sessionId}`;
  }
  #sign(sessionId: string, payload: unknown): string {
    return signClusterMessage(this.#mac!, {
      instanceId: this.instanceId,
      channel: this.#key(sessionId),
      payload,
    });
  }
  /** Presence needs Redis AND a signing key; without a key this instance stays local. */
  get #clustered(): boolean {
    return !!this.redis && !!this.#mac;
  }
  async join(sessionId: string, connId: string, entry: PresenceEntry) {
    const local = this.#local.get(sessionId) ?? new Map();
    local.set(connId, entry);
    this.#local.set(sessionId, local);
    if (this.#clustered) {
      await this.redis!.hset(
        this.#key(sessionId),
        this.#field(connId),
        this.#sign(sessionId, entry),
      );
      await this.redis!.expire(this.#key(sessionId), 60);
      await this.redis!.publish(this.#key(sessionId), this.#sign(sessionId, 'changed'));
    }
    this.#notify(sessionId);
  }
  async leave(sessionId: string, connId: string) {
    this.#local.get(sessionId)?.delete(connId);
    if (this.#clustered) {
      await this.redis!.hdel(this.#key(sessionId), this.#field(connId));
      await this.redis!.publish(this.#key(sessionId), this.#sign(sessionId, 'changed'));
    }
    this.#notify(sessionId);
  }
  async list(sessionId: string): Promise<PresenceEntry[]> {
    if (!this.#clustered) return [...(this.#local.get(sessionId)?.values() ?? [])];
    const rows = await this.redis!.hvals(this.#key(sessionId));
    const byUser = new Map<string, PresenceEntry>();
    for (const row of rows) {
      // Stale, malformed or unsigned presence is ignored.
      const verified = verifyClusterMessage<unknown>(this.#mac, row, {
        channel: this.#key(sessionId),
        maxAgeMs: 120_000,
      });
      const entry = verified ? parseEntry(verified.payload) : null;
      if (entry) byUser.set(entry.id, entry);
    }
    return [...byUser.values()];
  }
  subscribe(sessionId: string, listener: () => void) {
    const set = this.#listeners.get(sessionId) ?? new Set();
    set.add(listener);
    this.#listeners.set(sessionId, set);
    if (this.#clustered && !this.#sub) {
      this.#sub = this.redis!.duplicate();
      this.#sub.on('error', (err) =>
        this.logger.warn({ err: { message: err.message } }, 'presence subscriber error'),
      );
      this.#sub.on('pmessage', (_pattern, channel: string, raw: string) => {
        const verified = verifyClusterMessage<unknown>(this.#mac, raw, { channel });
        if (!verified || verified.payload !== 'changed') {
          this.logger.warn({ channel, reason: 'bad_signature' }, 'cluster message rejected');
          return;
        }
        this.#notify(channel.slice('presence:'.length));
      });
      this.#subscribed = this.#sub.psubscribe('presence:*').then(() => undefined);
    }
    return () => {
      set.delete(listener);
      if (!set.size) this.#listeners.delete(sessionId);
    };
  }
  async ready(): Promise<void> {
    await this.#subscribed;
  }
  #notify(sessionId: string) {
    for (const f of this.#listeners.get(sessionId) ?? []) f();
  }
  async close() {
    await this.#sub?.quit().catch(() => undefined);
  }
}
