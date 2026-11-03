/**
 * Session event bus (spec §11): per-session ordered event log + fan-out.
 *
 * Every user-visible session event (`session_status`, `chat_message`, …) goes through
 * `publish()`, which assigns a per-session monotonically increasing `seq`, validates the
 * payload against the shared WS schema, keeps it in a bounded replay log (24 h) and fans
 * it out to subscribers (the WS gateway).
 *
 * Audiences: the Output Translation Layer produces mode-specific variants of some events
 * (Simple-mode text vs Pro verbatim). Each stored entry carries an `audience`:
 *  - `all`    → delivered to everyone (Simple viewers get `toSimpleModeMessage(msg)`),
 *  - `pro`    → Pro viewers only,
 *  - `simple` → Simple viewers only.
 * Both variants share one seq space, so a viewer may observe seq gaps (by design).
 * `deliverableFor()` implements the per-recipient filter.
 *
 * Implementations: `InMemorySessionEventBus` (single process; tests/dev without Redis) and
 * `RedisSessionEventBus` (INCR `sess:<id>:seq`, capped list `sess:<id>:events` with 24 h
 * TTL, pub/sub channel `sess:<id>` for multi-instance fan-out).
 */
import {
  buildServerMessage,
  serverMessageSchema,
  toSimpleModeMessage,
  WS_EVENT_LOG_MAX_EVENTS,
  WS_EVENT_LOG_TTL_SEC,
  type Mode,
  type ServerMessage,
  type ServerMessageType,
  type ServerPayloadInput,
  type ServerWsMessageOf,
} from '@loose/shared';
import type { Logger } from '../logger';
import type { Redis } from '../redis';
import { deriveClusterKey, signClusterMessage, verifyClusterMessage } from './envelope';

export interface RedisSessionEventBusOptions {
  maxEvents?: number;
  ttlSec?: number;
  /** `SESSION_SECRET`: enables authenticated cluster envelopes (P10-SEC-004). */
  secret?: string | undefined;
  /** Publisher id recorded in the envelope (`ctx.instanceId`). */
  instanceId?: string | undefined;
}

export type EventAudience = 'all' | 'pro' | 'simple';

export interface BusEntry {
  message: ServerMessage;
  audience: EventAudience;
}

export type SessionEventListener = (message: ServerMessage, audience: EventAudience) => void;

export interface ReplayResult {
  /** All retained messages after `afterSeq` (every audience), oldest first. */
  events: ServerMessage[];
  /** Same as `events`, with the audience of each entry. */
  entries: BusEntry[];
  /** false when events after `afterSeq` were already evicted (client must reload via REST). */
  complete: boolean;
  lastSeq: number;
}

export interface PublishOptions {
  audience?: EventAudience;
}

export interface SessionEventBus {
  publish<T extends ServerMessageType>(
    sessionId: string,
    type: T,
    payload: ServerPayloadInput<T>,
    opts?: PublishOptions,
  ): Promise<ServerWsMessageOf<T>>;
  /** Events with seq > afterSeq, oldest first. */
  replay(sessionId: string, afterSeq: number): Promise<ReplayResult>;
  subscribe(sessionId: string, listener: SessionEventListener): () => void;
  lastSeq(sessionId: string): Promise<number>;
  /** Drop the replay log of a finished session (optional housekeeping). */
  clear(sessionId: string): Promise<void>;
  /** Resolves once a `subscribe()` for this session is live (Redis SUBSCRIBE acked). */
  ready?(sessionId: string): Promise<void>;
  close?(): Promise<void>;
}

/** The message a viewer in `mode` should receive for an entry, or null (filtered out). */
export function deliverableFor(entry: BusEntry, mode: Mode): ServerMessage | null {
  if (mode === 'PRO') return entry.audience === 'simple' ? null : entry.message;
  if (entry.audience === 'pro') return null;
  return toSimpleModeMessage(entry.message);
}

interface Log {
  seq: number;
  entries: BusEntry[];
}

function notify(
  listeners: Set<SessionEventListener> | undefined,
  msg: ServerMessage,
  aud: EventAudience,
) {
  for (const l of listeners ?? []) {
    try {
      l(msg, aud);
    } catch {
      /* a broken listener must not break publishing */
    }
  }
}

export class InMemorySessionEventBus implements SessionEventBus {
  readonly #logs = new Map<string, Log>();
  readonly #listeners = new Map<string, Set<SessionEventListener>>();

  constructor(private readonly maxEvents = WS_EVENT_LOG_MAX_EVENTS) {}

  #log(sessionId: string): Log {
    let log = this.#logs.get(sessionId);
    if (!log) {
      log = { seq: 0, entries: [] };
      this.#logs.set(sessionId, log);
    }
    return log;
  }

  async publish<T extends ServerMessageType>(
    sessionId: string,
    type: T,
    payload: ServerPayloadInput<T>,
    opts: PublishOptions = {},
  ): Promise<ServerWsMessageOf<T>> {
    const log = this.#log(sessionId);
    const msg = buildServerMessage(type, sessionId, log.seq + 1, payload);
    const audience = opts.audience ?? 'all';
    log.seq += 1;
    log.entries.push({ message: msg, audience });
    if (log.entries.length > this.maxEvents)
      log.entries.splice(0, log.entries.length - this.maxEvents);
    notify(this.#listeners.get(sessionId), msg, audience);
    return msg;
  }

  async replay(sessionId: string, afterSeq: number): Promise<ReplayResult> {
    const log = this.#logs.get(sessionId);
    if (!log) return { events: [], entries: [], complete: afterSeq <= 0, lastSeq: 0 };
    const entries = log.entries.filter((e) => e.message.seq > afterSeq);
    const oldest = log.entries[0]?.message.seq ?? log.seq + 1;
    return {
      events: entries.map((e) => e.message),
      entries,
      complete: afterSeq >= oldest - 1,
      lastSeq: log.seq,
    };
  }

  subscribe(sessionId: string, listener: SessionEventListener) {
    let set = this.#listeners.get(sessionId);
    if (!set) {
      set = new Set();
      this.#listeners.set(sessionId, set);
    }
    set.add(listener);
    return () => {
      set.delete(listener);
      if (set.size === 0) this.#listeners.delete(sessionId);
    };
  }

  async lastSeq(sessionId: string) {
    return this.#logs.get(sessionId)?.seq ?? 0;
  }

  async clear(sessionId: string) {
    this.#logs.delete(sessionId);
  }
}

/**
 * Redis-backed bus. The list holds authenticated cluster envelopes whose payload is
 * `{a: audience, m: message}`; the channel carries the same envelope so every API instance
 * can deliver to its own WS connections.
 *
 * P10-SEC-004: entries are MAC-ed (HKDF from `SESSION_SECRET`) and bound to the session's
 * channel, and `message.sessionId` must match that channel. Unsigned, forged, stale or
 * cross-session entries are dropped instead of being delivered to a browser (a forged
 * `preview_updated` would otherwise reach the preview iframe).
 */
export class RedisSessionEventBus implements SessionEventBus {
  #sub: Redis | null = null;
  readonly #listeners = new Map<string, Set<SessionEventListener>>();
  readonly #subscribed = new Map<string, Promise<void>>();
  readonly #mac: Buffer | null;
  readonly #maxEvents: number;
  readonly #ttlSec: number;
  readonly #instanceId: string;

  constructor(
    private readonly redis: Redis,
    private readonly logger: Logger,
    opts: RedisSessionEventBusOptions = {},
  ) {
    this.#maxEvents = opts.maxEvents ?? WS_EVENT_LOG_MAX_EVENTS;
    this.#ttlSec = opts.ttlSec ?? WS_EVENT_LOG_TTL_SEC;
    this.#mac = opts.secret ? deriveClusterKey(opts.secret) : null;
    this.#instanceId = opts.instanceId ?? 'session-events';
  }

  #key = (id: string, k: 'seq' | 'events') => `sess:${id}:${k}`;
  #channel = (id: string) => `sess:${id}`;

  async publish<T extends ServerMessageType>(
    sessionId: string,
    type: T,
    payload: ServerPayloadInput<T>,
    opts: PublishOptions = {},
  ): Promise<ServerWsMessageOf<T>> {
    // Validate before consuming a seq so a bad payload never leaves a hole.
    buildServerMessage(type, sessionId, 0, payload);
    const seq = await this.redis.incr(this.#key(sessionId, 'seq'));
    const msg = buildServerMessage(type, sessionId, seq, payload);
    const body = { a: opts.audience ?? 'all', m: msg };
    const json = this.#mac
      ? signClusterMessage(this.#mac, {
          instanceId: this.#instanceId,
          channel: this.#channel(sessionId),
          payload: body,
        })
      : JSON.stringify(body);
    await this.redis
      .multi()
      .rpush(this.#key(sessionId, 'events'), json)
      .ltrim(this.#key(sessionId, 'events'), -this.#maxEvents, -1)
      .expire(this.#key(sessionId, 'events'), this.#ttlSec)
      .expire(this.#key(sessionId, 'seq'), this.#ttlSec)
      .publish(this.#channel(sessionId), json)
      .exec();
    return msg;
  }

  /**
   * Parses one wire/stored entry for `sessionId`. With a signing key configured, only
   * correctly signed entries bound to this session's channel are accepted; the message's own
   * `sessionId` must match too (no cross-session injection).
   */
  #parse(sessionId: string, raw: string): BusEntry | null {
    let value: unknown;
    if (this.#mac) {
      const verified = verifyClusterMessage<unknown>(this.#mac, raw, {
        channel: this.#channel(sessionId),
        // Replay log entries are read long after they were written.
        maxAgeMs: this.#ttlSec * 1000,
      });
      if (!verified) {
        this.logger.warn(
          { channel: this.#channel(sessionId), reason: 'bad_signature' },
          'cluster message rejected',
        );
        return null;
      }
      value = verified.payload;
    } else {
      try {
        value = JSON.parse(raw);
      } catch {
        return null;
      }
    }
    if (!value || typeof value !== 'object') return null;
    const j = value as { a?: EventAudience; m?: unknown };
    const m = serverMessageSchema.safeParse(j.m);
    if (!m.success) return null;
    if (m.data.sessionId !== sessionId) return null;
    const a = j.a === 'pro' || j.a === 'simple' ? j.a : 'all';
    return { message: m.data, audience: a };
  }

  async replay(sessionId: string, afterSeq: number): Promise<ReplayResult> {
    const [rows, seqRaw] = await Promise.all([
      this.redis.lrange(this.#key(sessionId, 'events'), 0, -1),
      this.redis.get(this.#key(sessionId, 'seq')),
    ]);
    const lastSeq = Number(seqRaw ?? 0) || 0;
    const all = rows.map((r) => this.#parse(sessionId, r)).filter((e): e is BusEntry => !!e);
    const oldest = all[0]?.message.seq ?? lastSeq + 1;
    const entries = all.filter((e) => e.message.seq > afterSeq);
    return {
      events: entries.map((e) => e.message),
      entries,
      complete: lastSeq === 0 ? afterSeq <= 0 : afterSeq >= oldest - 1,
      lastSeq,
    };
  }

  #subscriber(): Redis {
    if (this.#sub) return this.#sub;
    const sub = this.redis.duplicate();
    sub.on('error', (err) =>
      this.logger.warn({ err: { message: err.message } }, 'session event subscriber error'),
    );
    sub.on('message', (channel: string, raw: string) => {
      const sessionId = channel.slice('sess:'.length);
      const entry = this.#parse(sessionId, raw);
      if (entry) notify(this.#listeners.get(sessionId), entry.message, entry.audience);
    });
    this.#sub = sub;
    return sub;
  }

  subscribe(sessionId: string, listener: SessionEventListener) {
    let set = this.#listeners.get(sessionId);
    if (!set) {
      set = new Set();
      this.#listeners.set(sessionId, set);
      this.#subscribed.set(
        sessionId,
        this.#subscriber()
          .subscribe(this.#channel(sessionId))
          .then(() => undefined)
          .catch((err: unknown) =>
            this.logger.warn({ err, sessionId }, 'session event subscribe failed'),
          ),
      );
    }
    set.add(listener);
    return () => {
      set.delete(listener);
      if (set.size === 0 && this.#listeners.get(sessionId) === set) {
        this.#listeners.delete(sessionId);
        this.#subscribed.delete(sessionId);
        void this.#sub?.unsubscribe(this.#channel(sessionId)).catch(() => undefined);
      }
    };
  }

  async ready(sessionId: string) {
    await this.#subscribed.get(sessionId);
  }

  async lastSeq(sessionId: string) {
    return Number((await this.redis.get(this.#key(sessionId, 'seq'))) ?? 0) || 0;
  }

  async clear(sessionId: string) {
    await this.redis.del(this.#key(sessionId, 'events'));
  }

  async close() {
    await this.#sub?.quit().catch(() => undefined);
  }
}
