/**
 * Authenticated cluster messages (P10-SEC-004).
 *
 * Redis pub/sub carries control-plane traffic between API instances (forwarded WS commands
 * and their replies, session events, presence). Redis itself is a shared dependency: anything
 * that can write to it could otherwise publish a forged command naming an arbitrary user, or
 * inject chat / `preview_updated` events into a browser. Every cluster message is therefore
 * wrapped in a MAC-ed envelope:
 *
 *   wire   = `v1.<base64url(body)>.<base64url(HMAC-SHA256(key, "v1." + base64url(body)))>`
 *   body   = {"v":1,"iid":<source instance>,"ts":<epoch ms>,"n":<nonce>,"ch":<channel>,"p":<payload>}
 *   key    = HKDF-SHA256(SESSION_SECRET, salt 'loose-cluster-bus', info 'v1', 32)
 *
 * `ch` binds a message to the channel it was published on (a session event cannot be replayed
 * on another session's channel), `ts` bounds replay to `CLUSTER_MESSAGE_MAX_AGE_MS`, and `n`
 * lets consumers of side-effecting messages reject exact replays (`NonceCache`).
 *
 * Verification never throws: a malformed/unsigned/stale/forged message returns null and is
 * dropped by the caller (fail closed).
 */
import { createHmac, hkdfSync, randomBytes, timingSafeEqual } from 'node:crypto';

export const CLUSTER_ENVELOPE_VERSION = 'v1';
/** Messages older (or more than this far in the future) than this are rejected. */
export const CLUSTER_MESSAGE_MAX_AGE_MS = 60_000;

const KEY_SALT = 'loose-cluster-bus';
const KEY_INFO = 'v1';
const KEY_BYTES = 32;

export interface ClusterEnvelopeBody<T> {
  v: 1;
  /** `ctx.instanceId` of the publisher. */
  iid: string;
  ts: number;
  n: string;
  ch: string;
  p: T;
}

export interface VerifiedClusterMessage<T> {
  instanceId: string;
  ts: number;
  nonce: string;
  payload: T;
}

/** HKDF-SHA256(SESSION_SECRET, 'loose-cluster-bus', 'v1'). */
export function deriveClusterKey(secret: string): Buffer {
  return Buffer.from(hkdfSync('sha256', secret, KEY_SALT, KEY_INFO, KEY_BYTES) as ArrayBuffer);
}

const b64url = (b: Buffer) => b.toString('base64url');

function mac(key: Buffer, signed: string): Buffer {
  return createHmac('sha256', key).update(signed).digest();
}

export function signClusterMessage<T>(
  key: Buffer,
  input: { instanceId: string; channel: string; payload: T; now?: number },
): string {
  const body: ClusterEnvelopeBody<T> = {
    v: 1,
    iid: input.instanceId,
    ts: input.now ?? Date.now(),
    n: randomBytes(12).toString('base64url'),
    ch: input.channel,
    p: input.payload,
  };
  const signed = `${CLUSTER_ENVELOPE_VERSION}.${b64url(Buffer.from(JSON.stringify(body), 'utf8'))}`;
  return `${signed}.${b64url(mac(key, signed))}`;
}

/**
 * Returns the payload of a well-formed, correctly signed, in-window message published on
 * `channel`, or null. `null` keys (Redis-less single process) accept nothing: callers that
 * work without Redis never go through the wire.
 */
export function verifyClusterMessage<T>(
  key: Buffer | null,
  raw: string,
  opts: { channel: string; maxAgeMs?: number; now?: number },
): VerifiedClusterMessage<T> | null {
  if (!key || typeof raw !== 'string') return null;
  const parts = raw.split('.');
  if (parts.length !== 3 || parts[0] !== CLUSTER_ENVELOPE_VERSION) return null;
  const signed = `${parts[0]}.${parts[1]}`;
  let provided: Buffer;
  try {
    provided = Buffer.from(parts[2]!, 'base64url');
  } catch {
    return null;
  }
  const expected = mac(key, signed);
  if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) return null;
  let body: ClusterEnvelopeBody<T>;
  try {
    body = JSON.parse(
      Buffer.from(parts[1]!, 'base64url').toString('utf8'),
    ) as ClusterEnvelopeBody<T>;
  } catch {
    return null;
  }
  if (!body || body.v !== 1 || typeof body.iid !== 'string' || !body.iid) return null;
  if (typeof body.n !== 'string' || !body.n) return null;
  if (typeof body.ts !== 'number' || !Number.isFinite(body.ts)) return null;
  if (body.ch !== opts.channel) return null;
  const now = opts.now ?? Date.now();
  const maxAge = opts.maxAgeMs ?? CLUSTER_MESSAGE_MAX_AGE_MS;
  if (Math.abs(now - body.ts) > maxAge) return null;
  return { instanceId: body.iid, ts: body.ts, nonce: body.n, payload: body.p };
}

/**
 * Bounded nonce cache: exact replays of a side-effecting message (a forwarded command) are
 * rejected for as long as the message itself would pass `verifyClusterMessage` (its signed `ts`
 * within `windowMs` of now, in either direction).
 *
 * Memory is bounded without ever forgetting a live nonce silently (P10-SEC-004-R): when the cache
 * is full of in-window entries, the oldest-inserted entry is evicted and its message `ts` raises a
 * `floor`. Every message with `ts <= floor` is then refused, so an evicted nonce can never be
 * accepted again; under saturation some fresh-but-older messages are dropped instead (fail closed).
 * Entries whose message is outside the window are dropped first, since such a message is refused
 * by verification anyway.
 */
export class NonceCache {
  /** nonce → signed message ts, in insertion order. */
  readonly #seen = new Map<string, number>();
  #floor = Number.NEGATIVE_INFINITY;

  constructor(
    private readonly windowMs = CLUSTER_MESSAGE_MAX_AGE_MS,
    private readonly maxEntries = 10_000,
  ) {}

  /**
   * True when the nonce is new (and now remembered); false for a replay, or for a message at or
   * below the eviction floor. `ts` is the message's signed timestamp (defaults to `now`).
   */
  accept(nonce: string, now = Date.now(), ts = now): boolean {
    this.#prune(now);
    if (ts <= this.#floor || this.#seen.has(nonce)) return false;
    while (this.#seen.size >= this.maxEntries) {
      const [oldest, oldestTs] = this.#seen.entries().next().value as [string, number];
      this.#seen.delete(oldest);
      if (oldestTs > this.#floor) this.#floor = oldestTs;
      if (ts <= this.#floor) return false;
    }
    this.#seen.set(nonce, ts);
    return true;
  }

  /** Number of remembered nonces (tests/metrics). */
  get size(): number {
    return this.#seen.size;
  }

  #prune(now: number) {
    for (const [n, ts] of this.#seen) {
      // Insertion order roughly follows ts; stop at the first live entry (bounded work per call).
      if (now - ts <= this.windowMs) break;
      this.#seen.delete(n);
    }
  }
}
