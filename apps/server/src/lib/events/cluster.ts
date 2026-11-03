import { randomBytes } from 'node:crypto';
import type { ApiToken, AuthSession, User } from '@prisma/client';
import { clientMessageSchema, type ClientMessage, type ErrorCode } from '@loose/shared';
import type { AppContext } from '../../context';
import { AppError } from '../errors';
import type { Logger } from '../logger';
import type { Redis } from '../redis';
import type { Caller } from '../../services/sessionLifecycle.service';
import { deriveClusterKey, NonceCache, signClusterMessage, verifyClusterMessage } from './envelope';

const OWNER_TTL_SECONDS = 60;
const OWNER_REFRESH_MS = 20_000;
const COMMAND_TIMEOUT_MS = 5_000;

type ForwardedCaller = {
  userId: string;
  apiTokenId?: string;
  authSessionId?: string;
  ip?: string;
};

type CommandRequest = {
  id: string;
  caller: ForwardedCaller;
  message: ClientMessage;
};

type CommandReply =
  { id: string; ok: true; value?: unknown } | { id: string; ok: false; code: ErrorCode };

/** Shape check for a payload that arrived over Redis (it is MAC-verified, but still parsed). */
function parseCommandRequest(payload: unknown): CommandRequest | null {
  if (!payload || typeof payload !== 'object') return null;
  const p = payload as Record<string, unknown>;
  if (typeof p.id !== 'string' || !p.id) return null;
  const caller = p.caller as Record<string, unknown> | undefined;
  if (!caller || typeof caller.userId !== 'string' || !caller.userId) return null;
  const apiTokenId = typeof caller.apiTokenId === 'string' ? caller.apiTokenId : undefined;
  const authSessionId = typeof caller.authSessionId === 'string' ? caller.authSessionId : undefined;
  // P10-SEC-004: never infer an "internal" caller from missing credentials.
  if (!apiTokenId && !authSessionId) return null;
  const message = clientMessageSchema.safeParse(p.message);
  if (!message.success) return null;
  return {
    id: p.id,
    caller: {
      userId: caller.userId,
      ...(apiTokenId ? { apiTokenId } : {}),
      ...(authSessionId ? { authSessionId } : {}),
      ...(typeof caller.ip === 'string' ? { ip: caller.ip } : {}),
    },
    message: message.data,
  };
}

function parseCommandReply(payload: unknown): CommandReply | null {
  if (!payload || typeof payload !== 'object') return null;
  const p = payload as Record<string, unknown>;
  if (typeof p.id !== 'string' || !p.id) return null;
  if (p.ok === true) return { id: p.id, ok: true, value: p.value };
  if (p.ok === false && typeof p.code === 'string') {
    return { id: p.id, ok: false, code: p.code as ErrorCode };
  }
  return null;
}

function ownerKey(sessionId: string) {
  return `sess:${sessionId}:owner`;
}
function commandChannel(instanceId: string) {
  return `cmd:${instanceId}`;
}
function replyChannel(instanceId: string) {
  return `cmd:reply:${instanceId}`;
}

/** A renewable Redis lease saying which API instance owns a live runner. */
export class SessionOwnerLease {
  readonly #sessions = new Set<string>();
  readonly #timer?: NodeJS.Timeout;

  constructor(
    private readonly redis: Redis | null,
    private readonly instanceId: string,
    private readonly logger: Logger,
  ) {
    if (redis) {
      this.#timer = setInterval(() => void this.#refresh(), OWNER_REFRESH_MS);
      this.#timer.unref();
    }
  }

  async claim(sessionId: string): Promise<void> {
    this.#sessions.add(sessionId);
    if (!this.redis) return;
    await this.redis
      .set(ownerKey(sessionId), this.instanceId, 'EX', OWNER_TTL_SECONDS)
      .catch((err) => this.logger.warn({ err, sessionId }, 'session owner lease claim failed'));
  }

  async release(sessionId: string): Promise<void> {
    this.#sessions.delete(sessionId);
    if (!this.redis) return;
    // Do not delete a lease acquired by a replacement instance.
    const key = ownerKey(sessionId);
    await this.redis
      .eval(
        "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end return 0",
        1,
        key,
        this.instanceId,
      )
      .catch((err) => this.logger.warn({ err, sessionId }, 'session owner lease release failed'));
  }

  async owner(sessionId: string): Promise<string | null> {
    return this.redis ? this.redis.get(ownerKey(sessionId)) : null;
  }

  async #refresh(): Promise<void> {
    if (!this.redis || !this.#sessions.size) return;
    await Promise.all(
      [...this.#sessions].map(async (sessionId) => {
        const key = ownerKey(sessionId);
        await this.redis!.eval(
          "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('EXPIRE', KEYS[1], ARGV[2]) end return 0",
          1,
          key,
          this.instanceId,
          String(OWNER_TTL_SECONDS),
        ).catch((err) =>
          this.logger.warn({ err, sessionId }, 'session owner lease refresh failed'),
        );
      }),
    );
  }

  async close(): Promise<void> {
    clearInterval(this.#timer);
    await Promise.all([...this.#sessions].map((id) => this.release(id)));
  }
}

/**
 * Forwards WS controls to the process that owns the runner. The wire payload contains only
 * database ids; the owner reloads the User/API token/cookie session, re-checks that the
 * credential still exists and has not expired, and executes normal service authorization
 * again. Redis is unavailable => local/single-instance behavior.
 *
 * P10-SEC-004: every request/reply is an authenticated cluster envelope (MAC over the
 * canonical body, bound to the channel, with a freshness window and a replay-nonce cache).
 * Unsigned, forged, stale, replayed or credential-less messages are dropped.
 */
export class ClusterCommandForwarder {
  #sub?: Redis;
  #started?: Promise<void>;
  readonly #key: Buffer | null;
  readonly #nonces = new NonceCache();
  readonly #pending = new Map<
    string,
    { resolve(value: unknown): void; reject(reason: unknown): void; timer: NodeJS.Timeout }
  >();

  constructor(
    private readonly ctx: AppContext,
    private readonly execute: (caller: Caller, message: ClientMessage) => Promise<unknown>,
  ) {
    this.#key = ctx.env.SESSION_SECRET ? deriveClusterKey(ctx.env.SESSION_SECRET) : null;
  }

  async forwardIfRemote(
    caller: Caller,
    message: ClientMessage,
  ): Promise<{ forwarded: boolean; value?: unknown }> {
    if (!this.ctx.redis || !this.#key) return { forwarded: false };
    const owner = await this.ctx.redis.get(ownerKey(message.sessionId)).catch(() => null);
    if (!owner || owner === this.ctx.instanceId) return { forwarded: false };
    if (!caller.apiToken && !caller.authSession) {
      // Only credential-backed callers may be relayed (the owner re-validates them).
      throw new AppError('LSE-AUTH-001', {
        devMessage: 'A forwarded session command requires a cookie session or API token',
      });
    }
    await this.start();
    const id = randomBytes(16).toString('hex');
    const req: CommandRequest = {
      id,
      caller: {
        userId: caller.user.id,
        ...(caller.apiToken ? { apiTokenId: caller.apiToken.id } : {}),
        ...(caller.authSession ? { authSessionId: caller.authSession.id } : {}),
        ...(caller.ip ? { ip: caller.ip } : {}),
      },
      message,
    };
    const channel = commandChannel(owner);
    const raw = signClusterMessage(this.#key, {
      instanceId: this.ctx.instanceId,
      channel,
      payload: req,
    });
    const value = await new Promise<unknown>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(
          new AppError('LSE-SYS-005', { devMessage: 'Session owner did not answer command relay' }),
        );
      }, COMMAND_TIMEOUT_MS);
      timer.unref();
      this.#pending.set(id, { resolve, reject, timer });
      void this.ctx.redis!.publish(channel, raw).catch((err) => {
        clearTimeout(timer);
        this.#pending.delete(id);
        reject(
          new AppError('LSE-SYS-005', { devMessage: 'Session command relay failed', cause: err }),
        );
      });
    });
    return { forwarded: true, value };
  }

  async start(): Promise<void> {
    if (!this.ctx.redis || !this.#key) return;
    this.#started ??= (async () => {
      const sub = this.ctx.redis!.duplicate();
      sub.on('error', (err) => this.ctx.logger.warn({ err }, 'cluster command subscriber error'));
      sub.on('message', (channel: string, raw: string) => void this.#onMessage(channel, raw));
      await sub.subscribe(commandChannel(this.ctx.instanceId), replyChannel(this.ctx.instanceId));
      this.#sub = sub;
    })();
    await this.#started;
  }

  /** Verifies the envelope of a message that arrived on one of our own channels. */
  #verified(channel: string, raw: string): { payload: unknown; instanceId: string } | null {
    const verified = verifyClusterMessage<unknown>(this.#key, raw, { channel });
    if (!verified) {
      this.ctx.logger.warn({ channel, reason: 'bad_signature' }, 'cluster message rejected');
      return null;
    }
    if (!this.#nonces.accept(`${channel}:${verified.nonce}`, Date.now(), verified.ts)) {
      this.ctx.logger.warn({ channel, reason: 'replay' }, 'cluster message rejected');
      return null;
    }
    return { payload: verified.payload, instanceId: verified.instanceId };
  }

  async #onMessage(channel: string, raw: string): Promise<void> {
    if (channel === replyChannel(this.ctx.instanceId)) {
      const envelope = this.#verified(channel, raw);
      if (!envelope) return;
      const reply = parseCommandReply(envelope.payload);
      if (!reply) return;
      const pending = this.#pending.get(reply.id);
      if (!pending) return;
      clearTimeout(pending.timer);
      this.#pending.delete(reply.id);
      if (reply.ok) pending.resolve(reply.value);
      else pending.reject(new AppError(reply.code));
      return;
    }
    if (channel !== commandChannel(this.ctx.instanceId)) return;
    const envelope = this.#verified(channel, raw);
    if (!envelope) return;
    const req = parseCommandRequest(envelope.payload);
    if (!req) {
      this.ctx.logger.warn({ channel, reason: 'bad_payload' }, 'cluster message rejected');
      return;
    }
    let reply: CommandReply;
    try {
      reply = {
        id: req.id,
        ok: true,
        value: await this.execute(await this.#caller(req.caller), req.message),
      };
    } catch (err) {
      const code: ErrorCode = err instanceof AppError ? err.code : 'LSE-SYS-001';
      reply = { id: req.id, ok: false, code };
      if (!(err instanceof AppError))
        this.ctx.logger.error(
          { err, sessionId: req.message.sessionId },
          'forwarded command failed',
        );
    }
    if (!this.#key) return;
    const replyTo = replyChannel(envelope.instanceId);
    await this.ctx.redis
      ?.publish(
        replyTo,
        signClusterMessage(this.#key, {
          instanceId: this.ctx.instanceId,
          channel: replyTo,
          payload: reply,
        }),
      )
      .catch((err) =>
        this.ctx.logger.warn({ err, commandId: req.id }, 'cluster command reply failed'),
      );
  }

  async #caller(input: ForwardedCaller): Promise<Caller> {
    const [user, apiToken, authSession] = await Promise.all([
      this.ctx.prisma.user.findUnique({ where: { id: input.userId } }),
      input.apiTokenId
        ? this.ctx.prisma.apiToken.findFirst({
            where: { id: input.apiTokenId, userId: input.userId },
          })
        : null,
      input.authSessionId
        ? this.ctx.prisma.authSession.findFirst({
            where: { id: input.authSessionId, userId: input.userId },
          })
        : null,
    ]);
    const now = Date.now();
    const tokenValid = !input.apiTokenId
      ? true
      : !!apiToken && (!apiToken.expiresAt || apiToken.expiresAt.getTime() > now);
    const sessionValid = !input.authSessionId
      ? true
      : !!authSession && authSession.expiresAt.getTime() > now;
    // P10-SEC-003: a revoked or expired credential must not keep working through the relay.
    if (!user || !tokenValid || !sessionValid) throw new AppError('LSE-AUTH-001');
    return {
      user: user as User,
      ...(apiToken ? { apiToken: apiToken as ApiToken } : {}),
      ...(authSession ? { authSession: authSession as AuthSession } : {}),
      ...(input.ip ? { ip: input.ip } : {}),
    };
  }

  async close(): Promise<void> {
    for (const [id, pending] of this.#pending) {
      clearTimeout(pending.timer);
      pending.reject(new AppError('LSE-SYS-005', { devMessage: 'Session command relay closed' }));
      this.#pending.delete(id);
    }
    await this.#sub?.quit().catch(() => undefined);
  }
}
