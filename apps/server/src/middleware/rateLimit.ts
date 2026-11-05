/**
 * Rate limits (spec §15): Redis-backed in production, in-memory when Redis is
 * not wired (tests). Limits come from env (defaults = shared RATE_LIMITS).
 */
import type { Request, RequestHandler } from 'express';
import { ipKeyGenerator, rateLimit, type Store } from 'express-rate-limit';
import { RedisStore, type RedisReply } from 'rate-limit-redis';
import { RATE_LIMITS, type ErrorCode } from '@loose/shared';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';

/**
 * RedisStore loads its Lua scripts in the constructor; if Redis is down at boot
 * those promises reject unhandled (which would trip our crash handler). Mark
 * them handled — the store reloads scripts on the next increment anyway.
 */
class ResilientRedisStore extends RedisStore {
  constructor(options: ConstructorParameters<typeof RedisStore>[0]) {
    super(options);
    this.incrementScriptSha.catch(() => undefined);
    this.getScriptSha.catch(() => undefined);
  }
}

function makeStore(ctx: AppContext, prefix: string): Store | undefined {
  const redis = ctx.redis;
  if (!redis) return undefined; // express-rate-limit MemoryStore
  return new ResilientRedisStore({
    prefix: `rl:${prefix}:`,
    sendCommand: (command: string, ...args: string[]) =>
      redis.call(command, ...args) as Promise<RedisReply>,
  });
}

const ipKey = (req: Request) => `ip:${ipKeyGenerator(req.ip ?? '0.0.0.0')}`;

/**
 * Per caller: the authenticated user id when auth has already run, else IP.
 * Never key on unverified client-supplied cookies/tokens — rotating a random
 * value per request would otherwise yield a fresh bucket each time (bypass).
 */
function callerKey(req: Request): string {
  if (req.auth) return `user:${req.auth.user.id}`;
  return ipKey(req);
}

function limiter(
  ctx: AppContext,
  name: string,
  max: number,
  windowMs: number,
  code: ErrorCode,
  keyGenerator: (req: Request) => string,
): RequestHandler {
  return rateLimit({
    windowMs,
    limit: max,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    keyGenerator,
    store: makeStore(ctx, name),
    passOnStoreError: true, // fail open if Redis is down (logged by the redis client)
    handler: (req, _res, next) => {
      const reset = (req as Request & { rateLimit?: { resetTime?: Date } }).rateLimit?.resetTime;
      const retryAfter = Math.max(
        1,
        Math.ceil(((reset?.getTime() ?? Date.now() + windowMs) - Date.now()) / 1000),
      );
      next(
        new AppError(code, {
          devMessage: `Rate limit "${name}" exceeded (${max}/${windowMs / 1000}s)`,
          headers: { 'Retry-After': String(retryAfter) },
        }),
      );
    },
  });
}

export interface RateLimiters {
  auth: RequestHandler;
  keyValidation: RequestHandler;
  general: RequestHandler;
  sessionCreate: RequestHandler;
}

export function createRateLimiters(ctx: AppContext): RateLimiters {
  return {
    /** 20/min per IP on sign-in routes → LSE-AUTH-008. */
    auth: limiter(
      ctx,
      'auth',
      ctx.env.RATE_LIMIT_AUTH_MAX,
      RATE_LIMITS.auth.windowMs,
      'LSE-AUTH-008',
      ipKey,
    ),
    /** 10/min per user on live key validation → LSE-RATE-001. */
    keyValidation: limiter(
      ctx,
      'keyval',
      ctx.env.RATE_LIMIT_KEY_VALIDATION_MAX,
      RATE_LIMITS.keyValidation.windowMs,
      'LSE-RATE-001',
      callerKey,
    ),
    /** 300/min per caller across the API → LSE-RATE-001. */
    general: limiter(
      ctx,
      'general',
      ctx.env.RATE_LIMIT_GENERAL_MAX,
      RATE_LIMITS.general.windowMs,
      'LSE-RATE-001',
      callerKey,
    ),
    /** 10/min per user on `POST /sessions` → LSE-RATE-001. */
    sessionCreate: limiter(
      ctx,
      'session-create',
      ctx.env.RATE_LIMIT_SESSION_CREATE_MAX,
      RATE_LIMITS.sessionCreate.windowMs,
      'LSE-RATE-001',
      callerKey,
    ),
  };
}
