import { Router } from 'express';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';
const CHECK_TIMEOUT_MS = 2_000;
const cache = new WeakMap<AppContext, { until: number; ok: boolean }>();
function withTimeout<T>(p: Promise<T>, what: string): Promise<T> {
  return Promise.race([
    p,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error(`${what} check timed out`)), CHECK_TIMEOUT_MS).unref(),
    ),
  ]);
}
async function e2bReady(ctx: AppContext) {
  if (!ctx.env.READYZ_CHECK_E2B) return 'skipped' as const;
  const previous = cache.get(ctx);
  if (previous && previous.until > Date.now()) {
    if (!previous.ok)
      throw new AppError('LSE-SYS-005', { devMessage: 'Sandbox provider readiness check failed' });
    return 'ok' as const;
  }
  try {
    await withTimeout(
      ctx.sandbox.ping ? ctx.sandbox.ping() : ctx.sandbox.list().then(() => undefined),
      'sandbox provider',
    );
    cache.set(ctx, { until: Date.now() + 30_000, ok: true });
    return 'ok' as const;
  } catch (cause) {
    cache.set(ctx, { until: Date.now() + 30_000, ok: false });
    throw new AppError('LSE-SYS-005', {
      devMessage: 'Sandbox provider readiness check failed',
      cause,
    });
  }
}
export function healthRouter(ctx: AppContext): Router {
  const r = Router();
  r.get('/healthz', (_req, res) => res.json({ data: { status: 'ok' } }));
  r.get('/readyz', async (_req, res) => {
    try {
      await withTimeout(ctx.prisma.$queryRaw`SELECT 1`, 'database');
    } catch (cause) {
      throw new AppError('LSE-SYS-002', { devMessage: 'Database readiness check failed', cause });
    }
    try {
      if (!ctx.redis) throw new Error('Redis client not configured');
      if ((await withTimeout(ctx.redis.ping(), 'redis')) !== 'PONG')
        throw new Error('unexpected PING reply');
    } catch (cause) {
      throw new AppError('LSE-SYS-003', { devMessage: 'Redis readiness check failed', cause });
    }
    const e2b = await e2bReady(ctx);
    res.json({ data: { status: 'ok', checks: { db: 'ok', redis: 'ok', e2b } } });
  });
  return r;
}
