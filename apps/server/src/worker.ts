/**
 * Background worker entry (production): runs BullMQ workers for template builds,
 * session provisioning and the repeatable maintenance jobs. The API process
 * (src/index.ts) only enqueues when JOBS_INLINE=false.
 *
 *   node --env-file-if-exists=.env dist/worker.js
 */
import { buildContext } from './app';
import { EnvError, loadEnv } from './config/env';
import { createLogger } from './lib/logger';
import { createPrisma } from './lib/prisma';
import { createRedis } from './lib/redis';
import { startMetricsServer } from './services/observability/register';
import { MAINTENANCE_SCHEDULES } from './services/sessionJobs.service';

async function main(): Promise<void> {
  let env;
  try {
    env = loadEnv();
  } catch (err) {
    console.error(err instanceof EnvError ? err.message : err);
    process.exit(1);
  }
  const logger = createLogger({ level: env.LOG_LEVEL });
  const prisma = createPrisma(env.DATABASE_URL);
  const redis = createRedis(env.REDIS_URL, logger);
  // Runners are owned by the API process (it serves the session WebSockets).
  const ctx = buildContext({ env, prisma, logger, redis, agentHooks: false });
  if (ctx.jobs.inline) {
    logger.warn('JOBS_INLINE=true: the worker runs jobs in-process only (development)');
  }
  await ctx.jobs.start(MAINTENANCE_SCHEDULES);
  // Phase 10 (W3): queue depth etc. on the internal metrics listener (METRICS_PORT).
  const metricsServer = await startMetricsServer(ctx);
  logger.info({ sandbox: ctx.sandboxKind }, 'loose.ai worker started');

  let stopping = false;
  const shutdown = async (reason: string, code: number) => {
    if (stopping) return;
    stopping = true;
    logger.info({ reason }, 'worker shutting down');
    const force = setTimeout(() => process.exit(code || 1), 30_000);
    force.unref();
    await Promise.allSettled([ctx.jobs.close(), metricsServer?.close() ?? Promise.resolve()]);
    await Promise.allSettled([prisma.$disconnect(), redis.quit()]);
    process.exit(code);
  };
  process.on('SIGTERM', () => void shutdown('SIGTERM', 0));
  process.on('SIGINT', () => void shutdown('SIGINT', 0));
  process.on('unhandledRejection', (reason) => {
    logger.error({ err: reason }, 'unhandled promise rejection');
    void shutdown('unhandledRejection', 1);
  });
}

void main();
