/**
 * Server entry point: validate env (fail fast), connect dependencies, listen,
 * and shut down gracefully on SIGTERM/SIGINT or fatal process errors.
 */
import type { Server } from 'node:http';
import { buildContext, createApp } from './app';
import { EnvError, loadEnv } from './config/env';
import { createLogger, type Logger } from './lib/logger';
import { createPrisma } from './lib/prisma';
import { createRedis } from './lib/redis';
import { startMetricsServer } from './services/observability/register';
import { MAINTENANCE_SCHEDULES } from './services/sessionJobs.service';
import { attachWsGateway } from './ws/gateway';

const SHUTDOWN_TIMEOUT_MS = 10_000;

async function main(): Promise<void> {
  let env;
  try {
    env = loadEnv();
  } catch (err) {
    // Names of bad variables only — values are never printed.
    console.error(err instanceof EnvError ? err.message : err);
    process.exit(1);
  }

  const logger = createLogger({
    level: env.LOG_LEVEL,
    pretty: env.NODE_ENV === 'development' && process.stdout.isTTY,
  });
  const prisma = createPrisma(env.DATABASE_URL);
  const redis = createRedis(env.REDIS_URL, logger);
  const ctx = buildContext({ env, prisma, logger, redis });
  const app = createApp(ctx);
  // JOBS_INLINE (dev): run maintenance jobs in-process. Production runs src/worker.ts.
  if (ctx.jobs.inline) await ctx.jobs.start(MAINTENANCE_SCHEDULES);

  // Express 5 passes listen errors (e.g. EADDRINUSE) to this callback.
  const server: Server = app.listen(env.PORT, (err?: Error) => {
    if (err) {
      logger.fatal({ err, port: env.PORT }, 'failed to listen');
      void shutdown('listen-failed', 1);
      return;
    }
    logger.info({ port: env.PORT, env: env.NODE_ENV }, 'loose.ai server listening');
  });
  server.keepAliveTimeout = 65_000;
  const gateway = attachWsGateway(server, ctx);
  // Phase 10 (W3): internal Prometheus listener when METRICS_PORT is set.
  const metricsServer = await startMetricsServer(ctx);

  let shuttingDown = false;
  const shutdown = async (reason: string, exitCode: number) => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info({ reason }, 'shutting down');
    const force = setTimeout(() => {
      logger.error('forced shutdown after timeout');
      process.exit(exitCode || 1);
    }, SHUTDOWN_TIMEOUT_MS);
    force.unref();
    // Drain WebSockets first (clients reconnect to another instance), then HTTP.
    await gateway.close().catch(() => undefined);
    await new Promise<void>((resolve) => {
      server.close(() => resolve()); // stop accepting; wait for in-flight requests
      server.closeIdleConnections();
    });
    await Promise.allSettled([
      ctx.agent.shutdownAll(),
      ctx.jobs.close(),
      metricsServer?.close() ?? Promise.resolve(),
    ]);
    await Promise.allSettled([ctx.sessionEvents.close?.()]);
    await Promise.allSettled([prisma.$disconnect(), redis.quit()]);
    logger.info('shutdown complete');
    logger.flush?.();
    process.exit(exitCode);
  };

  installProcessHandlers(logger, shutdown);
}

export function installProcessHandlers(
  logger: Logger,
  shutdown: (reason: string, code: number) => Promise<void>,
) {
  process.on('SIGTERM', () => void shutdown('SIGTERM', 0));
  process.on('SIGINT', () => void shutdown('SIGINT', 0));
  process.on('unhandledRejection', (reason) => {
    logger.error({ err: reason }, 'unhandled promise rejection');
    void shutdown('unhandledRejection', 1);
  });
  process.on('uncaughtException', (err) => {
    logger.fatal({ err }, 'uncaught exception');
    void shutdown('uncaughtException', 1);
  });
}

void main();
