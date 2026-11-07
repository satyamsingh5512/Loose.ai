import { createServer } from 'node:http';
import { monitorEventLoopDelay } from 'node:perf_hooks';
import { createHash, timingSafeEqual } from 'node:crypto';
import { isLoopbackHost } from '../../lib/net/ip';
import type { AppContext } from '../../context';
import type { PlatformRole } from '../../platform/register';

export function registerObservability(ctx: AppContext, _role: PlatformRole): void {
  const memory = ctx.metrics.gauge(
    'loose_process_resident_memory_bytes',
    'Resident process memory in bytes',
  );
  const uptime = ctx.metrics.gauge('loose_process_uptime_seconds', 'Process uptime in seconds');
  const lag = ctx.metrics.gauge(
    'loose_nodejs_eventloop_lag_seconds',
    'Node event loop lag in seconds',
  );
  const loop = monitorEventLoopDelay({ resolution: 20 });
  loop.enable();
  ctx.metrics.gauge(
    'loose_process_resident_memory_bytes',
    'Resident process memory in bytes',
    [],
    () => memory.set(process.memoryUsage().rss),
  );
  ctx.metrics.gauge('loose_process_uptime_seconds', 'Process uptime in seconds', [], () =>
    uptime.set(process.uptime()),
  );
  ctx.metrics.gauge(
    'loose_nodejs_eventloop_lag_seconds',
    'Node event loop lag in seconds',
    [],
    () => {
      lag.set(Number.isFinite(loop.mean) ? loop.mean / 1e9 : 0);
      loop.reset();
    },
  );
}
export interface MetricsServerHandle {
  close(): Promise<void>;
}

const sha256 = (v: string) => createHash('sha256').update(v).digest();

/** Constant-time bearer check; digests make the compared buffers equally long. */
function bearerMatches(header: string | undefined, token: string): boolean {
  const m = /^Bearer (.+)$/.exec(header ?? '');
  return m ? timingSafeEqual(sha256(m[1]!), sha256(token)) : false;
}

export async function startMetricsServer(ctx: AppContext): Promise<MetricsServerHandle | null> {
  if (!ctx.env.METRICS_PORT) return null;
  // Loopback listeners stay open for a local scraper/sidecar; any other bind address must
  // authenticate (the env schema refuses that configuration without METRICS_TOKEN) (P10-SEC-017).
  const needsAuth = !isLoopbackHost(ctx.env.METRICS_HOST);
  const token = ctx.env.METRICS_TOKEN;
  if (needsAuth && !token) {
    throw new Error('METRICS_TOKEN is required when METRICS_HOST is not a loopback address');
  }
  const server = createServer(async (req, res) => {
    if (req.method !== 'GET' || req.url?.split('?')[0] !== '/metrics') {
      res.statusCode = 404;
      res.end();
      return;
    }
    if (needsAuth && token && !bearerMatches(req.headers.authorization, token)) {
      res.statusCode = 404; // do not reveal the endpoint to unauthenticated scanners
      res.end();
      return;
    }
    try {
      res.statusCode = 200;
      res.setHeader('content-type', 'text/plain; version=0.0.4; charset=utf-8');
      res.end(await ctx.metrics.render());
    } catch {
      res.statusCode = 503;
      res.end('# metrics unavailable\n');
    }
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(ctx.env.METRICS_PORT, ctx.env.METRICS_HOST, () => {
      server.off('error', reject);
      resolve();
    });
  });
  return { close: () => new Promise((resolve) => server.close(() => resolve())) };
}
