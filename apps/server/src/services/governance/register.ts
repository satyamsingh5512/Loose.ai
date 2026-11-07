/**
 * Governance wiring (Phase 10): installs the audit hash-chain key and registers the background jobs
 * `data-export`, `retention-purge` and `deletion-sweep`. Runs in every process (api and worker).
 */
import type { AppContext } from '../../context';
import type { PlatformRole } from '../../platform/register';
import { deriveAuditChainKey } from './auditChain';
import { buildDataExport } from './dataExport';
import { runDeletionSweep } from './deletion';
import { RETENTION_LAST_SUCCESS_KEY, runRetentionPurge } from './retention';

export function registerGovernance(ctx: AppContext, _role: PlatformRole): void {
  // Must happen before anything records an audit entry.
  ctx.audit.useChainKey(deriveAuditChainKey(ctx.env));

  // Exposed by every process (the purge may run in a worker, Prometheus scrapes the API too):
  // read the shared timestamp at scrape time so a restart does not lose it.
  ctx.metrics.gauge(
    'loose_retention_last_success_timestamp_seconds',
    'Unix time of the last fully successful retention purge run',
    [],
    async (g) => {
      const raw = await ctx.kv.get(RETENTION_LAST_SUCCESS_KEY).catch(() => null);
      const seconds = raw ? Number(raw) : Number.NaN;
      if (Number.isFinite(seconds)) g.set(seconds);
    },
  );

  ctx.jobs.register('data-export', async (data) => {
    const id = typeof data.exportId === 'string' ? data.exportId : '';
    if (id) await buildDataExport(ctx, id);
  });
  ctx.jobs.register('retention-purge', async (data) => {
    const orgId = typeof data.orgId === 'string' ? data.orgId : undefined;
    await runRetentionPurge(ctx, orgId ? { orgId } : {});
  });
  ctx.jobs.register('deletion-sweep', async () => {
    await runDeletionSweep(ctx);
  });
}
