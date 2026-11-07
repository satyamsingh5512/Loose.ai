/**
 * Per-org data retention (spec §8.20; phase10-design.md §5.3).
 *
 * Settings live in `Organization.policy.retentionDays`. The daily `retention-purge` job removes,
 * per org and always in small batches (idempotent: a second run finds nothing left):
 *  - transcripts:    ChatMessage rows of sessions that ENDED before the cutoff
 *  - rawToolOutput:  ChatMessage.rawContent (nulled) and `log` artifacts older than the cutoff
 *  - screenshots:    every other artifact (rows + stored objects) older than the cutoff
 *  - auditLog:       the oldest prefix of the hash chain (anchor kept), see purgeAuditLog()
 * Sessions that are queued/starting/running/paused/stopping are never touched. There is no
 * legal-hold feature in the data model, so none is applied.
 */
import { Prisma, type Organization } from '@prisma/client';
import {
  RETENTION_KINDS,
  TERMINAL_SESSION_STATUSES,
  parseOrgPolicy,
  retentionPurgeCountsSchema,
  type RetentionKind,
  type RetentionPurgeCounts,
  type RetentionSettingsDto,
  type UpdateRetentionBody,
} from '@loose/shared';
import type { AppContext } from '../../context';
import type { Actor } from '../org.service';
import { appendChainedEntry, backfillChain, chainsWithLegacyRows } from './auditChain';

const DAY_MS = 86_400_000;
const BATCH = 500;
const LOCK_TTL_SEC = 3600;

const TERMINAL = [...TERMINAL_SESSION_STATUSES];

export function emptyCounts(): RetentionPurgeCounts {
  return { transcripts: 0, rawToolOutput: 0, screenshots: 0, auditLog: 0 };
}

export function addCounts(a: RetentionPurgeCounts, b: RetentionPurgeCounts): RetentionPurgeCounts {
  return {
    transcripts: a.transcripts + b.transcripts,
    rawToolOutput: a.rawToolOutput + b.rawToolOutput,
    screenshots: a.screenshots + b.screenshots,
    auditLog: a.auditLog + b.auditLog,
  };
}

const sum = (c: RetentionPurgeCounts) =>
  c.transcripts + c.rawToolOutput + c.screenshots + c.auditLog;

// ---- settings -------------------------------------------------------------------------------

export async function getRetention(
  ctx: AppContext,
  org: Organization,
): Promise<RetentionSettingsDto> {
  const last = await ctx.prisma.auditLog.findFirst({
    where: { orgId: org.id, action: 'retention.purge' },
    orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
    select: { createdAt: true, meta: true },
  });
  const counts = retentionPurgeCountsSchema.safeParse(
    (last?.meta as { counts?: unknown } | null)?.counts,
  );
  return {
    settings: parseOrgPolicy(org.policy).retentionDays,
    lastPurgeAt: last ? last.createdAt.toISOString() : null,
    lastPurgeCounts: counts.success ? counts.data : null,
  };
}

export async function updateRetention(
  ctx: AppContext,
  org: Organization,
  actor: Actor,
  body: UpdateRetentionBody,
): Promise<RetentionSettingsDto> {
  const before = parseOrgPolicy(org.policy).retentionDays;
  await ctx.prisma.$transaction(async (tx) => {
    // Lock the row so a concurrent `PUT /policy` can't be overwritten with a stale policy.
    const rows = await tx.$queryRaw<{ policy: unknown }[]>`
      SELECT "policy" FROM "Organization" WHERE "id" = ${org.id} FOR UPDATE`;
    const current = parseOrgPolicy(rows[0]?.policy ?? org.policy);
    const next = { ...current, retentionDays: body };
    await tx.organization.update({
      where: { id: org.id },
      data: { policy: next as Prisma.InputJsonValue },
    });
    // P10-SEC-011: the audit row commits (or rolls back) together with the change.
    await ctx.audit.record(
      {
        orgId: org.id,
        actorId: actor.userId,
        action: 'retention.update',
        target: org.id,
        meta: { before, after: next.retentionDays },
        ip: actor.ip,
      },
      tx,
    );
  });
  const fresh = await ctx.prisma.organization.findUniqueOrThrow({ where: { id: org.id } });
  return getRetention(ctx, fresh);
}

// ---- purge steps ----------------------------------------------------------------------------

/** `ChatMessage.sessionId` filter shared by the message purges: ended sessions of this org. */
const endedSessionOf = (orgId: string, extra: Prisma.SessionWhereInput = {}) =>
  ({ project: { orgId }, status: { in: TERMINAL }, ...extra }) satisfies Prisma.SessionWhereInput;

async function purgeTranscripts(ctx: AppContext, orgId: string, cutoff: Date): Promise<number> {
  let total = 0;
  for (;;) {
    const rows = await ctx.prisma.chatMessage.findMany({
      where: { session: endedSessionOf(orgId, { endedAt: { lt: cutoff } }) },
      select: { id: true },
      orderBy: { id: 'asc' },
      take: BATCH,
    });
    if (rows.length === 0) return total;
    // Re-check the session state in the delete itself (a session may be resumed in between).
    const res = await ctx.prisma.chatMessage.deleteMany({
      where: {
        id: { in: rows.map((r) => r.id) },
        session: { status: { in: TERMINAL }, endedAt: { lt: cutoff } },
      },
    });
    total += res.count;
    if (res.count === 0 || rows.length < BATCH) return total;
  }
}

async function nullRawContent(ctx: AppContext, orgId: string, cutoff: Date): Promise<number> {
  let total = 0;
  for (;;) {
    const rows = await ctx.prisma.chatMessage.findMany({
      where: {
        createdAt: { lt: cutoff },
        rawContent: { not: Prisma.DbNull },
        session: endedSessionOf(orgId),
      },
      select: { id: true },
      orderBy: { id: 'asc' },
      take: BATCH,
    });
    if (rows.length === 0) return total;
    const res = await ctx.prisma.chatMessage.updateMany({
      where: { id: { in: rows.map((r) => r.id) }, session: { status: { in: TERMINAL } } },
      data: { rawContent: Prisma.DbNull },
    });
    total += res.count;
    if (res.count === 0 || rows.length < BATCH) return total;
  }
}

/** Delete artifacts (stored object first, then the row) older than the cutoff. */
async function purgeArtifacts(
  ctx: AppContext,
  orgId: string,
  cutoff: Date,
  kind: Prisma.StringFilter,
): Promise<number> {
  let total = 0;
  const failed: string[] = [];
  for (;;) {
    const rows = await ctx.prisma.artifact.findMany({
      where: {
        kind,
        createdAt: { lt: cutoff },
        session: endedSessionOf(orgId),
        ...(failed.length > 0 ? { id: { notIn: failed } } : {}),
      },
      select: { id: true, storageKey: true },
      orderBy: { id: 'asc' },
      take: BATCH,
    });
    if (rows.length === 0) return total;
    const ok: string[] = [];
    for (const row of rows) {
      try {
        if (row.storageKey) await ctx.storage.delete(row.storageKey);
        ok.push(row.id);
      } catch (err) {
        // Keep the row so the next run retries; never leave an object without its row.
        failed.push(row.id);
        ctx.logger.warn({ err, artifactId: row.id }, 'retention: artifact object delete failed');
      }
    }
    if (ok.length > 0) {
      const res = await ctx.prisma.artifact.deleteMany({
        where: { id: { in: ok }, session: { status: { in: TERMINAL } } },
      });
      total += res.count;
    }
    if (ok.length === 0 || rows.length < BATCH) return total;
  }
}

/**
 * Chain-aware audit purge. Removes the oldest prefix of the org's chain whose rows are all older
 * than the cutoff (chain order is `seq`; sealed legacy rows sit at the tail with old timestamps and
 * leave once the rows in front of them have aged out). An `audit.retention_purged` marker
 * `{purgedThroughSeq, anchorHash}` is appended BEFORE deleting, so verification can tell a purge
 * from an attacker removing the start of the chain. Unchained legacy rows are deleted by age.
 */
export async function purgeAuditLog(ctx: AppContext, orgId: string, cutoff: Date): Promise<number> {
  const chain = orgId;
  const lowest = await ctx.prisma.auditLog.findFirst({
    where: { chain, seq: { not: null } },
    orderBy: { seq: 'asc' },
    select: { seq: true },
  });
  let purged = 0;
  if (lowest?.seq != null) {
    const firstKept = await ctx.prisma.auditLog.findFirst({
      where: { chain, seq: { not: null }, createdAt: { gte: cutoff } },
      orderBy: { seq: 'asc' },
      select: { seq: true },
    });
    const head = await ctx.prisma.auditLog.findFirst({
      where: { chain, seq: { not: null } },
      orderBy: { seq: 'desc' },
      select: { seq: true },
    });
    const through = firstKept?.seq != null ? firstKept.seq - 1 : (head?.seq ?? 0);
    if (through >= lowest.seq) {
      const anchor = await ctx.prisma.auditLog.findFirst({
        where: { chain, seq: through },
        select: { hash: true },
      });
      const planned = await ctx.prisma.auditLog.count({
        where: { chain, seq: { not: null, lte: through } },
      });
      // The marker goes in FIRST (and must succeed): if the purge is interrupted half-way, the
      // chain still explains why its oldest rows are gone, so verification never raises a false alarm.
      await ctx.prisma.$transaction((tx) =>
        appendChainedEntry(tx, ctx.audit.chainKey, {
          orgId,
          action: 'audit.retention_purged',
          target: orgId,
          meta: {
            purgedThroughSeq: through,
            anchorHash: anchor?.hash ?? null,
            count: planned,
            cutoff: cutoff.toISOString(),
          },
        }),
      );
      for (;;) {
        const n = await deleteChainPrefix(ctx.prisma, chain, through);
        purged += n;
        if (n < BATCH) break;
      }
    }
  }
  // Rows written before Phase 10 that were never sealed into the chain.
  for (;;) {
    const [row] = await ctx.prisma.$queryRaw<{ n: number }[]>`
      SELECT loose_audit_purge_legacy(
        ${orgId},
        (${cutoff.toISOString()}::timestamptz AT TIME ZONE 'UTC')::timestamp(3),
        ${BATCH}::int
      ) AS n`;
    const n = Number(row?.n ?? 0);
    purged += n;
    if (n < BATCH) break;
  }
  return purged;
}

/**
 * Delete up to BATCH rows with the lowest seqs (<= `through`). The runtime DB role has no DELETE
 * on "AuditLog" (P10-SEC-006-R2); `loose_audit_purge_prefix` (SECURITY DEFINER, migration
 * 20261019120000_audit_retention_definer) re-checks the marker, anchor, cutoff and minimum
 * retention itself, so it can never remove the chain tail.
 */
async function deleteChainPrefix(
  prisma: AppContext['prisma'],
  chain: string,
  through: number,
): Promise<number> {
  const [row] = await prisma.$queryRaw<{ n: number }[]>`
    SELECT loose_audit_purge_prefix(${chain}, ${through}::int, ${BATCH}::int) AS n`;
  return Number(row?.n ?? 0);
}

// ---- orchestration --------------------------------------------------------------------------

export async function purgeOrg(
  ctx: AppContext,
  org: Pick<Organization, 'id' | 'policy'>,
  now: Date,
): Promise<RetentionPurgeCounts> {
  const days = parseOrgPolicy(org.policy).retentionDays;
  const cutoff = (kind: RetentionKind) => new Date(now.getTime() - days[kind] * DAY_MS);

  const counts = emptyCounts();
  counts.transcripts = await purgeTranscripts(ctx, org.id, cutoff('transcripts'));
  counts.rawToolOutput =
    (await nullRawContent(ctx, org.id, cutoff('rawToolOutput'))) +
    (await purgeArtifacts(ctx, org.id, cutoff('rawToolOutput'), { equals: 'log' }));
  counts.screenshots = await purgeArtifacts(ctx, org.id, cutoff('screenshots'), { not: 'log' });
  counts.auditLog = await purgeAuditLog(ctx, org.id, cutoff('auditLog'));

  if (sum(counts) > 0) {
    await ctx.audit.record({
      orgId: org.id,
      action: 'retention.purge',
      target: org.id,
      meta: { counts, retentionDays: days },
    });
    const metric = ctx.metrics.counter(
      'loose_retention_purged_total',
      'Rows/objects removed by the retention purge job',
      ['kind'],
    );
    for (const kind of RETENTION_KINDS) if (counts[kind] > 0) metric.inc({ kind }, counts[kind]);
  }
  return counts;
}

export interface RetentionRunResult {
  orgs: number;
  failed: number;
  sealedAuditRows: number;
  totals: RetentionPurgeCounts;
}

/** Seal pre-Phase-10 audit rows into their hash chains (idempotent). */
export async function sealLegacyAuditRows(ctx: AppContext): Promise<number> {
  let sealed = 0;
  for (const chain of await chainsWithLegacyRows(ctx.prisma)) {
    sealed += await backfillChain(ctx.prisma, ctx.audit.chainKey, chain);
  }
  return sealed;
}

/**
 * The `retention-purge` job body. `orgId` limits the run to one org (tests, manual runs); `now` is
 * injectable. Overlapping runs for one org are prevented with a short-lived KV lock.
 */
export async function runRetentionPurge(
  ctx: AppContext,
  opts: { orgId?: string; now?: Date } = {},
): Promise<RetentionRunResult> {
  const now = opts.now ?? new Date();
  const result: RetentionRunResult = {
    orgs: 0,
    failed: 0,
    sealedAuditRows: 0,
    totals: emptyCounts(),
  };
  try {
    result.sealedAuditRows = await sealLegacyAuditRows(ctx);
  } catch (err) {
    ctx.logger.error({ err }, 'retention: sealing legacy audit rows failed');
  }

  let cursor: string | undefined;
  for (;;) {
    const orgs = await ctx.prisma.organization.findMany({
      where: opts.orgId ? { id: opts.orgId } : {},
      select: { id: true, policy: true },
      orderBy: { id: 'asc' },
      take: 100,
      ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
    });
    if (orgs.length === 0) break;
    for (const org of orgs) {
      const lockKey = `retention:${org.id}`;
      let locked = false;
      try {
        locked = await ctx.kv.setIfAbsent(lockKey, ctx.instanceId, LOCK_TTL_SEC);
        if (!locked) continue; // another worker is purging this org
        result.totals = addCounts(result.totals, await purgeOrg(ctx, org, now));
        result.orgs += 1;
      } catch (err) {
        result.failed += 1;
        ctx.logger.error({ err, orgId: org.id }, 'retention purge failed for org');
      } finally {
        if (locked) await ctx.kv.del(lockKey).catch(() => undefined);
      }
    }
    cursor = orgs[orgs.length - 1]?.id;
    if (orgs.length < 100) break;
  }
  // Staleness signal for the LooseRetentionJobStale alert: only a fully successful run counts.
  if (result.failed === 0 && !opts.orgId) await recordRetentionSuccess(ctx);
  return result;
}

/** KV key holding the unix time (seconds) of the last fully successful retention run. */
export const RETENTION_LAST_SUCCESS_KEY = 'retention:last-success';
const RETENTION_LAST_SUCCESS_TTL_SEC = 30 * 86_400;

export async function recordRetentionSuccess(ctx: AppContext, now = new Date()): Promise<void> {
  const seconds = Math.floor(now.getTime() / 1000);
  ctx.metrics
    .gauge(
      'loose_retention_last_success_timestamp_seconds',
      'Unix time of the last fully successful retention purge run',
    )
    .set(seconds);
  await ctx.kv
    .set(RETENTION_LAST_SUCCESS_KEY, String(seconds), RETENTION_LAST_SUCCESS_TTL_SEC)
    .catch((err: unknown) => ctx.logger.warn({ err }, 'retention: could not persist last success'));
}
