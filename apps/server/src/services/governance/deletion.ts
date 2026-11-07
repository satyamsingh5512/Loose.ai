/**
 * Account and organization deletion with a grace period (GDPR Art. 17 / DPDP erasure, spec §8.20).
 *
 *  schedule → `DeletionRequest(PENDING, scheduledFor = now + DELETION_GRACE_DAYS)` and a
 *             `deletionScheduledAt` flag on the user/org (orgs: writes are blocked with LSE-ORG-012)
 *  cancel   → request CANCELLED, flag cleared
 *  sweep    → hourly job executes due requests: stop live sessions, delete the rows (FK cascades),
 *             then delete the stored files. The (de-identified) request row stays as proof.
 *
 * Audit rows are immutable; on account deletion the actor link and the recorded IP addresses are
 * redacted (`actorId`/`ip` → NULL) through the SECURITY DEFINER `loose_audit_redact_user` (the
 * runtime DB role cannot UPDATE attribution itself), with a signed `audit.redacted` marker per
 * affected chain, so the hash chain stays valid and unannounced redaction is detectable.
 */
import type { DeletionRequest, Prisma } from '@prisma/client';
import {
  AUDIT_GLOBAL_CHAIN,
  type DeletionRequestDto,
  type ScheduleDeletionBody,
} from '@loose/shared';
import type { AppContext } from '../../context';
import { AppError } from '../../lib/errors';
import type { AuditEntry } from '../audit.service';
import { actorDigestOf } from './auditChain';
import { stopSession } from '../sessionLifecycle.service';
import { expireDataExports } from './dataExport';
import { collectOrgStorageKeys, collectUserStorageKeys, deleteStorageKeys } from './storageCleanup';

const DAY_MS = 86_400_000;
/** Session statuses that may still hold a sandbox / runner. */
const LIVE_STATUSES = ['QUEUED', 'STARTING', 'RUNNING', 'PAUSED'] as const;

export function toDeletionDto(r: DeletionRequest): DeletionRequestDto {
  return {
    id: r.id,
    kind: r.kind,
    status: r.status,
    scheduledFor: r.scheduledFor.toISOString(),
    cancelledAt: r.cancelledAt ? r.cancelledAt.toISOString() : null,
    completedAt: r.completedAt ? r.completedAt.toISOString() : null,
    createdAt: r.createdAt.toISOString(),
  };
}

function confirmationError(expected: 'organization slug' | 'email address'): AppError {
  return new AppError('LSE-VAL-001', {
    fields: { confirm: [`Type your ${expected} to confirm`] },
    devMessage: 'Deletion confirmation did not match',
  });
}

// ---- guards ---------------------------------------------------------------------------------

/** Orgs where `userId` is the only OWNER (and that are not already being deleted). */
export async function soleOwnedOrgs(
  ctx: AppContext,
  userId: string,
): Promise<{ id: string; slug: string }[]> {
  const owned = await ctx.prisma.orgMember.findMany({
    where: { userId, role: 'OWNER', org: { deletionScheduledAt: null } },
    select: { orgId: true, org: { select: { id: true, slug: true } } },
  });
  const sole: { id: string; slug: string }[] = [];
  for (const m of owned) {
    const owners = await ctx.prisma.orgMember.count({ where: { orgId: m.orgId, role: 'OWNER' } });
    if (owners <= 1) sole.push(m.org);
  }
  return sole;
}

function graceEnd(ctx: AppContext, now = new Date()): Date {
  return new Date(now.getTime() + ctx.env.DELETION_GRACE_DAYS * DAY_MS);
}

// ---- schedule / cancel / get ------------------------------------------------------------------

export async function getPendingDeletion(
  ctx: AppContext,
  target: { userId: string } | { orgId: string },
): Promise<DeletionRequestDto | null> {
  const row = await ctx.prisma.deletionRequest.findFirst({
    where: {
      status: 'PENDING',
      ...('userId' in target ? { userId: target.userId } : { orgId: target.orgId }),
    },
    orderBy: { createdAt: 'desc' },
  });
  return row ? toDeletionDto(row) : null;
}

export async function scheduleUserDeletion(
  ctx: AppContext,
  user: { id: string; email: string },
  body: ScheduleDeletionBody,
  ip?: string,
): Promise<{ dto: DeletionRequestDto; created: boolean }> {
  if (body.confirm.trim().toLowerCase() !== user.email.toLowerCase()) {
    throw confirmationError('email address');
  }
  const sole = await soleOwnedOrgs(ctx, user.id);
  if (sole.length > 0) {
    throw new AppError('LSE-ORG-007', {
      devMessage: `Sole owner of: ${sole.map((o) => o.slug).join(', ')}. Transfer ownership or delete the org first`,
    });
  }
  const res = await ctx.prisma.$transaction(
    async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${`deletion:user:${user.id}`}, 0))`;
      const existing = await tx.deletionRequest.findFirst({
        where: { kind: 'USER', userId: user.id, status: 'PENDING' },
      });
      if (existing) return { row: existing, created: false };
      const scheduledFor = graceEnd(ctx);
      const row = await tx.deletionRequest.create({
        data: { kind: 'USER', userId: user.id, requestedById: user.id, scheduledFor },
      });
      await tx.user.update({ where: { id: user.id }, data: { deletionScheduledAt: scheduledFor } });
      // Same transaction: if the audit append fails the schedule rolls back (P10-SEC-011).
      await ctx.audit.record(
        {
          actorId: user.id,
          action: 'deletion.schedule',
          target: user.id,
          meta: { kind: 'USER', scheduledFor: scheduledFor.toISOString() },
          ip,
        },
        tx,
      );
      return { row, created: true };
    },
    { maxWait: 10_000, timeout: 15_000 },
  );
  return { dto: toDeletionDto(res.row), created: res.created };
}

export async function cancelUserDeletion(
  ctx: AppContext,
  userId: string,
  ip?: string,
): Promise<DeletionRequestDto> {
  const row = await ctx.prisma.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${`deletion:user:${userId}`}, 0))`;
    const pending = await tx.deletionRequest.findFirst({
      where: { kind: 'USER', userId, status: 'PENDING' },
    });
    if (!pending) return null;
    await tx.user.update({ where: { id: userId }, data: { deletionScheduledAt: null } });
    const cancelled = await tx.deletionRequest.update({
      where: { id: pending.id },
      data: { status: 'CANCELLED', cancelledAt: new Date() },
    });
    await ctx.audit.record(
      {
        actorId: userId,
        action: 'deletion.cancel',
        target: userId,
        meta: { kind: 'USER', requestId: cancelled.id },
        ip,
      },
      tx,
    );
    return cancelled;
  });
  if (!row) throw new AppError('LSE-NF-001', { devMessage: 'No pending account deletion' });
  return toDeletionDto(row);
}

export async function scheduleOrgDeletion(
  ctx: AppContext,
  org: { id: string; slug: string },
  actorId: string,
  body: ScheduleDeletionBody,
  ip?: string,
): Promise<{ dto: DeletionRequestDto; created: boolean }> {
  if (body.confirm.trim() !== org.slug) throw confirmationError('organization slug');
  const res = await ctx.prisma.$transaction(
    async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${`deletion:org:${org.id}`}, 0))`;
      const existing = await tx.deletionRequest.findFirst({
        where: { kind: 'ORG', orgId: org.id, status: 'PENDING' },
      });
      if (existing) return { row: existing, created: false };
      const scheduledFor = graceEnd(ctx);
      const row = await tx.deletionRequest.create({
        data: { kind: 'ORG', orgId: org.id, requestedById: actorId, scheduledFor },
      });
      await tx.organization.update({
        where: { id: org.id },
        data: { deletionScheduledAt: scheduledFor },
      });
      await ctx.audit.record(
        {
          orgId: org.id,
          actorId,
          action: 'deletion.schedule',
          target: org.id,
          meta: { kind: 'ORG', scheduledFor: scheduledFor.toISOString() },
          ip,
        },
        tx,
      );
      return { row, created: true };
    },
    { maxWait: 10_000, timeout: 15_000 },
  );
  return { dto: toDeletionDto(res.row), created: res.created };
}

export async function cancelOrgDeletion(
  ctx: AppContext,
  orgId: string,
  actorId: string,
  ip?: string,
): Promise<DeletionRequestDto> {
  const row = await ctx.prisma.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${`deletion:org:${orgId}`}, 0))`;
    const pending = await tx.deletionRequest.findFirst({
      where: { kind: 'ORG', orgId, status: 'PENDING' },
    });
    if (!pending) return null;
    await tx.organization.update({ where: { id: orgId }, data: { deletionScheduledAt: null } });
    const cancelled = await tx.deletionRequest.update({
      where: { id: pending.id },
      data: { status: 'CANCELLED', cancelledAt: new Date() },
    });
    await ctx.audit.record(
      {
        orgId,
        actorId,
        action: 'deletion.cancel',
        target: orgId,
        meta: { kind: 'ORG', requestId: cancelled.id },
        ip,
      },
      tx,
    );
    return cancelled;
  });
  if (!row) throw new AppError('LSE-NF-001', { devMessage: 'No pending organization deletion' });
  return toDeletionDto(row);
}

// ---- execution --------------------------------------------------------------------------------

/** End every live session (kills sandboxes) so nothing keeps running for a deleted tenant. */
async function stopLiveSessions(
  ctx: AppContext,
  where: { userId: string } | { orgId: string },
): Promise<void> {
  const sessions = await ctx.prisma.session.findMany({
    where: {
      status: { in: [...LIVE_STATUSES] },
      ...('userId' in where ? { userId: where.userId } : { project: { orgId: where.orgId } }),
    },
    select: { id: true, status: true },
  });
  for (const s of sessions) {
    try {
      await stopSession(ctx, s.id, {
        to: 'COMPLETED',
        reason: 'stopped',
        pushWip: false,
        from: [s.status],
      });
    } catch (err) {
      ctx.logger.warn({ err, sessionId: s.id }, 'deletion: could not stop session');
    }
  }
}

type Outcome = 'completed' | 'failed' | 'skipped';

/** Mark a request FAILED; `audit` (when given) is appended in the same transaction (P10-SEC-011). */
async function failRequest(
  ctx: AppContext,
  req: DeletionRequest,
  error: string,
  audit?: AuditEntry,
): Promise<void> {
  await ctx.prisma.$transaction(async (tx) => {
    await tx.deletionRequest.update({
      where: { id: req.id },
      data: { status: 'FAILED', error, completedAt: new Date() },
    });
    if (req.kind === 'USER' && req.userId) {
      await tx.user.updateMany({ where: { id: req.userId }, data: { deletionScheduledAt: null } });
    }
    if (req.kind === 'ORG' && req.orgId) {
      await tx.organization.updateMany({
        where: { id: req.orgId },
        data: { deletionScheduledAt: null },
      });
    }
    if (audit) await ctx.audit.record(audit, tx);
  });
}

/** Run inside the final transaction: take the request lock and re-validate it. */
async function lockPending(
  tx: Prisma.TransactionClient,
  id: string,
  now: Date,
): Promise<DeletionRequest | null> {
  const lock = await tx.$queryRaw<{ locked: boolean }[]>`
    SELECT pg_try_advisory_xact_lock(hashtextextended(${`deletion-exec:${id}`}, 0)) AS locked`;
  if (!lock[0]?.locked) return null;
  const row = await tx.deletionRequest.findUnique({ where: { id } });
  return row && row.status === 'PENDING' && row.scheduledFor.getTime() <= now.getTime()
    ? row
    : null;
}

async function executeUserDeletion(
  ctx: AppContext,
  req: DeletionRequest,
  now: Date,
): Promise<Outcome> {
  if (!req.userId) {
    await ctx.prisma.deletionRequest.update({
      where: { id: req.id },
      data: { status: 'COMPLETED', completedAt: now },
    });
    return 'completed';
  }
  const userId = req.userId;
  const sole = await soleOwnedOrgs(ctx, userId);
  if (sole.length > 0) {
    await failRequest(
      ctx,
      req,
      `Account is the only owner of: ${sole.map((o) => o.slug).join(', ')}`,
      {
        actorId: userId,
        action: 'deletion.cancel',
        target: userId,
        meta: { kind: 'USER', requestId: req.id, reason: 'sole_owner' },
      },
    );
    return 'failed';
  }
  await stopLiveSessions(ctx, { userId });
  const keys = await collectUserStorageKeys(ctx, userId);
  const done = await ctx.prisma.$transaction(
    async (tx) => {
      const locked = await lockPending(tx, req.id, now);
      if (!locked) return false;
      await redactUserAudit(ctx, tx, req.id, userId);
      await tx.deletionRequest.update({
        where: { id: req.id },
        data: { status: 'COMPLETED', completedAt: now, requestedById: null, error: null },
      });
      await tx.user.deleteMany({ where: { id: userId } });
      await ctx.audit.record(
        { action: 'deletion.complete', target: req.id, meta: { kind: 'USER' } },
        tx,
      );
      return true;
    },
    { maxWait: 10_000, timeout: 60_000 },
  );
  if (!done) return 'skipped';
  await cleanupAfterDeletion(ctx, req.id, keys);
  return 'completed';
}

/**
 * GDPR redaction of a deleted user's audit attribution (REAUDIT-007). The runtime role has no
 * UPDATE on "AuditLog": `loose_audit_redact_user` (SECURITY DEFINER, migration
 * 20261019180000_audit_redaction_definer) nulls "actorId"/"ip" only while this due request is
 * PENDING and its execution lock is held. Every affected chain then gets a signed
 * `audit.redacted` marker carrying the user's actorDigest, so verifyChain can tell this
 * redaction from an attribution removed behind its back. Must run inside the final transaction,
 * after `lockPending` and before the request is marked COMPLETED.
 */
async function redactUserAudit(
  ctx: AppContext,
  tx: Prisma.TransactionClient,
  requestId: string,
  userId: string,
): Promise<void> {
  const chains = await tx.auditLog.groupBy({
    by: ['chain'],
    where: { actorId: userId, chain: { not: null }, actorDigest: { not: null } },
    _count: { _all: true },
  });
  await tx.$queryRaw`SELECT loose_audit_redact_user(${requestId})::INTEGER AS "n"`;
  const actorDigest = actorDigestOf(userId);
  for (const { chain, _count } of chains) {
    if (!chain) continue;
    await ctx.audit.record(
      {
        orgId: chain === AUDIT_GLOBAL_CHAIN ? null : chain,
        action: 'audit.redacted',
        target: requestId,
        meta: { kind: 'USER', actorDigest, rows: _count._all },
      },
      tx,
    );
  }
}

async function executeOrgDeletion(
  ctx: AppContext,
  req: DeletionRequest,
  now: Date,
): Promise<Outcome> {
  if (!req.orgId) {
    await ctx.prisma.deletionRequest.update({
      where: { id: req.id },
      data: { status: 'COMPLETED', completedAt: now },
    });
    return 'completed';
  }
  const orgId = req.orgId;
  await stopLiveSessions(ctx, { orgId });
  const keys = await collectOrgStorageKeys(ctx, orgId);
  const done = await ctx.prisma.$transaction(
    async (tx) => {
      const locked = await lockPending(tx, req.id, now);
      if (!locked) return false;
      await tx.deletionRequest.update({
        where: { id: req.id },
        data: { status: 'COMPLETED', completedAt: now },
      });
      // Cascades members, projects, sessions, artifacts rows, usage, the org's audit chain, …
      await tx.organization.deleteMany({ where: { id: orgId } });
      await ctx.audit.record(
        {
          actorId: req.requestedById,
          action: 'deletion.complete',
          target: req.id,
          meta: { kind: 'ORG', orgId },
        },
        tx,
      );
      return true;
    },
    { maxWait: 10_000, timeout: 60_000 },
  );
  if (!done) return 'skipped';
  await cleanupAfterDeletion(ctx, req.id, keys);
  return 'completed';
}

async function cleanupAfterDeletion(ctx: AppContext, requestId: string, keys: string[]) {
  if (keys.length === 0) return;
  const failed = await deleteStorageKeys(ctx, keys);
  if (failed.length > 0) {
    // The rows are gone; surface the leftover files to operators (keys are opaque ids).
    ctx.logger.error(
      { requestId, leftover: failed.length },
      'deletion completed but some stored files could not be removed',
    );
    await ctx.prisma.deletionRequest
      .update({
        where: { id: requestId },
        data: { error: `${failed.length} stored file(s) could not be removed` },
      })
      .catch(() => undefined);
  }
}

export interface DeletionSweepResult {
  completed: number;
  failed: number;
  skipped: number;
  expiredExports: number;
}

/**
 * The `deletion-sweep` job body: expire old data exports, then execute due deletion requests
 * (organizations first, so a user who solely owned a doomed org is not blocked by it).
 */
export async function runDeletionSweep(
  ctx: AppContext,
  opts: { now?: Date } = {},
): Promise<DeletionSweepResult> {
  const now = opts.now ?? new Date();
  const result: DeletionSweepResult = { completed: 0, failed: 0, skipped: 0, expiredExports: 0 };
  result.expiredExports = await expireDataExports(ctx, now);
  const due = await ctx.prisma.deletionRequest.findMany({
    where: { status: 'PENDING', scheduledFor: { lte: now } },
    orderBy: { scheduledFor: 'asc' },
    take: 100,
  });
  due.sort((a, b) => (a.kind === b.kind ? 0 : a.kind === 'ORG' ? -1 : 1));
  for (const req of due) {
    try {
      const outcome =
        req.kind === 'ORG'
          ? await executeOrgDeletion(ctx, req, now)
          : await executeUserDeletion(ctx, req, now);
      if (outcome === 'completed') result.completed += 1;
      else if (outcome === 'failed') result.failed += 1;
      else result.skipped += 1;
    } catch (err) {
      // Keep the request PENDING so the next sweep retries; leave a hint for operators.
      result.failed += 1;
      ctx.logger.error({ err, requestId: req.id }, 'deletion request failed; will retry');
      await ctx.prisma.deletionRequest
        .update({ where: { id: req.id }, data: { error: 'Deletion attempt failed; retrying' } })
        .catch(() => undefined);
    }
  }
  return result;
}
