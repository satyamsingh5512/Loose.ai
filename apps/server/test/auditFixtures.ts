/**
 * Fixtures for audit rows the application can no longer write (pre-Phase-10 "legacy" rows with a
 * historical `createdAt`, bulk rows with chosen timestamps). The AuditLog insert/update triggers
 * (migration 20261019001500_audit_insert_guard) refuse those on purpose, so tests write them the way
 * an operator restoring a dump would: in a transaction with `session_replication_role = replica`,
 * which skips ordinary triggers and needs a superuser (the local test role is one; the production
 * application role must not be).
 */
import type { AuditLog, Prisma, PrismaClient } from '@prisma/client';

export function withoutAuditTriggers<T>(
  prisma: PrismaClient,
  fn: (tx: Prisma.TransactionClient) => Promise<T>,
): Promise<T> {
  return prisma.$transaction(async (tx) => {
    await tx.$executeRaw`SET LOCAL session_replication_role = replica`;
    return fn(tx);
  });
}

/** Insert one audit row exactly as given (e.g. a backdated, unchained legacy row). */
export function legacyAuditRow(
  prisma: PrismaClient,
  data: Prisma.AuditLogUncheckedCreateInput,
): Promise<AuditLog> {
  return withoutAuditTriggers(prisma, (tx) => tx.auditLog.create({ data }));
}
