/**
 * Streaming audit-log export (spec §8.20): CSV or JSON Lines, filtered, oldest first, in keyset
 * batches so memory stays flat. CSV cells that a spreadsheet could interpret as a formula are
 * neutralised (OWASP "CSV injection").
 */
import type { Response } from 'express';
import {
  AUDIT_EXPORT_MAX_ROWS,
  AUDIT_EXPORT_COLUMNS,
  type AuditExportFormat,
  type AuditLogExportQuery,
} from '@loose/shared';
import type { Organization } from '@prisma/client';
import type { AppContext } from '../../context';
import { AppError } from '../../lib/errors';
import { auditLogWhere, type Actor } from '../org.service';

const BATCH = 500;

/** Characters that make Excel/Sheets/LibreOffice treat a cell as a formula (or a DDE command). */
const FORMULA_START = /^[=+\-@\t\r]/;

/** RFC 4180 field encoding plus formula neutralisation. Numbers and null are not strings. */
export function csvCell(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  let s = typeof value === 'string' ? value : JSON.stringify(value);
  if (FORMULA_START.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
}

export function csvLine(values: readonly unknown[]): string {
  return `${values.map(csvCell).join(',')}\r\n`;
}

interface ExportRow {
  id: string;
  createdAt: Date;
  orgId: string | null;
  actorId: string | null;
  actor: { email: string } | null;
  action: string;
  target: string | null;
  ip: string | null;
  meta: unknown;
  chain: string | null;
  seq: number | null;
  prevHash: string | null;
  hash: string | null;
}

/** Flat object with the `AUDIT_EXPORT_COLUMNS` keys (used by both formats). */
export function exportRecord(r: ExportRow): Record<(typeof AUDIT_EXPORT_COLUMNS)[number], unknown> {
  return {
    id: r.id,
    createdAt: r.createdAt.toISOString(),
    orgId: r.orgId,
    actorId: r.actorId,
    actorEmail: r.actor?.email ?? null,
    action: r.action,
    target: r.target,
    ip: r.ip,
    meta: r.meta ?? null,
    chain: r.chain,
    seq: r.seq,
    prevHash: r.prevHash,
    hash: r.hash,
  };
}

export function formatRow(format: AuditExportFormat, r: ExportRow): string {
  const rec = exportRecord(r);
  return format === 'csv'
    ? csvLine(AUDIT_EXPORT_COLUMNS.map((c) => rec[c]))
    : `${JSON.stringify(rec)}\n`;
}

const CONTENT_TYPE: Record<AuditExportFormat, string> = {
  csv: 'text/csv; charset=utf-8',
  jsonl: 'application/x-ndjson; charset=utf-8',
};

/**
 * Stream the export to `res`. Rejects with LSE-VAL-002 before sending anything when the filter
 * matches more than `AUDIT_EXPORT_MAX_ROWS` rows (narrow the date range). Failures after the first
 * byte abort the connection — a truncated download must never look complete.
 */
export async function streamAuditExport(
  ctx: AppContext,
  org: Pick<Organization, 'id' | 'slug'>,
  actor: Actor,
  q: AuditLogExportQuery,
  res: Response,
): Promise<void> {
  const where = auditLogWhere(org.id, q);
  const total = await ctx.prisma.auditLog.count({ where });
  if (total > AUDIT_EXPORT_MAX_ROWS) {
    throw new AppError('LSE-VAL-002', {
      devMessage: `Export matches ${total} rows (limit ${AUDIT_EXPORT_MAX_ROWS}); narrow the date range`,
    });
  }
  const { format } = q;
  await ctx.audit.record({
    orgId: org.id,
    actorId: actor.userId,
    action: 'audit.export',
    target: org.id,
    meta: {
      format,
      rows: total,
      filters: {
        action: q.action ?? null,
        actionPrefix: q.actionPrefix ?? null,
        actorId: q.actorId ?? null,
        from: q.from ?? null,
        to: q.to ?? null,
      },
    },
    ip: actor.ip,
  });

  const fetchBatch = (cursor: string | undefined): Promise<ExportRow[]> =>
    ctx.prisma.auditLog.findMany({
      where,
      include: { actor: { select: { email: true } } },
      orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
      take: BATCH,
      ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
    });

  // Fetch the first batch before committing to a 200, so a DB error is still a normal error response.
  let batch = await fetchBatch(undefined);
  const stamp = new Date().toISOString().slice(0, 10);
  res.status(200);
  res.setHeader('Content-Type', CONTENT_TYPE[format]);
  res.setHeader(
    'Content-Disposition',
    `attachment; filename="audit-${org.slug}-${stamp}.${format === 'csv' ? 'csv' : 'jsonl'}"`,
  );
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  let aborted = false;
  res.once('close', () => {
    aborted = true;
  });

  // Backpressure: wait for 'drain', but never hang on a client that went away ('close').
  const write = async (chunk: string) => {
    if (res.write(chunk) || aborted) return;
    await new Promise<void>((resolve) => {
      const done = () => {
        res.off('drain', done);
        res.off('close', done);
        resolve();
      };
      res.once('drain', done);
      res.once('close', done);
    });
  };

  try {
    if (format === 'csv') await write(csvLine(AUDIT_EXPORT_COLUMNS));
    while (batch.length > 0 && !aborted) {
      await write(batch.map((r) => formatRow(format, r)).join(''));
      if (batch.length < BATCH) break;
      batch = await fetchBatch(batch[batch.length - 1]?.id);
    }
    if (!aborted) res.end();
  } catch (err) {
    ctx.logger.error({ err, orgId: org.id }, 'audit export aborted mid-stream');
    res.destroy(err instanceof Error ? err : undefined);
  }
}
