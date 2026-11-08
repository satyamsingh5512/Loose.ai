/**
 * Usage & cost analytics (spec §8.19): `GET /orgs/:orgId/usage` (Admin) as
 * `UsageSummaryDto` or a CSV export (one row per usage event). Aggregates are computed on
 * read from `UsageEvent` rows (tenant-scoped by orgId).
 */
import { Prisma } from '@prisma/client';
import {
  cacheHitRatio,
  USAGE_CSV_COLUMNS,
  usageSummaryDtoSchema,
  type UsageQuery,
  type UsageSummaryDto,
} from '@loose/shared';
import type { AppContext } from '../context';

const DAY_MS = 86_400_000;
const CSV_MAX_ROWS = 50_000;

export function usageRange(q: Pick<UsageQuery, 'from' | 'to'>, now = new Date()) {
  const to = q.to ? new Date(q.to) : now;
  const from = q.from ? new Date(q.from) : new Date(to.getTime() - 30 * DAY_MS);
  return { from, to };
}

function filters(orgId: string, q: UsageQuery, from: Date, to: Date): Prisma.Sql {
  const parts = [
    Prisma.sql`u."orgId" = ${orgId}`,
    Prisma.sql`u."createdAt" >= ${from}`,
    Prisma.sql`u."createdAt" <= ${to}`,
  ];
  if (q.userId) parts.push(Prisma.sql`u."userId" = ${q.userId}`);
  if (q.projectId) parts.push(Prisma.sql`s."projectId" = ${q.projectId}`);
  return Prisma.join(parts, ' AND ');
}

export async function usageSummary(
  ctx: AppContext,
  orgId: string,
  q: UsageQuery,
): Promise<UsageSummaryDto> {
  const { from, to } = usageRange(q);
  const where = filters(orgId, q, from, to);
  const from_ = Prisma.sql`FROM "UsageEvent" u JOIN "Session" s ON s.id = u."sessionId"`;
  const [totals] = await ctx.prisma.$queryRaw<
    { cost: unknown; sessions: unknown; tin: unknown; tout: unknown; cread: unknown }[]
  >`SELECT COALESCE(SUM(u."costUsd"),0) AS cost, COUNT(DISTINCT u."sessionId") AS sessions,
      COALESCE(SUM(u."tokensIn"),0) AS tin, COALESCE(SUM(u."tokensOut"),0) AS tout,
      COALESCE(SUM(u."cacheRead"),0) AS cread ${from_} WHERE ${where}`;
  const byUser = await ctx.prisma.$queryRaw<
    {
      userId: string;
      name: string | null;
      email: string;
      cost: unknown;
      sessions: unknown;
      tin: unknown;
      tout: unknown;
    }[]
  >`SELECT u."userId", us.name, us.email, SUM(u."costUsd") AS cost, COUNT(DISTINCT u."sessionId") AS sessions,
      SUM(u."tokensIn") AS tin, SUM(u."tokensOut") AS tout
      ${from_} JOIN "User" us ON us.id = u."userId" WHERE ${where}
      GROUP BY u."userId", us.name, us.email ORDER BY cost DESC LIMIT 200`;
  const byProject = await ctx.prisma.$queryRaw<
    { projectId: string; name: string; cost: unknown; sessions: unknown }[]
  >`SELECT s."projectId", p.name, SUM(u."costUsd") AS cost, COUNT(DISTINCT u."sessionId") AS sessions
      ${from_} JOIN "Project" p ON p.id = s."projectId" WHERE ${where}
      GROUP BY s."projectId", p.name ORDER BY cost DESC LIMIT 200`;
  const byModel = await ctx.prisma.$queryRaw<
    { model: string; cost: unknown; tin: unknown; tout: unknown; cread: unknown }[]
  >`SELECT u.model, SUM(u."costUsd") AS cost, SUM(u."tokensIn") AS tin, SUM(u."tokensOut") AS tout,
      SUM(u."cacheRead") AS cread ${from_} WHERE ${where} GROUP BY u.model ORDER BY cost DESC LIMIT 50`;
  // Per-subagent attribution (spec §8.8); NULL = the main agent.
  const bySubagent = await ctx.prisma.$queryRaw<
    { subagent: string | null; cost: unknown; tin: unknown; tout: unknown; calls: unknown }[]
  >`SELECT u.subagent, SUM(u."costUsd") AS cost, SUM(u."tokensIn") AS tin, SUM(u."tokensOut") AS tout,
      COUNT(*) AS calls ${from_} WHERE ${where} GROUP BY u.subagent ORDER BY cost DESC LIMIT 50`;

  // PR metrics over sessions started in range.
  const sessionWhere: Prisma.SessionWhereInput = {
    project: { orgId, ...(q.projectId ? { id: q.projectId } : {}) },
    ...(q.userId ? { userId: q.userId } : {}),
    createdAt: { gte: from, lte: to },
    prCreatedAt: { not: null },
  };
  const prs = await ctx.prisma.session.findMany({
    where: sessionWhere,
    select: { prState: true, startedAt: true, createdAt: true, prCreatedAt: true, outcome: true },
    take: 10_000,
  });
  const merged = prs.filter((p) => p.prState === 'merged' || p.outcome === 'COMMITTED_TO_MAIN');
  const minutes = prs
    .map((p) => (p.prCreatedAt!.getTime() - (p.startedAt ?? p.createdAt).getTime()) / 60_000)
    .filter((m) => Number.isFinite(m) && m >= 0);

  return usageSummaryDtoSchema.parse({
    range: { from, to },
    totalCostUsd: totals?.cost ?? 0,
    sessions: totals?.sessions ?? 0,
    tokensIn: totals?.tin ?? 0,
    tokensOut: totals?.tout ?? 0,
    cacheRead: totals?.cread ?? 0,
    cacheHitRatio: cacheHitRatio(Number(totals?.tin ?? 0), Number(totals?.cread ?? 0)),
    bySubagent: bySubagent.map((r) => ({
      subagent: r.subagent,
      costUsd: r.cost,
      tokensIn: r.tin,
      tokensOut: r.tout,
      calls: r.calls,
    })),
    byUser: byUser.map((r) => ({
      userId: r.userId,
      name: r.name,
      email: r.email,
      costUsd: r.cost,
      sessions: r.sessions,
      tokensIn: r.tin,
      tokensOut: r.tout,
    })),
    byProject: byProject.map((r) => ({
      projectId: r.projectId,
      name: r.name,
      costUsd: r.cost,
      sessions: r.sessions,
    })),
    byModel: byModel.map((r) => ({
      model: r.model,
      costUsd: r.cost,
      tokensIn: r.tin,
      tokensOut: r.tout,
      cacheRead: r.cread,
    })),
    prAcceptanceRate: prs.length ? merged.length / prs.length : null,
    meanTimeToPrMin: minutes.length
      ? Math.round((minutes.reduce((a, b) => a + b, 0) / minutes.length) * 10) / 10
      : null,
  });
}

/** CSV cell: quoted, and neutralised against spreadsheet formula injection. */
export function csvCell(v: unknown): string {
  let s = v instanceof Date ? v.toISOString() : String(v ?? '');
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\n\r']/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export async function usageCsv(ctx: AppContext, orgId: string, q: UsageQuery): Promise<string> {
  const { from, to } = usageRange(q);
  const rows = await ctx.prisma.usageEvent.findMany({
    where: {
      orgId,
      createdAt: { gte: from, lte: to },
      ...(q.userId ? { userId: q.userId } : {}),
      ...(q.projectId ? { session: { projectId: q.projectId } } : {}),
    },
    include: {
      session: { select: { projectId: true, project: { select: { name: true } } } },
      user: { select: { email: true } },
    },
    orderBy: { createdAt: 'asc' },
    take: CSV_MAX_ROWS,
  });
  const lines = [USAGE_CSV_COLUMNS.join(',')];
  for (const r of rows) {
    const record: Record<(typeof USAGE_CSV_COLUMNS)[number], unknown> = {
      createdAt: r.createdAt,
      sessionId: r.sessionId,
      projectId: r.session.projectId,
      projectName: r.session.project.name,
      userId: r.userId,
      userEmail: r.user.email,
      model: r.model,
      tokensIn: r.tokensIn,
      tokensOut: r.tokensOut,
      cacheRead: r.cacheRead,
      costUsd: Number(r.costUsd).toFixed(6),
      subagent: r.subagent ?? '',
    };
    lines.push(USAGE_CSV_COLUMNS.map((c) => csvCell(record[c])).join(','));
  }
  return `${lines.join('\n')}\n`;
}
