/**
 * GDPR / DPDP data export (spec §8.20): an async job collects a person's (or an org's) data into a
 * ZIP of JSON / NDJSON files stored in ObjectStorage, downloadable until it expires.
 *
 * What is NOT exported, by design: credential material (BYOK key ciphertext, OAuth tokens, token
 * hashes, session ids, project env vars, SSO client secrets, TOTP secrets, invite tokens), raw agent
 * events (`ChatMessage.rawContent`) and internal storage keys.
 */
import { Zip, ZipDeflate } from 'fflate';
import type { Prisma } from '@prisma/client';
import {
  API_PREFIX,
  DATA_EXPORT_CONTENT_TYPE,
  MAX_ACTIVE_DATA_EXPORTS,
  type DataExportDto,
} from '@loose/shared';
import type { DataExport } from '@prisma/client';
import type { AppContext } from '../../context';
import { AppError } from '../../lib/errors';
import { pageArgs, toPage, type Page } from '../../lib/pagination';
import type { PaginationQuery } from '@loose/shared';

/** Compressed-size ceiling of one export (it is assembled in memory before upload). */
export const DATA_EXPORT_MAX_BYTES = 256 * 1024 * 1024;
const ROW_BATCH = 500;
const STALE_RUNNING_MS = 60 * 60_000;

// ---- DTO ------------------------------------------------------------------------------------

export function exportDownloadPath(row: Pick<DataExport, 'id' | 'kind' | 'orgId'>): string {
  return row.kind === 'ORG' && row.orgId
    ? `${API_PREFIX}/orgs/${row.orgId}/data-exports/${row.id}/download`
    : `${API_PREFIX}/users/me/privacy/exports/${row.id}/download`;
}

/** Upper bound of a download link, whatever the configured storage TTL (bearer-link hygiene). */
export const DATA_EXPORT_MAX_LINK_TTL_SEC = 300;

/** `min(configured, 5 min, seconds until the export expires)`, floored; 0 when already expired. */
export function exportLinkTtlSec(
  configuredSec: number,
  expiresAt: Date | null,
  now: Date = new Date(),
): number {
  const cap = Math.min(configuredSec, DATA_EXPORT_MAX_LINK_TTL_SEC);
  if (!expiresAt) return Math.max(0, cap);
  return Math.max(0, Math.min(cap, Math.floor((expiresAt.getTime() - now.getTime()) / 1000)));
}

function isDownloadable(row: DataExport, now = new Date()): boolean {
  return (
    row.status === 'SUCCEEDED' &&
    Boolean(row.storageKey) &&
    (row.expiresAt === null || row.expiresAt.getTime() > now.getTime())
  );
}

export function toDataExportDto(row: DataExport, now = new Date()): DataExportDto {
  const expired = row.status === 'SUCCEEDED' && !isDownloadable(row, now);
  return {
    id: row.id,
    kind: row.kind,
    status: expired ? 'EXPIRED' : row.status,
    orgId: row.orgId,
    bytes: row.bytes,
    error: row.error,
    expiresAt: row.expiresAt ? row.expiresAt.toISOString() : null,
    completedAt: row.completedAt ? row.completedAt.toISOString() : null,
    createdAt: row.createdAt.toISOString(),
    downloadUrl: isDownloadable(row, now) ? exportDownloadPath(row) : null,
  };
}

// ---- requests -------------------------------------------------------------------------------

export interface ExportScope {
  kind: 'USER' | 'ORG';
  requestedById: string;
  orgId?: string;
}

/**
 * Queue an export. At most `MAX_ACTIVE_DATA_EXPORTS` pending/running export per requester and scope:
 * asking again while one is in progress returns that one (`created: false`).
 */
export async function requestDataExport(
  ctx: AppContext,
  scope: ExportScope,
  ip?: string,
): Promise<{ dto: DataExportDto; created: boolean }> {
  const where: Prisma.DataExportWhereInput = {
    kind: scope.kind,
    requestedById: scope.requestedById,
    orgId: scope.kind === 'ORG' ? (scope.orgId ?? null) : null,
    status: { in: ['PENDING', 'RUNNING'] },
  };
  const res = await ctx.prisma.$transaction(
    async (tx) => {
      // Serialise concurrent requests of the same requester/scope.
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${`data-export:${scope.requestedById}:${scope.orgId ?? ''}`}, 0))`;
      const active = await tx.dataExport.findMany({ where, orderBy: { createdAt: 'desc' } });
      if (active.length >= MAX_ACTIVE_DATA_EXPORTS && active[0]) {
        return { row: active[0], created: false };
      }
      const created = await tx.dataExport.create({
        data: {
          kind: scope.kind,
          orgId: scope.kind === 'ORG' ? (scope.orgId ?? null) : null,
          requestedById: scope.requestedById,
        },
      });
      return { row: created, created: true };
    },
    { maxWait: 10_000, timeout: 15_000 },
  );
  if (res.created) {
    await ctx.audit.record({
      orgId: res.row.orgId,
      actorId: scope.requestedById,
      action: 'data_export.create',
      target: res.row.id,
      meta: { kind: scope.kind },
      ip,
    });
    await ctx.jobs.enqueue(
      'data-export',
      { exportId: res.row.id },
      { jobId: `data-export:${res.row.id}` },
    );
  }
  return { dto: toDataExportDto(res.row), created: res.created };
}

export async function listDataExports(
  ctx: AppContext,
  scope: { kind: 'USER' | 'ORG'; requestedById?: string; orgId?: string },
  q: PaginationQuery,
): Promise<Page<DataExportDto>> {
  const rows = await ctx.prisma.dataExport.findMany({
    where:
      scope.kind === 'ORG'
        ? { kind: 'ORG', orgId: scope.orgId ?? '__none__' }
        : { kind: 'USER', requestedById: scope.requestedById ?? '__none__' },
    orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
    ...pageArgs(q),
  });
  const now = new Date();
  return toPage(rows, q.limit, (r) => toDataExportDto(r, now));
}

export async function getDataExport(
  ctx: AppContext,
  scope: { kind: 'USER' | 'ORG'; requestedById?: string; orgId?: string },
  id: string,
): Promise<DataExport> {
  const row = await ctx.prisma.dataExport.findFirst({
    where:
      scope.kind === 'ORG'
        ? { id, kind: 'ORG', orgId: scope.orgId ?? '__none__' }
        : { id, kind: 'USER', requestedById: scope.requestedById ?? '__none__' },
  });
  if (!row) throw new AppError('LSE-NF-001', { devMessage: 'Data export not found' });
  return row;
}

/** Resolve a downloadable export's file: a signed URL when the backend has one, else a stream. */
export async function openDataExportDownload(
  ctx: AppContext,
  row: DataExport,
): Promise<
  | { kind: 'redirect'; url: string }
  | { kind: 'stream'; stream: NodeJS.ReadableStream; bytes: number; filename: string }
> {
  if (!isDownloadable(row) || !row.storageKey) {
    throw new AppError('LSE-NF-001', {
      devMessage:
        row.status === 'SUCCEEDED' ? 'Data export has expired' : 'Data export is not ready',
    });
  }
  const filename = `loose-${row.kind.toLowerCase()}-export-${row.id}.zip`;
  // A presigned URL is a bearer link: it must not outlive the export itself (P10-SEC-016). When
  // less than a second of validity is left the file is streamed through the authenticated API.
  const ttlSec = exportLinkTtlSec(ctx.env.S3_SIGNED_URL_TTL_SEC, row.expiresAt);
  const url =
    ttlSec >= 1
      ? ((await ctx.storage.signedUrl?.(row.storageKey, {
          filename,
          contentType: DATA_EXPORT_CONTENT_TYPE,
          ttlSec,
        })) ?? null)
      : null;
  if (url) return { kind: 'redirect', url };
  const obj = await ctx.storage.get(row.storageKey);
  if (!obj) throw new AppError('LSE-NF-001', { devMessage: 'Data export file is missing' });
  return { kind: 'stream', stream: obj.stream, bytes: obj.bytes, filename };
}

// ---- ZIP assembly ---------------------------------------------------------------------------

const jsonReplacer = (_k: string, v: unknown) => (typeof v === 'bigint' ? v.toString() : v);

class ZipBuilder {
  readonly #chunks: Uint8Array[] = [];
  #bytes = 0;
  #done = false;
  #error: Error | undefined;
  readonly #zip: Zip;
  readonly manifest: { file: string; rows: number }[] = [];

  constructor() {
    this.#zip = new Zip((err, chunk, final) => {
      if (err) {
        this.#error = err;
        return;
      }
      this.#chunks.push(chunk);
      this.#bytes += chunk.length;
      if (final) this.#done = true;
    });
  }

  #check() {
    if (this.#error) throw this.#error;
    if (this.#bytes > DATA_EXPORT_MAX_BYTES) {
      throw new Error('Export exceeds the maximum size');
    }
  }

  addJson(name: string, value: unknown) {
    const file = new ZipDeflate(name, { level: 6 });
    this.#zip.add(file);
    file.push(new TextEncoder().encode(JSON.stringify(value, jsonReplacer, 2)), true);
    this.manifest.push({ file: name, rows: Array.isArray(value) ? value.length : 1 });
    this.#check();
  }

  /** NDJSON file fed by keyset-paginated batches (never holds more than one batch of rows). */
  async addNdjson<T extends { id: string }>(
    name: string,
    fetchBatch: (after: string | undefined) => Promise<T[]>,
  ) {
    const file = new ZipDeflate(name, { level: 6 });
    this.#zip.add(file);
    const enc = new TextEncoder();
    let rows = 0;
    let after: string | undefined;
    for (;;) {
      const batch = await fetchBatch(after);
      if (batch.length === 0) break;
      const text = batch.map((r) => JSON.stringify(r, jsonReplacer)).join('\n') + '\n';
      file.push(enc.encode(text), false);
      rows += batch.length;
      after = batch[batch.length - 1]?.id;
      this.#check();
      if (batch.length < ROW_BATCH) break;
    }
    file.push(new Uint8Array(0), true);
    this.manifest.push({ file: name, rows });
    this.#check();
  }

  finish(): Uint8Array {
    this.#zip.end();
    this.#check();
    if (!this.#done) throw new Error('ZIP assembly did not complete');
    const out = new Uint8Array(this.#bytes);
    let off = 0;
    for (const c of this.#chunks) {
      out.set(c, off);
      off += c.length;
    }
    return out;
  }
}

const cursorArgs = (cursor: string | undefined): { cursor?: { id: string }; skip?: number } =>
  cursor ? { cursor: { id: cursor }, skip: 1 } : {};

async function collectUser(ctx: AppContext, zip: ZipBuilder, userId: string) {
  const p = ctx.prisma;
  zip.addJson(
    'profile.json',
    await p.user.findUniqueOrThrow({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        name: true,
        avatarUrl: true,
        preferredMode: true,
        memory: true,
        githubId: true,
        googleId: true,
        totpEnabledAt: true,
        deletionScheduledAt: true,
        createdAt: true,
      },
    }),
  );
  zip.addJson(
    'memberships.json',
    await p.orgMember.findMany({
      where: { userId },
      select: {
        role: true,
        lockedMode: true,
        createdAt: true,
        org: { select: { id: true, name: true, slug: true } },
      },
    }),
  );
  zip.addJson(
    'oauth-accounts.json',
    await p.oAuthAccount.findMany({
      where: { userId },
      select: { provider: true, providerAccountId: true, scopes: true, createdAt: true },
    }),
  );
  zip.addJson(
    'api-keys.json',
    await p.apiKey.findMany({
      where: { userId },
      select: {
        id: true,
        orgId: true,
        provider: true,
        label: true,
        last4: true,
        status: true,
        lastValidatedAt: true,
        monthlyLimitUsd: true,
        createdAt: true,
      },
    }),
  );
  zip.addJson(
    'api-tokens.json',
    await p.apiToken.findMany({
      where: { userId },
      select: {
        id: true,
        orgId: true,
        name: true,
        scopes: true,
        lastUsedAt: true,
        expiresAt: true,
        createdAt: true,
      },
    }),
  );
  zip.addJson(
    'sign-in-sessions.json',
    await p.authSession.findMany({
      where: { userId },
      select: { createdAt: true, expiresAt: true, ip: true, userAgent: true },
    }),
  );
  await zip.addNdjson('sessions.ndjson', (c) =>
    p.session.findMany({
      where: { userId },
      omit: { sandboxId: true, runnerPid: true, agentSessionId: true },
      orderBy: { id: 'asc' },
      take: ROW_BATCH,
      ...cursorArgs(c),
    }),
  );
  await zip.addNdjson('messages.ndjson', (c) =>
    p.chatMessage.findMany({
      where: { session: { userId } },
      omit: { rawContent: true },
      orderBy: { id: 'asc' },
      take: ROW_BATCH,
      ...cursorArgs(c),
    }),
  );
  await zip.addNdjson('artifacts.ndjson', (c) =>
    p.artifact.findMany({
      where: { session: { userId } },
      omit: { storageKey: true },
      orderBy: { id: 'asc' },
      take: ROW_BATCH,
      ...cursorArgs(c),
    }),
  );
  await zip.addNdjson('usage-events.ndjson', (c) =>
    p.usageEvent.findMany({
      where: { userId },
      orderBy: { id: 'asc' },
      take: ROW_BATCH,
      ...cursorArgs(c),
    }),
  );
  await zip.addNdjson('runs.ndjson', (c) =>
    p.run.findMany({
      where: { userId },
      orderBy: { id: 'asc' },
      take: ROW_BATCH,
      ...cursorArgs(c),
    }),
  );
  await zip.addNdjson('audit-log.ndjson', (c) =>
    p.auditLog.findMany({
      where: { actorId: userId },
      select: {
        id: true,
        orgId: true,
        action: true,
        target: true,
        meta: true,
        ip: true,
        createdAt: true,
      },
      orderBy: { id: 'asc' },
      take: ROW_BATCH,
      ...cursorArgs(c),
    }),
  );
}

async function collectOrg(ctx: AppContext, zip: ZipBuilder, orgId: string) {
  const p = ctx.prisma;
  zip.addJson(
    'organization.json',
    await p.organization.findUniqueOrThrow({
      where: { id: orgId },
      select: {
        id: true,
        name: true,
        slug: true,
        policy: true,
        memory: true,
        ipAllowlistEnabled: true,
        ipAllowlist: true,
        requireAdmin2fa: true,
        featureFlags: true,
        deletionScheduledAt: true,
        createdAt: true,
      },
    }),
  );
  zip.addJson(
    'members.json',
    await p.orgMember.findMany({
      where: { orgId },
      select: {
        role: true,
        lockedMode: true,
        createdAt: true,
        user: { select: { id: true, email: true, name: true } },
      },
    }),
  );
  zip.addJson(
    'invites.json',
    await p.orgInvite.findMany({
      where: { orgId },
      select: {
        id: true,
        email: true,
        role: true,
        expiresAt: true,
        acceptedAt: true,
        revokedAt: true,
        createdAt: true,
      },
    }),
  );
  zip.addJson(
    'projects.json',
    await p.project.findMany({ where: { orgId }, omit: { envVarsEnc: true } }),
  );
  zip.addJson('policy-packs.json', await p.policyPack.findMany({ where: { orgId } }));
  zip.addJson(
    'domains.json',
    await p.orgDomain.findMany({
      where: { orgId },
      select: { domain: true, verifiedAt: true, createdAt: true },
    }),
  );
  zip.addJson(
    'sso-connection.json',
    await p.ssoConnection.findUnique({
      where: { orgId },
      select: {
        protocol: true,
        enabled: true,
        issuer: true,
        clientId: true,
        defaultRole: true,
        jitProvisioning: true,
        enforce: true,
        allowOwnerBypass: true,
        createdAt: true,
      },
    }),
  );
  await zip.addNdjson('sessions.ndjson', (c) =>
    p.session.findMany({
      where: { project: { orgId } },
      omit: { sandboxId: true, runnerPid: true, agentSessionId: true },
      orderBy: { id: 'asc' },
      take: ROW_BATCH,
      ...cursorArgs(c),
    }),
  );
  await zip.addNdjson('messages.ndjson', (c) =>
    p.chatMessage.findMany({
      where: { session: { project: { orgId } } },
      omit: { rawContent: true },
      orderBy: { id: 'asc' },
      take: ROW_BATCH,
      ...cursorArgs(c),
    }),
  );
  await zip.addNdjson('artifacts.ndjson', (c) =>
    p.artifact.findMany({
      where: { session: { project: { orgId } } },
      omit: { storageKey: true },
      orderBy: { id: 'asc' },
      take: ROW_BATCH,
      ...cursorArgs(c),
    }),
  );
  await zip.addNdjson('usage-events.ndjson', (c) =>
    p.usageEvent.findMany({
      where: { orgId },
      orderBy: { id: 'asc' },
      take: ROW_BATCH,
      ...cursorArgs(c),
    }),
  );
  await zip.addNdjson('runs.ndjson', (c) =>
    p.run.findMany({ where: { orgId }, orderBy: { id: 'asc' }, take: ROW_BATCH, ...cursorArgs(c) }),
  );
  await zip.addNdjson('audit-log.ndjson', (c) =>
    p.auditLog.findMany({
      where: { orgId },
      orderBy: { id: 'asc' },
      take: ROW_BATCH,
      ...cursorArgs(c),
    }),
  );
}

// ---- job ------------------------------------------------------------------------------------

/** The `data-export` job body. Idempotent: only a PENDING export is claimed. */
export async function buildDataExport(ctx: AppContext, exportId: string): Promise<void> {
  const claimed = await ctx.prisma.dataExport.updateMany({
    where: { id: exportId, status: 'PENDING' },
    data: { status: 'RUNNING', startedAt: new Date(), error: null },
  });
  if (claimed.count === 0) return;
  const row = await ctx.prisma.dataExport.findUniqueOrThrow({ where: { id: exportId } });
  const key = `exports/${row.id}.zip`;
  try {
    const zip = new ZipBuilder();
    if (row.kind === 'ORG') {
      if (!row.orgId) throw new Error('Org export without an org');
      await collectOrg(ctx, zip, row.orgId);
    } else {
      await collectUser(ctx, zip, row.requestedById);
    }
    zip.addJson('manifest.json', {
      kind: row.kind,
      exportId: row.id,
      generatedAt: new Date().toISOString(),
      subjectId: row.kind === 'ORG' ? row.orgId : row.requestedById,
      files: zip.manifest,
      note: 'Credentials (API keys, tokens, env vars, secrets) and raw agent events are not included.',
    });
    const data = zip.finish();
    const { bytes } = await ctx.storage.put(key, data, { contentType: DATA_EXPORT_CONTENT_TYPE });
    const now = new Date();
    await ctx.prisma.dataExport.update({
      where: { id: row.id },
      data: {
        status: 'SUCCEEDED',
        storageKey: key,
        bytes,
        completedAt: now,
        expiresAt: new Date(now.getTime() + ctx.env.DATA_EXPORT_TTL_HOURS * 3_600_000),
        error: null,
      },
    });
  } catch (err) {
    ctx.logger.error({ err, exportId }, 'data export failed');
    await ctx.storage.delete(key).catch(() => undefined);
    const code = err instanceof AppError ? err.code : undefined;
    await ctx.prisma.dataExport
      .update({
        where: { id: row.id },
        data: {
          status: 'FAILED',
          completedAt: new Date(),
          error:
            code ??
            (err instanceof Error && err.message === 'Export exceeds the maximum size'
              ? err.message
              : 'Export failed'),
        },
      })
      .catch(() => undefined);
  }
}

/**
 * Housekeeping (hourly sweep): delete expired export files, fail exports stuck in RUNNING
 * (their worker died). Returns how many exports were expired.
 */
export async function expireDataExports(ctx: AppContext, now = new Date()): Promise<number> {
  const stale = await ctx.prisma.dataExport.updateMany({
    where: {
      status: 'RUNNING',
      startedAt: { lt: new Date(now.getTime() - STALE_RUNNING_MS) },
    },
    data: { status: 'FAILED', error: 'Export timed out', completedAt: now },
  });
  if (stale.count > 0) ctx.logger.warn({ count: stale.count }, 'failed stuck data exports');
  let expired = 0;
  for (;;) {
    const rows = await ctx.prisma.dataExport.findMany({
      where: { status: 'SUCCEEDED', expiresAt: { lte: now } },
      take: ROW_BATCH,
      orderBy: { id: 'asc' },
    });
    if (rows.length === 0) return expired;
    let progress = 0;
    for (const r of rows) {
      try {
        if (r.storageKey) await ctx.storage.delete(r.storageKey);
        await ctx.prisma.dataExport.update({
          where: { id: r.id },
          data: { status: 'EXPIRED', storageKey: null },
        });
        expired += 1;
        progress += 1;
      } catch (err) {
        ctx.logger.warn({ err, exportId: r.id }, 'could not delete expired data export');
      }
    }
    if (progress === 0 || rows.length < ROW_BATCH) return expired;
  }
}
