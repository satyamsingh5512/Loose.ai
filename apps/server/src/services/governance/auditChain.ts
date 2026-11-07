/**
 * Tamper-evident audit log (spec §8.20; phase10-design.md §2.2).
 *
 * Every audit row belongs to a chain (`orgId`, or `global` for user-level events) and carries
 * `seq`, `prevHash` and `hash = HMAC-SHA256(key, canonicalJson({v, chain, seq, prevHash, orgId,
 * actorDigest, action, target, meta, createdAt}))`. `ip` and the raw `actorId` are excluded so GDPR
 * redaction (nulling them) never breaks verification; `actorDigest` stands in for the actor.
 * REAUDIT-007: redaction is only legitimate as part of an account deletion, which appends a signed
 * `audit.redacted` marker (meta.actorDigest) to every affected chain; verification reports a row
 * whose actorId was removed without such a marker (`hash_mismatch`). The runtime DB role cannot
 * UPDATE attribution at all (runtime-role.sql, migration 20261019180000_audit_redaction_definer).
 *
 * Appends are serialised per chain with `pg_advisory_xact_lock`. The database trigger from the
 * Phase 10 migration additionally forbids UPDATE/DELETE of audit rows; this module is the only code
 * that opens a `loose.audit_maintenance` transaction for legacy sealing; retention deletes through the
 * SECURITY DEFINER functions of migration 20261019120000_audit_retention_definer (the production
 * runtime role has no DELETE on AuditLog).
 */
import { createHash, createHmac, hkdfSync } from 'node:crypto';
import type { Prisma, AuditLog, PrismaClient } from '@prisma/client';
import {
  AUDIT_GENESIS_HASH,
  AUDIT_GLOBAL_CHAIN,
  type AuditChainBreakReason,
  type AuditChainVerifyDto,
} from '@loose/shared';

export type Db = PrismaClient | Prisma.TransactionClient;

/** Hash-format version, part of the signed payload. */
export const AUDIT_CHAIN_VERSION = 1;

const VERIFY_BATCH = 1000;
const BACKFILL_BATCH = 500;

// ---- primitives ---------------------------------------------------------------------------------

/** JSON with recursively sorted object keys and no whitespace (stable across JSONB round-trips). */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
}

/** `AUDIT_CHAIN_SECRET`, else HKDF-SHA256(SESSION_SECRET, salt 'loose-audit-chain', info 'v1'). */
export function deriveAuditChainKey(env: {
  AUDIT_CHAIN_SECRET?: string | undefined;
  SESSION_SECRET: string;
}): Buffer {
  if (env.AUDIT_CHAIN_SECRET) return Buffer.from(env.AUDIT_CHAIN_SECRET, 'utf8');
  return Buffer.from(
    hkdfSync('sha256', env.SESSION_SECRET, 'loose-audit-chain', 'v1', 32) as ArrayBuffer,
  );
}

export function actorDigestOf(actorId: string | null | undefined): string | null {
  return actorId ? createHash('sha256').update(`actor:${actorId}`).digest('hex') : null;
}

export function chainOf(orgId: string | null | undefined): string {
  return orgId ?? AUDIT_GLOBAL_CHAIN;
}

/** The fields covered by an entry's hash. */
export interface ChainedFields {
  chain: string;
  seq: number;
  prevHash: string;
  orgId: string | null;
  actorDigest: string | null;
  action: string;
  target: string | null;
  meta: unknown;
  createdAt: Date;
}

export function computeEntryHash(key: Buffer, f: ChainedFields): string {
  const payload = canonicalJson({
    v: AUDIT_CHAIN_VERSION,
    chain: f.chain,
    seq: f.seq,
    prevHash: f.prevHash,
    orgId: f.orgId,
    actorDigest: f.actorDigest,
    action: f.action,
    target: f.target,
    meta: f.meta ?? null,
    createdAt: f.createdAt.toISOString(),
  });
  return createHmac('sha256', key).update(payload).digest('hex');
}

/** Normalise like JSONB would (drops undefined, NaN → null, Dates → strings). */
export function normalizeMeta(meta: unknown): Prisma.InputJsonValue | undefined {
  if (meta === undefined || meta === null) return undefined;
  return JSON.parse(JSON.stringify(meta)) as Prisma.InputJsonValue;
}

function lockChain(tx: Prisma.TransactionClient, chain: string) {
  return tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${chain}, 0))`;
}

/**
 * Enter maintenance mode for this transaction (the DB trigger then permits UPDATE/DELETE). Not a
 * privilege boundary: any session can set it, which is why the runtime role holds no DELETE.
 */
export function enterAuditMaintenance(tx: Prisma.TransactionClient) {
  return tx.$executeRaw`SELECT set_config('loose.audit_maintenance', 'on', true)`;
}

async function chainHead(
  tx: Prisma.TransactionClient,
  chain: string,
): Promise<{ seq: number; hash: string }> {
  const head = await tx.auditLog.findFirst({
    where: { chain, seq: { not: null }, hash: { not: null } },
    orderBy: { seq: 'desc' },
    select: { seq: true, hash: true },
  });
  return head?.seq != null && head.hash ? { seq: head.seq, hash: head.hash } : { seq: 0, hash: '' };
}

// ---- append -------------------------------------------------------------------------------------

export interface NewAuditRow {
  orgId?: string | null | undefined;
  actorId?: string | null | undefined;
  action: string;
  target?: string | null | undefined;
  /** Already scrubbed of secrets. */
  meta?: unknown;
  ip?: string | null | undefined;
}

/**
 * Append one entry to its chain. Takes the chain's advisory lock for the rest of the transaction
 * `tx` (so concurrent appends to one chain are strictly ordered and gap-free).
 */
export async function appendChainedEntry(
  tx: Prisma.TransactionClient,
  key: Buffer,
  row: NewAuditRow,
): Promise<AuditLog> {
  const orgId = row.orgId ?? null;
  const chain = chainOf(orgId);
  await lockChain(tx, chain);
  const head = await chainHead(tx, chain);
  const meta = normalizeMeta(row.meta);
  const seq = head.seq + 1;
  const prevHash = head.hash || AUDIT_GENESIS_HASH;
  const actorDigest = actorDigestOf(row.actorId);
  // Generated after the lock is held, at ms precision (what Postgres stores) so the hash matches.
  const createdAt = new Date();
  const hash = computeEntryHash(key, {
    chain,
    seq,
    prevHash,
    orgId,
    actorDigest,
    action: row.action,
    target: row.target ?? null,
    meta,
    createdAt,
  });
  return tx.auditLog.create({
    data: {
      orgId,
      actorId: row.actorId ?? null,
      action: row.action,
      target: row.target ?? null,
      ...(meta !== undefined ? { meta } : {}),
      ip: row.ip?.slice(0, 64) ?? null,
      chain,
      seq,
      prevHash,
      hash,
      actorDigest,
      createdAt,
    },
  });
}

// ---- cutover marker (P10-SEC-006) -------------------------------------------------------------

/**
 * Instant before which unchained audit rows are legitimate history. A missing marker fails closed
 * (the epoch): every unchained row then counts as post-cutover and verification reports it.
 */
export async function getAuditCutover(db: Db): Promise<Date> {
  const row = await db.auditChainCutover.findUnique({ where: { id: 'singleton' } });
  return row?.cutoverAt ?? new Date(0);
}

// ---- backfill (pre-Phase-10 rows) ---------------------------------------------------------------

/** Chains (org ids and `global`) that still have unchained rows. */
export async function chainsWithLegacyRows(prisma: PrismaClient): Promise<string[]> {
  const rows = await prisma.auditLog.groupBy({
    by: ['orgId'],
    where: { chain: null, createdAt: { lt: await getAuditCutover(prisma) } },
  });
  return rows.map((r) => chainOf(r.orgId));
}

/**
 * Seal unchained (pre-Phase-10) rows into their chain, oldest first, appended after the current
 * head. The chain proves the history is unchanged *since sealing*, not since it was written.
 * Only rows older than the chain cutover are sealed: an unchained row from after the cutover is
 * left in place as evidence (verification fails on it) instead of being laundered into the chain.
 * Idempotent and resumable; returns the number of rows sealed.
 */
export async function backfillChain(
  prisma: PrismaClient,
  key: Buffer,
  chain: string,
  opts: { maxRows?: number } = {},
): Promise<number> {
  const orgId = chain === AUDIT_GLOBAL_CHAIN ? null : chain;
  const maxRows = opts.maxRows ?? Number.POSITIVE_INFINITY;
  const cutover = await getAuditCutover(prisma);
  let sealed = 0;
  for (;;) {
    const n = await prisma.$transaction(
      async (tx) => {
        await lockChain(tx, chain);
        const legacy = await tx.auditLog.findMany({
          where: { orgId, chain: null, createdAt: { lt: cutover } },
          orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
          take: Math.min(BACKFILL_BATCH, maxRows - sealed),
        });
        if (legacy.length === 0) return 0;
        await enterAuditMaintenance(tx);
        let head = await chainHead(tx, chain);
        for (const r of legacy) {
          const seq = head.seq + 1;
          const prevHash = head.hash || AUDIT_GENESIS_HASH;
          const actorDigest = actorDigestOf(r.actorId);
          const hash = computeEntryHash(key, {
            chain,
            seq,
            prevHash,
            orgId,
            actorDigest,
            action: r.action,
            target: r.target,
            meta: r.meta,
            createdAt: r.createdAt,
          });
          await tx.auditLog.update({
            where: { id: r.id },
            data: { chain, seq, prevHash, hash, actorDigest },
          });
          head = { seq, hash };
        }
        return legacy.length;
      },
      { maxWait: 10_000, timeout: 60_000 },
    );
    sealed += n;
    if (n === 0 || sealed >= maxRows) return sealed;
  }
}

// ---- verify -------------------------------------------------------------------------------------

type VerifyRow = Pick<
  AuditLog,
  | 'id'
  | 'orgId'
  | 'actorId'
  | 'action'
  | 'target'
  | 'meta'
  | 'chain'
  | 'seq'
  | 'prevHash'
  | 'hash'
  | 'actorDigest'
  | 'createdAt'
>;

/**
 * Walk a chain in `seq` order and report the first inconsistency. Entries before the lowest
 * remaining `seq` (removed by retention) are not checked: the first row's `prevHash` is the anchor,
 * and it is cross-checked against the `audit.retention_purged` marker when one is present.
 */
export async function verifyChain(
  prisma: PrismaClient,
  key: Buffer,
  chain: string,
): Promise<AuditChainVerifyDto> {
  const orgId = chain === AUDIT_GLOBAL_CHAIN ? null : chain;
  const cutover = await getAuditCutover(prisma);
  // Unchained rows older than the cutover are pre-Phase-10 history; newer ones are not legitimate.
  const legacyUnchained = await prisma.auditLog.count({
    where: { orgId, chain: null, createdAt: { lt: cutover } },
  });

  let checked = 0;
  let firstSeq: number | null = null;
  let lastSeq: number | null = null;
  let lastHash: string | null = null;
  let brokenAt: AuditChainVerifyDto['brokenAt'] = null;
  const fail = (row: Pick<VerifyRow, 'id' | 'seq'>, reason: AuditChainBreakReason) => {
    brokenAt = { seq: row.seq, id: row.id, reason };
  };

  // REAUDIT-007: actor digests announced by signed `audit.redacted` markers, and the first row per
  // digest whose raw actorId is gone.
  const redactedDigests = new Set<string>();
  const unattributed = new Map<string, Pick<VerifyRow, 'id' | 'seq'>>();

  let cursor = 0;
  scan: for (;;) {
    const rows: VerifyRow[] = await prisma.auditLog.findMany({
      where: { chain, seq: { gt: cursor } },
      orderBy: { seq: 'asc' },
      take: VERIFY_BATCH,
      select: {
        id: true,
        orgId: true,
        actorId: true,
        action: true,
        target: true,
        meta: true,
        chain: true,
        seq: true,
        prevHash: true,
        hash: true,
        actorDigest: true,
        createdAt: true,
      },
    });
    if (rows.length === 0) break;
    for (const r of rows) {
      if (r.seq == null || !r.hash || !r.prevHash) {
        fail(r, 'missing_hash');
        break scan;
      }
      if (firstSeq === null) {
        firstSeq = r.seq;
        // Anchored at seq 1 the chain must start at GENESIS; otherwise older rows were purged.
        if (r.seq === 1 && r.prevHash !== AUDIT_GENESIS_HASH) {
          fail(r, 'prev_mismatch');
          break scan;
        }
      } else {
        if (r.seq !== (lastSeq ?? 0) + 1) {
          fail(r, 'seq_gap');
          break scan;
        }
        if (r.prevHash !== lastHash) {
          fail(r, 'prev_mismatch');
          break scan;
        }
      }
      if (
        r.chain !== chain ||
        r.orgId !== orgId ||
        (r.actorId !== null && actorDigestOf(r.actorId) !== r.actorDigest)
      ) {
        fail(r, 'hash_mismatch');
        break scan;
      }
      const expected = computeEntryHash(key, {
        chain,
        seq: r.seq,
        prevHash: r.prevHash,
        orgId,
        actorDigest: r.actorDigest,
        action: r.action,
        target: r.target,
        meta: r.meta,
        createdAt: r.createdAt,
      });
      if (expected !== r.hash) {
        fail(r, 'hash_mismatch');
        break scan;
      }
      if (r.action === 'audit.redacted') {
        const digest = (r.meta as { actorDigest?: unknown } | null)?.actorDigest;
        if (typeof digest === 'string') redactedDigests.add(digest);
      }
      if (r.actorId === null && r.actorDigest !== null && !unattributed.has(r.actorDigest)) {
        unattributed.set(r.actorDigest, { id: r.id, seq: r.seq });
      }
      checked += 1;
      lastSeq = r.seq;
      lastHash = r.hash;
    }
    cursor = lastSeq ?? cursor;
    if (rows.length < VERIFY_BATCH) break;
  }

  if (!brokenAt) {
    for (const [digest, row] of unattributed) {
      if (!redactedDigests.has(digest)) {
        fail(row, 'hash_mismatch'); // attribution removed outside an account deletion
        break;
      }
    }
  }
  if (!brokenAt) {
    const forged = await prisma.auditLog.findFirst({
      where: { orgId, chain: null, createdAt: { gte: cutover } },
      orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
      select: { id: true },
    });
    if (forged) brokenAt = { seq: null, id: forged.id, reason: 'unchained_after_cutover' };
  }
  if (!brokenAt) {
    // Rows the walk above never visits but the org's log lists: filed under another chain, or in
    // this chain without a position/hash (the triggers of 20261019001500_audit_insert_guard refuse
    // both; this catches rows written around them).
    const hidden = await prisma.auditLog.findFirst({
      where: {
        OR: [
          { orgId, AND: [{ chain: { not: null } }, { chain: { not: chain } }] },
          { chain, OR: [{ seq: null }, { hash: null }, { prevHash: null }] },
        ],
      },
      orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
      select: { id: true, seq: true, chain: true },
    });
    if (hidden) {
      brokenAt = {
        seq: hidden.seq,
        id: hidden.id,
        reason: hidden.chain === chain ? 'missing_hash' : 'hash_mismatch',
      };
    }
  }

  const anchoredAt = firstSeq !== null && firstSeq > 1 ? firstSeq : null;
  if (!brokenAt && anchoredAt !== null)
    brokenAt = await checkPurgeCoversStart(prisma, chain, anchoredAt);

  return {
    ok: brokenAt === null,
    chain,
    checked,
    firstSeq,
    lastSeq,
    lastHash,
    legacyUnchained,
    anchoredAt,
    brokenAt,
    verifiedAt: new Date().toISOString(),
  };
}

/**
 * Rows before `firstSeq` are gone. That is legitimate only if a retention purge says so: the chain
 * must contain an `audit.retention_purged` marker whose `purgedThroughSeq` reaches `firstSeq - 1`
 * (an interrupted purge may have deleted less than it announced, never more). When the marker ends
 * exactly there, its `anchorHash` must equal the first remaining row's `prevHash`.
 */
async function checkPurgeCoversStart(
  prisma: PrismaClient,
  chain: string,
  firstSeq: number,
): Promise<AuditChainVerifyDto['brokenAt']> {
  const first = await prisma.auditLog.findFirst({
    where: { chain, seq: firstSeq },
    select: { id: true, prevHash: true },
  });
  if (!first) return null;
  const markers = await prisma.auditLog.findMany({
    where: { chain, action: 'audit.retention_purged' },
    orderBy: { seq: 'desc' },
    take: 50,
    select: { meta: true },
  });
  let covered = false;
  for (const m of markers) {
    const meta = m.meta as { purgedThroughSeq?: unknown; anchorHash?: unknown } | null;
    const through = typeof meta?.purgedThroughSeq === 'number' ? meta.purgedThroughSeq : -1;
    if (through < firstSeq - 1) continue;
    covered = true;
    if (through === firstSeq - 1 && typeof meta?.anchorHash === 'string') {
      if (first.prevHash !== meta.anchorHash) {
        return { seq: firstSeq, id: first.id, reason: 'prev_mismatch' };
      }
    }
    break;
  }
  return covered ? null : { seq: firstSeq, id: first.id, reason: 'seq_gap' };
}
