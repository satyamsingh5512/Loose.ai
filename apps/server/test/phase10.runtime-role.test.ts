/**
 * P10-SEC-006 remainder: the API/worker must not run as the owner of the AuditLog table. A table
 * owner can disable or replace the insert/update guard triggers (or a superuser can set
 * `session_replication_role = replica`) and then backdate unchained rows so verification treats
 * them as pre-cutover legacy history.
 *
 * This applies the production grant script (`docker/postgres/runtime-role.sql`) verbatim, with the
 * role name swapped for a throwaway one, to the test database, connects as that role and proves:
 * every way to switch off or rewrite the guards is denied, the cutover marker is read-only, a
 * backdated insert still gets a post-cutover `createdAt` (so verification fails), and the normal
 * audited workflow (chained append + verify) still works.
 *
 * P10-SEC-006-R2: the runtime role holds no DELETE on AuditLog (even with the maintenance GUC on);
 * retention deletes through SECURITY DEFINER functions that never remove the chain tail.
 *
 * REAUDIT-007: the runtime role holds no UPDATE of AuditLog attribution (actorId / ip) either; a
 * deleted user's attribution is redacted only through `loose_audit_redact_user` during a due,
 * executing account deletion, which leaves a signed `audit.redacted` marker per chain, and
 * verifyChain flags attribution removed without one.
 */
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { PrismaClient } from '@prisma/client';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AppContext } from '../src/context';
import { AuditService } from '../src/services/audit.service';
import {
  actorDigestOf,
  backfillChain,
  enterAuditMaintenance,
  getAuditCutover,
  verifyChain,
} from '../src/services/governance/auditChain';
import { runDeletionSweep } from '../src/services/governance/deletion';
import { purgeAuditLog } from '../src/services/governance/retention';
import { createLogger } from '../src/lib/logger';
import { legacyAuditRow } from './auditFixtures';
import { makeApp, resetDb, TEST_DATABASE_URL, testPrisma } from './helpers';

const DAY = 86_400_000;

const owner = testPrisma();
const role = `loose_rt_${randomBytes(4).toString('hex')}`;
const password = randomBytes(18).toString('hex');
const key = randomBytes(32);
let runtime: PrismaClient;

/** Split a plain SQL script into statements (`;` at line end, outside `$$` bodies). */
function statements(sql: string): string[] {
  const out: string[] = [];
  let current = '';
  let inBody = false;
  for (const line of sql.split('\n')) {
    if (line.trim().startsWith('--') && !inBody) continue;
    current += `${line}\n`;
    if ((line.match(/\$\$/g) ?? []).length % 2 === 1) inBody = !inBody;
    if (!inBody && /;\s*$/.test(line)) {
      out.push(current.trim());
      current = '';
    }
  }
  if (current.trim()) out.push(current.trim());
  return out;
}

const script = readFileSync(
  new URL('../../../docker/postgres/runtime-role.sql', import.meta.url),
  'utf8',
).replaceAll('loose_app', role);

async function applyScript() {
  for (const stmt of statements(script)) await owner.$executeRawUnsafe(stmt);
}

/** Run `sql` as the runtime role and return the PostgreSQL error text (or null on success). */
async function asRuntime(sql: string): Promise<string | null> {
  try {
    await runtime.$executeRawUnsafe(sql);
    return null;
  } catch (err) {
    return String((err as Error).message);
  }
}

const DENIED = /permission denied|must be owner|must be superuser/i;

beforeAll(async () => {
  await applyScript();
  // Password never in the script; hex is safe to inline for this throwaway role.
  await owner.$executeRawUnsafe(`ALTER ROLE ${role} WITH LOGIN PASSWORD '${password}'`);
  const url = new URL(TEST_DATABASE_URL);
  url.username = role;
  url.password = password;
  runtime = new PrismaClient({ datasources: { db: { url: url.toString() } } });
});

afterAll(async () => {
  await runtime?.$disconnect();
  await owner.$executeRawUnsafe(`DROP OWNED BY ${role}`);
  await owner.$executeRawUnsafe(`DROP ROLE IF EXISTS ${role}`);
  await owner.$disconnect();
});

beforeEach(async () => {
  await resetDb(owner);
});

async function org(): Promise<string> {
  const o = await owner.organization.create({
    data: { name: 'Runtime role', slug: `rt-${randomBytes(4).toString('hex')}` },
  });
  return o.id;
}

describe('P10-SEC-006: the runtime DB role cannot switch off the AuditLog guards', () => {
  it('is neither superuser nor owner nor member of any role, and the script is idempotent', async () => {
    await applyScript(); // second run: no error, same result
    const [attrs] = await owner.$queryRawUnsafe<
      {
        rolsuper: boolean;
        rolcreatedb: boolean;
        rolcreaterole: boolean;
        rolbypassrls: boolean;
        rolreplication: boolean;
      }[]
    >(
      `SELECT rolsuper, rolcreatedb, rolcreaterole, rolbypassrls, rolreplication FROM pg_roles WHERE rolname = '${role}'`,
    );
    expect(attrs).toEqual({
      rolsuper: false,
      rolcreatedb: false,
      rolcreaterole: false,
      rolbypassrls: false,
      rolreplication: false,
    });
    const memberships = await owner.$queryRawUnsafe<unknown[]>(
      `SELECT 1 FROM pg_auth_members WHERE member = '${role}'::regrole`,
    );
    expect(memberships).toHaveLength(0);
    const owned = await owner.$queryRawUnsafe<unknown[]>(
      `SELECT 1 FROM pg_class WHERE relowner = '${role}'::regrole`,
    );
    expect(owned).toHaveLength(0);
  });

  it('control: the owner role CAN disable the guard (why the API must not run as it)', async () => {
    const rollback = new Error('rollback');
    await expect(
      owner.$transaction(async (tx) => {
        await tx.$executeRawUnsafe(
          `ALTER TABLE "AuditLog" DISABLE TRIGGER "AuditLog_insert_guard"`,
        );
        throw rollback;
      }),
    ).rejects.toBe(rollback);
  });

  it.each([
    `ALTER TABLE "AuditLog" DISABLE TRIGGER "AuditLog_insert_guard"`,
    `ALTER TABLE "AuditLog" DISABLE TRIGGER "AuditLog_immutable"`,
    `ALTER TABLE "AuditLog" DISABLE TRIGGER USER`,
    `ALTER TABLE "AuditLog" DISABLE TRIGGER ALL`,
    `DROP TRIGGER "AuditLog_insert_guard" ON "AuditLog"`,
    `ALTER TABLE "AuditLog" ALTER COLUMN "createdAt" SET DEFAULT '2001-01-01'`,
    `CREATE OR REPLACE FUNCTION loose_audit_log_insert_guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$`,
    `CREATE OR REPLACE FUNCTION loose_audit_log_guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$`,
    `CREATE TRIGGER "x_bypass" BEFORE INSERT ON "AuditLog" FOR EACH ROW EXECUTE FUNCTION loose_audit_log_insert_guard()`,
    `CREATE FUNCTION public.x_noop() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$`,
    `CREATE SCHEMA x_bypass`,
    `TRUNCATE "AuditLog"`,
    `SET session_replication_role = replica`,
    `UPDATE "AuditChainCutover" SET "cutoverAt" = now() + interval '10 years'`,
    `DELETE FROM "AuditChainCutover"`,
    `INSERT INTO "AuditChainCutover" ("id", "cutoverAt") VALUES ('x', now())`,
    `DELETE FROM "_prisma_migrations"`,
  ])('denies: %s', async (sql) => {
    expect(await asRuntime(sql)).toMatch(DENIED);
  });

  it('the guard triggers stay enabled and the cutover marker unchanged after every attempt', async () => {
    const triggers = await owner.$queryRawUnsafe<{ tgname: string; tgenabled: string }[]>(
      `SELECT tgname, tgenabled FROM pg_trigger WHERE tgrelid = '"AuditLog"'::regclass AND NOT tgisinternal ORDER BY tgname`,
    );
    expect(triggers).toEqual([
      { tgname: 'AuditLog_immutable', tgenabled: 'O' },
      { tgname: 'AuditLog_insert_guard', tgenabled: 'O' },
    ]);
  });

  it('a backdated insert as the runtime role cannot pose as legacy: verification fails', async () => {
    const orgId = await org();
    const audit = new AuditService(runtime, createLogger({ level: 'silent' }), key);
    // The normal chained append works as the runtime role.
    await audit.record({ orgId, action: 'org.update', target: 'chained' });
    expect(await verifyChain(runtime, key, orgId)).toMatchObject({ ok: true, legacyUnchained: 0 });

    const cutover = await getAuditCutover(runtime);
    const ancient = new Date(Date.UTC(2001, 0, 1));
    const viaOrm = await runtime.auditLog.create({
      data: { orgId, action: 'member.remove', target: 'forged-orm', createdAt: ancient },
    });
    await runtime.$executeRawUnsafe(
      `INSERT INTO "AuditLog" ("id", "orgId", "action", "target", "createdAt", "updatedAt") VALUES ('forged-raw', '${orgId}', 'member.remove', 'forged-raw', '2001-01-01', now())`,
    );
    for (const id of [viaOrm.id, 'forged-raw']) {
      const row = await owner.auditLog.findUniqueOrThrow({ where: { id } });
      expect(row.createdAt.getTime()).toBeGreaterThanOrEqual(cutover.getTime());
    }
    const v = await verifyChain(runtime, key, orgId);
    expect(v.ok).toBe(false);
    expect(v.legacyUnchained).toBe(0);
    expect(v.brokenAt?.reason).toBe('unchained_after_cutover');

    // Nor can the runtime role rewrite a row's createdAt afterwards, even in maintenance mode.
    await expect(
      runtime.$transaction(async (tx) => {
        await enterAuditMaintenance(tx);
        await tx.auditLog.update({ where: { id: 'forged-raw' }, data: { createdAt: ancient } });
      }),
    ).rejects.toThrow(/immutable|permission denied/); // REAUDIT-007: no UPDATE of createdAt at all
  });
});

// REAUDIT-004 / P10-SEC-006-R2: the runtime role could set `loose.audit_maintenance` itself and
// DELETE any audit row, including the newest (a removed tail is invisible to verifyChain).
describe('P10-SEC-006-R2: the runtime DB role cannot delete audit rows', () => {
  async function chainOf3(orgId: string) {
    const audit = new AuditService(runtime, createLogger({ level: 'silent' }), key);
    for (const t of ['one', 'two', 'three'])
      await audit.record({ orgId, action: 'org.update', target: t });
    return owner.auditLog.findMany({ where: { orgId }, orderBy: { seq: 'asc' } });
  }

  it('denies DELETE of the tail, a middle row and the whole chain, even with the maintenance GUC on', async () => {
    const orgId = await org();
    const rows = await chainOf3(orgId);
    const tail = rows.at(-1)!;
    for (const where of [{ id: tail.id }, { id: rows[1]!.id }, { orgId }]) {
      await expect(
        runtime.$transaction(async (tx) => {
          await enterAuditMaintenance(tx);
          await tx.auditLog.deleteMany({ where });
        }),
      ).rejects.toThrow(DENIED);
    }
    expect(await asRuntime(`DELETE FROM "AuditLog" WHERE "id" = '${tail.id}'`)).toMatch(DENIED);
    expect(await owner.auditLog.count({ where: { orgId } })).toBe(3);
    expect(await verifyChain(runtime, key, orgId)).toMatchObject({
      ok: true,
      checked: 3,
      lastSeq: 3,
    });
  });

  it('the definer purge refuses the tail without a marker, with a forged marker and inside the minimum retention', async () => {
    const orgId = await org();
    const rows = await chainOf3(orgId);
    const purge = (through: number) =>
      asRuntime(`SELECT loose_audit_purge_prefix('${orgId}', ${through}, 500)`);
    // no marker at all
    expect(await purge(3)).toMatch(/no retention marker/);
    expect(await purge(2)).toMatch(/no retention marker/);
    // forged chained marker (runtime role has INSERT, not the HMAC key) announcing the whole chain
    const forge = async (cutoff: string, through: number, seq: number) =>
      runtime.auditLog.create({
        data: {
          orgId,
          chain: orgId,
          seq,
          prevHash: rows.at(-1)!.hash!,
          hash: 'f'.repeat(64),
          action: 'audit.retention_purged',
          target: orgId,
          meta: {
            purgedThroughSeq: through,
            anchorHash: rows[through - 1]!.hash,
            count: through,
            cutoff,
          },
        },
      });
    // a cutoff inside the 30-day minimum retention
    await forge(new Date().toISOString(), 3, 4);
    expect(await purge(3)).toMatch(/minimum retention/);
    // an old enough cutoff, but the rows are newer than it
    await forge(new Date(Date.UTC(2001, 0, 1)).toISOString(), 3, 5);
    expect(await purge(3)).toMatch(/newer than the cutoff/);
    // the latest marker can never cover itself or anything after it
    expect(await purge(5)).toMatch(/no retention marker/);
    expect(await owner.auditLog.count({ where: { orgId } })).toBe(5);
    // and the forged markers break verification on their own
    const v = await verifyChain(runtime, key, orgId);
    expect(v.ok).toBe(false);
    expect(v.brokenAt).toMatchObject({ seq: 4, reason: 'hash_mismatch' });
    // invalid arguments, the global chain and a direct call to the legacy purge are bounded too
    expect(await asRuntime(`SELECT loose_audit_purge_prefix('global', 1, 500)`)).toMatch(/invalid/);
    expect(await asRuntime(`SELECT loose_audit_purge_prefix('${orgId}', 1, 1000000)`)).toMatch(
      /invalid/,
    );
    const [legacy] = await runtime.$queryRawUnsafe<{ n: number }[]>(
      `SELECT loose_audit_purge_legacy('${orgId}', now()::timestamp(3), 500) AS n`,
    );
    expect(Number(legacy!.n)).toBe(0);
  });

  it('valid retention still works as the runtime role: aged prefix and legacy rows go, the tail stays, verify ok', async () => {
    const orgId = await org();
    const audit = new AuditService(runtime, createLogger({ level: 'silent' }), key);
    vi.useFakeTimers({ toFake: ['Date'] });
    try {
      vi.setSystemTime(new Date(Date.now() - 800 * DAY));
      for (const t of ['old1', 'old2', 'old3'])
        await audit.record({ orgId, action: 'org.update', target: t });
    } finally {
      vi.useRealTimers();
    }
    for (const t of ['new1', 'new2'])
      await audit.record({ orgId, action: 'org.update', target: t });
    const legacy = await legacyAuditRow(owner, {
      orgId,
      action: 'member.add',
      target: 'legacy',
      createdAt: new Date(Date.UTC(2001, 0, 1)),
    });

    const ctx = { prisma: runtime, audit: { chainKey: key } } as unknown as AppContext;
    const purged = await purgeAuditLog(ctx, orgId, new Date(Date.now() - 365 * DAY));
    expect(purged).toBe(4); // 3 aged chained rows + 1 unchained legacy row
    const left = await owner.auditLog.findMany({ where: { orgId }, orderBy: { seq: 'asc' } });
    expect(left.map((r) => r.target)).toEqual(['new1', 'new2', orgId]);
    expect(left.at(-1)!.action).toBe('audit.retention_purged');
    expect(await owner.auditLog.findUnique({ where: { id: legacy.id } })).toBeNull();
    expect(await verifyChain(runtime, key, orgId)).toMatchObject({
      ok: true,
      anchoredAt: 4,
      legacyUnchained: 0,
    });
    // idempotent: the definer finds nothing left, and the marker/tail stay undeletable
    expect(await purgeAuditLog(ctx, orgId, new Date(Date.now() - 365 * DAY))).toBe(0);
    expect(await asRuntime(`SELECT loose_audit_purge_prefix('${orgId}', 6, 500)`)).toMatch(
      /no retention marker/,
    );
  });

  it('org deletion still cascades to its audit rows (FK actions run as the owner)', async () => {
    const orgId = await org();
    await chainOf3(orgId);
    await runtime.organization.delete({ where: { id: orgId } });
    expect(await owner.auditLog.count({ where: { orgId } })).toBe(0);
  });
});

// REAUDIT-007: the runtime role could `UPDATE "AuditLog" SET "actorId" = NULL, "ip" = NULL` and
// verifyChain still answered ok:true (neither column is hashed).
describe('REAUDIT-007: the runtime DB role cannot erase audit attribution', () => {
  async function attributed(orgId: string) {
    const user = await owner.user.create({
      data: { email: `rt-${randomBytes(4).toString('hex')}@example.com`, name: 'Actor' },
    });
    const audit = new AuditService(runtime, createLogger({ level: 'silent' }), key);
    await audit.record({
      orgId,
      actorId: user.id,
      action: 'member.remove',
      target: 'victim',
      ip: '198.51.100.7',
    });
    const row = await owner.auditLog.findFirstOrThrow({
      where: { orgId, actorId: user.id, action: 'member.remove' },
    });
    return { user, row };
  }

  const dueRequest = (userId: string, overrides: Record<string, unknown> = {}) =>
    owner.deletionRequest.create({
      data: { kind: 'USER', userId, scheduledFor: new Date(Date.now() - 60_000), ...overrides },
    });

  it('denies direct actorId / ip nulling, with or without the maintenance GUC', async () => {
    const orgId = await org();
    const { row } = await attributed(orgId);
    for (const sql of [
      `UPDATE "AuditLog" SET "actorId" = NULL, "ip" = NULL WHERE "id" = '${row.id}'`,
      `UPDATE "AuditLog" SET "ip" = NULL WHERE "id" = '${row.id}'`,
      `UPDATE "AuditLog" SET "actorId" = NULL WHERE "id" = '${row.id}'`,
      `UPDATE "AuditLog" SET "meta" = '{}' WHERE "id" = '${row.id}'`,
    ]) {
      expect(await asRuntime(sql)).toMatch(DENIED);
    }
    await expect(
      runtime.$transaction(async (tx) => {
        await enterAuditMaintenance(tx);
        await tx.auditLog.updateMany({ where: { id: row.id }, data: { actorId: null, ip: null } });
      }),
    ).rejects.toThrow(DENIED);
    // The chain columns it may write (legacy sealing) are refused on chained rows by the trigger.
    await expect(
      runtime.$transaction(async (tx) => {
        await enterAuditMaintenance(tx);
        await tx.auditLog.update({ where: { id: row.id }, data: { actorDigest: null } });
      }),
    ).rejects.toThrow(/immutable/);
    expect(await owner.auditLog.findUniqueOrThrow({ where: { id: row.id } })).toMatchObject({
      actorId: row.actorId,
      ip: '198.51.100.7',
      actorDigest: row.actorDigest,
    });
    expect(await verifyChain(runtime, key, orgId)).toMatchObject({ ok: true });
  });

  it('the trigger refuses attribution nulling even for a non-owner role that holds UPDATE', async () => {
    const orgId = await org();
    const { row } = await attributed(orgId);
    await owner.$executeRawUnsafe(`GRANT UPDATE ("actorId", "ip") ON "AuditLog" TO ${role}`);
    try {
      const err = await asRuntime(
        `UPDATE "AuditLog" SET "actorId" = NULL, "ip" = NULL WHERE "id" = '${row.id}'`,
      );
      expect(err).toMatch(/can only be redacted by loose_audit_redact_user/);
    } finally {
      await owner.$executeRawUnsafe(`REVOKE UPDATE ("actorId", "ip") ON "AuditLog" FROM ${role}`);
    }
  });

  it('the definer redacts only for a due, pending account deletion', async () => {
    const orgId = await org();
    const { user, row } = await attributed(orgId);
    const redact = (id: string) => asRuntime(`SELECT loose_audit_redact_user('${id}')`);
    expect(await redact('no-such-request')).toMatch(/not a due, pending account deletion/);
    const later = await dueRequest(user.id, { scheduledFor: new Date(Date.now() + 86_400_000) });
    expect(await redact(later.id)).toMatch(/not a due, pending account deletion/);
    const cancelled = await dueRequest(user.id, { status: 'CANCELLED' });
    expect(await redact(cancelled.id)).toMatch(/not a due, pending account deletion/);
    const orgKind = await owner.deletionRequest.create({
      data: { kind: 'ORG', orgId, userId: user.id, scheduledFor: new Date(Date.now() - 60_000) },
    });
    expect(await redact(orgKind.id)).toMatch(/not a due, pending account deletion/);
    expect(await owner.auditLog.findUniqueOrThrow({ where: { id: row.id } })).toMatchObject({
      actorId: user.id,
      ip: '198.51.100.7',
    });

    // A due request works — but without the signed marker the server writes alongside it,
    // verification reports the removed attribution (e.g. a forged DeletionRequest row).
    const due = await dueRequest(user.id);
    const [out] = await runtime.$queryRawUnsafe<{ n: number }[]>(
      `SELECT loose_audit_redact_user('${due.id}')::INTEGER AS n`,
    );
    expect(Number(out!.n)).toBe(1);
    expect(await owner.auditLog.findUniqueOrThrow({ where: { id: row.id } })).toMatchObject({
      actorId: null,
      ip: null,
      actorDigest: actorDigestOf(user.id),
    });
    const v = await verifyChain(runtime, key, orgId);
    expect(v.ok).toBe(false);
    expect(v.brokenAt).toMatchObject({ id: row.id, reason: 'hash_mismatch' });
  });

  it('EXECUTE is not granted to PUBLIC', async () => {
    const [acl] = await owner.$queryRawUnsafe<{ public_exec: boolean; runtime_exec: boolean }[]>(
      `SELECT has_function_privilege('public', 'loose_audit_redact_user(text)', 'EXECUTE') AS public_exec,
              has_function_privilege('${role}', 'loose_audit_redact_user(text)', 'EXECUTE') AS runtime_exec`,
    );
    expect(acl).toEqual({ public_exec: false, runtime_exec: true });
    const [cfg] = await owner.$queryRawUnsafe<{ secdef: boolean; config: string[] | null }[]>(
      `SELECT prosecdef AS secdef, proconfig AS config FROM pg_proc WHERE proname = 'loose_audit_redact_user'`,
    );
    expect(cfg!.secdef).toBe(true);
    expect(cfg!.config?.join(',')).toMatch(/search_path=pg_catalog, ?public, ?pg_temp/);
  });

  it('a real account deletion as the runtime role redacts, deletes the user and still verifies', async () => {
    const orgId = await org();
    const { user, row } = await attributed(orgId);
    const audit = new AuditService(runtime, createLogger({ level: 'silent' }), key);
    await audit.record({ actorId: user.id, action: 'auth.sign_in', target: user.id, ip: '::1' });
    const request_ = await dueRequest(user.id);
    await owner.user.update({ where: { id: user.id }, data: { deletionScheduledAt: new Date() } });

    const { ctx } = makeApp({ context: { prisma: runtime } });
    ctx.audit.useChainKey(key);
    expect(await runDeletionSweep(ctx)).toMatchObject({ completed: 1, failed: 0 });

    expect(await owner.user.count({ where: { id: user.id } })).toBe(0);
    expect(await owner.auditLog.count({ where: { ip: { in: ['198.51.100.7', '::1'] } } })).toBe(0);
    expect(await owner.auditLog.findUniqueOrThrow({ where: { id: row.id } })).toMatchObject({
      actorId: null,
      ip: null,
      actorDigest: actorDigestOf(user.id),
    });
    for (const chain of [orgId, 'global']) {
      const marker = await owner.auditLog.findFirstOrThrow({
        where: { chain, action: 'audit.redacted' },
      });
      expect(marker).toMatchObject({ target: request_.id, actorId: null });
      expect(marker.meta).toMatchObject({ actorDigest: actorDigestOf(user.id), rows: 1 });
      expect(await verifyChain(runtime, key, chain)).toMatchObject({ ok: true });
    }
    expect(
      await owner.deletionRequest.findUniqueOrThrow({ where: { id: request_.id } }),
    ).toMatchObject({ status: 'COMPLETED', userId: null });
  });

  it('deleting a user row behind the deletion flow still works (FK SET NULL), but is detected', async () => {
    const orgId = await org();
    const { user, row } = await attributed(orgId);
    await runtime.user.delete({ where: { id: user.id } });
    expect(await owner.auditLog.findUniqueOrThrow({ where: { id: row.id } })).toMatchObject({
      actorId: null,
      actorDigest: actorDigestOf(user.id),
    });
    const v = await verifyChain(runtime, key, orgId);
    expect(v.ok).toBe(false);
    expect(v.brokenAt).toMatchObject({ id: row.id, reason: 'hash_mismatch' });
  });

  it('legacy sealing still works as the runtime role (column-level UPDATE on chain fields)', async () => {
    const orgId = await org();
    const audit = new AuditService(runtime, createLogger({ level: 'silent' }), key);
    await audit.record({ orgId, action: 'org.update', target: 'chained' });
    await legacyAuditRow(owner, {
      orgId,
      action: 'member.add',
      target: 'legacy',
      createdAt: new Date(Date.UTC(2001, 0, 1)),
    });
    expect(await verifyChain(runtime, key, orgId)).toMatchObject({ ok: true, legacyUnchained: 1 });
    expect(await backfillChain(runtime, key, orgId)).toBe(1);
    expect(await verifyChain(runtime, key, orgId)).toMatchObject({
      ok: true,
      legacyUnchained: 0,
      checked: 2,
    });
  });
});
