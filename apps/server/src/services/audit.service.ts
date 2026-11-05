/**
 * Audit log writer. Meta is scrubbed of secrets; callers must still only pass
 * non-sensitive identifiers (ids, names, last4, role changes).
 * Audit failures are logged and do not fail the user's request, EXCEPT for security-sensitive
 * actions (`FAIL_CLOSED_AUDIT_ACTIONS`): there a failed append surfaces as `LSE-SYS-001`, so an
 * attacker cannot starve the audit store to make a privileged change leave no trace (P10-SEC-011).
 * Flows that must be atomic should call `record(entry, tx)` inside their own transaction; the
 * mutation then rolls back together with the failed append.
 *
 * Phase 10: every entry is appended to a per-chain HMAC hash chain (services/governance/auditChain.ts)
 * so tampering with stored history is detectable (`GET /orgs/:orgId/audit-log/verify`).
 */
import type { Prisma, PrismaClient } from '@prisma/client';
import { scrubSecretsDeep, type AuditAction } from '@loose/shared';
import { AppError } from '../lib/errors';
import type { Logger } from '../lib/logger';
import { appendChainedEntry } from './governance/auditChain';

export interface AuditEntry {
  orgId?: string | null;
  actorId?: string | null;
  action: AuditAction;
  target?: string | null;
  meta?: Record<string, unknown>;
  ip?: string | undefined;
}

/**
 * Actions whose audit record is part of the security control: authorisation changes, identity /
 * SSO / SCIM configuration, credential lifecycle and destructive-data state. A failed append for
 * one of these is never swallowed.
 */
export const FAIL_CLOSED_AUDIT_ACTIONS: ReadonlySet<AuditAction> = new Set<AuditAction>([
  'member.role_change',
  'member.remove',
  'policy.update',
  'security.update',
  'sso.update',
  'sso.delete',
  'domain.create',
  'domain.verify',
  'domain.delete',
  'scim_token.create',
  'scim_token.revoke',
  'auth.2fa_disabled',
  'auth.sso_linked',
  'api_key.create',
  'api_key.delete',
  'token.create',
  'token.delete',
  'deletion.schedule',
  'deletion.cancel',
  'retention.update',
  'policy_pack.apply',
  'audit.redacted',
]);

type Db = PrismaClient | Prisma.TransactionClient;

const isClient = (db: Db): db is PrismaClient => '$transaction' in db;

export class AuditService {
  #chainKey: Buffer | undefined;

  constructor(
    private readonly prisma: PrismaClient,
    private readonly logger: Logger,
    chainKey?: Buffer,
  ) {
    this.#chainKey = chainKey;
  }

  /** Install the HMAC key of the hash chain (`registerGovernance` does this at boot). */
  useChainKey(key: Buffer): void {
    this.#chainKey = key;
  }

  get chainKey(): Buffer {
    if (!this.#chainKey) throw new Error('Audit chain key is not configured');
    return this.#chainKey;
  }

  /**
   * Pass `db` to write inside the caller's transaction (the chain lock is then held until that
   * transaction ends; keep such transactions short). When `db` is a transaction a failure always
   * propagates (the surrounding mutation must roll back); otherwise it propagates only for
   * `FAIL_CLOSED_AUDIT_ACTIONS` and is logged-and-swallowed for the rest.
   */
  async record(entry: AuditEntry, db: Db = this.prisma): Promise<void> {
    try {
      const row = {
        orgId: entry.orgId ?? null,
        actorId: entry.actorId ?? null,
        action: entry.action,
        target: entry.target ?? null,
        meta: entry.meta ? scrubSecretsDeep(entry.meta) : undefined,
        ip: entry.ip,
      };
      const key = this.chainKey;
      if (isClient(db)) {
        await db.$transaction((tx) => appendChainedEntry(tx, key, row), {
          maxWait: 10_000,
          timeout: 15_000,
        });
      } else {
        await appendChainedEntry(db, key, row);
      }
    } catch (err) {
      this.logger.error({ err, action: entry.action }, 'failed to write audit log');
      if (!isClient(db) || FAIL_CLOSED_AUDIT_ACTIONS.has(entry.action)) {
        throw new AppError('LSE-SYS-001', {
          devMessage: `Audit append failed for ${entry.action}; refusing to complete the change without an audit record`,
          cause: err,
        });
      }
    }
  }
}
