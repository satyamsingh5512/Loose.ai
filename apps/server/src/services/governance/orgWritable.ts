/**
 * Org write freeze while a deletion is pending (LSE-ORG-012, spec §8.20).
 * Wired into `requireOrg` (FOUNDATION), so it covers every `/orgs/:orgId/*` route.
 */
import type { Request } from 'express';
import type { Organization } from '@prisma/client';
import type { AppContext } from '../../context';
import { AppError } from '../../lib/errors';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Writes that stay possible during the grace period: cancelling the deletion (the only way out),
 * repeating the schedule request (idempotent: returns the pending request) and requesting a data
 * export (so owners can take their data before it is gone).
 */
function isAllowedDuringDeletion(method: string, path: string): boolean {
  const p = path.replace(/\/+$/, '');
  if (method === 'DELETE' && p === '/deletion') return true;
  if (method === 'POST' && (p === '/deletion' || p === '/data-exports')) return true;
  return false;
}

/** Non-GET on an org with `deletionScheduledAt` → LSE-ORG-012, except cancelling the deletion. */
export function assertOrgWritable(_ctx: AppContext, req: Request, org: Organization): void {
  if (!org.deletionScheduledAt) return;
  if (SAFE_METHODS.has(req.method)) return;
  // `req.path` is relative to the `/orgs/:orgId` mount when this runs inside the org router.
  if (isAllowedDuringDeletion(req.method, req.path)) return;
  throw new AppError('LSE-ORG-012', {
    devMessage: `Org ${org.id} is scheduled for deletion on ${org.deletionScheduledAt.toISOString()}; cancel the deletion to make changes`,
  });
}

/** Same rule for code paths that act on an org outside `/orgs/:orgId/*` (e.g. starting a session). */
export function assertOrgNotPendingDeletion(org: Pick<Organization, 'id' | 'deletionScheduledAt'>) {
  if (org.deletionScheduledAt) {
    throw new AppError('LSE-ORG-012', {
      devMessage: `Org ${org.id} is scheduled for deletion`,
    });
  }
}
