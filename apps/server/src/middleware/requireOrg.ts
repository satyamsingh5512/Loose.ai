/**
 * Org membership + role enforcement (RBAC, spec §15).
 * Unknown org → LSE-ORG-003; exists but caller isn't a member → LSE-ORG-001;
 * role too low → LSE-ORG-002. API tokens are bound to a single org.
 */
import type { Request, RequestHandler } from 'express';
import { hasRoleAtLeast, idSchema, type Role } from '@loose/shared';
import type { Organization, OrgMember } from '@prisma/client';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';
import { assertOrgWritable } from '../services/governance/orgWritable';
import { enforceOrgAccess, orgAccessSubjectFromRequest } from '../services/identity/accessPolicy';

export function requireOrg(ctx: AppContext): RequestHandler {
  return async (req, _res, next) => {
    const user = req.auth?.user;
    if (!user) throw new AppError('LSE-AUTH-001');
    const parsed = idSchema.safeParse(req.params.orgId);
    if (!parsed.success) throw new AppError('LSE-ORG-003', { devMessage: 'Malformed org id' });
    const orgId = parsed.data;
    const org = await ctx.prisma.organization.findUnique({ where: { id: orgId } });
    if (!org) throw new AppError('LSE-ORG-003');
    if (req.auth?.apiToken && req.auth.apiToken.orgId !== org.id) {
      throw new AppError('LSE-ORG-001', { devMessage: 'API token is scoped to a different org' });
    }
    const membership = await ctx.prisma.orgMember.findUnique({
      where: { userId_orgId: { userId: user.id, orgId: org.id } },
    });
    if (!membership) throw new AppError('LSE-ORG-001');
    // Phase 10: IP allowlist / SSO / admin 2FA (W1) and the deletion write freeze (W2).
    await enforceOrgAccess(ctx, orgAccessSubjectFromRequest(req), org, membership);
    assertOrgWritable(ctx, req, org);
    req.org = org;
    req.membership = membership;
    next();
  };
}

export function requireRole(min: Role): RequestHandler {
  return (req, _res, next) => {
    if (!req.membership) throw new AppError('LSE-ORG-001');
    if (!hasRoleAtLeast(req.membership.role, min)) {
      throw new AppError('LSE-ORG-002', {
        devMessage: `Requires ${min} or higher; caller is ${req.membership.role}`,
      });
    }
    next();
  };
}

/** Typed accessors for handlers mounted behind requireAuth/requireOrg. */
export function authUser(req: Request) {
  if (!req.auth) throw new AppError('LSE-AUTH-001');
  return req.auth.user;
}

export function orgOf(req: Request): { org: Organization; membership: OrgMember } {
  if (!req.org || !req.membership) throw new AppError('LSE-ORG-001');
  return { org: req.org, membership: req.membership };
}
