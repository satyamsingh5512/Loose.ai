/** Organizations, members, invites, policy, audit log (spec §10.2). */
import { Router, type Request, type RequestHandler } from 'express';
import {
  auditLogQuerySchema,
  createInviteBodySchema,
  createOrgBodySchema,
  inviteIdParamsSchema,
  inviteTokenParamsSchema,
  orgSessionsQuerySchema,
  paginationQuerySchema,
  updateMemberBodySchema,
  updateOrgBodySchema,
  updateOrgMemoryBodySchema,
  updateOrgPolicyBodySchema,
  usageQuerySchema,
  userIdParamsSchema,
  type AuditLogQuery,
  type CreateInviteBody,
  type CreateOrgBody,
  type OrgPolicy,
  type OrgSessionsQuery,
  type PaginationQuery,
  type UpdateMemberBody,
  type UpdateOrgBody,
  type UsageQuery,
} from '@loose/shared';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';
import { idempotency } from '../middleware/idempotency';
import type { RateLimiters } from '../middleware/rateLimit';
import { requireAuth } from '../middleware/requireAuth';
import { authUser, orgOf, requireOrg, requireRole } from '../middleware/requireOrg';
import { queryOf, validate } from '../middleware/validate';
import {
  acceptInvite,
  createInvite,
  listInvites,
  previewInvite,
  revokeInvite,
} from '../services/invite.service';
import {
  createOrg,
  getMember,
  getPolicy,
  listAuditLog,
  listMembers,
  listOrgs,
  removeMember,
  toOrgDto,
  updateMember,
  updateOrg,
  updatePolicy,
  type Actor,
} from '../services/org.service';
import { orgMemoryDto, updateOrgMemory } from '../services/memory.service';
import { listOrgSessions } from '../services/sessionLifecycle.service';
import { usageCsv, usageSummary } from '../services/usage.service';
import { extensionsRouter } from './extensions';
import { mountGovernanceOrgRoutes } from './governance';
import { mountIdentityOrgRoutes } from './identity';
import { mountObservabilityOrgRoutes } from './observability';
import { projectsRouter } from './projects';
import { triggersRouter } from './triggers';
import { webhooksRouter } from './webhooks';

function actorOf(req: Request): Actor {
  return { userId: authUser(req).id, role: orgOf(req).membership.role, ip: req.ip };
}

/**
 * Personal API tokens are read-only and org-bound: GET only, and the token
 * must carry `projects:read` for project routes or `org:read` otherwise.
 */
const tokenScopeGuard: RequestHandler = (req, _res, next) => {
  const token = req.auth?.apiToken;
  if (!token) return next();
  const scope = /\/projects(\/|$)/.test(req.path)
    ? 'projects:read'
    : /^\/sessions(\/|$)/.test(req.path)
      ? 'sessions:read'
      : 'org:read';
  if (req.method !== 'GET' || !token.scopes.includes(scope)) {
    throw new AppError('LSE-ORG-002', {
      devMessage: `API token lacks permission (${req.method} needs ${scope})`,
    });
  }
  next();
};

export function orgsRouter(ctx: AppContext, limiters: RateLimiters): Router {
  const r = Router();
  const sessionOnly = requireAuth(ctx, { allowToken: false });

  // ---- invite landing + accept (not org-scoped) ------------------------------------
  r.get(
    '/invites/:token',
    limiters.auth,
    validate({ params: inviteTokenParamsSchema }),
    async (req, res) => {
      res.json({ data: await previewInvite(ctx, req.params.token as string) });
    },
  );

  r.post(
    '/invites/:token/accept',
    sessionOnly,
    validate({ params: inviteTokenParamsSchema }),
    async (req, res) => {
      res.json({
        data: await acceptInvite(ctx, req.params.token as string, authUser(req), req.ip),
      });
    },
  );

  // ---- orgs ------------------------------------------------------------------------
  r.post(
    '/',
    sessionOnly,
    idempotency(ctx),
    validate({ body: createOrgBodySchema }),
    async (req, res) => {
      const dto = await createOrg(ctx, authUser(req).id, req.body as CreateOrgBody, req.ip);
      res.status(201).json({ data: dto });
    },
  );

  r.get('/', requireAuth(ctx), async (req, res) => {
    let orgs = await listOrgs(ctx, authUser(req).id);
    const token = req.auth?.apiToken;
    if (token) orgs = orgs.filter((o) => o.id === token.orgId);
    res.json({ data: orgs, nextCursor: null });
  });

  // ---- org-scoped -------------------------------------------------------------------
  const org = Router({ mergeParams: true });
  org.use(requireAuth(ctx), requireOrg(ctx), tokenScopeGuard);

  // Phase 10 (phase10-design.md §5.1): identity (W1), governance (W2), feature flags (W3).
  mountIdentityOrgRoutes(org, ctx);
  mountGovernanceOrgRoutes(org, ctx);
  mountObservabilityOrgRoutes(org, ctx);

  org.get('/', requireRole('VIEWER'), (req, res) => {
    const { org: o, membership } = orgOf(req);
    res.json({ data: toOrgDto(o, membership.role) });
  });

  org.put('/', requireRole('ADMIN'), validate({ body: updateOrgBodySchema }), async (req, res) => {
    res.json({
      data: await updateOrg(ctx, orgOf(req).org, actorOf(req), req.body as UpdateOrgBody),
    });
  });

  // There is deliberately no `DELETE /orgs/:orgId`: organizations are deleted only through the
  // confirmed, grace-period flow `POST /orgs/:orgId/deletion` (P10-SEC-005).

  // members
  org.get(
    '/members',
    requireRole('ADMIN'),
    validate({ query: paginationQuerySchema }),
    async (req, res) => {
      res.json(await listMembers(ctx, orgOf(req).org.id, queryOf<PaginationQuery>(req)));
    },
  );

  org.get(
    '/members/:userId',
    requireRole('ADMIN'),
    validate({ params: userIdParamsSchema }),
    async (req, res) => {
      res.json({ data: await getMember(ctx, orgOf(req).org.id, req.params.userId as string) });
    },
  );

  org.put(
    '/members/:userId',
    requireRole('ADMIN'),
    validate({ params: userIdParamsSchema, body: updateMemberBodySchema }),
    async (req, res) => {
      const dto = await updateMember(
        ctx,
        orgOf(req).org.id,
        req.params.userId as string,
        actorOf(req),
        req.body as UpdateMemberBody,
      );
      res.json({ data: dto });
    },
  );

  // Admins remove others; any member may remove themselves (leave the org).
  const adminOrSelf: RequestHandler = (req, res, next) => {
    if (req.params.userId === req.auth?.user.id) return next();
    return requireRole('ADMIN')(req, res, next);
  };
  org.delete(
    '/members/:userId',
    validate({ params: userIdParamsSchema }),
    adminOrSelf,
    async (req, res) => {
      await removeMember(ctx, orgOf(req).org.id, req.params.userId as string, actorOf(req));
      res.status(204).end();
    },
  );

  // invites
  org.post(
    '/invites',
    requireRole('ADMIN'),
    idempotency(ctx),
    validate({ body: createInviteBodySchema }),
    async (req, res) => {
      const dto = await createInvite(
        ctx,
        orgOf(req).org.id,
        actorOf(req),
        req.body as CreateInviteBody,
      );
      res.status(201).json({ data: dto });
    },
  );

  org.get(
    '/invites',
    requireRole('ADMIN'),
    validate({ query: paginationQuerySchema }),
    async (req, res) => {
      res.json(await listInvites(ctx, orgOf(req).org.id, queryOf<PaginationQuery>(req)));
    },
  );

  org.delete(
    '/invites/:inviteId',
    requireRole('ADMIN'),
    validate({ params: inviteIdParamsSchema }),
    async (req, res) => {
      await revokeInvite(ctx, orgOf(req).org.id, req.params.inviteId as string, actorOf(req));
      res.status(204).end();
    },
  );

  // policy
  org.get('/policy', requireRole('ADMIN'), (req, res) => {
    res.json({ data: getPolicy(orgOf(req).org) });
  });

  org.put(
    '/policy',
    requireRole('ADMIN'),
    validate({ body: updateOrgPolicyBodySchema }),
    async (req, res) => {
      res.json({
        data: await updatePolicy(ctx, orgOf(req).org, actorOf(req), req.body as OrgPolicy),
      });
    },
  );

  // audit log
  org.get(
    '/audit-log',
    requireRole('ADMIN'),
    validate({ query: auditLogQuerySchema }),
    async (req, res) => {
      res.json(await listAuditLog(ctx, orgOf(req).org.id, queryOf<AuditLogQuery>(req)));
    },
  );

  // sessions (members: their own; admins: everyone's)
  org.get(
    '/sessions',
    requireRole('MEMBER'),
    validate({ query: orgSessionsQuerySchema }),
    async (req, res) => {
      const { org: o, membership } = orgOf(req);
      res.json(await listOrgSessions(ctx, o.id, membership, queryOf<OrgSessionsQuery>(req)));
    },
  );

  // usage & cost (spec §8.19)
  org.get(
    '/usage',
    requireRole('ADMIN'),
    validate({ query: usageQuerySchema }),
    async (req, res) => {
      const q = queryOf<UsageQuery>(req);
      const orgId = orgOf(req).org.id;
      if (q.format === 'csv') {
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="usage-${orgId}.csv"`);
        res.send(await usageCsv(ctx, orgId, q));
        return;
      }
      res.json({ data: await usageSummary(ctx, orgId, q) });
    },
  );
  // Phase 9: outbound webhooks (W1) and automation triggers (W4) live in their own routers.
  org.use('/webhooks', webhooksRouter(ctx));
  org.use('/triggers', triggersRouter(ctx));

  // memory hierarchy (spec §8.10): org layer
  org.get('/memory', requireRole('MEMBER'), (req, res) => {
    res.json({ data: orgMemoryDto(orgOf(req).org) });
  });
  org.put(
    '/memory',
    requireRole('ADMIN'),
    validate({ body: updateOrgMemoryBodySchema }),
    async (req, res) => {
      const dto = await updateOrgMemory(
        ctx,
        orgOf(req).org,
        actorOf(req),
        (req.body as { memory: string | null }).memory,
      );
      res.json({ data: dto });
    },
  );

  // extensions (spec §10.4.1)
  org.use('/', extensionsRouter(ctx));

  org.use('/projects', projectsRouter(ctx));

  r.use('/:orgId', org);
  return r;
}
