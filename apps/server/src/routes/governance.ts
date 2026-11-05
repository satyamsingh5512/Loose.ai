/**
 * Governance routes (Phase 10, spec §8.20; phase10-design.md §5.3):
 *  - org: audit-log export + hash-chain verification, retention, org data export, org deletion,
 *    policy packs (inside the org router: requireAuth + requireOrg already ran)
 *  - user: `/users/me/privacy/*` — personal data export and account deletion (session-only)
 * Everything here is gated by feature flags and audited by the services.
 */
import { Router, type Request, type RequestHandler, type Response } from 'express';
import {
  applyPolicyPackBodySchema,
  auditLogExportQuerySchema,
  createPolicyPackBodySchema,
  dataExportParamsSchema,
  listDataExportsQuerySchema,
  policyPackParamsSchema,
  scheduleDeletionBodySchema,
  updatePolicyPackBodySchema,
  updateRetentionBodySchema,
  userDataExportParamsSchema,
  type ApplyPolicyPackBody,
  type AuditLogExportQuery,
  type CreatePolicyPackBody,
  type PaginationQuery,
  type ScheduleDeletionBody,
  type UpdatePolicyPackBody,
  type UpdateRetentionBody,
} from '@loose/shared';
import type { DataExport } from '@prisma/client';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';
import { requireFeature } from '../lib/featureFlags';
import { idempotency } from '../middleware/idempotency';
import type { RateLimiters } from '../middleware/rateLimit';
import { requireAuth } from '../middleware/requireAuth';
import { authUser, orgOf, requireRole } from '../middleware/requireOrg';
import { queryOf, validate } from '../middleware/validate';
import { verifyChain } from '../services/governance/auditChain';
import { streamAuditExport } from '../services/governance/auditExport';
import {
  getDataExport,
  listDataExports,
  openDataExportDownload,
  requestDataExport,
  toDataExportDto,
} from '../services/governance/dataExport';
import {
  cancelOrgDeletion,
  cancelUserDeletion,
  getPendingDeletion,
  scheduleOrgDeletion,
  scheduleUserDeletion,
} from '../services/governance/deletion';
import {
  applyPolicyPackToProjects,
  createPolicyPack,
  deletePolicyPack,
  getPolicyPack,
  listPolicyPacks,
  updatePolicyPack,
} from '../services/governance/policyPacks.service';
import { getRetention, updateRetention } from '../services/governance/retention';
import type { Actor } from '../services/org.service';

const AUDIT_VERIFY_LOCK_TTL_SEC = 120;

function actorOf(req: Request): Actor {
  return { userId: authUser(req).id, role: orgOf(req).membership.role, ip: req.ip };
}

/** Personal API tokens must never reach exports, deletion or pack edits (browser session only). */
const sessionOnly: RequestHandler = (req, _res, next) => {
  if (req.auth?.apiToken) {
    throw new AppError('LSE-AUTH-001', {
      devMessage: 'This endpoint requires a browser session; API tokens are not accepted',
    });
  }
  next();
};

/** Send a data-export download: redirect to a short-lived signed URL, or stream through the API. */
async function sendExport(
  ctx: AppContext,
  req: Request,
  res: Response,
  row: DataExport,
  orgId: string | null,
): Promise<void> {
  const dl = await openDataExportDownload(ctx, row);
  await ctx.audit.record({
    orgId,
    actorId: authUser(req).id,
    action: 'data_export.download',
    target: row.id,
    meta: { kind: row.kind, via: dl.kind },
    ip: req.ip,
  });
  res.setHeader('Cache-Control', 'no-store');
  if (dl.kind === 'redirect') {
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.redirect(302, dl.url);
    return;
  }
  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Length', String(dl.bytes));
  res.setHeader('Content-Disposition', `attachment; filename="${dl.filename}"`);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  dl.stream.on('error', () => res.destroy());
  dl.stream.pipe(res);
}

/** `/users/me/privacy/*` (data export + account deletion) — mounted before `/users`. */
export function mountGovernanceApiRoutes(
  api: Router,
  ctx: AppContext,
  _limiters: RateLimiters,
): void {
  const r = Router();
  r.use(requireAuth(ctx, { allowToken: false }));

  r.post('/exports', idempotency(ctx), async (req, res) => {
    ctx.featureFlags.assertEnabled('data_export');
    const { dto, created } = await requestDataExport(
      ctx,
      { kind: 'USER', requestedById: authUser(req).id },
      req.ip,
    );
    res.status(created ? 202 : 200).json({ data: dto });
  });

  r.get('/exports', validate({ query: listDataExportsQuerySchema }), async (req, res) => {
    ctx.featureFlags.assertEnabled('data_export');
    res.json(
      await listDataExports(
        ctx,
        { kind: 'USER', requestedById: authUser(req).id },
        queryOf<PaginationQuery>(req),
      ),
    );
  });

  r.get('/exports/:id', validate({ params: userDataExportParamsSchema }), async (req, res) => {
    ctx.featureFlags.assertEnabled('data_export');
    const row = await getDataExport(
      ctx,
      { kind: 'USER', requestedById: authUser(req).id },
      req.params.id as string,
    );
    res.json({ data: toDataExportDto(row) });
  });

  r.get(
    '/exports/:id/download',
    validate({ params: userDataExportParamsSchema }),
    async (req, res) => {
      ctx.featureFlags.assertEnabled('data_export');
      const row = await getDataExport(
        ctx,
        { kind: 'USER', requestedById: authUser(req).id },
        req.params.id as string,
      );
      await sendExport(ctx, req, res, row, null);
    },
  );

  r.get('/deletion', async (req, res) => {
    res.json({ data: await getPendingDeletion(ctx, { userId: authUser(req).id }) });
  });

  r.post('/deletion', validate({ body: scheduleDeletionBodySchema }), async (req, res) => {
    const user = authUser(req);
    const { dto, created } = await scheduleUserDeletion(
      ctx,
      user,
      req.body as ScheduleDeletionBody,
      req.ip,
    );
    res.status(created ? 201 : 200).json({ data: dto });
  });

  r.delete('/deletion', async (req, res) => {
    res.json({ data: await cancelUserDeletion(ctx, authUser(req).id, req.ip) });
  });

  api.use('/users/me/privacy', r);
}

/** Org-scoped governance routes — inside the org router (requireAuth + requireOrg already ran). */
export function mountGovernanceOrgRoutes(org: Router, ctx: AppContext): void {
  // ---- audit log: export + verify ------------------------------------------------------------
  const audit = Router({ mergeParams: true });
  audit.get(
    '/export',
    requireRole('ADMIN'),
    requireFeature(ctx, 'audit_export'),
    sessionOnly,
    validate({ query: auditLogExportQuerySchema }),
    async (req, res) => {
      await streamAuditExport(
        ctx,
        orgOf(req).org,
        actorOf(req),
        queryOf<AuditLogExportQuery>(req),
        res,
      );
    },
  );
  audit.get(
    '/verify',
    requireRole('ADMIN'),
    requireFeature(ctx, 'audit_export'),
    async (req, res) => {
      const { org: o } = orgOf(req);
      // One verification per chain at a time: it reads the whole chain.
      const lockKey = `audit-verify:${o.id}`;
      if (!(await ctx.kv.setIfAbsent(lockKey, ctx.instanceId, AUDIT_VERIFY_LOCK_TTL_SEC))) {
        throw new AppError('LSE-RATE-001', {
          devMessage: 'An audit verification is already running',
        });
      }
      try {
        const result = await verifyChain(ctx.prisma, ctx.audit.chainKey, o.id);
        if (!result.ok) {
          ctx.metrics
            .counter('loose_audit_chain_breaks_total', 'Audit hash-chain verification failures')
            .inc();
          ctx.logger.error(
            { orgId: o.id, brokenAt: result.brokenAt },
            'audit chain verification FAILED',
          );
        }
        await ctx.audit.record({
          orgId: o.id,
          actorId: authUser(req).id,
          action: 'audit.verify',
          target: o.id,
          meta: {
            ok: result.ok,
            checked: result.checked,
            lastSeq: result.lastSeq,
            brokenAt: result.brokenAt,
          },
          ip: req.ip,
        });
        res.json({ data: result });
      } finally {
        await ctx.kv.del(lockKey).catch(() => undefined);
      }
    },
  );
  org.use('/audit-log', audit);

  // ---- retention -------------------------------------------------------------------------------
  const retention = Router({ mergeParams: true });
  retention.use(requireRole('ADMIN'));
  retention.get('/', async (req, res) => {
    res.json({ data: await getRetention(ctx, orgOf(req).org) });
  });
  retention.put(
    '/',
    requireRole('OWNER'),
    sessionOnly,
    validate({ body: updateRetentionBodySchema }),
    async (req, res) => {
      res.json({
        data: await updateRetention(
          ctx,
          orgOf(req).org,
          actorOf(req),
          req.body as UpdateRetentionBody,
        ),
      });
    },
  );
  org.use('/retention', retention);

  // ---- org data export -------------------------------------------------------------------------
  const exports = Router({ mergeParams: true });
  exports.use(requireRole('OWNER'), requireFeature(ctx, 'data_export'), sessionOnly);
  exports.post('/', idempotency(ctx), async (req, res) => {
    const { org: o } = orgOf(req);
    const { dto, created } = await requestDataExport(
      ctx,
      { kind: 'ORG', requestedById: authUser(req).id, orgId: o.id },
      req.ip,
    );
    res.status(created ? 202 : 200).json({ data: dto });
  });
  exports.get('/', validate({ query: listDataExportsQuerySchema }), async (req, res) => {
    res.json(
      await listDataExports(
        ctx,
        { kind: 'ORG', orgId: orgOf(req).org.id },
        queryOf<PaginationQuery>(req),
      ),
    );
  });
  exports.get('/:id', validate({ params: dataExportParamsSchema }), async (req, res) => {
    const row = await getDataExport(
      ctx,
      { kind: 'ORG', orgId: orgOf(req).org.id },
      req.params.id as string,
    );
    res.json({ data: toDataExportDto(row) });
  });
  exports.get('/:id/download', validate({ params: dataExportParamsSchema }), async (req, res) => {
    const { org: o } = orgOf(req);
    const row = await getDataExport(ctx, { kind: 'ORG', orgId: o.id }, req.params.id as string);
    await sendExport(ctx, req, res, row, o.id);
  });
  org.use('/data-exports', exports);

  // ---- org deletion (grace period + cancel) -------------------------------------------------------
  const deletion = Router({ mergeParams: true });
  deletion.use(requireRole('OWNER'), sessionOnly);
  deletion.get('/', async (req, res) => {
    res.json({ data: await getPendingDeletion(ctx, { orgId: orgOf(req).org.id }) });
  });
  deletion.post('/', validate({ body: scheduleDeletionBodySchema }), async (req, res) => {
    const { dto, created } = await scheduleOrgDeletion(
      ctx,
      orgOf(req).org,
      authUser(req).id,
      req.body as ScheduleDeletionBody,
      req.ip,
    );
    res.status(created ? 201 : 200).json({ data: dto });
  });
  deletion.delete('/', async (req, res) => {
    res.json({ data: await cancelOrgDeletion(ctx, orgOf(req).org.id, authUser(req).id, req.ip) });
  });
  org.use('/deletion', deletion);

  // ---- policy packs ----------------------------------------------------------------------------
  const packs = Router({ mergeParams: true });
  packs.use(requireRole('ADMIN'), requireFeature(ctx, 'policy_packs'));
  packs.get('/', async (req, res) => {
    res.json({ data: await listPolicyPacks(ctx, orgOf(req).org.id), nextCursor: null });
  });
  packs.post(
    '/',
    sessionOnly,
    idempotency(ctx),
    validate({ body: createPolicyPackBodySchema }),
    async (req, res) => {
      const dto = await createPolicyPack(
        ctx,
        orgOf(req).org.id,
        actorOf(req),
        req.body as CreatePolicyPackBody,
      );
      res.status(201).json({ data: dto });
    },
  );
  packs.get('/:packId', validate({ params: policyPackParamsSchema }), async (req, res) => {
    res.json({ data: await getPolicyPack(ctx, orgOf(req).org.id, req.params.packId as string) });
  });
  packs.put(
    '/:packId',
    sessionOnly,
    validate({ params: policyPackParamsSchema, body: updatePolicyPackBodySchema }),
    async (req, res) => {
      res.json({
        data: await updatePolicyPack(
          ctx,
          orgOf(req).org.id,
          actorOf(req),
          req.params.packId as string,
          req.body as UpdatePolicyPackBody,
        ),
      });
    },
  );
  packs.delete(
    '/:packId',
    sessionOnly,
    validate({ params: policyPackParamsSchema }),
    async (req, res) => {
      await deletePolicyPack(ctx, orgOf(req).org.id, actorOf(req), req.params.packId as string);
      res.status(204).end();
    },
  );
  packs.post(
    '/:packId/apply',
    sessionOnly,
    validate({ params: policyPackParamsSchema, body: applyPolicyPackBodySchema }),
    async (req, res) => {
      res.json({
        data: await applyPolicyPackToProjects(
          ctx,
          orgOf(req).org.id,
          actorOf(req),
          req.params.packId as string,
          req.body as ApplyPolicyPackBody,
        ),
      });
    },
  );
  org.use('/policy-packs', packs);
}
