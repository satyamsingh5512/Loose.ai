/**
 * Org automation triggers admin API (spec §8.15; Phase 9) — OWNED BY W4.
 * Mounted at `/orgs/:orgId/triggers` inside the org router (requireAuth + requireOrg already
 * ran). ADMIN+ and browser-session only (like webhooks and token management): a leaked API
 * token must not be able to create triggers that run arbitrary prompts as another member.
 */
import { Router, type Request, type RequestHandler } from 'express';
import {
  createTriggerBodySchema,
  fireTriggerBodySchema,
  listTriggersQuerySchema,
  triggerParamsSchema,
  triggerRunsQuerySchema,
  updateTriggerBodySchema,
  type CreateTriggerBody,
  type FireTriggerBody,
  type ListTriggersQuery,
  type PaginationQuery,
  type UpdateTriggerBody,
} from '@loose/shared';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';
import { idempotency } from '../middleware/idempotency';
import { authUser, orgOf, requireRole } from '../middleware/requireOrg';
import { queryOf, validate } from '../middleware/validate';
import {
  createTrigger,
  deleteTrigger,
  fireTriggerManually,
  getTrigger,
  listTriggerRuns,
  listTriggers,
  updateTrigger,
  type TriggerActor,
} from '../services/triggers.service';

const sessionOnly: RequestHandler = (req, _res, next) => {
  if (req.auth?.apiToken) {
    throw new AppError('LSE-AUTH-001', {
      devMessage: 'This endpoint requires a browser session; API tokens are not accepted',
    });
  }
  next();
};

export function triggersRouter(ctx: AppContext): Router {
  const r = Router({ mergeParams: true });
  const actorOf = (req: Request): TriggerActor => ({ userId: authUser(req).id, ip: req.ip });
  const orgId = (req: Request) => orgOf(req).org.id;
  const id = (req: Request) => req.params.id as string;
  const params = validate({ params: triggerParamsSchema });

  r.use(sessionOnly, requireRole('ADMIN'));

  r.get('/', validate({ query: listTriggersQuerySchema }), async (req, res) => {
    res.json(await listTriggers(ctx, orgId(req), queryOf<ListTriggersQuery>(req)));
  });

  r.post('/', idempotency(ctx), validate({ body: createTriggerBodySchema }), async (req, res) => {
    const dto = await createTrigger(ctx, orgId(req), actorOf(req), req.body as CreateTriggerBody);
    res.status(201).json({ data: dto });
  });

  r.get('/:id', params, async (req, res) => {
    res.json({ data: await getTrigger(ctx, orgId(req), id(req)) });
  });

  r.put('/:id', params, validate({ body: updateTriggerBodySchema }), async (req, res) => {
    const dto = await updateTrigger(
      ctx,
      orgId(req),
      id(req),
      actorOf(req),
      req.body as UpdateTriggerBody,
    );
    res.json({ data: dto });
  });

  r.delete('/:id', params, async (req, res) => {
    await deleteTrigger(ctx, orgId(req), id(req), actorOf(req));
    res.status(204).end();
  });

  r.post(
    '/:id/fire',
    params,
    idempotency(ctx),
    validate({ body: fireTriggerBodySchema }),
    async (req, res) => {
      const result = await fireTriggerManually(
        ctx,
        orgId(req),
        id(req),
        actorOf(req),
        req.body as FireTriggerBody,
      );
      res.status(202).json({ data: result });
    },
  );

  r.get('/:id/runs', params, validate({ query: triggerRunsQuerySchema }), async (req, res) => {
    res.json(
      await listTriggerRuns(ctx, orgId(req), id(req), actorOf(req), queryOf<PaginationQuery>(req)),
    );
  });

  return r;
}
