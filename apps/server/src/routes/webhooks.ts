/**
 * Org outbound webhooks admin API (spec §8.15, §10.2; Phase 9) — OWNED BY W1.
 * Mounted at `/orgs/:orgId/webhooks` inside the org router (requireAuth + requireOrg already ran).
 * ADMIN+ and browser-session only: like token management, a leaked API token must not be able to
 * point org events (or read their secrets) at an attacker's endpoint.
 */
import { Router, type Request, type RequestHandler } from 'express';
import {
  createWebhookBodySchema,
  listWebhookDeliveriesQuerySchema,
  updateWebhookBodySchema,
  webhookDeliveryParamsSchema,
  webhookParamsSchema,
  type CreateWebhookBody,
  type ListWebhookDeliveriesQuery,
  type UpdateWebhookBody,
} from '@loose/shared';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';
import { idempotency } from '../middleware/idempotency';
import { authUser, orgOf, requireRole } from '../middleware/requireOrg';
import { queryOf, validate } from '../middleware/validate';
import {
  createWebhook,
  deleteWebhook,
  getDelivery,
  getWebhook,
  listDeliveries,
  listWebhooks,
  redeliver,
  rotateWebhookSecret,
  testWebhook,
  updateWebhook,
  type WebhookActor,
} from '../services/webhooks.service';

const sessionOnly: RequestHandler = (req, _res, next) => {
  if (req.auth?.apiToken) {
    throw new AppError('LSE-AUTH-001', {
      devMessage: 'This endpoint requires a browser session; API tokens are not accepted',
    });
  }
  next();
};

export function webhooksRouter(ctx: AppContext): Router {
  const r = Router({ mergeParams: true });
  const actorOf = (req: Request): WebhookActor => ({ userId: authUser(req).id, ip: req.ip });
  const orgId = (req: Request) => orgOf(req).org.id;
  const id = (req: Request) => req.params.id as string;
  const params = validate({ params: webhookParamsSchema });

  r.use(sessionOnly, requireRole('ADMIN'));

  r.get('/', async (req, res) => {
    res.json(await listWebhooks(ctx, orgId(req)));
  });

  r.post('/', idempotency(ctx), validate({ body: createWebhookBodySchema }), async (req, res) => {
    const dto = await createWebhook(ctx, orgId(req), actorOf(req), req.body as CreateWebhookBody);
    res.status(201).json({ data: dto });
  });

  r.get('/:id', params, async (req, res) => {
    res.json({ data: await getWebhook(ctx, orgId(req), id(req)) });
  });

  r.put('/:id', params, validate({ body: updateWebhookBodySchema }), async (req, res) => {
    const dto = await updateWebhook(
      ctx,
      orgId(req),
      id(req),
      actorOf(req),
      req.body as UpdateWebhookBody,
    );
    res.json({ data: dto });
  });

  r.delete('/:id', params, async (req, res) => {
    await deleteWebhook(ctx, orgId(req), id(req), actorOf(req));
    res.status(204).end();
  });

  r.post('/:id/rotate-secret', params, async (req, res) => {
    res.json({ data: await rotateWebhookSecret(ctx, orgId(req), id(req), actorOf(req)) });
  });

  r.post('/:id/test', params, async (req, res) => {
    res.json({ data: await testWebhook(ctx, orgId(req), id(req), actorOf(req)) });
  });

  r.get(
    '/:id/deliveries',
    params,
    validate({ query: listWebhookDeliveriesQuerySchema }),
    async (req, res) => {
      res.json(
        await listDeliveries(ctx, orgId(req), id(req), queryOf<ListWebhookDeliveriesQuery>(req)),
      );
    },
  );

  const deliveryParams = validate({ params: webhookDeliveryParamsSchema });
  r.get('/:id/deliveries/:deliveryId', deliveryParams, async (req, res) => {
    res.json({
      data: await getDelivery(ctx, orgId(req), id(req), req.params.deliveryId as string),
    });
  });

  r.post('/:id/deliveries/:deliveryId/redeliver', deliveryParams, async (req, res) => {
    const dto = await redeliver(
      ctx,
      orgId(req),
      id(req),
      req.params.deliveryId as string,
      actorOf(req),
    );
    res.status(202).json({ data: dto });
  });

  return r;
}
