import { Router, type Express } from 'express';
import {
  FEATURE_FLAGS,
  FEATURE_FLAG_DEFINITIONS,
  updateOrgFeatureFlagsBodySchema,
  type FeatureFlagsDto,
  type UpdateOrgFeatureFlagsBody,
} from '@loose/shared';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';
import { parseOrgFeatureFlags } from '@loose/shared';
import { orgOf, requireRole } from '../middleware/requireOrg';
import { validate } from '../middleware/validate';

function metricRoute(req: { route?: { path?: unknown }; baseUrl?: string }) {
  const route = typeof req.route?.path === 'string' ? req.route.path : 'unmatched';
  return route === 'unmatched' ? route : `${req.baseUrl ?? ''}${route}`;
}
/** Main-port metrics bearer endpoint plus HTTP request instrumentation. */
export function mountObservabilityRoutes(app: Express, ctx: AppContext): void {
  const requests = ctx.metrics.counter('loose_http_requests_total', 'HTTP requests completed', [
    'method',
    'route',
    'status',
  ]);
  const duration = ctx.metrics.histogram(
    'loose_http_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'route'],
  );
  app.use((req, res, next) => {
    const started = process.hrtime.bigint();
    res.once('finish', () => {
      const route = metricRoute(req);
      requests.inc({ method: req.method, route, status: res.statusCode });
      duration.observe(Number(process.hrtime.bigint() - started) / 1e9, {
        method: req.method,
        route,
      });
    });
    next();
  });
  app.get('/metrics', async (req, res) => {
    if (!ctx.env.METRICS_TOKEN)
      throw new AppError('LSE-NF-001', { devMessage: 'Metrics are not enabled' });
    const auth = req.header('authorization');
    if (auth !== `Bearer ${ctx.env.METRICS_TOKEN}`) throw new AppError('LSE-AUTH-001');
    res.type('text/plain; version=0.0.4; charset=utf-8').send(await ctx.metrics.render());
  });
}
export function mountObservabilityApiRoutes(api: Router, ctx: AppContext): void {
  api.get('/feature-flags', (_req, res) =>
    res.json({ data: { flags: ctx.featureFlags.all() } satisfies FeatureFlagsDto }),
  );
}
export function mountObservabilityOrgRoutes(org: Router, ctx: AppContext): void {
  const r = Router({ mergeParams: true });
  r.get('/', requireRole('VIEWER'), (req, res) => {
    const dto: FeatureFlagsDto = {
      flags: ctx.featureFlags.all(orgOf(req).org),
      orgControllable: FEATURE_FLAGS.filter((f) => FEATURE_FLAG_DEFINITIONS[f].orgControllable),
    };
    res.json({ data: dto });
  });
  r.put(
    '/',
    requireRole('OWNER'),
    validate({ body: updateOrgFeatureFlagsBodySchema }),
    async (req, res) => {
      if (req.auth?.via !== 'session')
        throw new AppError('LSE-AUTH-001', { devMessage: 'Cookie session required' });
      const { org: current } = orgOf(req);
      const patch = (req.body as UpdateOrgFeatureFlagsBody).flags;
      const stored = parseOrgFeatureFlags(current.featureFlags);
      for (const [flag, value] of Object.entries(patch)) {
        if (
          !FEATURE_FLAG_DEFINITIONS[flag as keyof typeof FEATURE_FLAG_DEFINITIONS]?.orgControllable
        )
          throw new AppError('LSE-VAL-001', {
            fields: { flags: [`${flag} is not organization-controllable`] },
          });
        if (value === null) delete stored[flag as keyof typeof stored];
        else stored[flag as keyof typeof stored] = value;
      }
      const updated = await ctx.prisma.organization.update({
        where: { id: current.id },
        data: { featureFlags: stored },
      });
      res.json({
        data: {
          flags: ctx.featureFlags.all(updated),
          orgControllable: FEATURE_FLAGS.filter((f) => FEATURE_FLAG_DEFINITIONS[f].orgControllable),
        } satisfies FeatureFlagsDto,
      });
    },
  );
  org.use('/feature-flags', r);
}
