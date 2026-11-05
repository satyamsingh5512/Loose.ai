/**
 * Headless runs API (spec §8.15, §10.6; Phase 9) — OWNED BY W1. Mounted at `/api/v1/runs`.
 *
 *   POST   /runs              start a run (Idempotency-Key, `runs:write`)           → 201 RunDto
 *   GET    /runs              list (members: own runs, admins: the org's)           → page
 *   GET    /runs/:id          one run                                                → RunDto
 *   POST   /runs/:id/cancel   interrupt + pause the session                          → RunDto
 *   GET    /runs/:id/events   Server-Sent Events (status / event / end, resumable)
 *
 * Cookie sessions and personal API tokens both work; tokens need `runs:read` / `runs:write`
 * (they do not imply each other) and only reach the org they were issued for.
 */
import { Router, type Request } from 'express';
import {
  createRunBodySchema,
  listRunsQuerySchema,
  runIdParamsSchema,
  type CreateRunBody,
  type ListRunsQuery,
} from '@loose/shared';
import type { AppContext } from '../context';
import { idempotency } from '../middleware/idempotency';
import type { RateLimiters } from '../middleware/rateLimit';
import { requireAuth } from '../middleware/requireAuth';
import { authUser } from '../middleware/requireOrg';
import { requireScope } from '../middleware/requireScope';
import { queryOf, validate } from '../middleware/validate';
import {
  cancelRun,
  createRun,
  getRun,
  listRuns,
  resolveRunProject,
} from '../services/runs.service';
import type { Caller } from '../services/sessionLifecycle.service';
import { streamRunEvents } from './runsSse';

function callerOf(req: Request): Caller {
  return {
    user: authUser(req),
    apiToken: req.auth?.apiToken,
    ip: req.ip,
    authSession: req.auth?.session,
  };
}

export function runsRouter(ctx: AppContext, limiters: RateLimiters): Router {
  const r = Router();
  r.use(requireAuth(ctx));
  const params = validate({ params: runIdParamsSchema });
  const id = (req: Request) => req.params.id as string;

  r.post(
    '/',
    requireScope('runs:write'),
    limiters.sessionCreate,
    idempotency(ctx),
    validate({ body: createRunBodySchema }),
    async (req, res) => {
      const body = req.body as CreateRunBody;
      const caller = callerOf(req);
      const project = await resolveRunProject(ctx, caller, {
        ...(body.projectId ? { projectId: body.projectId } : {}),
        ...(body.project ? { project: body.project } : {}),
        ...(body.orgId ? { orgId: body.orgId } : {}),
      });
      const dto = await createRun(ctx, caller, {
        projectId: project.id,
        prompt: body.prompt,
        options: body.options,
        source: body.source,
        ...(body.metadata ? { metadata: body.metadata } : {}),
      });
      res.status(201).json({ data: dto });
    },
  );

  r.get(
    '/',
    requireScope('runs:read'),
    validate({ query: listRunsQuerySchema }),
    async (req, res) => {
      res.json(await listRuns(ctx, callerOf(req), queryOf<ListRunsQuery>(req)));
    },
  );

  r.get('/:id', requireScope('runs:read'), params, async (req, res) => {
    res.json({ data: await getRun(ctx, callerOf(req), id(req)) });
  });

  r.post('/:id/cancel', requireScope('runs:write'), params, async (req, res) => {
    res.json({ data: await cancelRun(ctx, callerOf(req), id(req)) });
  });

  r.get('/:id/events', requireScope('runs:read'), params, async (req, res) => {
    await streamRunEvents(ctx, callerOf(req), id(req), req, res);
  });

  return r;
}
