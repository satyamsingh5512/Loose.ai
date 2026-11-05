/** Projects under `/orgs/:orgId/projects` (spec §10.4). Mounted behind requireOrg. */
import { Router } from 'express';
import {
  createProjectBodySchema,
  paginationQuerySchema,
  projectIdParamsSchema,
  updateProjectBodySchema,
  updateProjectExtensionsBodySchema,
  updateProjectMemoryBodySchema,
  type CreateProjectBody,
  type PaginationQuery,
  type UpdateProjectBody,
  type UpdateProjectExtensionsBody,
  type UpdateProjectMemoryBody,
} from '@loose/shared';
import type { Request } from 'express';
import type { AppContext } from '../context';
import { idempotency } from '../middleware/idempotency';
import { authUser, orgOf, requireRole } from '../middleware/requireOrg';
import { queryOf, validate } from '../middleware/validate';
import { getProjectExtensions, updateProjectExtensions } from '../services/extensions.service';
import { generateProjectMemory } from '../services/memory.service';
import type { Actor } from '../services/org.service';
import {
  createProject,
  deleteProject,
  findProject,
  listProjects,
  toMemoryDto,
  toProjectDto,
  updateMemory,
  updateProject,
} from '../services/project.service';
import { listActiveProjectSessions } from '../services/sessionLifecycle.service';
import {
  getTemplateStatus,
  requestTemplateBuild,
  runSmokeTest,
} from '../services/template.service';
import { actorOf as extActorOf } from './extensions';
import { streamTemplateLogs } from './templateLogsSse';

function actorOf(req: Request): Actor {
  return { userId: authUser(req).id, role: orgOf(req).membership.role, ip: req.ip };
}

export function projectsRouter(ctx: AppContext): Router {
  const r = Router({ mergeParams: true });
  const params = validate({ params: projectIdParamsSchema });
  const pid = (req: Request) => req.params.projectId as string;

  r.post(
    '/',
    requireRole('ADMIN'),
    idempotency(ctx),
    validate({ body: createProjectBodySchema }),
    async (req, res) => {
      const dto = await createProject(
        ctx,
        orgOf(req).org,
        actorOf(req),
        req.body as CreateProjectBody,
      );
      res.status(201).json({ data: dto });
    },
  );

  r.get(
    '/',
    requireRole('VIEWER'),
    validate({ query: paginationQuerySchema }),
    async (req, res) => {
      const { org, membership } = orgOf(req);
      res.json(await listProjects(ctx, org.id, membership.role, queryOf<PaginationQuery>(req)));
    },
  );

  r.get('/:projectId', requireRole('VIEWER'), params, async (req, res) => {
    const { org, membership } = orgOf(req);
    res.json({ data: toProjectDto(await findProject(ctx, org.id, pid(req), membership.role)) });
  });

  r.put(
    '/:projectId',
    requireRole('ADMIN'),
    params,
    validate({ body: updateProjectBodySchema }),
    async (req, res) => {
      const dto = await updateProject(
        ctx,
        orgOf(req).org.id,
        pid(req),
        actorOf(req),
        req.body as UpdateProjectBody,
      );
      res.json({ data: dto });
    },
  );

  r.delete('/:projectId', requireRole('ADMIN'), params, async (req, res) => {
    await deleteProject(ctx, orgOf(req).org.id, pid(req), actorOf(req));
    res.status(204).end();
  });

  r.get('/:projectId/memory', requireRole('ADMIN'), params, async (req, res) => {
    const { org, membership } = orgOf(req);
    res.json({ data: toMemoryDto(await findProject(ctx, org.id, pid(req), membership.role)) });
  });

  r.put(
    '/:projectId/memory',
    requireRole('ADMIN'),
    params,
    validate({ body: updateProjectMemoryBodySchema }),
    async (req, res) => {
      const dto = await updateMemory(
        ctx,
        orgOf(req).org.id,
        pid(req),
        actorOf(req),
        req.body as UpdateProjectMemoryBody,
      );
      res.json({ data: dto });
    },
  );

  // ---- templates (Phase 3) -----------------------------------------------------------
  r.post(
    '/:projectId/build-template',
    requireRole('ADMIN'),
    params,
    idempotency(ctx),
    async (req, res) => {
      const dto = await requestTemplateBuild(ctx, orgOf(req).org.id, pid(req), actorOf(req));
      res.status(202).json({ data: dto });
    },
  );

  r.get('/:projectId/template-status', requireRole('ADMIN'), params, async (req, res) => {
    res.json({ data: await getTemplateStatus(ctx, orgOf(req).org.id, pid(req), actorOf(req)) });
  });

  r.get('/:projectId/template-logs', requireRole('ADMIN'), params, async (req, res) => {
    const project = await findProject(ctx, orgOf(req).org.id, pid(req), orgOf(req).membership.role);
    await streamTemplateLogs(ctx, project.id, req, res);
  });

  r.post('/:projectId/smoke-test', requireRole('ADMIN'), params, async (req, res) => {
    res.json({ data: await runSmokeTest(ctx, orgOf(req).org, pid(req), actorOf(req)) });
  });

  // ---- sessions (Phase 4) -------------------------------------------------------------
  r.get('/:projectId/active-sessions', requireRole('MEMBER'), params, async (req, res) => {
    const { org, membership } = orgOf(req);
    const data = await listActiveProjectSessions(ctx, org.id, pid(req), membership);
    res.json({ data, nextCursor: null });
  });

  // ---- memory draft & extensions (Phase 7) ----------------------------------------------
  r.post('/:projectId/memory/generate', requireRole('ADMIN'), params, async (req, res) => {
    const { org, membership } = orgOf(req);
    const project = await findProject(ctx, org.id, pid(req), membership.role);
    res.json({ data: await generateProjectMemory(ctx, project, actorOf(req)) });
  });

  r.get('/:projectId/extensions', requireRole('ADMIN'), params, async (req, res) => {
    const { org, membership } = orgOf(req);
    const project = await findProject(ctx, org.id, pid(req), membership.role);
    res.json({ data: await getProjectExtensions(ctx, org, project) });
  });

  r.put(
    '/:projectId/extensions',
    requireRole('ADMIN'),
    params,
    validate({ body: updateProjectExtensionsBodySchema }),
    async (req, res) => {
      const { org, membership } = orgOf(req);
      const project = await findProject(ctx, org.id, pid(req), membership.role);
      const dto = await updateProjectExtensions(
        ctx,
        org,
        project,
        extActorOf(req),
        req.body as UpdateProjectExtensionsBody,
      );
      res.json({ data: dto });
    },
  );

  return r;
}
