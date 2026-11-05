/**
 * Extensions under `/orgs/:orgId` (spec §10.4.1; Phases 7–8): skills, slash commands,
 * MCP servers (+ catalog), subagents, hooks (+ recipes, test) and plugins (versions,
 * install / update / rollback). Viewing needs MEMBER; changing shared (ORG / PROJECT)
 * resources needs ADMIN, personal (USER) resources belong to their member (checked in
 * the service). Hooks and plugins are org policy: ADMIN only.
 */
import { Router, type Request, type RequestHandler } from 'express';
import { z } from 'zod';
import {
  createCommandBodySchema,
  createHookBodySchema,
  createMcpServerBodySchema,
  createPluginBodySchema,
  createSkillBodySchema,
  createSubagentBodySchema,
  extensionListQuerySchema,
  hookTestBodySchema,
  idSchema,
  importSkillBodySchema,
  installPluginBodySchema,
  pluginInstallQuerySchema,
  publishPluginVersionBodySchema,
  skillDryRunBodySchema,
  updateCommandBodySchema,
  updateHookBodySchema,
  updateMcpServerBodySchema,
  updatePluginInstallBodySchema,
  updateSkillBodySchema,
  updateSubagentBodySchema,
  validatePluginBodySchema,
  type CreateCommandBody,
  type CreateHookBody,
  type CreateMcpServerBody,
  type CreatePluginBody,
  type CreateSkillBody,
  type CreateSubagentBody,
  type ExtensionListQuery,
  type HookTestBody,
  type ImportSkillBody,
  type InstallPluginBody,
  type PluginInstallQuery,
  type PublishPluginVersionBody,
  type SkillFile,
  type UpdateCommandBody,
  type UpdateHookBody,
  type UpdateMcpServerBody,
  type UpdatePluginInstallBody,
  type UpdateSkillBody,
  type UpdateSubagentBody,
  type ValidatePluginBody,
} from '@loose/shared';
import type { AppContext } from '../context';
import { idempotency } from '../middleware/idempotency';
import { authUser, orgOf, requireRole } from '../middleware/requireOrg';
import { queryOf, validate } from '../middleware/validate';
import {
  createCommand,
  createMcpServer,
  createSkill,
  deleteCommand,
  deleteMcpServer,
  deleteSkill,
  dryRunSavedSkill,
  dryRunSkill,
  getMcpServer,
  getSkill,
  importSkill,
  listCommands,
  listMcpServers,
  listSkills,
  listSkillVersions,
  mcpCatalog,
  restoreSkillVersion,
  testMcpServer,
  updateCommand,
  updateMcpServer,
  updateSkill,
  type ExtActor,
} from '../services/extensions.service';
import {
  createHook,
  deleteHook,
  getHook,
  hookRecipes,
  listHooks,
  testHook,
  updateHook,
} from '../services/hooks.service';
import {
  createPlugin,
  deletePlugin,
  getPlugin,
  installPlugin,
  listPlugins,
  publishPluginVersion,
  uninstallPlugin,
  updatePluginInstall,
  validatePlugin,
} from '../services/plugins.service';
import {
  createSubagent,
  deleteSubagent,
  getSubagent,
  listSubagents,
  updateSubagent,
} from '../services/subagents.service';

/** Bodiless POSTs are validated as `{}`. */
const emptyBody: RequestHandler = (req, _res, next) => {
  req.body ??= {};
  next();
};

export function actorOf(req: Request): ExtActor {
  return { userId: authUser(req).id, membership: orgOf(req).membership, ip: req.ip };
}

const params = validate({ params: z.object({ orgId: idSchema, id: idSchema }) });
/** Skill ids include built-ins (`builtin:<name>`). */
const skillParams = validate({
  params: z.object({
    orgId: idSchema,
    id: z
      .string()
      .max(100)
      .regex(/^(?:builtin:[a-z0-9-]+|[A-Za-z0-9_-]+)$/, 'Invalid id'),
  }),
});
/** Subagent ids include built-ins (`builtin:<name>`). */
const subagentParams = validate({
  params: z.object({
    orgId: idSchema,
    id: z
      .string()
      .max(100)
      .regex(/^(?:builtin:[a-z0-9-]+|[A-Za-z0-9_-]+)$/, 'Invalid id'),
  }),
});
const versionParams = validate({
  params: z.object({ orgId: idSchema, id: idSchema, version: z.coerce.number().int().positive() }),
});
const listQuery = validate({ query: extensionListQuerySchema });

export function extensionsRouter(ctx: AppContext): Router {
  const r = Router({ mergeParams: true });
  const id = (req: Request) => req.params.id as string;
  const org = (req: Request) => orgOf(req).org;

  // ---- skills ----------------------------------------------------------------------------
  r.get('/skills', requireRole('MEMBER'), listQuery, async (req, res) => {
    const data = await listSkills(ctx, org(req), actorOf(req), queryOf<ExtensionListQuery>(req));
    res.json({ data, nextCursor: null });
  });
  r.post(
    '/skills',
    requireRole('MEMBER'),
    idempotency(ctx),
    validate({ body: createSkillBodySchema }),
    async (req, res) => {
      const dto = await createSkill(ctx, org(req), actorOf(req), req.body as CreateSkillBody);
      res.status(201).json({ data: dto });
    },
  );
  r.post(
    '/skills/import',
    requireRole('MEMBER'),
    idempotency(ctx),
    validate({ body: importSkillBodySchema }),
    async (req, res) => {
      const dto = await importSkill(ctx, org(req), actorOf(req), req.body as ImportSkillBody);
      res.status(201).json({ data: dto });
    },
  );
  r.post(
    '/skills/dry-run',
    requireRole('MEMBER'),
    validate({ body: skillDryRunBodySchema }),
    (req, res) => {
      res.json({ data: dryRunSkill((req.body as { files: SkillFile[] }).files) });
    },
  );
  r.get('/skills/:id', requireRole('MEMBER'), skillParams, async (req, res) => {
    res.json({ data: await getSkill(ctx, org(req), actorOf(req), id(req)) });
  });
  r.put(
    '/skills/:id',
    requireRole('MEMBER'),
    params,
    validate({ body: updateSkillBodySchema }),
    async (req, res) => {
      const dto = await updateSkill(
        ctx,
        org(req),
        actorOf(req),
        id(req),
        req.body as UpdateSkillBody,
      );
      res.json({ data: dto });
    },
  );
  r.delete('/skills/:id', requireRole('MEMBER'), params, async (req, res) => {
    await deleteSkill(ctx, org(req), actorOf(req), id(req));
    res.status(204).end();
  });
  r.get('/skills/:id/versions', requireRole('MEMBER'), params, async (req, res) => {
    const data = await listSkillVersions(ctx, org(req), actorOf(req), id(req));
    res.json({ data, nextCursor: null });
  });
  r.post(
    '/skills/:id/versions/:version/restore',
    requireRole('MEMBER'),
    versionParams,
    async (req, res) => {
      const dto = await restoreSkillVersion(
        ctx,
        org(req),
        actorOf(req),
        id(req),
        Number(req.params.version),
      );
      res.json({ data: dto });
    },
  );
  r.post('/skills/:id/dry-run', requireRole('MEMBER'), skillParams, async (req, res) => {
    res.json({ data: await dryRunSavedSkill(ctx, org(req), actorOf(req), id(req)) });
  });

  // ---- slash commands ------------------------------------------------------------------
  r.get('/commands', requireRole('MEMBER'), listQuery, async (req, res) => {
    const data = await listCommands(ctx, org(req), actorOf(req), queryOf<ExtensionListQuery>(req));
    res.json({ data, nextCursor: null });
  });
  r.post(
    '/commands',
    requireRole('MEMBER'),
    idempotency(ctx),
    validate({ body: createCommandBodySchema }),
    async (req, res) => {
      const dto = await createCommand(ctx, org(req), actorOf(req), req.body as CreateCommandBody);
      res.status(201).json({ data: dto });
    },
  );
  r.put(
    '/commands/:id',
    requireRole('MEMBER'),
    params,
    validate({ body: updateCommandBodySchema }),
    async (req, res) => {
      const dto = await updateCommand(
        ctx,
        org(req),
        actorOf(req),
        id(req),
        req.body as UpdateCommandBody,
      );
      res.json({ data: dto });
    },
  );
  r.delete('/commands/:id', requireRole('MEMBER'), params, async (req, res) => {
    await deleteCommand(ctx, org(req), actorOf(req), id(req));
    res.status(204).end();
  });

  // ---- MCP servers -----------------------------------------------------------------------
  r.get('/mcp-catalog', requireRole('MEMBER'), (_req, res) => {
    res.json({ data: mcpCatalog(), nextCursor: null });
  });
  r.get('/mcp-servers', requireRole('MEMBER'), listQuery, async (req, res) => {
    const data = await listMcpServers(
      ctx,
      org(req),
      actorOf(req),
      queryOf<ExtensionListQuery>(req),
    );
    res.json({ data, nextCursor: null });
  });
  r.post(
    '/mcp-servers',
    requireRole('MEMBER'),
    idempotency(ctx),
    validate({ body: createMcpServerBodySchema }),
    async (req, res) => {
      const dto = await createMcpServer(
        ctx,
        org(req),
        actorOf(req),
        req.body as CreateMcpServerBody,
      );
      res.status(201).json({ data: dto });
    },
  );
  r.get('/mcp-servers/:id', requireRole('MEMBER'), params, async (req, res) => {
    res.json({ data: await getMcpServer(ctx, org(req), actorOf(req), id(req)) });
  });
  r.put(
    '/mcp-servers/:id',
    requireRole('MEMBER'),
    params,
    validate({ body: updateMcpServerBodySchema }),
    async (req, res) => {
      const dto = await updateMcpServer(
        ctx,
        org(req),
        actorOf(req),
        id(req),
        req.body as UpdateMcpServerBody,
      );
      res.json({ data: dto });
    },
  );
  r.delete('/mcp-servers/:id', requireRole('MEMBER'), params, async (req, res) => {
    await deleteMcpServer(ctx, org(req), actorOf(req), id(req));
    res.status(204).end();
  });
  r.post('/mcp-servers/:id/test', requireRole('MEMBER'), params, async (req, res) => {
    res.json({ data: await testMcpServer(ctx, org(req), actorOf(req), id(req)) });
  });

  // ---- subagents (Phase 8, spec §8.8) ------------------------------------------------------
  r.get('/subagents', requireRole('MEMBER'), listQuery, async (req, res) => {
    const data = await listSubagents(ctx, org(req), actorOf(req), queryOf<ExtensionListQuery>(req));
    res.json({ data, nextCursor: null });
  });
  r.post(
    '/subagents',
    requireRole('MEMBER'),
    idempotency(ctx),
    validate({ body: createSubagentBodySchema }),
    async (req, res) => {
      const dto = await createSubagent(ctx, org(req), actorOf(req), req.body as CreateSubagentBody);
      res.status(201).json({ data: dto });
    },
  );
  r.get('/subagents/:id', requireRole('MEMBER'), subagentParams, async (req, res) => {
    res.json({ data: await getSubagent(ctx, org(req), actorOf(req), id(req)) });
  });
  r.put(
    '/subagents/:id',
    requireRole('MEMBER'),
    params,
    validate({ body: updateSubagentBodySchema }),
    async (req, res) => {
      const dto = await updateSubagent(
        ctx,
        org(req),
        actorOf(req),
        id(req),
        req.body as UpdateSubagentBody,
      );
      res.json({ data: dto });
    },
  );
  r.delete('/subagents/:id', requireRole('MEMBER'), params, async (req, res) => {
    await deleteSubagent(ctx, org(req), actorOf(req), id(req));
    res.status(204).end();
  });

  // ---- hooks (Phase 8, spec §8.9) ----------------------------------------------------------
  r.get('/hooks/recipes', requireRole('MEMBER'), (_req, res) => {
    res.json({ data: hookRecipes(), nextCursor: null });
  });
  r.get('/hooks', requireRole('MEMBER'), listQuery, async (req, res) => {
    const data = await listHooks(ctx, org(req), actorOf(req), queryOf<ExtensionListQuery>(req));
    res.json({ data, nextCursor: null });
  });
  r.post(
    '/hooks',
    requireRole('ADMIN'),
    idempotency(ctx),
    validate({ body: createHookBodySchema }),
    async (req, res) => {
      const dto = await createHook(ctx, org(req), actorOf(req), req.body as CreateHookBody);
      res.status(201).json({ data: dto });
    },
  );
  r.get('/hooks/:id', requireRole('MEMBER'), params, async (req, res) => {
    res.json({ data: await getHook(ctx, org(req), actorOf(req), id(req)) });
  });
  r.put(
    '/hooks/:id',
    requireRole('ADMIN'),
    params,
    validate({ body: updateHookBodySchema }),
    async (req, res) => {
      const dto = await updateHook(
        ctx,
        org(req),
        actorOf(req),
        id(req),
        req.body as UpdateHookBody,
      );
      res.json({ data: dto });
    },
  );
  r.delete('/hooks/:id', requireRole('ADMIN'), params, async (req, res) => {
    await deleteHook(ctx, org(req), actorOf(req), id(req));
    res.status(204).end();
  });
  r.post(
    '/hooks/:id/test',
    requireRole('ADMIN'),
    params,
    emptyBody,
    validate({ body: hookTestBodySchema }),
    async (req, res) => {
      const dto = await testHook(ctx, org(req), actorOf(req), id(req), req.body as HookTestBody);
      res.json({ data: dto });
    },
  );

  // ---- plugins (Phase 8, spec §8.16) -------------------------------------------------------
  r.get('/plugins', requireRole('MEMBER'), listQuery, async (req, res) => {
    const data = await listPlugins(ctx, org(req), actorOf(req), queryOf<ExtensionListQuery>(req));
    res.json({ data, nextCursor: null });
  });
  r.post(
    '/plugins',
    requireRole('ADMIN'),
    idempotency(ctx),
    validate({ body: createPluginBodySchema }),
    async (req, res) => {
      const dto = await createPlugin(ctx, org(req), actorOf(req), req.body as CreatePluginBody);
      res.status(201).json({ data: dto });
    },
  );
  r.post(
    '/plugins/validate',
    requireRole('ADMIN'),
    validate({ body: validatePluginBodySchema }),
    async (req, res) => {
      const dto = await validatePlugin(ctx, org(req), actorOf(req), req.body as ValidatePluginBody);
      res.json({ data: dto });
    },
  );
  r.get('/plugins/:id', requireRole('MEMBER'), params, listQuery, async (req, res) => {
    const q = queryOf<ExtensionListQuery>(req);
    res.json({ data: await getPlugin(ctx, org(req), actorOf(req), id(req), q) });
  });
  r.post(
    '/plugins/:id/versions',
    requireRole('ADMIN'),
    params,
    idempotency(ctx),
    validate({ body: publishPluginVersionBodySchema }),
    async (req, res) => {
      const dto = await publishPluginVersion(
        ctx,
        org(req),
        actorOf(req),
        id(req),
        req.body as PublishPluginVersionBody,
      );
      res.status(201).json({ data: dto });
    },
  );
  r.delete('/plugins/:id', requireRole('ADMIN'), params, async (req, res) => {
    await deletePlugin(ctx, org(req), actorOf(req), id(req));
    res.status(204).end();
  });
  r.post(
    '/plugins/:id/install',
    requireRole('ADMIN'),
    params,
    idempotency(ctx),
    validate({ body: installPluginBodySchema }),
    async (req, res) => {
      const dto = await installPlugin(
        ctx,
        org(req),
        actorOf(req),
        id(req),
        req.body as InstallPluginBody,
      );
      res.status(201).json({ data: dto });
    },
  );
  r.put(
    '/plugins/:id/install',
    requireRole('ADMIN'),
    params,
    validate({ body: updatePluginInstallBodySchema }),
    async (req, res) => {
      const dto = await updatePluginInstall(
        ctx,
        org(req),
        actorOf(req),
        id(req),
        req.body as UpdatePluginInstallBody,
      );
      res.json({ data: dto });
    },
  );
  r.delete(
    '/plugins/:id/install',
    requireRole('ADMIN'),
    params,
    validate({ query: pluginInstallQuerySchema }),
    async (req, res) => {
      await uninstallPlugin(
        ctx,
        org(req),
        actorOf(req),
        id(req),
        queryOf<PluginInstallQuery>(req).projectId,
      );
      res.status(204).end();
    },
  );

  return r;
}
