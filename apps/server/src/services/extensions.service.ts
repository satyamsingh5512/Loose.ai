/**
 * Extensions (spec §8.6, §8.6.1, §8.7, §10.4.1; Phase 7): skills (with version history,
 * GitHub import, dry-run validation), custom slash commands and MCP servers (encrypted
 * credentials, connection test), per-project overrides, and the resolution of what a
 * session gets (Built-in → Org → Project → User; narrower scopes override by name).
 *
 * Scopes: ORG and PROJECT resources are managed by org ADMINs; USER resources belong to
 * one member (in one org) and are allowed by the org policy (`allowUserSkills` /
 * `allowUserMcp`). Every row carries its `orgId` (tenant isolation).
 */
import type { McpServer, Organization, Prisma, Project, Skill, SlashCommand } from '@prisma/client';
import {
  BUILTIN_SKILLS,
  commandDtoSchema,
  extensionOverridesSchema,
  findBuiltinSkill,
  isAllowedMcpCommand,
  isBuiltinCommand,
  MCP_CATALOG,
  MCP_SECRET_ENV_PREFIX,
  mcpServerDtoSchema,
  mcpToolPolicySchema,
  normalizeBundlePath,
  parseCommandMeta,
  parseOrgPolicy,
  skillDetailDtoSchema,
  skillDtoSchema,
  SKILL_ENTRY_FILE,
  skillVersionDtoSchema,
  validateSkillBundle,
  type CommandDto,
  type CreateCommandBody,
  type CreateMcpServerBody,
  type CreateSkillBody,
  type ErrorCode,
  type ExtensionListQuery,
  type ExtensionOverrides,
  type ImportSkillBody,
  type McpServerDto,
  type McpTestResultDto,
  type McpToolPolicy,
  type OrgPolicy,
  type ProjectExtensionsDto,
  type RunnerMcpServerInput,
  type RunnerSubagentInput,
  type SkillDetailDto,
  type SkillDryRunDto,
  type SkillDto,
  type SkillFile,
  type SkillVersionDto,
  type UpdateCommandBody,
  type UpdateMcpServerBody,
  type UpdateProjectExtensionsBody,
  type UpdateSkillBody,
  type WritableExtScope,
} from '@loose/shared';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';
import { safeFetch, type SafeFetchInit } from '../lib/net/safeFetch';
import type { SandboxHandle } from '../lib/sandbox';
import {
  assertCanWrite,
  assertNameFree,
  assertProjectInOrg,
  assertPublicUrl,
  isRecord,
  json,
  scopeIds,
  visibleWhere,
  type ExtActor,
} from './extensionsCommon';
import { shq } from './gitAccess.service';
import { githubClientFor, mapGithubError } from './github.service';
import { hookToDto, pluginHookToDto, resolveHooks, type ResolvedHook } from './hooks.service';
import {
  listProjectInstalls,
  resolvePluginContents,
  type ResolvedPluginSkill,
} from './plugins.service';
import { subagentCandidates, toRunnerSubagent } from './subagents.service';

export { assertPublicUrl } from './extensionsCommon';
export type { ExtActor } from './extensionsCommon';

// ---- skills --------------------------------------------------------------------------------

function filesOf(v: Prisma.JsonValue): SkillFile[] {
  return Array.isArray(v)
    ? v.filter(
        (f): f is { path: string; content: string } =>
          isRecord(f) && typeof f.path === 'string' && typeof f.content === 'string',
      )
    : [];
}

function normalizeFiles(files: readonly SkillFile[]): SkillFile[] {
  return files.map((f) => ({ path: normalizeBundlePath(f.path) ?? f.path, content: f.content }));
}

function validateOrThrow(files: readonly SkillFile[]) {
  const v = validateSkillBundle(files);
  if (!v.ok || !v.name || !v.description) {
    const first = v.issues[0];
    throw new AppError((first?.code ?? 'LSE-EXT-001') as ErrorCode, {
      devMessage: first?.message ?? 'Invalid skill',
      fields: { files: v.issues.map((i) => (i.path ? `${i.path}: ${i.message}` : i.message)) },
    });
  }
  return v as typeof v & { name: string; description: string };
}

export function skillToDto(row: Skill): SkillDto {
  return skillDtoSchema.parse({ ...row, builtin: false });
}

function builtinSkillDto(name: string, policy: OrgPolicy): SkillDto {
  const b = findBuiltinSkill(name)!;
  return skillDtoSchema.parse({
    id: `builtin:${b.name}`,
    scope: 'BUILTIN',
    orgId: null,
    projectId: null,
    userId: null,
    name: b.name,
    description: b.description,
    quickAction: b.quickAction ?? null,
    version: 1,
    enabled: !policy.extensions.disabledBuiltinSkills.includes(b.name),
    builtin: true,
    createdAt: null,
    updatedAt: null,
  });
}

export async function listSkills(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  q: ExtensionListQuery,
): Promise<SkillDto[]> {
  const policy = parseOrgPolicy(org.policy);
  const rows = await ctx.prisma.skill.findMany({
    where: visibleWhere(org.id, actor.userId, q),
    orderBy: [{ scope: 'asc' }, { name: 'asc' }],
  });
  return [...BUILTIN_SKILLS.map((b) => builtinSkillDto(b.name, policy)), ...rows.map(skillToDto)];
}

async function loadSkill(ctx: AppContext, orgId: string, actor: ExtActor, id: string) {
  const row = await ctx.prisma.skill.findFirst({ where: { id, orgId } });
  if (!row || (row.scope === 'USER' && row.userId !== actor.userId)) {
    throw new AppError('LSE-NF-001', { devMessage: 'Skill not found' });
  }
  return row;
}

export async function getSkill(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  id: string,
): Promise<SkillDetailDto> {
  if (id.startsWith('builtin:')) {
    const b = findBuiltinSkill(id.slice('builtin:'.length));
    if (!b) throw new AppError('LSE-NF-001', { devMessage: 'Skill not found' });
    return skillDetailDtoSchema.parse({
      ...builtinSkillDto(b.name, parseOrgPolicy(org.policy)),
      files: [{ path: SKILL_ENTRY_FILE, content: b.skillMd }],
      warnings: [],
    });
  }
  const row = await loadSkill(ctx, org.id, actor, id);
  const files = filesOf(row.files);
  return skillDetailDtoSchema.parse({
    ...skillToDto(row),
    files,
    warnings: validateSkillBundle(files).warnings,
  });
}

export async function createSkill(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  body: Pick<CreateSkillBody, 'scope' | 'projectId' | 'files' | 'enabled'>,
): Promise<SkillDetailDto> {
  assertCanWrite(actor, parseOrgPolicy(org.policy), 'skill', body.scope);
  await assertProjectInOrg(ctx, org.id, body.projectId);
  const files = normalizeFiles(body.files);
  const v = validateOrThrow(files);
  const ids = scopeIds(org.id, actor, body.scope, body.projectId);
  await assertNameFree(
    (where) => ctx.prisma.skill.findFirst({ where, select: { id: true } }),
    ids,
    v.name,
  );
  const row = await ctx.prisma.skill.create({
    data: {
      ...ids,
      name: v.name,
      description: v.description,
      quickAction: v.quickAction ?? null,
      files: json(files),
      version: 1,
      enabled: body.enabled,
      versions: {
        create: {
          version: 1,
          description: v.description,
          files: json(files),
          bytes: v.totalBytes,
          createdById: actor.userId,
        },
      },
    },
  });
  await ctx.audit.record({
    orgId: org.id,
    actorId: actor.userId,
    action: 'skill.create',
    target: row.id,
    meta: { name: row.name, scope: row.scope, projectId: row.projectId },
    ip: actor.ip,
  });
  return { ...(await getSkill(ctx, org, actor, row.id)), warnings: v.warnings };
}

export async function updateSkill(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  id: string,
  body: UpdateSkillBody,
): Promise<SkillDetailDto> {
  const row = await loadSkill(ctx, org.id, actor, id);
  assertCanWrite(
    actor,
    parseOrgPolicy(org.policy),
    'skill',
    row.scope as WritableExtScope,
    row.userId,
  );
  const data: Prisma.SkillUpdateInput = {};
  let warnings: string[] = [];
  if (body.files) {
    const files = normalizeFiles(body.files);
    const v = validateOrThrow(files);
    if (v.name !== row.name) {
      throw new AppError('LSE-EXT-001', {
        devMessage: 'The skill name cannot change; create a new skill instead',
        fields: { files: [`${SKILL_ENTRY_FILE}: "name" must stay "${row.name}"`] },
      });
    }
    const version = row.version + 1;
    warnings = v.warnings;
    Object.assign(data, {
      description: v.description,
      quickAction: v.quickAction ?? null,
      files: json(files),
      version,
      versions: {
        create: {
          version,
          description: v.description,
          files: json(files),
          bytes: v.totalBytes,
          createdById: actor.userId,
        },
      },
    });
  }
  if (body.enabled !== undefined) data.enabled = body.enabled;
  await ctx.prisma.skill.update({ where: { id: row.id }, data });
  await ctx.audit.record({
    orgId: org.id,
    actorId: actor.userId,
    action: 'skill.update',
    target: row.id,
    meta: { name: row.name, fields: Object.keys(body) },
    ip: actor.ip,
  });
  return { ...(await getSkill(ctx, org, actor, row.id)), warnings };
}

export async function deleteSkill(ctx: AppContext, org: Organization, actor: ExtActor, id: string) {
  const row = await loadSkill(ctx, org.id, actor, id);
  assertCanWrite(
    actor,
    parseOrgPolicy(org.policy),
    'skill',
    row.scope as WritableExtScope,
    row.userId,
  );
  await ctx.prisma.skill.delete({ where: { id: row.id } });
  await ctx.audit.record({
    orgId: org.id,
    actorId: actor.userId,
    action: 'skill.delete',
    target: row.id,
    meta: { name: row.name, scope: row.scope },
    ip: actor.ip,
  });
}

export async function listSkillVersions(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  id: string,
): Promise<SkillVersionDto[]> {
  const row = await loadSkill(ctx, org.id, actor, id);
  const versions = await ctx.prisma.skillVersion.findMany({
    where: { skillId: row.id },
    orderBy: { version: 'desc' },
    include: { createdBy: { select: { name: true, email: true } } },
    take: 100,
  });
  return versions.map((v) =>
    skillVersionDtoSchema.parse({
      version: v.version,
      description: v.description,
      fileCount: filesOf(v.files).length,
      bytes: v.bytes,
      createdByName: v.createdBy ? (v.createdBy.name ?? v.createdBy.email) : null,
      createdAt: v.createdAt,
    }),
  );
}

/** Restore an old version (creates a new version with its files). */
export async function restoreSkillVersion(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  id: string,
  version: number,
): Promise<SkillDetailDto> {
  const row = await loadSkill(ctx, org.id, actor, id);
  const v = await ctx.prisma.skillVersion.findUnique({
    where: { skillId_version: { skillId: row.id, version } },
  });
  if (!v) throw new AppError('LSE-NF-001', { devMessage: 'Version not found' });
  return updateSkill(ctx, org, actor, id, { files: filesOf(v.files) });
}

/** "Try this skill": validation + what the agent would see. Nothing is saved. */
export function dryRunSkill(files: readonly SkillFile[]): SkillDryRunDto {
  const normalized = normalizeFiles(files);
  const v = validateSkillBundle(normalized);
  return {
    valid: v.ok,
    name: v.name ?? null,
    description: v.description ?? null,
    issues: v.issues,
    warnings: v.warnings,
    files: normalized.map((f) => ({ path: f.path, bytes: Buffer.byteLength(f.content) })),
    listingPreview: v.name && v.description ? `- ${v.name}: ${v.description}` : '',
  };
}

export async function dryRunSavedSkill(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  id: string,
): Promise<SkillDryRunDto> {
  const detail = await getSkill(ctx, org, actor, id);
  return dryRunSkill(detail.files);
}

const IMPORT_MAX_DEPTH = 2;

/** Import a skill directory from GitHub (`.claude/skills/<name>`, `skills/<name>`). */
export async function importSkill(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  body: ImportSkillBody,
): Promise<SkillDetailDto> {
  assertCanWrite(actor, parseOrgPolicy(org.policy), 'skill', body.scope);
  const [owner = '', repo = ''] = body.repo.split('/');
  const root = body.path.replace(/^\/+|\/+$/g, '');
  const octokit = await githubClientFor(ctx, actor.userId);
  const files: SkillFile[] = [];
  const walk = async (dir: string, depth: number): Promise<void> => {
    let res;
    try {
      res = await octokit.rest.repos.getContent({
        owner,
        repo,
        path: dir,
        ...(body.ref ? { ref: body.ref } : {}),
      });
    } catch (err) {
      const mapped = mapGithubError(err);
      throw mapped.code === 'LSE-GH-001' || mapped.code === 'LSE-GH-002'
        ? mapped
        : new AppError('LSE-EXT-004', { devMessage: mapped.devMessage ?? 'GitHub request failed' });
    }
    const entries = Array.isArray(res.data) ? res.data : [res.data];
    for (const e of entries as { type: string; path: string; size?: number; content?: string }[]) {
      if (files.length > 60) break;
      if (e.type === 'dir' && depth < IMPORT_MAX_DEPTH) await walk(e.path, depth + 1);
      if (e.type !== 'file') continue;
      let content = e.content;
      if (content === undefined) {
        const f = await octokit.rest.repos
          .getContent({ owner, repo, path: e.path, ...(body.ref ? { ref: body.ref } : {}) })
          .catch((err: unknown) => {
            throw new AppError('LSE-EXT-004', { devMessage: mapGithubError(err).devMessage ?? '' });
          });
        content = (f.data as { content?: string }).content ?? '';
      }
      files.push({
        path: e.path.slice(root.length).replace(/^\/+/, ''),
        content: Buffer.from(content, 'base64').toString('utf8'),
      });
    }
  };
  await walk(root, 0);
  if (!files.length) {
    throw new AppError('LSE-EXT-001', { devMessage: `No files found at ${body.repo}/${root}` });
  }
  return createSkill(ctx, org, actor, {
    scope: body.scope,
    ...(body.projectId ? { projectId: body.projectId } : {}),
    files,
    enabled: true,
  });
}

// ---- slash commands ------------------------------------------------------------------------

export function commandToDto(row: SlashCommand): CommandDto {
  const meta = parseCommandMeta(row.body);
  return commandDtoSchema.parse({
    ...row,
    description: meta.description ?? null,
    argumentHint: meta.argumentHint ?? null,
    allowedTools: meta.allowedTools,
    model: meta.model ?? null,
    builtin: false,
  });
}

export async function listCommands(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  q: ExtensionListQuery,
): Promise<CommandDto[]> {
  const rows = await ctx.prisma.slashCommand.findMany({
    where: visibleWhere(org.id, actor.userId, q),
    orderBy: [{ scope: 'asc' }, { name: 'asc' }],
  });
  return rows.map(commandToDto);
}

async function loadCommand(ctx: AppContext, orgId: string, actor: ExtActor, id: string) {
  const row = await ctx.prisma.slashCommand.findFirst({ where: { id, orgId } });
  if (!row || (row.scope === 'USER' && row.userId !== actor.userId)) {
    throw new AppError('LSE-NF-001', { devMessage: 'Command not found' });
  }
  return row;
}

function assertCommandName(name: string) {
  if (isBuiltinCommand(name)) {
    throw new AppError('LSE-EXT-005', { fields: { name: [`/${name} is a built-in command`] } });
  }
}

export async function createCommand(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  body: CreateCommandBody,
): Promise<CommandDto> {
  assertCanWrite(actor, parseOrgPolicy(org.policy), 'command', body.scope);
  await assertProjectInOrg(ctx, org.id, body.projectId);
  assertCommandName(body.name);
  const ids = scopeIds(org.id, actor, body.scope, body.projectId);
  await assertNameFree(
    (where) => ctx.prisma.slashCommand.findFirst({ where, select: { id: true } }),
    ids,
    body.name,
  );
  const row = await ctx.prisma.slashCommand.create({
    data: { ...ids, name: body.name, body: body.body },
  });
  await ctx.audit.record({
    orgId: org.id,
    actorId: actor.userId,
    action: 'command.create',
    target: row.id,
    meta: { name: row.name, scope: row.scope },
    ip: actor.ip,
  });
  return commandToDto(row);
}

export async function updateCommand(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  id: string,
  body: UpdateCommandBody,
): Promise<CommandDto> {
  const row = await loadCommand(ctx, org.id, actor, id);
  assertCanWrite(
    actor,
    parseOrgPolicy(org.policy),
    'command',
    row.scope as WritableExtScope,
    row.userId,
  );
  if (body.name !== undefined && body.name !== row.name) {
    assertCommandName(body.name);
    await assertNameFree(
      (where) => ctx.prisma.slashCommand.findFirst({ where, select: { id: true } }),
      {
        scope: row.scope as WritableExtScope,
        orgId: org.id,
        projectId: row.projectId,
        userId: row.userId,
      },
      body.name,
      row.id,
    );
  }
  const updated = await ctx.prisma.slashCommand.update({
    where: { id: row.id },
    data: {
      ...(body.name !== undefined ? { name: body.name } : {}),
      ...(body.body !== undefined ? { body: body.body } : {}),
    },
  });
  await ctx.audit.record({
    orgId: org.id,
    actorId: actor.userId,
    action: 'command.update',
    target: row.id,
    meta: { name: updated.name, fields: Object.keys(body) },
    ip: actor.ip,
  });
  return commandToDto(updated);
}

export async function deleteCommand(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  id: string,
) {
  const row = await loadCommand(ctx, org.id, actor, id);
  assertCanWrite(
    actor,
    parseOrgPolicy(org.policy),
    'command',
    row.scope as WritableExtScope,
    row.userId,
  );
  await ctx.prisma.slashCommand.delete({ where: { id: row.id } });
  await ctx.audit.record({
    orgId: org.id,
    actorId: actor.userId,
    action: 'command.delete',
    target: row.id,
    meta: { name: row.name },
    ip: actor.ip,
  });
}

// ---- MCP servers ---------------------------------------------------------------------------

interface McpCredentials {
  env: Record<string, string>;
  headers: Record<string, string>;
}

async function encryptCredentials(ctx: AppContext, c: McpCredentials) {
  if (!Object.keys(c.env).length && !Object.keys(c.headers).length) return null;
  return ctx.crypto.encryptPacked(JSON.stringify(c), 'generic');
}

/** Decrypted credentials — for the sandbox/runner and connection tests only. */
export async function decryptCredentials(
  ctx: AppContext,
  row: Pick<McpServer, 'credentialsEnc'>,
): Promise<McpCredentials> {
  if (!row.credentialsEnc) return { env: {}, headers: {} };
  const raw = JSON.parse(
    await ctx.crypto.decryptPackedString(row.credentialsEnc, 'generic'),
  ) as Partial<McpCredentials>;
  return { env: raw.env ?? {}, headers: raw.headers ?? {} };
}

function toolPolicyOf(v: Prisma.JsonValue): McpToolPolicy {
  const r = mcpToolPolicySchema.safeParse(v ?? {});
  return r.success ? r.data : { default: 'allow', tools: {} };
}

const MCP_STATUSES = new Set([
  'connected',
  'failed',
  'needs_auth',
  'pending',
  'disabled',
  'untested',
]);

export async function mcpToDto(ctx: AppContext, row: McpServer): Promise<McpServerDto> {
  const creds = await decryptCredentials(ctx, row).catch(() => ({ env: {}, headers: {} }));
  return mcpServerDtoSchema.parse({
    ...row,
    envKeys: Object.keys(creds.env).sort(),
    headerKeys: Object.keys(creds.headers).sort(),
    toolPolicy: toolPolicyOf(row.toolPolicy),
    lastStatus: row.lastStatus && MCP_STATUSES.has(row.lastStatus) ? row.lastStatus : 'untested',
  });
}

function assertMcpCommand(
  transport: string,
  command: string | null | undefined,
  policy: OrgPolicy,
) {
  if (transport !== 'STDIO') return;
  if (!command || !isAllowedMcpCommand(command, policy.extensions.mcpAllowDocker)) {
    throw new AppError('LSE-MCP-004', {
      devMessage: `stdio command "${command ?? ''}" is not an allowed package runner`,
      fields: {
        command: [
          `Use one of: npx, uvx, bunx${policy.extensions.mcpAllowDocker ? ', docker' : ' (docker is disabled by the org policy)'}`,
        ],
      },
    });
  }
}

export async function listMcpServers(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  q: ExtensionListQuery,
): Promise<McpServerDto[]> {
  const rows = await ctx.prisma.mcpServer.findMany({
    where: visibleWhere(org.id, actor.userId, q),
    orderBy: [{ scope: 'asc' }, { name: 'asc' }],
  });
  return Promise.all(rows.map((r) => mcpToDto(ctx, r)));
}

/** `GET /users/me/mcp-servers`: personal connections across orgs. */
export async function listMyMcpServers(ctx: AppContext, userId: string): Promise<McpServerDto[]> {
  const rows = await ctx.prisma.mcpServer.findMany({
    where: { scope: 'USER', userId },
    orderBy: { name: 'asc' },
  });
  return Promise.all(rows.map((r) => mcpToDto(ctx, r)));
}

async function loadMcp(ctx: AppContext, orgId: string, actor: ExtActor, id: string) {
  const row = await ctx.prisma.mcpServer.findFirst({ where: { id, orgId } });
  if (!row || (row.scope === 'USER' && row.userId !== actor.userId)) {
    throw new AppError('LSE-NF-001', { devMessage: 'MCP server not found' });
  }
  return row;
}

export async function getMcpServer(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  id: string,
) {
  return mcpToDto(ctx, await loadMcp(ctx, org.id, actor, id));
}

export async function createMcpServer(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  body: CreateMcpServerBody,
): Promise<McpServerDto> {
  const policy = parseOrgPolicy(org.policy);
  assertCanWrite(actor, policy, 'mcp', body.scope);
  await assertProjectInOrg(ctx, org.id, body.projectId);
  assertMcpCommand(body.transport, body.command, policy);
  const ids = scopeIds(org.id, actor, body.scope, body.projectId);
  await assertNameFree(
    (where) => ctx.prisma.mcpServer.findFirst({ where, select: { id: true } }),
    ids,
    body.name,
  );
  const stdio = body.transport === 'STDIO';
  const row = await ctx.prisma.mcpServer.create({
    data: {
      ...ids,
      name: body.name,
      transport: body.transport,
      command: stdio ? (body.command ?? null) : null,
      args: stdio ? body.args : [],
      url: stdio ? null : (body.url ?? null),
      credentialsEnc: await encryptCredentials(ctx, {
        env: stdio ? body.env : {},
        headers: stdio ? {} : body.headers,
      }),
      toolPolicy: json(body.toolPolicy),
      enabled: body.enabled,
      catalogId: body.catalogId ?? null,
      lastStatus: 'untested',
    },
  });
  await ctx.audit.record({
    orgId: org.id,
    actorId: actor.userId,
    action: 'mcp_server.create',
    target: row.id,
    // Names only — never credential values.
    meta: {
      name: row.name,
      scope: row.scope,
      transport: row.transport,
      envKeys: Object.keys(body.env),
      headerKeys: Object.keys(body.headers),
    },
    ip: actor.ip,
  });
  return mcpToDto(ctx, row);
}

export async function updateMcpServer(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  id: string,
  body: UpdateMcpServerBody,
): Promise<McpServerDto> {
  const row = await loadMcp(ctx, org.id, actor, id);
  const policy = parseOrgPolicy(org.policy);
  assertCanWrite(actor, policy, 'mcp', row.scope as WritableExtScope, row.userId);
  const stdio = row.transport === 'STDIO';
  const command = body.command !== undefined ? body.command : row.command;
  const url = body.url !== undefined ? body.url : row.url;
  if (stdio) assertMcpCommand('STDIO', command, policy);
  else if (!url)
    throw new AppError('LSE-MCP-004', { fields: { url: ['url is required for http/sse'] } });
  if (body.name !== undefined && body.name !== row.name) {
    await assertNameFree(
      (where) => ctx.prisma.mcpServer.findFirst({ where, select: { id: true } }),
      {
        scope: row.scope as WritableExtScope,
        orgId: org.id,
        projectId: row.projectId,
        userId: row.userId,
      },
      body.name,
      row.id,
    );
  }
  const data: Prisma.McpServerUpdateInput = {};
  if (body.name !== undefined) data.name = body.name;
  if (stdio && body.command !== undefined) data.command = body.command;
  if (stdio && body.args !== undefined) data.args = body.args;
  if (!stdio && body.url !== undefined) data.url = body.url;
  if (body.toolPolicy !== undefined) data.toolPolicy = json(body.toolPolicy);
  if (body.enabled !== undefined) data.enabled = body.enabled;
  if (body.env !== undefined || body.headers !== undefined) {
    const current = await decryptCredentials(ctx, row);
    data.credentialsEnc = await encryptCredentials(ctx, {
      env: stdio ? (body.env ?? current.env) : {},
      headers: stdio ? {} : (body.headers ?? current.headers),
    });
    data.lastStatus = 'untested';
    data.lastError = null;
  }
  const updated = await ctx.prisma.mcpServer.update({ where: { id: row.id }, data });
  await ctx.audit.record({
    orgId: org.id,
    actorId: actor.userId,
    action: 'mcp_server.update',
    target: row.id,
    meta: { name: updated.name, fields: Object.keys(body) },
    ip: actor.ip,
  });
  return mcpToDto(ctx, updated);
}

export async function deleteMcpServer(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  id: string,
) {
  const row = await loadMcp(ctx, org.id, actor, id);
  assertCanWrite(
    actor,
    parseOrgPolicy(org.policy),
    'mcp',
    row.scope as WritableExtScope,
    row.userId,
  );
  await ctx.prisma.mcpServer.delete({ where: { id: row.id } });
  await ctx.audit.record({
    orgId: org.id,
    actorId: actor.userId,
    action: 'mcp_server.delete',
    target: row.id,
    meta: { name: row.name },
    ip: actor.ip,
  });
}

const MCP_TEST_TIMEOUT_MS = 10_000;
const MCP_PROTOCOL_VERSION = '2025-06-18';

/**
 * P10-SEC-012: MCP connection tests are DNS-pinned like hooks and outbound webhooks. `safeFetch`
 * resolves once, refuses any non-public answer and connects to exactly the address it validated,
 * so a host that answers public for `assertPublicUrl` and private at connect time (DNS
 * rebinding) never reaches an internal socket. The test transport is injected (MSW).
 */
function mcpFetch(ctx: AppContext, url: URL, init: SafeFetchInit) {
  if (ctx.env.NODE_ENV === 'test') {
    const { headersOnly: _headersOnly, ...rest } = init;
    return ctx.fetch(url, rest);
  }
  return safeFetch(ctx, url, {
    errorCode: 'LSE-MCP-004',
    timeoutMs: MCP_TEST_TIMEOUT_MS,
    ...init,
  });
}

/** A timeout either surfaces directly (test transport) or as the cause of a safeFetch error. */
function isTimeout(err: unknown): boolean {
  const e = err as { name?: string; cause?: { name?: string; message?: string } } | null;
  const names = [e?.name, e?.cause?.name];
  return (
    names.includes('TimeoutError') ||
    names.includes('AbortError') ||
    e?.cause?.message === 'timeout'
  );
}

/** Parse a JSON-RPC response that may come as JSON or as an SSE stream. */
async function rpcResult(res: Response, id: number): Promise<Record<string, unknown> | null> {
  const text = (await res.text()).slice(0, 1_000_000);
  const candidates = (res.headers.get('content-type') ?? '').includes('text/event-stream')
    ? text
        .split('\n')
        .filter((l) => l.startsWith('data:'))
        .map((l) => l.slice(5).trim())
    : [text];
  for (const c of candidates) {
    try {
      const msg = JSON.parse(c) as { id?: unknown; result?: unknown; error?: { message?: string } };
      if (msg.id !== id) continue;
      if (msg.error) throw new Error(msg.error.message ?? 'MCP error');
      return isRecord(msg.result) ? msg.result : {};
    } catch (e) {
      if (e instanceof SyntaxError) continue;
      throw e;
    }
  }
  return null;
}

async function testHttp(ctx: AppContext, url: URL, headers: Record<string, string>) {
  const signal = AbortSignal.timeout(MCP_TEST_TIMEOUT_MS);
  const base = {
    'Content-Type': 'application/json',
    Accept: 'application/json, text/event-stream',
    ...headers,
  };
  const post = (body: unknown, extra: Record<string, string> = {}) =>
    mcpFetch(ctx, url, {
      method: 'POST',
      headers: { ...base, ...extra },
      body: JSON.stringify(body),
      redirect: 'manual',
      signal,
    });
  const init = await post({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: 'loose.ai', version: '1.0.0' },
    },
  });
  if (init.status === 401 || init.status === 403) return { status: 'needs_auth' as const };
  if (!init.ok) throw new Error(`HTTP ${init.status}`);
  if (!(await rpcResult(init, 1))) throw new Error('No initialize response');
  const sid = init.headers.get('mcp-session-id');
  const session: Record<string, string> = {
    ...(sid ? { 'mcp-session-id': sid } : {}),
    'mcp-protocol-version': MCP_PROTOCOL_VERSION,
  };
  await post({ jsonrpc: '2.0', method: 'notifications/initialized' }, session)
    .then((r) => r.body?.cancel())
    .catch(() => undefined);
  const list = await post({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }, session);
  if (!list.ok) throw new Error(`tools/list HTTP ${list.status}`);
  const result = await rpcResult(list, 2);
  const tools = Array.isArray(result?.tools)
    ? (result.tools as { name?: unknown; description?: unknown }[])
        .filter((t) => typeof t.name === 'string')
        .slice(0, 500)
        .map((t) => ({
          name: t.name as string,
          description: typeof t.description === 'string' ? t.description.slice(0, 500) : null,
        }))
    : [];
  return { status: 'connected' as const, tools };
}

async function testSse(ctx: AppContext, url: URL, headers: Record<string, string>) {
  const res = await mcpFetch(ctx, url, {
    method: 'GET',
    headers: { Accept: 'text/event-stream', ...headers },
    redirect: 'manual',
    signal: AbortSignal.timeout(MCP_TEST_TIMEOUT_MS),
    headersOnly: true,
  });
  await res.body?.cancel().catch(() => undefined);
  if (res.status === 401 || res.status === 403) return { status: 'needs_auth' as const };
  if (!res.ok || !(res.headers.get('content-type') ?? '').includes('text/event-stream')) {
    throw new Error(`HTTP ${res.status}`);
  }
  return { status: 'connected' as const, tools: [] };
}

/** `POST …/mcp-servers/:id/test`: connection test + tool discovery (http/sse). */
export async function testMcpServer(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  id: string,
): Promise<McpTestResultDto> {
  const row = await loadMcp(ctx, org.id, actor, id);
  const policy = parseOrgPolicy(org.policy);
  const started = Date.now();
  let result: McpTestResultDto;
  if (row.transport === 'STDIO') {
    assertMcpCommand('STDIO', row.command, policy);
    result = {
      ok: true,
      status: 'untested',
      latencyMs: null,
      tools: [],
      error: null,
      note: 'Local (stdio) servers start inside the session workspace; their status appears when a session starts.',
    };
  } else {
    const url = await assertPublicUrl(row.url ?? '');
    const { headers } = await decryptCredentials(ctx, row);
    try {
      const r =
        row.transport === 'SSE'
          ? await testSse(ctx, url, headers)
          : await testHttp(ctx, url, headers);
      const latencyMs = Date.now() - started;
      result =
        r.status === 'needs_auth'
          ? {
              ok: false,
              status: 'needs_auth',
              latencyMs,
              tools: [],
              error: { code: 'LSE-MCP-002', message: 'The server rejected the credentials.' },
              note: null,
            }
          : {
              ok: true,
              status: 'connected',
              latencyMs,
              tools: r.tools,
              error: null,
              note:
                row.transport === 'SSE'
                  ? 'Tools of SSE servers are listed when a session starts.'
                  : null,
            };
    } catch (err) {
      // The pinned transport refused the address it resolved at connect time: same answer as
      // `assertPublicUrl` above, never a "connection failed" that hides the SSRF refusal.
      if (err instanceof AppError && err.code === 'LSE-MCP-004') throw err;
      const timeout = isTimeout(err);
      result = {
        ok: false,
        status: 'failed',
        latencyMs: Date.now() - started,
        tools: [],
        error: {
          code: timeout ? 'LSE-MCP-003' : 'LSE-MCP-001',
          message: timeout
            ? 'The server did not answer in time.'
            : String((err as Error).message).slice(0, 300),
        },
        note: null,
      };
    }
  }
  await ctx.prisma.mcpServer.update({
    where: { id: row.id },
    data: {
      lastStatus: result.status,
      lastError: result.error ? `${result.error.code}: ${result.error.message}` : null,
      lastCheckedAt: new Date(),
      ...(result.tools.length ? { lastTools: json(result.tools.map((t) => t.name)) } : {}),
    },
  });
  return result;
}

export function mcpCatalog() {
  return MCP_CATALOG;
}

/** Record statuses reported by a session's runner (health & diagnostics). */
export async function recordMcpStatuses(
  ctx: AppContext,
  idsByName: ReadonlyMap<string, string>,
  servers: readonly {
    name: string;
    status: string;
    error?: string | undefined;
    tools?: string[] | undefined;
  }[],
) {
  for (const s of servers) {
    const id = idsByName.get(s.name);
    if (!id) continue;
    await ctx.prisma.mcpServer
      .update({
        where: { id },
        data: {
          lastStatus: MCP_STATUSES.has(s.status) ? s.status : 'failed',
          lastError: s.error ? s.error.slice(0, 1000) : null,
          lastCheckedAt: new Date(),
          ...(s.tools?.length ? { lastTools: json(s.tools.slice(0, 500)) } : {}),
        },
      })
      .catch(() => undefined);
  }
}

// ---- per-project overrides ---------------------------------------------------------------

export function parseOverrides(v: Prisma.JsonValue): ExtensionOverrides {
  const r = extensionOverridesSchema.safeParse(v ?? {});
  return r.success ? r.data : { skills: {}, mcpServers: {}, subagents: {} };
}

interface SkillCandidate {
  name: string;
  description: string;
  quickAction: string | null;
  files: SkillFile[];
  enabled: boolean;
  scope: Skill['scope'];
  pluginName?: string | undefined;
  dto: SkillDto;
}

const SCOPE_RANK = { BUILTIN: 0, ORG: 1, PROJECT: 2, USER: 3 } as const;

/** Built-in → ORG → plugin → PROJECT → USER, overriding by name. */
function skillCandidates(
  policy: OrgPolicy,
  rows: Skill[],
  pluginSkills: readonly ResolvedPluginSkill[] = [],
): Map<string, SkillCandidate> {
  const map = new Map<string, SkillCandidate>();
  for (const b of BUILTIN_SKILLS) {
    const dto = builtinSkillDto(b.name, policy);
    map.set(b.name, {
      name: b.name,
      description: b.description,
      quickAction: b.quickAction ?? null,
      files: [{ path: SKILL_ENTRY_FILE, content: b.skillMd }],
      enabled: dto.enabled,
      scope: 'BUILTIN',
      dto,
    });
  }
  const put = (r: Skill) =>
    map.set(r.name, {
      name: r.name,
      description: r.description,
      quickAction: r.quickAction,
      files: filesOf(r.files),
      enabled: r.enabled,
      scope: r.scope,
      dto: skillToDto(r),
    });
  for (const r of rows.filter((r) => r.scope === 'ORG')) put(r);
  for (const p of pluginSkills) {
    map.set(p.name, {
      name: p.name,
      description: p.description,
      quickAction: p.quickAction,
      files: normalizeFiles(p.files),
      enabled: true,
      scope: 'PROJECT',
      pluginName: p.pluginName,
      dto: skillDtoSchema.parse({
        id: `${p.pluginName}:${p.name}`.slice(0, 100),
        scope: 'PROJECT',
        orgId: null,
        projectId: null,
        userId: null,
        name: p.name,
        description: p.description,
        quickAction: p.quickAction,
        version: 1,
        enabled: true,
        builtin: false,
        createdAt: null,
        updatedAt: null,
      }),
    });
  }
  for (const r of rows
    .filter((r) => r.scope !== 'ORG')
    .sort((a, b) => SCOPE_RANK[a.scope] - SCOPE_RANK[b.scope]))
    put(r);
  return map;
}

export async function getProjectExtensions(
  ctx: AppContext,
  org: Organization,
  project: Project,
): Promise<ProjectExtensionsDto> {
  const policy = parseOrgPolicy(org.policy);
  const overrides = parseOverrides(project.extensionOverrides);
  const orgOrProject = {
    orgId: org.id,
    OR: [{ scope: 'ORG' as const }, { scope: 'PROJECT' as const, projectId: project.id }],
  };
  const skills = await ctx.prisma.skill.findMany({ where: orgOrProject });
  const servers = await ctx.prisma.mcpServer.findMany({
    where: orgOrProject,
    orderBy: { name: 'asc' },
  });
  const subagentRows = await ctx.prisma.subagent.findMany({ where: orgOrProject });
  const hookRows = await ctx.prisma.hook.findMany({
    where: orgOrProject,
    orderBy: [{ scope: 'asc' }, { event: 'asc' }, { name: 'asc' }],
  });
  const plugins = await resolvePluginContents(ctx, project.id);
  const effective = (inherited: boolean, override: boolean | undefined) => ({
    inherited,
    override: override ?? null,
    enabled: override ?? inherited,
  });
  return {
    skills: [...skillCandidates(policy, skills).values()].map((c) => ({
      ...c.dto,
      ...effective(c.enabled, overrides.skills[c.name]),
    })),
    mcpServers: await Promise.all(
      servers.map(async (s) => ({
        ...(await mcpToDto(ctx, s)),
        ...effective(s.enabled, overrides.mcpServers[s.id]),
      })),
    ),
    subagents: [...subagentCandidates(subagentRows, plugins.subagents).values()].map((c) => ({
      ...c.dto,
      ...effective(c.enabled, overrides.subagents[c.name]),
    })),
    hooks: [...hookRows.map(hookToDto), ...plugins.hooks.map(pluginHookToDto)],
    plugins: await listProjectInstalls(ctx, project.id),
  };
}

export async function updateProjectExtensions(
  ctx: AppContext,
  org: Organization,
  project: Project,
  actor: ExtActor,
  body: UpdateProjectExtensionsBody,
): Promise<ProjectExtensionsDto> {
  const current = parseOverrides(project.extensionOverrides);
  const apply = (
    base: Record<string, boolean>,
    patch: Record<string, boolean | null> | undefined,
  ) => {
    const next = { ...base };
    for (const [k, v] of Object.entries(patch ?? {})) {
      if (v === null) delete next[k];
      else next[k] = v;
    }
    return next;
  };
  const next: ExtensionOverrides = {
    skills: apply(current.skills, body.skills),
    mcpServers: apply(current.mcpServers, body.mcpServers),
    subagents: apply(current.subagents, body.subagents),
  };
  const updated = await ctx.prisma.project.update({
    where: { id: project.id },
    data: { extensionOverrides: json(next) },
  });
  await ctx.audit.record({
    orgId: org.id,
    actorId: actor.userId,
    action: 'project.extensions_update',
    target: project.id,
    meta: {
      skills: Object.keys(body.skills ?? {}),
      mcpServers: Object.keys(body.mcpServers ?? {}),
      subagents: Object.keys(body.subagents ?? {}),
    },
    ip: actor.ip,
  });
  return getProjectExtensions(ctx, org, updated);
}

// ---- session resolution & delivery ---------------------------------------------------------

export interface ResolvedSkill {
  name: string;
  description: string;
  quickAction: string | null;
  files: SkillFile[];
  scope: Skill['scope'];
  /** Set when the skill comes from an installed plugin. */
  pluginName?: string | undefined;
}

export interface ResolvedMcp {
  id: string;
  name: string;
  config: RunnerMcpServerInput;
  pluginName?: string | undefined;
}

/** A custom slash command, from a database row or from an installed plugin. */
export interface ResolvedCommand {
  id: string;
  name: string;
  body: string;
  scope: SlashCommand['scope'];
  pluginName?: string | undefined;
}

export interface SessionExtensions {
  skills: ResolvedSkill[];
  /** Skills that failed validation (skipped, LSE-AGT-015). */
  skippedSkills: string[];
  commands: ResolvedCommand[];
  mcp: ResolvedMcp[];
  /** `LOOSE_MCP_SECRET_<n>` → value, passed to the runner process env only. */
  mcpEnv: Record<string, string>;
  /** Subagents the agent may delegate to (spec §8.8). */
  subagents: RunnerSubagentInput[];
  /** Hooks that apply to this session (org + project + plugins; spec §8.9). */
  hooks: ResolvedHook[];
  /** Non-blocking plugin problems (skipped MCP servers, invalid manifests). */
  pluginWarnings: string[];
}

/**
 * Everything a session's agent gets: enabled skills and MCP servers after scope
 * precedence and project overrides, custom commands, and the MCP secret env.
 */
export async function resolveSessionExtensions(
  ctx: AppContext,
  input: { orgId: string; projectId: string; userId: string },
): Promise<SessionExtensions> {
  const [org, project] = await Promise.all([
    ctx.prisma.organization.findUniqueOrThrow({ where: { id: input.orgId } }),
    ctx.prisma.project.findUniqueOrThrow({ where: { id: input.projectId } }),
  ]);
  const policy = parseOrgPolicy(org.policy);
  const overrides = parseOverrides(project.extensionOverrides);
  const plugins = await resolvePluginContents(ctx, project.id);
  const scopes = (allowUser: boolean) => [
    { scope: 'ORG' as const },
    { scope: 'PROJECT' as const, projectId: project.id },
    ...(allowUser ? [{ scope: 'USER' as const, userId: input.userId }] : []),
  ];

  const skillRows = await ctx.prisma.skill.findMany({
    where: { orgId: org.id, OR: scopes(policy.extensions.allowUserSkills) },
  });
  const skills: ResolvedSkill[] = [];
  const skippedSkills: string[] = [];
  for (const c of skillCandidates(policy, skillRows, plugins.skills).values()) {
    // Personal skills are the user's own choice; project overrides govern shared ones.
    const enabled = c.scope === 'USER' ? c.enabled : (overrides.skills[c.name] ?? c.enabled);
    if (!enabled) continue;
    if (c.scope !== 'BUILTIN' && !validateSkillBundle(c.files).ok) {
      skippedSkills.push(c.name);
      continue;
    }
    skills.push({
      name: c.name,
      description: c.description,
      quickAction: c.quickAction,
      files: c.files,
      scope: c.scope,
      ...(c.pluginName ? { pluginName: c.pluginName } : {}),
    });
  }

  const commandRows = await ctx.prisma.slashCommand.findMany({
    where: { orgId: org.id, OR: scopes(true) },
  });
  const rank = SCOPE_RANK;
  const commands = new Map<string, ResolvedCommand>();
  for (const c of commandRows.filter((c) => c.scope === 'ORG'))
    commands.set(c.name, { id: c.id, name: c.name, body: c.body, scope: c.scope });
  for (const c of plugins.commands)
    commands.set(c.name, {
      id: c.id,
      name: c.name,
      body: c.body,
      scope: 'PROJECT',
      pluginName: c.pluginName,
    });
  for (const c of commandRows
    .filter((c) => c.scope !== 'ORG')
    .sort((a, b) => rank[a.scope] - rank[b.scope]))
    commands.set(c.name, { id: c.id, name: c.name, body: c.body, scope: c.scope });

  const subagentRows = await ctx.prisma.subagent.findMany({
    where: { orgId: org.id, OR: scopes(policy.extensions.allowUserSkills) },
  });
  const subagents = [...subagentCandidates(subagentRows, plugins.subagents).values()]
    .filter((c) => (c.scope === 'USER' ? c.enabled : (overrides.subagents[c.name] ?? c.enabled)))
    .map(toRunnerSubagent);

  const hooks = await resolveHooks(ctx, {
    orgId: org.id,
    projectId: project.id,
    pluginHooks: plugins.hooks,
  });

  const mcpRows = await ctx.prisma.mcpServer.findMany({
    where: { orgId: org.id, OR: scopes(policy.extensions.allowUserMcp) },
  });
  const byName = new Map<string, McpServer>();
  for (const r of [...mcpRows].sort((a, b) => rank[a.scope] - rank[b.scope])) {
    const enabled = r.scope === 'USER' ? r.enabled : (overrides.mcpServers[r.id] ?? r.enabled);
    if (!enabled) continue;
    if (
      r.transport === 'STDIO' &&
      !isAllowedMcpCommand(r.command ?? '', policy.extensions.mcpAllowDocker)
    )
      continue;
    byName.set(r.name, r);
  }
  const mcp: ResolvedMcp[] = [];
  const mcpEnv: Record<string, string> = {};
  let n = 0;
  const secretRef = (value: string) => {
    const key = `${MCP_SECRET_ENV_PREFIX}${n++}`;
    mcpEnv[key] = value;
    return `\${${key}}`;
  };
  for (const r of byName.values()) {
    let creds: McpCredentials;
    try {
      creds = await decryptCredentials(ctx, r);
    } catch (err) {
      ctx.logger.warn(
        { err, mcpServerId: r.id },
        'could not decrypt MCP credentials; skipping server',
      );
      continue;
    }
    const placeholders = (m: Record<string, string>) =>
      Object.fromEntries(Object.entries(m).map(([k, v]) => [k, secretRef(v)]));
    mcp.push({
      id: r.id,
      name: r.name,
      config: {
        name: r.name,
        transport: r.transport.toLowerCase() as 'stdio' | 'http' | 'sse',
        ...(r.command ? { command: r.command } : {}),
        args: r.args,
        ...(r.url ? { url: r.url } : {}),
        env: placeholders(creds.env),
        headers: placeholders(creds.headers),
        toolPolicy: toolPolicyOf(r.toolPolicy),
      },
    });
  }
  for (const p of plugins.mcp) {
    const placeholders = (m: Record<string, string>) =>
      Object.fromEntries(Object.entries(m).map(([k, v]) => [k, secretRef(v)]));
    if (byName.has(p.name)) continue;
    mcp.push({
      id: p.id,
      name: p.name,
      pluginName: p.pluginName,
      config: {
        ...p.config,
        env: placeholders(p.config.env ?? {}),
        headers: placeholders(p.config.headers ?? {}),
      },
    });
  }
  return {
    skills,
    skippedSkills,
    commands: [...commands.values()],
    mcp,
    mcpEnv,
    subagents,
    hooks,
    pluginWarnings: plugins.warnings,
  };
}

export const PLUGIN_DIRNAME = 'plugin';

/**
 * Write the session's skills as a local Claude Code plugin under the runner state dir
 * (outside the repo, so skill files never end up in a PR). Returns the plugin dir, or
 * undefined when there are no skills.
 */
export async function writeSkillsPlugin(
  sandbox: SandboxHandle,
  skills: readonly ResolvedSkill[],
): Promise<string | undefined> {
  const dir = `${sandbox.paths.state}/${PLUGIN_DIRNAME}`;
  await sandbox.run(`rm -rf ${shq(dir)}`, { cwd: sandbox.paths.state, timeoutMs: 30_000 });
  if (!skills.length) return undefined;
  await sandbox.writeFile(
    `${dir}/.claude-plugin/plugin.json`,
    `${JSON.stringify({ name: 'loose', version: '1.0.0', description: 'Skills managed by loose.ai' }, null, 2)}\n`,
  );
  for (const s of skills) {
    for (const f of s.files) {
      const rel = normalizeBundlePath(f.path);
      if (!rel) continue;
      await sandbox.writeFile(`${dir}/skills/${s.name}/${rel}`, f.content);
    }
  }
  return dir;
}
