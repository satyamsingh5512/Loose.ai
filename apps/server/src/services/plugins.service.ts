/**
 * Plugins (spec §8.16; Phase 8): skills + slash commands + subagents + hooks + MCP
 * config bundled in one versioned manifest (semver) and installed per project. The org
 * plugin list is the private marketplace; every published version is kept so an install
 * can be updated or rolled back.
 *
 * Installed plugin contents are NOT copied into Skill/SlashCommand/… rows: they are
 * resolved from the install's manifest at session start (`resolvePluginContents`), which
 * makes update / rollback / uninstall exact. MCP credentials declared by a manifest are
 * filled in on install and envelope-encrypted; a server whose required credentials are
 * missing is skipped with a warning.
 */
import type { Organization, Plugin, PluginInstall, Prisma } from '@prisma/client';
import {
  collectPluginCredentialRequirements,
  compareSemver,
  findPluginConflicts,
  latestVersion,
  pluginContentsDtoSchema,
  pluginDetailDtoSchema,
  pluginDtoSchema,
  pluginInstallDtoSchema,
  pluginManifestSchema,
  pluginValidationDtoSchema,
  pluginVersionChange,
  pluginVersionDtoSchema,
  validatePluginManifest,
  validateSkillBundle,
  type ExtensionListQuery,
  type InstallPluginBody,
  type PluginConflict,
  type PluginContentsDto,
  type PluginDetailDto,
  type PluginDto,
  type PluginInstallDto,
  type PluginManifest,
  type PluginValidationDto,
  type PluginVersionDto,
  type RunnerMcpServerInput,
  type SkillFile,
  type UpdatePluginInstallBody,
} from '@loose/shared';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';
import { assertAdmin, assertProjectInOrg, isRecord, json, type ExtActor } from './extensionsCommon';

type PluginWithCounts = Plugin & { _count?: { installs: number } };

/** Deterministic id for a resource that only exists inside an installed manifest. */
export function pluginResourceId(pluginId: string, kind: string, name: string): string {
  const raw = `pl_${pluginId}_${kind}_${name}`.replace(/[^A-Za-z0-9_-]/g, '-');
  return raw.slice(0, 64);
}

export function manifestOf(v: Prisma.JsonValue): PluginManifest | null {
  const r = pluginManifestSchema.safeParse(v);
  return r.success ? r.data : null;
}

export function pluginContents(m: PluginManifest): PluginContentsDto {
  return {
    skills: m.skills.map((s) => validateSkillBundle(s.files).name ?? '?'),
    commands: m.commands.map((c) => c.name),
    subagents: m.subagents.map((s) => subagentNameOf(s.definition)),
    mcpServers: m.mcpServers.map((s) => s.name),
    hooks: m.hooks.length,
  };
}

function subagentNameOf(definition: string): string {
  const m = /^\s*---[\s\S]*?\n\s*name:\s*([^\n#]+)/.exec(definition);
  return (m?.[1] ?? '?').trim().replace(/^["']|["']$/g, '');
}

const EMPTY_CONTENTS: PluginContentsDto = {
  skills: [],
  commands: [],
  subagents: [],
  mcpServers: [],
  hooks: 0,
};

function contentsOfRow(v: Prisma.JsonValue): PluginContentsDto {
  const m = manifestOf(v);
  return m ? pluginContents(m) : EMPTY_CONTENTS;
}

function validateOrThrow(input: unknown): PluginManifest {
  const v = validatePluginManifest(input);
  if (!v.ok || !v.manifest) {
    const first = v.issues[0];
    throw new AppError(first?.code === 'LSE-EXT-007' ? 'LSE-EXT-007' : 'LSE-EXT-001', {
      devMessage: first?.message ?? 'Invalid plugin manifest',
      fields: {
        manifest: v.issues.map((i) => (i.path ? `${i.path}: ${i.message}` : i.message)),
      },
    });
  }
  return v.manifest;
}

// ---- DTOs ----------------------------------------------------------------------------------

export function pluginToDto(
  row: PluginWithCounts,
  opts: { installCount?: number; install?: PluginInstall | null | undefined } = {},
): PluginDto {
  const m = manifestOf(row.manifest);
  const install = opts.install;
  return pluginDtoSchema.parse({
    id: row.id,
    orgId: row.orgId,
    name: row.name,
    title: m?.title ?? row.name,
    description: m?.description ?? '',
    version: row.version,
    author: m?.author ?? null,
    homepage: m?.homepage ?? null,
    contents: contentsOfRow(row.manifest),
    installCount: opts.installCount ?? row._count?.installs ?? 0,
    install: install
      ? {
          version: install.version,
          enabled: install.enabled,
          updateAvailable: compareSemver(row.version, install.version) > 0,
        }
      : null,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  });
}

function credentialMetaOf(v: Prisma.JsonValue): Record<string, string[]> {
  if (!isRecord(v)) return {};
  const out: Record<string, string[]> = {};
  for (const [server, keys] of Object.entries(v)) {
    if (Array.isArray(keys)) out[server] = keys.filter((k): k is string => typeof k === 'string');
  }
  return out;
}

/** Contents + warnings recorded when the install was created / updated. */
function installedResources(v: Prisma.JsonValue): {
  contents: PluginContentsDto | null;
  warnings: string[];
} {
  if (!isRecord(v)) return { contents: null, warnings: [] };
  const warnings = Array.isArray(v.warnings)
    ? v.warnings.filter((w): w is string => typeof w === 'string')
    : [];
  const { warnings: _w, ...rest } = v;
  const parsed = pluginContentsDtoSchema.safeParse(rest);
  return { contents: parsed.success ? parsed.data : null, warnings };
}

export function pluginInstallToDto(install: PluginInstall, plugin: Plugin): PluginInstallDto {
  const stored = installedResources(install.resources);
  const contents = stored.contents ?? contentsOfRow(plugin.manifest);
  const meta = credentialMetaOf(install.credentialMeta);
  const warnings = stored.warnings;
  return pluginInstallDtoSchema.parse({
    id: install.id,
    pluginId: install.pluginId,
    pluginName: plugin.name,
    projectId: install.projectId,
    version: install.version,
    latestVersion: plugin.version,
    updateAvailable: compareSemver(plugin.version, install.version) > 0,
    enabled: install.enabled,
    contents,
    credentialKeys: Object.entries(meta)
      .flatMap(([server, keys]) => keys.map((k) => `${server}.${k}`))
      .sort(),
    warnings,
    createdAt: install.createdAt,
    updatedAt: install.updatedAt,
  });
}

// ---- CRUD ------------------------------------------------------------------------------------

export async function listPlugins(
  ctx: AppContext,
  org: Organization,
  _actor: ExtActor,
  q: ExtensionListQuery,
): Promise<PluginDto[]> {
  const rows = await ctx.prisma.plugin.findMany({
    where: { orgId: org.id },
    orderBy: { name: 'asc' },
    include: { _count: { select: { installs: true } } },
  });
  if (!q.projectId) return rows.map((r) => pluginToDto(r));
  const installs = await ctx.prisma.pluginInstall.findMany({ where: { projectId: q.projectId } });
  const byPlugin = new Map(installs.map((i) => [i.pluginId, i]));
  return rows.map((r) => pluginToDto(r, { install: byPlugin.get(r.id) ?? null }));
}

async function loadPlugin(ctx: AppContext, orgId: string, id: string) {
  const row = await ctx.prisma.plugin.findFirst({ where: { id, orgId } });
  if (!row) throw new AppError('LSE-NF-001', { devMessage: 'Plugin not found' });
  return row;
}

export async function getPlugin(
  ctx: AppContext,
  org: Organization,
  _actor: ExtActor,
  id: string,
  q: { projectId?: string | undefined } = {},
): Promise<PluginDetailDto> {
  const row = await loadPlugin(ctx, org.id, id);
  const [versions, installCount, install] = await Promise.all([
    ctx.prisma.pluginVersion.findMany({
      where: { pluginId: row.id },
      orderBy: { createdAt: 'desc' },
      include: { createdBy: { select: { name: true, email: true } } },
      take: 100,
    }),
    ctx.prisma.pluginInstall.count({ where: { pluginId: row.id } }),
    q.projectId
      ? ctx.prisma.pluginInstall.findUnique({
          where: { pluginId_projectId: { pluginId: row.id, projectId: q.projectId } },
        })
      : Promise.resolve(null),
  ]);
  const manifest = manifestOf(row.manifest);
  if (!manifest) throw new AppError('LSE-EXT-001', { devMessage: 'Stored manifest is invalid' });
  const v = validatePluginManifest(manifest);
  return pluginDetailDtoSchema.parse({
    ...pluginToDto(row, { installCount, install }),
    manifest,
    versions: versions.map((x) => toVersionDto(x, x.createdBy)),
    credentials: collectPluginCredentialRequirements(manifest),
    warnings: v.warnings,
  });
}

function toVersionDto(
  row: { version: string; manifest: Prisma.JsonValue; createdAt: Date },
  createdBy?: { name: string | null; email: string } | null,
): PluginVersionDto {
  return pluginVersionDtoSchema.parse({
    version: row.version,
    contents: contentsOfRow(row.manifest),
    createdByName: createdBy ? (createdBy.name ?? createdBy.email) : null,
    createdAt: row.createdAt,
  });
}

export async function createPlugin(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  body: { manifest: unknown },
): Promise<PluginDto> {
  assertAdmin(actor, 'plugins');
  const manifest = validateOrThrow(body.manifest);
  const existing = await ctx.prisma.plugin.findUnique({
    where: { orgId_name: { orgId: org.id, name: manifest.name } },
  });
  if (existing) {
    throw new AppError('LSE-EXT-005', {
      fields: { name: [`A plugin called "${manifest.name}" already exists`] },
    });
  }
  const row = await ctx.prisma.plugin.create({
    data: {
      orgId: org.id,
      name: manifest.name,
      version: manifest.version,
      manifest: json(manifest),
      createdById: actor.userId,
      versions: {
        create: {
          version: manifest.version,
          manifest: json(manifest),
          createdById: actor.userId,
        },
      },
    },
  });
  await ctx.audit.record({
    orgId: org.id,
    actorId: actor.userId,
    action: 'plugin.create',
    target: row.id,
    meta: { name: row.name, version: row.version, contents: pluginContents(manifest) },
    ip: actor.ip,
  });
  return pluginToDto(row, { installCount: 0 });
}

export async function publishPluginVersion(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  id: string,
  body: { manifest: unknown },
): Promise<PluginVersionDto> {
  assertAdmin(actor, 'plugins');
  const row = await loadPlugin(ctx, org.id, id);
  const manifest = validateOrThrow(body.manifest);
  if (manifest.name !== row.name) {
    throw new AppError('LSE-EXT-007', {
      devMessage: 'A new version must keep the plugin name',
      fields: { manifest: [`"name" must stay "${row.name}"`] },
    });
  }
  const dup = await ctx.prisma.pluginVersion.findUnique({
    where: { pluginId_version: { pluginId: row.id, version: manifest.version } },
  });
  if (dup) {
    throw new AppError('LSE-EXT-007', {
      devMessage: `Version ${manifest.version} already exists`,
      fields: { manifest: [`Version ${manifest.version} was already published`] },
    });
  }
  const version = await ctx.prisma.pluginVersion.create({
    data: {
      pluginId: row.id,
      version: manifest.version,
      manifest: json(manifest),
      createdById: actor.userId,
    },
  });
  // The plugin row always mirrors the highest published version.
  if (compareSemver(manifest.version, row.version) > 0) {
    await ctx.prisma.plugin.update({
      where: { id: row.id },
      data: { version: manifest.version, manifest: json(manifest) },
    });
  }
  await ctx.audit.record({
    orgId: org.id,
    actorId: actor.userId,
    action: 'plugin.publish',
    target: row.id,
    meta: { name: row.name, version: manifest.version },
    ip: actor.ip,
  });
  return toVersionDto(version);
}

export async function deletePlugin(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  id: string,
) {
  assertAdmin(actor, 'plugins');
  const row = await loadPlugin(ctx, org.id, id);
  await ctx.prisma.plugin.delete({ where: { id: row.id } });
  await ctx.audit.record({
    orgId: org.id,
    actorId: actor.userId,
    action: 'plugin.delete',
    target: row.id,
    meta: { name: row.name, version: row.version },
    ip: actor.ip,
  });
}

// ---- validation / conflicts ------------------------------------------------------------------

async function existingResources(
  ctx: AppContext,
  orgId: string,
  projectId: string | undefined,
  exceptPluginId?: string,
) {
  const where = {
    orgId,
    OR: [
      { scope: 'ORG' as const },
      ...(projectId ? [{ scope: 'PROJECT' as const, projectId }] : []),
    ],
  };
  const [skills, commands, subagents, mcpServers] = await Promise.all([
    ctx.prisma.skill.findMany({ where, select: { name: true } }),
    ctx.prisma.slashCommand.findMany({ where, select: { name: true } }),
    ctx.prisma.subagent.findMany({ where, select: { name: true } }),
    ctx.prisma.mcpServer.findMany({ where, select: { name: true } }),
  ]);
  const installedPlugins: Record<string, string> = {};
  if (projectId) {
    const installs = await ctx.prisma.pluginInstall.findMany({
      where: { projectId },
      include: { plugin: { select: { id: true, name: true } } },
    });
    for (const i of installs) {
      if (i.pluginId === exceptPluginId) continue;
      installedPlugins[i.plugin.name] = i.version;
    }
  }
  return {
    skills: skills.map((s) => s.name),
    commands: commands.map((s) => s.name),
    subagents: subagents.map((s) => s.name),
    mcpServers: mcpServers.map((s) => s.name),
    installedPlugins,
  };
}

export async function validatePlugin(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  body: { manifest: unknown; projectId?: string | undefined },
): Promise<PluginValidationDto> {
  assertAdmin(actor, 'plugins');
  await assertProjectInOrg(ctx, org.id, body.projectId);
  const v = validatePluginManifest(body.manifest);
  let conflicts: PluginConflict[] = [];
  if (v.manifest) {
    const existing = await existingResources(ctx, org.id, body.projectId, undefined);
    const current = body.projectId
      ? await ctx.prisma.pluginInstall.findFirst({
          where: { projectId: body.projectId, plugin: { name: v.manifest.name, orgId: org.id } },
          select: { version: true },
        })
      : null;
    conflicts = findPluginConflicts(
      v.manifest,
      { ...existing, currentVersion: current?.version ?? null },
      {},
    );
  }
  return pluginValidationDtoSchema.parse({
    // Credential conflicts do not block an install (the server is skipped instead).
    valid: v.ok && !conflicts.some((c) => c.kind !== 'credential'),
    name: v.manifest?.name ?? null,
    version: v.manifest?.version ?? null,
    issues: v.issues,
    conflicts,
    warnings: v.warnings,
    contents: v.manifest ? pluginContents(v.manifest) : EMPTY_CONTENTS,
  });
}

function throwConflicts(conflicts: readonly PluginConflict[]): never {
  throw new AppError('LSE-EXT-007', {
    devMessage: conflicts.map((c) => `${c.kind}: ${c.message}`).join('; '),
    fields: { manifest: conflicts.map((c) => c.message) },
  });
}

// ---- install / update / rollback / uninstall --------------------------------------------------

type Credentials = Record<string, Record<string, string>>;

async function decryptCredentials(ctx: AppContext, install: PluginInstall): Promise<Credentials> {
  if (!install.credentialsEnc) return {};
  try {
    const raw = JSON.parse(
      await ctx.crypto.decryptPackedString(install.credentialsEnc, 'generic'),
    ) as unknown;
    if (!isRecord(raw)) return {};
    const out: Credentials = {};
    for (const [server, map] of Object.entries(raw)) {
      if (!isRecord(map)) continue;
      out[server] = Object.fromEntries(
        Object.entries(map).filter((e): e is [string, string] => typeof e[1] === 'string'),
      );
    }
    return out;
  } catch (err) {
    ctx.logger.warn({ err, installId: install.id }, 'could not decrypt plugin credentials');
    return {};
  }
}

function credentialKeysOf(c: Credentials): Record<string, string[]> {
  return Object.fromEntries(Object.entries(c).map(([k, v]) => [k, Object.keys(v).sort()]));
}

async function manifestForVersion(
  ctx: AppContext,
  plugin: Plugin,
  version: string | undefined,
): Promise<{ version: string; manifest: PluginManifest }> {
  const versions = await ctx.prisma.pluginVersion.findMany({
    where: { pluginId: plugin.id },
    select: { version: true, manifest: true },
  });
  const wanted = version ?? latestVersion(versions.map((v) => v.version)) ?? plugin.version;
  const row = versions.find((v) => v.version === wanted);
  const manifest = manifestOf(row?.manifest ?? plugin.manifest);
  if (!row || !manifest) {
    throw new AppError('LSE-NF-001', { devMessage: `Plugin version ${wanted} not found` });
  }
  return { version: wanted, manifest };
}

/** Credential warnings (missing required keys ⇒ the MCP server is skipped). */
function credentialWarnings(manifest: PluginManifest, provided: Credentials): string[] {
  const conflicts = findPluginConflicts(manifest, {}, credentialKeysOf(provided));
  return conflicts
    .filter((c) => c.kind === 'credential')
    .map((c) => `${c.message} (the connection is skipped until it is filled in)`);
}

export async function installPlugin(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  id: string,
  body: InstallPluginBody,
): Promise<PluginInstallDto> {
  assertAdmin(actor, 'plugins');
  const plugin = await loadPlugin(ctx, org.id, id);
  await assertProjectInOrg(ctx, org.id, body.projectId);
  const existing = await ctx.prisma.pluginInstall.findUnique({
    where: { pluginId_projectId: { pluginId: plugin.id, projectId: body.projectId } },
  });
  if (existing) {
    throw new AppError('LSE-EXT-007', {
      devMessage: `"${plugin.name}" is already installed in this project`,
      fields: { projectId: [`"${plugin.name}" is already installed in this project`] },
    });
  }
  const { version, manifest } = await manifestForVersion(ctx, plugin, body.version);
  const resources = await existingResources(ctx, org.id, body.projectId, plugin.id);
  const credentials = body.credentials as Credentials;
  const conflicts = findPluginConflicts(
    manifest,
    { ...resources, currentVersion: null },
    credentialKeysOf(credentials),
  ).filter((c) => c.kind !== 'credential');
  if (conflicts.length) throwConflicts(conflicts);
  const warnings = credentialWarnings(manifest, credentials);
  const install = await ctx.prisma.pluginInstall.create({
    data: {
      pluginId: plugin.id,
      projectId: body.projectId,
      version,
      enabled: body.enabled,
      credentialsEnc: Object.keys(credentials).length
        ? await ctx.crypto.encryptPacked(JSON.stringify(credentials), 'generic')
        : null,
      credentialMeta: json(credentialKeysOf(credentials)),
      resources: json({ ...pluginContents(manifest), warnings }),
      installedById: actor.userId,
    },
  });
  await ctx.audit.record({
    orgId: org.id,
    actorId: actor.userId,
    action: 'plugin.install',
    target: plugin.id,
    // Credential KEYS only — never their values.
    meta: {
      name: plugin.name,
      version,
      projectId: body.projectId,
      credentialKeys: credentialKeysOf(credentials),
    },
    ip: actor.ip,
  });
  return pluginInstallToDto(install, plugin);
}

export async function updatePluginInstall(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  id: string,
  body: UpdatePluginInstallBody,
): Promise<PluginInstallDto> {
  assertAdmin(actor, 'plugins');
  const plugin = await loadPlugin(ctx, org.id, id);
  const install = await ctx.prisma.pluginInstall.findUnique({
    where: { pluginId_projectId: { pluginId: plugin.id, projectId: body.projectId } },
  });
  if (!install)
    throw new AppError('LSE-NF-001', { devMessage: 'The plugin is not installed here' });
  const { version, manifest } = await manifestForVersion(
    ctx,
    plugin,
    body.version ?? install.version,
  );
  const change = pluginVersionChange(install.version, version);
  const current = await decryptCredentials(ctx, install);
  const credentials: Credentials = body.credentials
    ? { ...current, ...(body.credentials as Credentials) }
    : current;
  if (body.version !== undefined) {
    const resources = await existingResources(ctx, org.id, body.projectId, plugin.id);
    const conflicts = findPluginConflicts(
      manifest,
      resources,
      credentialKeysOf(credentials),
    ).filter((c) => c.kind !== 'credential');
    if (conflicts.length) throwConflicts(conflicts);
  }
  const warnings = credentialWarnings(manifest, credentials);
  const updated = await ctx.prisma.pluginInstall.update({
    where: { id: install.id },
    data: {
      version,
      ...(body.enabled !== undefined ? { enabled: body.enabled } : {}),
      ...(body.credentials
        ? {
            credentialsEnc: Object.keys(credentials).length
              ? await ctx.crypto.encryptPacked(JSON.stringify(credentials), 'generic')
              : null,
            credentialMeta: json(credentialKeysOf(credentials)),
          }
        : {}),
      resources: json({ ...pluginContents(manifest), warnings }),
    },
  });
  await ctx.audit.record({
    orgId: org.id,
    actorId: actor.userId,
    action: change === 'rollback' ? 'plugin.rollback' : 'plugin.update',
    target: plugin.id,
    meta: {
      name: plugin.name,
      from: install.version,
      to: version,
      projectId: body.projectId,
      ...(body.enabled !== undefined ? { enabled: body.enabled } : {}),
      ...(body.credentials ? { credentialKeys: credentialKeysOf(credentials) } : {}),
    },
    ip: actor.ip,
  });
  return pluginInstallToDto(updated, plugin);
}

export async function uninstallPlugin(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  id: string,
  projectId: string,
) {
  assertAdmin(actor, 'plugins');
  const plugin = await loadPlugin(ctx, org.id, id);
  const install = await ctx.prisma.pluginInstall.findUnique({
    where: { pluginId_projectId: { pluginId: plugin.id, projectId } },
  });
  if (!install)
    throw new AppError('LSE-NF-001', { devMessage: 'The plugin is not installed here' });
  await ctx.prisma.pluginInstall.delete({ where: { id: install.id } });
  await ctx.audit.record({
    orgId: org.id,
    actorId: actor.userId,
    action: 'plugin.uninstall',
    target: plugin.id,
    meta: { name: plugin.name, version: install.version, projectId },
    ip: actor.ip,
  });
}

export async function listProjectInstalls(
  ctx: AppContext,
  projectId: string,
): Promise<PluginInstallDto[]> {
  const installs = await ctx.prisma.pluginInstall.findMany({
    where: { projectId },
    include: { plugin: true },
    orderBy: { createdAt: 'asc' },
  });
  return installs.map((i) => pluginInstallToDto(i, i.plugin));
}

// ---- session resolution ----------------------------------------------------------------------

export interface ResolvedPluginSkill {
  pluginName: string;
  name: string;
  description: string;
  quickAction: string | null;
  files: SkillFile[];
}

export interface ResolvedPluginCommand {
  id: string;
  pluginName: string;
  name: string;
  body: string;
}

export interface ResolvedPluginSubagent {
  id: string;
  pluginName: string;
  definition: string;
}

export interface ResolvedPluginHook {
  id: string;
  pluginName: string;
  name: string;
  event: PluginManifest['hooks'][number]['event'];
  matcher?: string | undefined;
  handler: PluginManifest['hooks'][number]['handler'];
  failMode?: PluginManifest['hooks'][number]['failMode'];
  timeoutSec?: number | undefined;
}

export interface ResolvedPluginMcp {
  id: string;
  pluginName: string;
  name: string;
  /** `env` / `headers` still hold plaintext values; the caller inserts placeholders. */
  config: RunnerMcpServerInput;
}

export interface ResolvedPluginContents {
  skills: ResolvedPluginSkill[];
  commands: ResolvedPluginCommand[];
  subagents: ResolvedPluginSubagent[];
  hooks: ResolvedPluginHook[];
  mcp: ResolvedPluginMcp[];
  /** Skipped MCP servers, invalid manifests, … (surfaced on the install). */
  warnings: string[];
}

function mcpOf(
  plugin: Plugin,
  server: PluginManifest['mcpServers'][number],
  values: Record<string, string>,
): ResolvedPluginMcp | null {
  const env: Record<string, string> = {};
  const headers: Record<string, string> = {};
  for (const field of server.credentials) {
    const raw = values[field.key];
    if (raw === undefined || raw === '') {
      if (field.required) return null;
      continue;
    }
    const value = `${field.prefix ?? ''}${raw}`;
    if (field.kind === 'header') headers[field.key] = value;
    else env[field.key] = value;
  }
  const transport = server.transport.toLowerCase() as 'stdio' | 'http' | 'sse';
  return {
    id: pluginResourceId(plugin.id, 'mcp', server.name),
    pluginName: plugin.name,
    name: server.name,
    config: {
      name: server.name,
      transport,
      ...(server.command ? { command: server.command } : {}),
      args: server.args,
      ...(server.url ? { url: server.url } : {}),
      env,
      headers,
      toolPolicy: {
        default: 'allow',
        tools: Object.fromEntries(server.approvalTools.map((t) => [t, 'approval' as const])),
      },
    },
  };
}

/**
 * Everything the enabled plugin installs of a project contribute. Nothing here is a
 * database row: the manifest of the installed version is the single source of truth.
 */
export async function resolvePluginContents(
  ctx: AppContext,
  projectId: string,
): Promise<ResolvedPluginContents> {
  const out: ResolvedPluginContents = {
    skills: [],
    commands: [],
    subagents: [],
    hooks: [],
    mcp: [],
    warnings: [],
  };
  const installs = await ctx.prisma.pluginInstall.findMany({
    where: { projectId, enabled: true },
    include: { plugin: true },
    orderBy: { createdAt: 'asc' },
  });
  for (const install of installs) {
    const { plugin } = install;
    const row = await ctx.prisma.pluginVersion.findUnique({
      where: { pluginId_version: { pluginId: plugin.id, version: install.version } },
      select: { manifest: true },
    });
    const manifest = manifestOf(row?.manifest ?? plugin.manifest);
    if (!manifest) {
      out.warnings.push(`The manifest of "${plugin.name}" ${install.version} is invalid`);
      continue;
    }
    for (const s of manifest.skills) {
      const v = validateSkillBundle(s.files);
      if (!v.ok || !v.name || !v.description) {
        out.warnings.push(`A skill of "${plugin.name}" was skipped (invalid SKILL.md)`);
        continue;
      }
      out.skills.push({
        pluginName: plugin.name,
        name: v.name,
        description: v.description,
        quickAction: v.quickAction ?? null,
        files: s.files.map((f) => ({ path: f.path, content: f.content })),
      });
    }
    for (const c of manifest.commands) {
      out.commands.push({
        id: pluginResourceId(plugin.id, 'cmd', c.name),
        pluginName: plugin.name,
        name: c.name,
        body: c.body,
      });
    }
    for (const s of manifest.subagents) {
      out.subagents.push({
        id: pluginResourceId(plugin.id, 'agent', subagentNameOf(s.definition)),
        pluginName: plugin.name,
        definition: s.definition,
      });
    }
    for (const h of manifest.hooks) {
      out.hooks.push({
        id: pluginResourceId(plugin.id, 'hook', h.name),
        pluginName: plugin.name,
        name: h.name,
        event: h.event,
        ...(h.matcher !== undefined ? { matcher: h.matcher } : {}),
        handler: h.handler,
        ...(h.failMode !== undefined ? { failMode: h.failMode } : {}),
        ...(h.timeoutSec !== undefined ? { timeoutSec: h.timeoutSec } : {}),
      });
    }
    if (manifest.mcpServers.length) {
      const credentials = await decryptCredentials(ctx, install);
      for (const server of manifest.mcpServers) {
        const resolved = mcpOf(plugin, server, credentials[server.name] ?? {});
        if (resolved) out.mcp.push(resolved);
        else
          out.warnings.push(
            `"${server.name}" from "${plugin.name}" is skipped until its credentials are filled in`,
          );
      }
    }
  }
  return out;
}
