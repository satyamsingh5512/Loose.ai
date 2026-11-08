/**
 * Subagents (spec §8.8; Phase 8): specialised agents defined as Markdown with
 * frontmatter (`name`, `description`, `tools`, `model`, `permissionMode`). Built-ins
 * (`code-reviewer`, `test-runner`, `ui-designer`, `researcher`) are always offered;
 * org / project / user rows add to or override them by name, and a project can switch
 * single subagents off through `extensionOverrides.subagents`.
 *
 * The Agent SDK does the actual delegation (`agents` option, `@agent-name` mentions):
 * the server only resolves which definitions a session gets.
 */
import type { Organization, Prisma, Subagent } from '@prisma/client';
import {
  BUILTIN_SUBAGENTS,
  findBuiltinSubagent,
  parseOrgPolicy,
  subagentDtoSchema,
  validateSubagentDefinition,
  type AgentPermissionMode,
  type CreateSubagentBody,
  type ExtensionListQuery,
  type RunnerSubagentInput,
  type SubagentDto,
  type UpdateSubagentBody,
  type WritableExtScope,
} from '@loose/shared';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';
import {
  assertCanWrite,
  assertNameFree,
  assertProjectInOrg,
  isRecord,
  json,
  scopeIds,
  visibleWhere,
  type ExtActor,
} from './extensionsCommon';

export const BUILTIN_SUBAGENT_PREFIX = 'builtin:';

interface SubagentMeta {
  description?: string;
  tools?: string[];
  model?: string | null;
  permissionMode?: string | null;
  /** Name of the plugin this subagent came from (plugin-provided rows only). */
  pluginName?: string;
}

function metaOf(v: Prisma.JsonValue): SubagentMeta {
  return isRecord(v) ? (v as SubagentMeta) : {};
}

function validateOrThrow(definition: string) {
  const v = validateSubagentDefinition(definition);
  if (!v.ok || !v.name || !v.description) {
    const first = v.issues[0];
    throw new AppError(first?.code ?? 'LSE-EXT-001', {
      devMessage: first?.message ?? 'Invalid subagent',
      fields: {
        definition: v.issues.map((i) => (i.path ? `${i.path}: ${i.message}` : i.message)),
      },
    });
  }
  return v as typeof v & { name: string; description: string };
}

export function subagentToDto(row: Subagent): SubagentDto {
  const parsed = validateSubagentDefinition(row.definition);
  const meta = metaOf(row.meta);
  return subagentDtoSchema.parse({
    id: row.id,
    scope: row.scope,
    orgId: row.orgId,
    projectId: row.projectId,
    userId: row.userId,
    name: row.name,
    description: parsed.description ?? meta.description ?? '',
    tools: parsed.tools,
    model: parsed.model ?? null,
    permissionMode: parsed.permissionMode ?? null,
    definition: row.definition,
    builtin: false,
    pluginName: meta.pluginName ?? null,
    warnings: parsed.warnings,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  });
}

export function builtinSubagentDto(name: string): SubagentDto {
  const b = findBuiltinSubagent(name)!;
  return subagentDtoSchema.parse({
    id: `${BUILTIN_SUBAGENT_PREFIX}${b.name}`,
    scope: 'BUILTIN',
    orgId: null,
    projectId: null,
    userId: null,
    name: b.name,
    description: b.description,
    tools: [...b.tools],
    model: b.model ?? null,
    permissionMode: b.permissionMode ?? null,
    definition: b.definition,
    builtin: true,
    pluginName: null,
    warnings: [],
    createdAt: null,
    updatedAt: null,
  });
}

export async function listSubagents(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  q: ExtensionListQuery,
): Promise<SubagentDto[]> {
  const rows = await ctx.prisma.subagent.findMany({
    where: visibleWhere(org.id, actor.userId, q),
    orderBy: [{ scope: 'asc' }, { name: 'asc' }],
  });
  return [...BUILTIN_SUBAGENTS.map((b) => builtinSubagentDto(b.name)), ...rows.map(subagentToDto)];
}

async function loadSubagent(ctx: AppContext, orgId: string, actor: ExtActor, id: string) {
  const row = await ctx.prisma.subagent.findFirst({ where: { id, orgId } });
  if (!row || (row.scope === 'USER' && row.userId !== actor.userId)) {
    throw new AppError('LSE-NF-001', { devMessage: 'Subagent not found' });
  }
  return row;
}

export async function getSubagent(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  id: string,
): Promise<SubagentDto> {
  if (id.startsWith(BUILTIN_SUBAGENT_PREFIX)) {
    const b = findBuiltinSubagent(id.slice(BUILTIN_SUBAGENT_PREFIX.length));
    if (!b) throw new AppError('LSE-NF-001', { devMessage: 'Subagent not found' });
    return builtinSubagentDto(b.name);
  }
  return subagentToDto(await loadSubagent(ctx, org.id, actor, id));
}

export async function createSubagent(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  body: CreateSubagentBody,
): Promise<SubagentDto> {
  assertCanWrite(actor, parseOrgPolicy(org.policy), 'subagent', body.scope);
  await assertProjectInOrg(ctx, org.id, body.projectId);
  const v = validateOrThrow(body.definition);
  const ids = scopeIds(org.id, actor, body.scope, body.projectId);
  await assertNameFree(
    (where) => ctx.prisma.subagent.findFirst({ where, select: { id: true } }),
    ids,
    v.name,
  );
  const row = await ctx.prisma.subagent.create({
    data: {
      ...ids,
      name: v.name,
      definition: body.definition,
      meta: json({
        description: v.description,
        tools: v.tools,
        model: v.model ?? null,
        permissionMode: v.permissionMode ?? null,
      }),
    },
  });
  await ctx.audit.record({
    orgId: org.id,
    actorId: actor.userId,
    action: 'subagent.create',
    target: row.id,
    meta: { name: row.name, scope: row.scope, projectId: row.projectId, tools: v.tools },
    ip: actor.ip,
  });
  return subagentToDto(row);
}

export async function updateSubagent(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  id: string,
  body: UpdateSubagentBody,
): Promise<SubagentDto> {
  const row = await loadSubagent(ctx, org.id, actor, id);
  assertCanWrite(
    actor,
    parseOrgPolicy(org.policy),
    'subagent',
    row.scope as WritableExtScope,
    row.userId,
  );
  const v = validateOrThrow(body.definition);
  if (v.name !== row.name) {
    throw new AppError('LSE-EXT-001', {
      devMessage: 'The subagent name cannot change; create a new subagent instead',
      fields: { definition: [`"name" must stay "${row.name}"`] },
    });
  }
  const updated = await ctx.prisma.subagent.update({
    where: { id: row.id },
    data: {
      definition: body.definition,
      meta: json({
        ...metaOf(row.meta),
        description: v.description,
        tools: v.tools,
        model: v.model ?? null,
        permissionMode: v.permissionMode ?? null,
      }),
    },
  });
  await ctx.audit.record({
    orgId: org.id,
    actorId: actor.userId,
    action: 'subagent.update',
    target: row.id,
    meta: { name: row.name, scope: row.scope },
    ip: actor.ip,
  });
  return subagentToDto(updated);
}

export async function deleteSubagent(
  ctx: AppContext,
  org: Organization,
  actor: ExtActor,
  id: string,
) {
  const row = await loadSubagent(ctx, org.id, actor, id);
  assertCanWrite(
    actor,
    parseOrgPolicy(org.policy),
    'subagent',
    row.scope as WritableExtScope,
    row.userId,
  );
  await ctx.prisma.subagent.delete({ where: { id: row.id } });
  await ctx.audit.record({
    orgId: org.id,
    actorId: actor.userId,
    action: 'subagent.delete',
    target: row.id,
    meta: { name: row.name, scope: row.scope },
    ip: actor.ip,
  });
}

// ---- session resolution ---------------------------------------------------------------------

export interface SubagentCandidate {
  name: string;
  description: string;
  tools: string[];
  model?: string | undefined;
  permissionMode?: AgentPermissionMode | undefined;
  prompt: string;
  enabled: boolean;
  scope: SubagentDto['scope'];
  pluginName?: string | undefined;
  dto: SubagentDto;
}

const SCOPE_RANK = { BUILTIN: 0, ORG: 1, PROJECT: 2, USER: 3 } as const;

/** Definitions provided by an installed plugin (project precedence, before USER rows). */
export interface PluginSubagentInput {
  pluginName: string;
  definition: string;
  id: string;
}

function candidateOf(
  dto: SubagentDto,
  definition: string,
  enabled: boolean,
  pluginName?: string | undefined,
): SubagentCandidate | null {
  const parsed = validateSubagentDefinition(definition);
  if (!parsed.ok || !parsed.name || !parsed.description) return null;
  return {
    name: parsed.name,
    description: parsed.description,
    tools: parsed.tools,
    ...(parsed.model ? { model: parsed.model } : {}),
    ...(parsed.permissionMode ? { permissionMode: parsed.permissionMode } : {}),
    prompt: parsed.prompt,
    enabled,
    scope: dto.scope,
    ...(pluginName ? { pluginName } : {}),
    dto,
  };
}

/**
 * Built-ins → ORG → plugin → PROJECT → USER, overriding by name. Invalid definitions
 * are dropped (they are reported when saved).
 */
export function subagentCandidates(
  rows: readonly Subagent[],
  plugins: readonly PluginSubagentInput[] = [],
): Map<string, SubagentCandidate> {
  const map = new Map<string, SubagentCandidate>();
  for (const b of BUILTIN_SUBAGENTS) {
    const c = candidateOf(builtinSubagentDto(b.name), b.definition, true);
    if (c) map.set(b.name, c);
  }
  const org = rows.filter((r) => r.scope === 'ORG');
  const rest = rows.filter((r) => r.scope !== 'ORG');
  for (const r of org) {
    const c = candidateOf(subagentToDto(r), r.definition, r.enabled, metaOf(r.meta).pluginName);
    if (c) map.set(c.name, c);
  }
  for (const p of plugins) {
    const parsed = validateSubagentDefinition(p.definition);
    if (!parsed.ok || !parsed.name) continue;
    const dto = pluginSubagentDto(p);
    const c = candidateOf(dto, p.definition, true, p.pluginName);
    if (c) map.set(c.name, c);
  }
  for (const r of [...rest].sort((a, b) => SCOPE_RANK[a.scope] - SCOPE_RANK[b.scope])) {
    const c = candidateOf(subagentToDto(r), r.definition, r.enabled, metaOf(r.meta).pluginName);
    if (c) map.set(c.name, c);
  }
  return map;
}

/** DTO for a subagent that lives in a plugin manifest (no database row). */
export function pluginSubagentDto(p: PluginSubagentInput): SubagentDto {
  const parsed = validateSubagentDefinition(p.definition);
  return subagentDtoSchema.parse({
    id: p.id,
    scope: 'PROJECT',
    orgId: null,
    projectId: null,
    userId: null,
    name: parsed.name ?? '',
    description: parsed.description ?? '',
    tools: parsed.tools,
    model: parsed.model ?? null,
    permissionMode: parsed.permissionMode ?? null,
    definition: p.definition,
    builtin: false,
    pluginName: p.pluginName,
    warnings: parsed.warnings,
    createdAt: null,
    updatedAt: null,
  });
}

export function toRunnerSubagent(c: SubagentCandidate): RunnerSubagentInput {
  return {
    name: c.name,
    description: c.description,
    prompt: c.prompt,
    ...(c.tools.length ? { tools: c.tools } : {}),
    ...(c.model ? { model: c.model } : {}),
    ...(c.permissionMode ? { permissionMode: c.permissionMode } : {}),
  };
}
