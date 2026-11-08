/**
 * Projects (spec §10.4, Phase 2 = CRUD + memory).
 * Env var values are envelope-encrypted in `envVarsEnc` and never returned;
 * `envVarMeta` keeps the non-secret names + secret flags for display.
 */
import { Prisma, type Organization, type Project } from '@prisma/client';
import {
  isAdminRole,
  projectDtoSchema,
  projectMemoryDtoSchema,
  type CreateProjectBody,
  type EnvVarNameEntry,
  type PaginationQuery,
  type ProjectDto,
  type ProjectMemoryDto,
  type UpdateProjectBody,
  type UpdateProjectMemoryBody,
} from '@loose/shared';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';
import { pageArgs, toPage, type Page } from '../lib/pagination';
import { getRepo } from './github.service';
import type { Actor } from './org.service';

type EnvVars = Record<string, string>;

export function toProjectDto(p: Project): ProjectDto {
  return projectDtoSchema.parse({
    ...p,
    envVarNames: Array.isArray(p.envVarMeta) ? p.envVarMeta : [],
    portMap: p.portMap ?? [],
    commandPolicy: p.commandPolicy ?? {},
    approvalGates: p.approvalGates ?? {},
    hasMemory: p.looseMd !== null && p.looseMd !== '',
  });
}

function envMeta(vars: EnvVars, secrets: readonly string[]): EnvVarNameEntry[] {
  const secretSet = new Set(secrets);
  return Object.keys(vars)
    .sort()
    .map((name) => ({ name, secret: secretSet.has(name) }));
}

async function encryptEnv(ctx: AppContext, vars: EnvVars): Promise<Uint8Array<ArrayBuffer>> {
  return ctx.crypto.encryptPacked(JSON.stringify(vars), 'project-env');
}

/** Decrypted env vars — for the sandbox runtime only; never put in a response. */
export async function decryptProjectEnv(ctx: AppContext, p: Project): Promise<EnvVars> {
  const json = await ctx.crypto.decryptPackedString(p.envVarsEnc, 'project-env');
  return JSON.parse(json) as EnvVars;
}

const json = (v: unknown) => v as Prisma.InputJsonValue;

export async function createProject(
  ctx: AppContext,
  org: Organization,
  actor: Actor,
  body: CreateProjectBody,
): Promise<ProjectDto> {
  const [owner = '', repoName = ''] = body.githubRepoFullName.split('/');
  // Verifies the admin can see the repo; yields canonical name, URL and default branch.
  const repo = await getRepo(ctx, actor.userId, owner, repoName);
  const project = await ctx.prisma.project.create({
    data: {
      orgId: org.id,
      name: body.name,
      githubRepoFullName: repo.fullName,
      githubRepoUrl: repo.htmlUrl,
      defaultBranch: body.defaultBranch ?? repo.defaultBranch,
      envVarsEnc: await encryptEnv(ctx, body.envVars),
      envVarMeta: json(envMeta(body.envVars, body.secretEnvVars)),
      contextInstructions: body.contextInstructions,
      startupCommands: body.startupCommands,
      requiredServices: body.requiredServices,
      portMap: json(body.portMap),
      healthCheck: body.healthCheck ? json(body.healthCheck) : Prisma.DbNull,
      allowedFilePatterns: body.allowedFilePatterns,
      deniedFilePatterns: body.deniedFilePatterns,
      commandPolicy: json(body.commandPolicy),
      approvalGates: json(body.approvalGates),
      networkAllowlist: body.networkAllowlist,
      defaultModel: body.defaultModel ?? null,
      maxSessionDurationMin: body.maxSessionDurationMin,
      maxBudgetUsd: body.maxBudgetUsd,
      planMode: body.planMode,
      repoMemory: body.repoMemory,
      autoCompactPercent: body.autoCompactPercent,
      screenshotViewports: body.screenshotViewports,
    },
  });
  await ctx.audit.record({
    orgId: org.id,
    actorId: actor.userId,
    action: 'project.create',
    target: project.id,
    meta: {
      name: project.name,
      repo: project.githubRepoFullName,
      envVarNames: Object.keys(body.envVars),
    },
    ip: actor.ip,
  });
  return toProjectDto(project);
}

/**
 * Non-admins (MEMBER/VIEWER) only see set-up projects (spec §7.1.6): READY, or with
 * a previously READY template that stays active during a rebuild (blue/green, §7.2).
 */
function visibilityFilter(role: Actor['role']): Prisma.ProjectWhereInput {
  return isAdminRole(role)
    ? {}
    : { OR: [{ templateStatus: 'READY' }, { e2bTemplateId: { not: null } }] };
}

export async function listProjects(
  ctx: AppContext,
  orgId: string,
  role: Actor['role'],
  q: PaginationQuery,
): Promise<Page<ProjectDto>> {
  const rows = await ctx.prisma.project.findMany({
    where: { orgId, ...visibilityFilter(role) },
    orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
    ...pageArgs(q),
  });
  return toPage(rows, q.limit, toProjectDto);
}

export async function findProject(
  ctx: AppContext,
  orgId: string,
  projectId: string,
  role: Actor['role'],
): Promise<Project> {
  const p = await ctx.prisma.project.findFirst({
    where: { id: projectId, orgId, ...visibilityFilter(role) },
  });
  if (!p) throw new AppError('LSE-NF-001', { devMessage: 'Project not found in this org' });
  return p;
}

export async function updateProject(
  ctx: AppContext,
  orgId: string,
  projectId: string,
  actor: Actor,
  body: UpdateProjectBody,
): Promise<ProjectDto> {
  const existing = await findProject(ctx, orgId, projectId, actor.role);
  const data: Prisma.ProjectUpdateInput = {};

  if (body.envVars !== undefined || body.secretEnvVars !== undefined) {
    const currentMeta = (Array.isArray(existing.envVarMeta)
      ? existing.envVarMeta
      : []) as unknown as EnvVarNameEntry[];
    let vars: EnvVars | undefined;
    if (body.envVars !== undefined) {
      vars = await decryptProjectEnv(ctx, existing);
      for (const [name, value] of Object.entries(body.envVars)) {
        if (value === null) delete vars[name];
        else vars[name] = value;
      }
    }
    const names = vars ? Object.keys(vars) : currentMeta.map((m) => m.name);
    const secrets = body.secretEnvVars ?? currentMeta.filter((m) => m.secret).map((m) => m.name);
    const missing = body.secretEnvVars?.filter((s) => !names.includes(s)) ?? [];
    if (missing.length) {
      throw new AppError('LSE-VAL-001', {
        fields: { secretEnvVars: missing.map((m) => `${m} is not defined in envVars`) },
      });
    }
    const effectiveSecrets = secrets.filter((s) => names.includes(s));
    if (vars) data.envVarsEnc = await encryptEnv(ctx, vars);
    data.envVarMeta = json(
      vars
        ? envMeta(vars, effectiveSecrets)
        : currentMeta.map((m) => ({ name: m.name, secret: effectiveSecrets.includes(m.name) })),
    );
  }

  if (body.name !== undefined) data.name = body.name;
  if (body.defaultBranch !== undefined) data.defaultBranch = body.defaultBranch;
  if (body.contextInstructions !== undefined) data.contextInstructions = body.contextInstructions;
  if (body.startupCommands !== undefined) data.startupCommands = body.startupCommands;
  if (body.requiredServices !== undefined) data.requiredServices = body.requiredServices;
  if (body.portMap !== undefined) data.portMap = json(body.portMap);
  if (body.healthCheck !== undefined)
    data.healthCheck = body.healthCheck === null ? Prisma.DbNull : json(body.healthCheck);
  if (body.allowedFilePatterns !== undefined) data.allowedFilePatterns = body.allowedFilePatterns;
  if (body.deniedFilePatterns !== undefined) data.deniedFilePatterns = body.deniedFilePatterns;
  if (body.commandPolicy !== undefined) data.commandPolicy = json(body.commandPolicy);
  if (body.approvalGates !== undefined) data.approvalGates = json(body.approvalGates);
  if (body.networkAllowlist !== undefined) data.networkAllowlist = body.networkAllowlist;
  if (body.defaultModel !== undefined) data.defaultModel = body.defaultModel;
  if (body.maxSessionDurationMin !== undefined)
    data.maxSessionDurationMin = body.maxSessionDurationMin;
  if (body.maxBudgetUsd !== undefined) data.maxBudgetUsd = body.maxBudgetUsd;
  if (body.planMode !== undefined) data.planMode = body.planMode;
  if (body.repoMemory !== undefined) data.repoMemory = body.repoMemory;
  if (body.autoCompactPercent !== undefined) data.autoCompactPercent = body.autoCompactPercent;
  if (body.screenshotViewports !== undefined) data.screenshotViewports = body.screenshotViewports;

  const updated = await ctx.prisma.project.update({ where: { id: existing.id }, data });
  await ctx.audit.record({
    orgId,
    actorId: actor.userId,
    action: 'project.update',
    target: existing.id,
    // Field names only — never values (env vars may be secrets).
    meta: {
      fields: Object.keys(body),
      ...(body.envVars ? { envVarNamesChanged: Object.keys(body.envVars) } : {}),
    },
    ip: actor.ip,
  });
  return toProjectDto(updated);
}

export async function deleteProject(
  ctx: AppContext,
  orgId: string,
  projectId: string,
  actor: Actor,
): Promise<void> {
  const p = await findProject(ctx, orgId, projectId, actor.role);
  await ctx.prisma.project.delete({ where: { id: p.id } });
  await ctx.audit.record({
    orgId,
    actorId: actor.userId,
    action: 'project.delete',
    target: p.id,
    meta: { name: p.name, repo: p.githubRepoFullName },
    ip: actor.ip,
  });
}

export function toMemoryDto(p: Project): ProjectMemoryDto {
  return projectMemoryDtoSchema.parse({
    looseMd: p.looseMd,
    componentLabels:
      p.componentLabels &&
      typeof p.componentLabels === 'object' &&
      !Array.isArray(p.componentLabels)
        ? p.componentLabels
        : {},
  });
}

export async function updateMemory(
  ctx: AppContext,
  orgId: string,
  projectId: string,
  actor: Actor,
  body: UpdateProjectMemoryBody,
): Promise<ProjectMemoryDto> {
  const p = await findProject(ctx, orgId, projectId, actor.role);
  const updated = await ctx.prisma.project.update({
    where: { id: p.id },
    data: {
      ...(body.looseMd !== undefined ? { looseMd: body.looseMd } : {}),
      ...(body.componentLabels !== undefined
        ? { componentLabels: json(body.componentLabels) }
        : {}),
    },
  });
  await ctx.audit.record({
    orgId,
    actorId: actor.userId,
    action: 'project.update',
    target: p.id,
    meta: { fields: ['memory', ...Object.keys(body)] },
    ip: actor.ip,
  });
  return toMemoryDto(updated);
}
