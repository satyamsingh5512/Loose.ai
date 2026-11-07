/**
 * Policy packs (spec §8.20): reusable guardrail presets. Four built-ins live in @loose/shared; orgs
 * can define their own. Applying a pack is copy-on-apply: its rules are merged into the project's
 * guardrails (tighten-only, see `applyPolicyPack`) and recorded in `Project.appliedPolicyPacks`;
 * later pack edits do not change projects until the pack is applied again.
 */
import { Prisma, type PolicyPack, type Project } from '@prisma/client';
import {
  BUILTIN_POLICY_PACKS,
  applyPolicyPack,
  approvalGatesSchema,
  builtinPolicyPackId,
  commandPolicySchema,
  findBuiltinPolicyPack,
  isBuiltinPolicyPackId,
  policyPackRulesSchema,
  policyPackSlugSchema,
  slugify,
  type ApplyPolicyPackBody,
  type ApplyPolicyPackResultDto,
  type CreatePolicyPackBody,
  type PlanModeSetting,
  type PolicyPackDto,
  type PolicyPackGuardrails,
  type PolicyPackRules,
  type ProjectAppliedPolicyPack,
  type UpdatePolicyPackBody,
} from '@loose/shared';
import type { AppContext } from '../../context';
import { AppError } from '../../lib/errors';
import type { Actor } from '../org.service';

// ---- helpers --------------------------------------------------------------------------------

function parseAppliedPacks(json: unknown): ProjectAppliedPolicyPack[] {
  return Array.isArray(json) ? (json as ProjectAppliedPolicyPack[]) : [];
}

function guardrailsOf(p: Project): PolicyPackGuardrails {
  return {
    allowedFilePatterns: [...p.allowedFilePatterns],
    deniedFilePatterns: [...p.deniedFilePatterns],
    commandPolicy: commandPolicySchema.parse(p.commandPolicy ?? {}),
    approvalGates: approvalGatesSchema.parse(p.approvalGates ?? {}),
    networkAllowlist: [...p.networkAllowlist],
    maxBudgetUsd: Number(p.maxBudgetUsd),
    maxSessionDurationMin: p.maxSessionDurationMin,
    planMode: (['OFF', 'AUTO', 'ALWAYS'].includes(p.planMode)
      ? p.planMode
      : 'AUTO') as PlanModeSetting,
  };
}

function appliedCount(projects: Pick<Project, 'appliedPolicyPacks'>[], packId: string): number {
  return projects.filter((p) =>
    parseAppliedPacks(p.appliedPolicyPacks).some((a) => a.packId === packId),
  ).length;
}

function rulesOf(row: Pick<PolicyPack, 'rules'>): PolicyPackRules {
  const parsed = policyPackRulesSchema.safeParse(row.rules);
  if (!parsed.success) {
    throw new AppError('LSE-SYS-001', { devMessage: 'Stored policy pack rules are invalid' });
  }
  return parsed.data;
}

function builtinDto(slug: string, applied: number): PolicyPackDto {
  const b = findBuiltinPolicyPack(slug);
  if (!b) throw new AppError('LSE-NF-001', { devMessage: 'Policy pack not found' });
  return {
    id: builtinPolicyPackId(b.slug),
    orgId: null,
    builtin: true,
    slug: b.slug,
    name: b.name,
    description: b.description,
    version: b.version,
    rules: b.rules,
    appliedProjectCount: applied,
    createdAt: null,
    updatedAt: null,
  };
}

function customDto(row: PolicyPack, applied: number): PolicyPackDto {
  return {
    id: row.id,
    orgId: row.orgId,
    builtin: false,
    slug: row.slug,
    name: row.name,
    description: row.description,
    version: row.version,
    rules: rulesOf(row),
    appliedProjectCount: applied,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

const orgProjects = (ctx: AppContext, orgId: string) =>
  ctx.prisma.project.findMany({ where: { orgId }, select: { id: true, appliedPolicyPacks: true } });

function readOnly(): AppError {
  return new AppError('LSE-VAL-001', {
    fields: { packId: ['Built-in policy packs are read-only'] },
    devMessage: 'Built-in policy packs cannot be changed or deleted',
  });
}

function slugTaken(): AppError {
  return new AppError('LSE-VAL-001', {
    fields: { slug: ['A policy pack with this name already exists'] },
    devMessage: 'Policy pack slug is already in use',
  });
}

async function findOrgPack(ctx: AppContext, orgId: string, packId: string): Promise<PolicyPack> {
  const row = await ctx.prisma.policyPack.findFirst({ where: { id: packId, orgId } });
  if (!row) throw new AppError('LSE-NF-001', { devMessage: 'Policy pack not found' });
  return row;
}

// ---- CRUD -----------------------------------------------------------------------------------

export async function listPolicyPacks(ctx: AppContext, orgId: string): Promise<PolicyPackDto[]> {
  const projects = await orgProjects(ctx, orgId);
  const custom = await ctx.prisma.policyPack.findMany({
    where: { orgId },
    orderBy: [{ name: 'asc' }, { id: 'asc' }],
  });
  return [
    ...BUILTIN_POLICY_PACKS.map((b) =>
      builtinDto(b.slug, appliedCount(projects, builtinPolicyPackId(b.slug))),
    ),
    ...custom.map((row) => customDto(row, appliedCount(projects, row.id))),
  ];
}

export async function getPolicyPack(
  ctx: AppContext,
  orgId: string,
  packId: string,
): Promise<PolicyPackDto> {
  const projects = await orgProjects(ctx, orgId);
  if (isBuiltinPolicyPackId(packId)) {
    const b = findBuiltinPolicyPack(packId);
    if (!b) throw new AppError('LSE-NF-001', { devMessage: 'Policy pack not found' });
    return builtinDto(b.slug, appliedCount(projects, packId));
  }
  return customDto(await findOrgPack(ctx, orgId, packId), appliedCount(projects, packId));
}

export async function createPolicyPack(
  ctx: AppContext,
  orgId: string,
  actor: Actor,
  body: CreatePolicyPackBody,
): Promise<PolicyPackDto> {
  const slug = body.slug ?? slugify(body.name);
  if (!policyPackSlugSchema.safeParse(slug).success) {
    throw new AppError('LSE-VAL-001', {
      fields: { slug: ['Use 3–48 lowercase letters, numbers and single dashes'] },
      devMessage: 'Invalid policy pack slug',
    });
  }
  if (findBuiltinPolicyPack(slug)) throw slugTaken();
  let row: PolicyPack;
  try {
    row = await ctx.prisma.policyPack.create({
      data: {
        orgId,
        slug,
        name: body.name,
        description: body.description,
        rules: body.rules as Prisma.InputJsonValue,
        createdById: actor.userId,
      },
    });
  } catch (err) {
    if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002')
      throw slugTaken();
    throw err;
  }
  await ctx.audit.record({
    orgId,
    actorId: actor.userId,
    action: 'policy_pack.create',
    target: row.id,
    meta: { slug: row.slug, name: row.name, rules: body.rules },
    ip: actor.ip,
  });
  return customDto(row, 0);
}

export async function updatePolicyPack(
  ctx: AppContext,
  orgId: string,
  actor: Actor,
  packId: string,
  body: UpdatePolicyPackBody,
): Promise<PolicyPackDto> {
  if (isBuiltinPolicyPackId(packId)) throw readOnly();
  const before = await findOrgPack(ctx, orgId, packId);
  const row = await ctx.prisma.policyPack.update({
    where: { id: before.id },
    data: {
      ...(body.name !== undefined ? { name: body.name } : {}),
      ...(body.description !== undefined ? { description: body.description } : {}),
      ...(body.rules !== undefined
        ? { rules: body.rules as Prisma.InputJsonValue, version: { increment: 1 } }
        : {}),
    },
  });
  await ctx.audit.record({
    orgId,
    actorId: actor.userId,
    action: 'policy_pack.update',
    target: row.id,
    meta: {
      slug: row.slug,
      version: { from: before.version, to: row.version },
      ...(body.rules !== undefined ? { rules: { before: before.rules, after: body.rules } } : {}),
    },
    ip: actor.ip,
  });
  return customDto(row, appliedCount(await orgProjects(ctx, orgId), row.id));
}

export async function deletePolicyPack(
  ctx: AppContext,
  orgId: string,
  actor: Actor,
  packId: string,
): Promise<void> {
  if (isBuiltinPolicyPackId(packId)) throw readOnly();
  const row = await findOrgPack(ctx, orgId, packId);
  await ctx.prisma.policyPack.delete({ where: { id: row.id } });
  await ctx.audit.record({
    orgId,
    actorId: actor.userId,
    action: 'policy_pack.delete',
    target: row.id,
    meta: { slug: row.slug, name: row.name },
    ip: actor.ip,
  });
}

// ---- apply ----------------------------------------------------------------------------------

export async function applyPolicyPackToProjects(
  ctx: AppContext,
  orgId: string,
  actor: Actor,
  packId: string,
  body: ApplyPolicyPackBody,
): Promise<ApplyPolicyPackResultDto> {
  let pack: { id: string; slug: string; name: string; version: number; rules: PolicyPackRules };
  if (isBuiltinPolicyPackId(packId)) {
    const b = findBuiltinPolicyPack(packId);
    if (!b) throw new AppError('LSE-NF-001', { devMessage: 'Policy pack not found' });
    pack = { id: builtinPolicyPackId(b.slug), ...b };
  } else {
    const row = await findOrgPack(ctx, orgId, packId);
    pack = {
      id: row.id,
      slug: row.slug,
      name: row.name,
      version: row.version,
      rules: rulesOf(row),
    };
  }

  const appliedAt = new Date().toISOString();
  const applied = await ctx.prisma.$transaction(async (tx) => {
    // Tenant isolation: only projects of this org; anything else is reported as not found.
    const projects = await tx.project.findMany({
      where: { id: { in: body.projectIds }, orgId },
    });
    if (projects.length !== body.projectIds.length) {
      throw new AppError('LSE-NF-001', { devMessage: 'Project not found' });
    }
    const out: ApplyPolicyPackResultDto['applied'] = [];
    for (const project of projects) {
      const { guardrails, changed } = applyPolicyPack(guardrailsOf(project), pack.rules);
      const entry: ProjectAppliedPolicyPack = {
        packId: pack.id,
        slug: pack.slug,
        name: pack.name,
        version: pack.version,
        appliedAt,
        appliedById: actor.userId,
      };
      // Re-applying the same pack replaces its previous entry.
      const history = [
        ...parseAppliedPacks(project.appliedPolicyPacks).filter((a) => a.packId !== pack.id),
        entry,
      ];
      await tx.project.update({
        where: { id: project.id },
        data: {
          allowedFilePatterns: guardrails.allowedFilePatterns,
          deniedFilePatterns: guardrails.deniedFilePatterns,
          commandPolicy: guardrails.commandPolicy as Prisma.InputJsonValue,
          approvalGates: guardrails.approvalGates as Prisma.InputJsonValue,
          networkAllowlist: guardrails.networkAllowlist,
          maxBudgetUsd: guardrails.maxBudgetUsd,
          maxSessionDurationMin: guardrails.maxSessionDurationMin,
          planMode: guardrails.planMode,
          appliedPolicyPacks: history as unknown as Prisma.InputJsonValue,
        },
      });
      out.push({ projectId: project.id, changed });
    }
    // Keep the caller's order.
    const ordered = body.projectIds.map((id) => out.find((o) => o.projectId === id)!);
    // P10-SEC-011: the audit row commits (or rolls back) together with the guardrail changes.
    await ctx.audit.record(
      {
        orgId,
        actorId: actor.userId,
        action: 'policy_pack.apply',
        target: pack.id,
        meta: {
          slug: pack.slug,
          version: pack.version,
          projects: ordered.map((a) => ({ projectId: a.projectId, changed: a.changed })),
        },
        ip: actor.ip,
      },
      tx,
    );
    return ordered;
  });

  return { packId: pack.id, version: pack.version, applied };
}
