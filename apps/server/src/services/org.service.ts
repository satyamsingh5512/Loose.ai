/**
 * Organizations, members, policy and audit log (spec §10.2).
 * Every query is filtered by orgId here in the service layer (tenant isolation).
 */
import type { Organization, OrgMember, Prisma, Role } from '@prisma/client';
import {
  auditLogEntryDtoSchema,
  defaultOrgPolicy,
  memberDtoSchema,
  orgDtoSchema,
  parseOrgPolicy,
  slugify,
  type AuditLogEntryDto,
  type AuditLogFilter,
  type AuditLogQuery,
  type CreateOrgBody,
  type MemberDto,
  type OrgDto,
  type OrgPolicy,
  type PaginationQuery,
  type UpdateMemberBody,
  type UpdateOrgBody,
} from '@loose/shared';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';
import { publishPolicyChanged } from '../lib/events/revocations';
import { pageArgs, toPage, type Page } from '../lib/pagination';

export interface Actor {
  userId: string;
  role: Role;
  ip?: string | undefined;
}

export function toOrgDto(org: Organization, role: Role): OrgDto {
  return orgDtoSchema.parse({
    ...org,
    role,
    hasGithubApp: Boolean(org.githubInstallationId),
    deletionScheduledAt: org.deletionScheduledAt ? org.deletionScheduledAt.toISOString() : null,
  });
}

const SLUG_MAX = 48;

async function uniqueSlug(ctx: AppContext, name: string): Promise<string> {
  const base = slugify(name);
  if (!(await ctx.prisma.organization.findUnique({ where: { slug: base } }))) return base;
  const stem = base.slice(0, SLUG_MAX - 4).replace(/-+$/, '');
  for (let i = 2; i < 100; i++) {
    const candidate = `${stem}-${i}`;
    if (!(await ctx.prisma.organization.findUnique({ where: { slug: candidate } })))
      return candidate;
  }
  return `${stem.slice(0, SLUG_MAX - 7)}-${Math.random().toString(36).slice(2, 8)}`;
}

export async function createOrg(
  ctx: AppContext,
  userId: string,
  body: CreateOrgBody,
  ip?: string,
): Promise<OrgDto> {
  let slug = body.slug;
  if (slug) {
    if (await ctx.prisma.organization.findUnique({ where: { slug } }))
      throw new AppError('LSE-ORG-004');
  } else {
    slug = await uniqueSlug(ctx, body.name);
  }
  const org = await ctx.prisma.organization.create({
    data: {
      name: body.name,
      slug,
      policy: defaultOrgPolicy() as Prisma.InputJsonValue,
      members: { create: { userId, role: 'OWNER' } },
    },
  });
  await ctx.audit.record({
    orgId: org.id,
    actorId: userId,
    action: 'org.create',
    target: org.id,
    meta: { name: org.name, slug: org.slug },
    ip,
  });
  return toOrgDto(org, 'OWNER');
}

export async function listOrgs(ctx: AppContext, userId: string): Promise<OrgDto[]> {
  const memberships = await ctx.prisma.orgMember.findMany({
    where: { userId },
    include: { org: true },
    orderBy: { createdAt: 'asc' },
  });
  return memberships.map((m) => toOrgDto(m.org, m.role));
}

export async function updateOrg(
  ctx: AppContext,
  org: Organization,
  actor: Actor,
  body: UpdateOrgBody,
): Promise<OrgDto> {
  if (body.slug && body.slug !== org.slug) {
    const taken = await ctx.prisma.organization.findUnique({ where: { slug: body.slug } });
    if (taken) throw new AppError('LSE-ORG-004');
  }
  const updated = await ctx.prisma.organization.update({
    where: { id: org.id },
    data: {
      ...(body.name !== undefined ? { name: body.name } : {}),
      ...(body.slug !== undefined ? { slug: body.slug } : {}),
    },
  });
  await ctx.audit.record({
    orgId: org.id,
    actorId: actor.userId,
    action: 'org.update',
    target: org.id,
    meta: {
      before: { name: org.name, slug: org.slug },
      after: { name: updated.name, slug: updated.slug },
    },
    ip: actor.ip,
  });
  return toOrgDto(updated, actor.role);
}

// ---- members ------------------------------------------------------------------------

const memberInclude = {
  user: { select: { id: true, email: true, name: true, avatarUrl: true } },
} as const;
type MemberRow = Prisma.OrgMemberGetPayload<{ include: typeof memberInclude }>;

export function toMemberDto(m: MemberRow): MemberDto {
  return memberDtoSchema.parse(m);
}

export async function listMembers(
  ctx: AppContext,
  orgId: string,
  q: PaginationQuery,
): Promise<Page<MemberDto>> {
  const rows = await ctx.prisma.orgMember.findMany({
    where: { orgId },
    include: memberInclude,
    orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
    ...pageArgs(q),
  });
  return toPage(rows, q.limit, toMemberDto);
}

async function findMember(ctx: AppContext, orgId: string, userId: string): Promise<MemberRow> {
  const m = await ctx.prisma.orgMember.findUnique({
    where: { userId_orgId: { userId, orgId } },
    include: memberInclude,
  });
  if (!m) throw new AppError('LSE-NF-001', { devMessage: 'Member not found in this org' });
  return m;
}

export async function getMember(
  ctx: AppContext,
  orgId: string,
  userId: string,
): Promise<MemberDto> {
  return toMemberDto(await findMember(ctx, orgId, userId));
}

function lockOrgRoles(tx: Prisma.TransactionClient, orgId: string) {
  return tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${`org-roles:${orgId}`}, 0))`;
}

async function ownerCount(tx: Prisma.TransactionClient, orgId: string): Promise<number> {
  return tx.orgMember.count({ where: { orgId, role: 'OWNER' } });
}

/**
 * Role rules: only an OWNER may grant OWNER or modify/remove another OWNER;
 * the last OWNER can't be demoted or removed (LSE-ORG-007).
 */
export async function updateMember(
  ctx: AppContext,
  orgId: string,
  targetUserId: string,
  actor: Actor,
  body: UpdateMemberBody,
): Promise<MemberDto> {
  const target = await findMember(ctx, orgId, targetUserId);
  const touchesOwner = target.role === 'OWNER' || body.role === 'OWNER';
  if (touchesOwner && actor.role !== 'OWNER') {
    throw new AppError('LSE-ORG-002', {
      devMessage: 'Only an owner can grant, change or revoke the owner role',
    });
  }
  const updated = await ctx.prisma.$transaction(
    async (tx) => {
      // Role changes of one org are serialised (last-owner invariant) with an advisory lock rather
      // than SERIALIZABLE isolation, so the audit append can share the transaction without
      // spurious serialization failures against concurrent audit writes (P10-SEC-011).
      await lockOrgRoles(tx, orgId);
      if (
        target.role === 'OWNER' &&
        body.role &&
        body.role !== 'OWNER' &&
        (await ownerCount(tx, orgId)) <= 1
      ) {
        throw new AppError('LSE-ORG-007');
      }
      const row = await tx.orgMember.update({
        where: { id: target.id },
        data: {
          ...(body.role !== undefined ? { role: body.role } : {}),
          ...(body.lockedMode !== undefined ? { lockedMode: body.lockedMode } : {}),
        },
        include: memberInclude,
      });
      await ctx.audit.record(
        {
          orgId,
          actorId: actor.userId,
          action: 'member.role_change',
          target: targetUserId,
          meta: {
            from: { role: target.role, lockedMode: target.lockedMode },
            to: { role: row.role, lockedMode: row.lockedMode },
          },
          ip: actor.ip,
        },
        tx,
      );
      return row;
    },
    { maxWait: 10_000, timeout: 15_000 },
  );
  // Roles are read from the DB on every request, so changes apply immediately; live sockets of
  // the member are re-validated on every instance (REAUDIT-006: admin 2FA / SSO depend on role).
  await publishPolicyChanged(orgId, { userId: targetUserId });
  return toMemberDto(updated);
}

export async function removeMember(
  ctx: AppContext,
  orgId: string,
  targetUserId: string,
  actor: Actor,
): Promise<void> {
  const target = await findMember(ctx, orgId, targetUserId);
  const self = targetUserId === actor.userId;
  if (target.role === 'OWNER' && actor.role !== 'OWNER') {
    throw new AppError('LSE-ORG-002', { devMessage: 'Only an owner can remove an owner' });
  }
  await ctx.prisma.$transaction(
    async (tx) => {
      await lockOrgRoles(tx, orgId);
      if (target.role === 'OWNER' && (await ownerCount(tx, orgId)) <= 1)
        throw new AppError('LSE-ORG-007');
      await tx.orgMember.delete({ where: { id: target.id } });
      // PATs are org-bound; a removed member's tokens for this org stop working.
      await tx.apiToken.deleteMany({ where: { orgId, userId: targetUserId } });
      await ctx.audit.record(
        {
          orgId,
          actorId: actor.userId,
          action: 'member.remove',
          target: targetUserId,
          meta: { role: target.role, self },
          ip: actor.ip,
        },
        tx,
      );
    },
    { maxWait: 10_000, timeout: 15_000 },
  );
  // REAUDIT-006: the removed member's sockets in this org (cookie and the deleted PATs) close.
  await publishPolicyChanged(orgId, { userId: targetUserId });
}

// ---- policy -----------------------------------------------------------------------

export function getPolicy(org: Organization): OrgPolicy {
  return parseOrgPolicy(org.policy);
}

export async function updatePolicy(
  ctx: AppContext,
  org: Organization,
  actor: Actor,
  policy: OrgPolicy,
): Promise<OrgPolicy> {
  const before = parseOrgPolicy(org.policy);
  await ctx.prisma.$transaction(async (tx) => {
    await tx.organization.update({
      where: { id: org.id },
      data: { policy: policy as Prisma.InputJsonValue },
    });
    await ctx.audit.record(
      {
        orgId: org.id,
        actorId: actor.userId,
        action: 'policy.update',
        target: org.id,
        meta: { before, after: policy },
        ip: actor.ip,
      },
      tx,
    );
  });
  return policy;
}

// ---- audit log ----------------------------------------------------------------------

/** Shared by the list endpoint and the streaming export (`action`/`actionPrefix`/`actorId`/range). */
export function auditLogWhere(orgId: string, f: AuditLogFilter): Prisma.AuditLogWhereInput {
  const and: Prisma.AuditLogWhereInput[] = [];
  if (f.action) and.push({ action: f.action });
  if (f.actionPrefix) and.push({ action: { startsWith: f.actionPrefix } });
  if (f.actorId) and.push({ actorId: f.actorId });
  if (f.from) and.push({ createdAt: { gte: new Date(f.from) } });
  if (f.to) and.push({ createdAt: { lte: new Date(f.to) } });
  return { orgId, ...(and.length > 0 ? { AND: and } : {}) };
}

export async function listAuditLog(
  ctx: AppContext,
  orgId: string,
  q: AuditLogQuery,
): Promise<Page<AuditLogEntryDto>> {
  const rows = await ctx.prisma.auditLog.findMany({
    where: auditLogWhere(orgId, q),
    include: { actor: { select: { id: true, email: true, name: true, avatarUrl: true } } },
    orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
    ...pageArgs(q),
  });
  return toPage(rows, q.limit, (r) =>
    auditLogEntryDtoSchema.parse({
      ...r,
      meta: r.meta && typeof r.meta === 'object' && !Array.isArray(r.meta) ? r.meta : null,
    }),
  );
}

export type { OrgMember };
