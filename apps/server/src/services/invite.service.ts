/**
 * Org invites. The raw token (32 random bytes, base64url) is returned once;
 * only sha256(token) is stored in `OrgInvite.token`.
 * - email invites: single use, accepting user's email must match (LSE-ORG-006)
 * - link invites (email null): multi-use until expiry/revocation
 * Expired / used / revoked → LSE-ORG-005 (410).
 */
import { Prisma, type OrgInvite } from '@prisma/client';
import {
  acceptInviteResponseSchema,
  computeInviteStatus,
  createInviteResponseSchema,
  INVITE_TOKEN_BYTES,
  inviteDtoSchema,
  invitePreviewDtoSchema,
  type AcceptInviteResponse,
  type CreateInviteBody,
  type CreateInviteResponse,
  type InviteDto,
  type InvitePreviewDto,
  type PaginationQuery,
} from '@loose/shared';
import type { User } from '@prisma/client';
import type { AppContext } from '../context';
import { randomToken, sha256Hex } from '../lib/crypto';
import { AppError } from '../lib/errors';
import { pageArgs, toPage, type Page } from '../lib/pagination';
import { toOrgDto, type Actor } from './org.service';

const DAY_MS = 24 * 60 * 60 * 1000;

export function toInviteDto(inv: OrgInvite): InviteDto {
  return inviteDtoSchema.parse({
    ...inv,
    kind: inv.email ? 'email' : 'link',
    status: computeInviteStatus(inv),
  });
}

export async function createInvite(
  ctx: AppContext,
  orgId: string,
  actor: Actor,
  body: CreateInviteBody,
): Promise<CreateInviteResponse> {
  const token = randomToken(INVITE_TOKEN_BYTES);
  const invite = await ctx.prisma.orgInvite.create({
    data: {
      orgId,
      email: body.email ?? null,
      token: sha256Hex(token),
      role: body.role,
      expiresAt: new Date(Date.now() + body.expiresInDays * DAY_MS),
      invitedById: actor.userId,
    },
  });
  await ctx.audit.record({
    orgId,
    actorId: actor.userId,
    action: 'invite.create',
    target: invite.id,
    meta: { kind: invite.email ? 'email' : 'link', email: invite.email, role: invite.role },
    ip: actor.ip,
  });
  const url = `${ctx.env.APP_URL.replace(/\/$/, '')}/invite/${token}`;
  return createInviteResponseSchema.parse({ ...toInviteDto(invite), token, url });
}

export async function listInvites(
  ctx: AppContext,
  orgId: string,
  q: PaginationQuery,
): Promise<Page<InviteDto>> {
  const rows = await ctx.prisma.orgInvite.findMany({
    where: { orgId },
    orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
    ...pageArgs(q),
  });
  return toPage(rows, q.limit, toInviteDto);
}

export async function revokeInvite(
  ctx: AppContext,
  orgId: string,
  inviteId: string,
  actor: Actor,
): Promise<void> {
  const inv = await ctx.prisma.orgInvite.findFirst({ where: { id: inviteId, orgId } });
  if (!inv) throw new AppError('LSE-NF-001', { devMessage: 'Invite not found in this org' });
  if (!inv.revokedAt) {
    await ctx.prisma.orgInvite.update({ where: { id: inv.id }, data: { revokedAt: new Date() } });
  }
  await ctx.audit.record({
    orgId,
    actorId: actor.userId,
    action: 'invite.revoke',
    target: inv.id,
    ip: actor.ip,
  });
}

async function findByToken(ctx: AppContext, token: string) {
  const inv = await ctx.prisma.orgInvite.findUnique({
    where: { token: sha256Hex(token) },
    include: { org: true, invitedBy: { select: { name: true } } },
  });
  if (!inv) throw new AppError('LSE-NF-001', { devMessage: 'Unknown invite token' });
  return inv;
}

function assertUsable(inv: OrgInvite) {
  const status = computeInviteStatus(inv);
  if (status !== 'pending')
    throw new AppError('LSE-ORG-005', { devMessage: `Invite is ${status}` });
}

export async function previewInvite(ctx: AppContext, token: string): Promise<InvitePreviewDto> {
  const inv = await findByToken(ctx, token);
  assertUsable(inv);
  return invitePreviewDtoSchema.parse({
    orgName: inv.org.name,
    orgSlug: inv.org.slug,
    role: inv.role,
    emailBound: Boolean(inv.email),
    invitedByName: inv.invitedBy.name,
    expiresAt: inv.expiresAt,
  });
}

export async function acceptInvite(
  ctx: AppContext,
  token: string,
  user: User,
  ip?: string,
): Promise<AcceptInviteResponse> {
  const inv = await findByToken(ctx, token);
  const existing = await ctx.prisma.orgMember.findUnique({
    where: { userId_orgId: { userId: user.id, orgId: inv.orgId } },
  });
  // Idempotent: already a member → return the membership unchanged.
  if (existing) {
    return acceptInviteResponseSchema.parse({
      org: toOrgDto(inv.org, existing.role),
      alreadyMember: true,
    });
  }
  assertUsable(inv);
  if (inv.email && inv.email.toLowerCase() !== user.email.toLowerCase()) {
    throw new AppError('LSE-ORG-006', { devMessage: 'Signed-in email does not match the invite' });
  }

  const member = await ctx.prisma.$transaction(async (tx) => {
    const now = new Date();
    if (inv.email) {
      // Single use: claim atomically so two concurrent accepts can't both succeed.
      const claimed = await tx.orgInvite.updateMany({
        where: { id: inv.id, acceptedAt: null, revokedAt: null, expiresAt: { gt: now } },
        data: { acceptedAt: now },
      });
      if (claimed.count !== 1)
        throw new AppError('LSE-ORG-005', { devMessage: 'Invite already used' });
    } else {
      await tx.orgInvite.update({ where: { id: inv.id }, data: { acceptedAt: now } });
    }
    try {
      return await tx.orgMember.create({
        data: { userId: user.id, orgId: inv.orgId, role: inv.role },
      });
    } catch (err) {
      if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002') {
        throw new AppError('LSE-CONF-001', {
          devMessage: 'Concurrent invite acceptance',
          cause: err,
        });
      }
      throw err;
    }
  });
  await ctx.audit.record({
    orgId: inv.orgId,
    actorId: user.id,
    action: 'invite.accept',
    target: inv.id,
    meta: { role: member.role, kind: inv.email ? 'email' : 'link' },
    ip,
  });
  return acceptInviteResponseSchema.parse({
    org: toOrgDto(inv.org, member.role),
    alreadyMember: false,
  });
}
