/** Personal API tokens (`loose_pat_…`). Only the sha256 hash is stored. */
import {
  apiTokenDtoSchema,
  createApiTokenResponseSchema,
  PAT_PREFIX,
  PAT_TOKEN_BYTES,
  type ApiTokenDto,
  type CreateApiTokenBody,
  type CreateApiTokenResponse,
} from '@loose/shared';
import type { AuthSession } from '@prisma/client';
import type { AppContext } from '../context';
import { randomToken, sha256Hex } from '../lib/crypto';
import { AppError } from '../lib/errors';
import { publishTokenRevoked } from '../lib/events/revocations';

const DAY_MS = 24 * 60 * 60 * 1000;

export async function listTokens(ctx: AppContext, userId: string): Promise<ApiTokenDto[]> {
  const rows = await ctx.prisma.apiToken.findMany({
    where: { userId },
    orderBy: { createdAt: 'desc' },
  });
  return rows.map((r) => apiTokenDtoSchema.parse(r));
}

export async function createToken(
  ctx: AppContext,
  userId: string,
  body: CreateApiTokenBody,
  ip?: string,
  session?: Pick<AuthSession, 'ssoOrgId' | 'ssoConnectionId' | 'mfaVerifiedAt'>,
): Promise<CreateApiTokenResponse> {
  const org = await ctx.prisma.organization.findUnique({ where: { id: body.orgId } });
  if (!org) throw new AppError('LSE-ORG-003');
  const member = await ctx.prisma.orgMember.findUnique({
    where: { userId_orgId: { userId, orgId: org.id } },
  });
  if (!member) throw new AppError('LSE-ORG-001');

  const token = `${PAT_PREFIX}${randomToken(PAT_TOKEN_BYTES)}`;
  // P10-SEC-011: a token never exists without its audit row.
  const row = await ctx.prisma.$transaction(
    async (tx) => {
      const created = await tx.apiToken.create({
        data: {
          userId,
          orgId: org.id,
          name: body.name,
          hash: sha256Hex(token),
          scopes: body.scopes,
          expiresAt: body.expiresInDays ? new Date(Date.now() + body.expiresInDays * DAY_MS) : null,
          // P10-SEC-002: a token inherits the assurance of the session that minted it — the org's
          // SSO connection (only when the session came through *this* org's SSO) and whether the
          // session had passed the 2FA challenge. `enforceOrgAccess` checks both against the org's
          // current policy on every token request.
          ssoConnectionId: session?.ssoOrgId === org.id ? (session.ssoConnectionId ?? null) : null,
          mfaVerifiedAt: session?.mfaVerifiedAt ?? null,
        },
      });
      await ctx.audit.record(
        {
          orgId: org.id,
          actorId: userId,
          action: 'token.create',
          target: created.id,
          meta: { name: created.name, scopes: created.scopes },
          ip,
        },
        tx,
      );
      return created;
    },
    { maxWait: 10_000, timeout: 15_000 },
  );
  return createApiTokenResponseSchema.parse({ ...row, token });
}

export async function deleteToken(
  ctx: AppContext,
  userId: string,
  id: string,
  ip?: string,
): Promise<void> {
  const row = await ctx.prisma.apiToken.findFirst({ where: { id, userId } });
  if (!row) throw new AppError('LSE-NF-001', { devMessage: 'Token not found' });
  // P10-SEC-011: deletion and its audit row commit together.
  await ctx.prisma.$transaction(
    async (tx) => {
      await tx.apiToken.delete({ where: { id: row.id } });
      await ctx.audit.record(
        {
          orgId: row.orgId,
          actorId: userId,
          action: 'token.delete',
          target: row.id,
          meta: { name: row.name },
          ip,
        },
        tx,
      );
    },
    { maxWait: 10_000, timeout: 15_000 },
  );
  // P10-SEC-003: close WebSockets authenticated with this token (every instance).
  await publishTokenRevoked([row.id], { userId });
}
