/** Users, OAuth account resolution and dev login. */
import type { AuthSession, Prisma, User } from '@prisma/client';
import { userDtoSchema, type OAuthProvider, type UpdateMeBody, type UserDto } from '@loose/shared';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';
import { sessionNeedsMfa } from './identity/accessPolicy';
import type { OAuthProfile, OAuthTokens } from './oauth.service';

export interface UserDtoOptions {
  /**
   * The caller's cookie session (Phase 10): fills `mfaRequired` so the web app knows this
   * session still has to pass the two-step challenge.
   */
  session?: Pick<AuthSession, 'mfaVerifiedAt'> | undefined;
}

export async function getUserDto(
  ctx: AppContext,
  userId: string,
  opts: UserDtoOptions = {},
): Promise<UserDto> {
  const user = await ctx.prisma.user.findUnique({
    where: { id: userId },
    include: { oauthAccounts: { select: { provider: true } } },
  });
  if (!user) throw new AppError('LSE-AUTH-001', { devMessage: 'User no longer exists' });
  return userDtoSchema.parse({
    ...user,
    linkedProviders: [...new Set(user.oauthAccounts.map((a) => a.provider))].sort(),
    twoFactorEnabled: user.totpEnabledAt !== null,
    mfaRequired: sessionNeedsMfa(user, opts.session),
    deletionScheduledAt: user.deletionScheduledAt,
  });
}

export async function updateMe(
  ctx: AppContext,
  userId: string,
  body: UpdateMeBody,
): Promise<UserDto> {
  await ctx.prisma.user.update({ where: { id: userId }, data: body });
  return getUserDto(ctx, userId);
}

async function encryptTokens(ctx: AppContext, tokens: OAuthTokens) {
  return {
    accessTokenEnc: await ctx.crypto.encryptPacked(tokens.accessToken, 'oauth-token'),
    refreshTokenEnc: tokens.refreshToken
      ? await ctx.crypto.encryptPacked(tokens.refreshToken, 'oauth-token')
      : null,
    scopes: tokens.scopes,
    expiresAt: tokens.expiresAt ?? null,
  };
}

function providerIdField(provider: OAuthProvider): 'githubId' | 'googleId' {
  return provider === 'github' ? 'githubId' : 'googleId';
}

export interface ResolveOAuthInput {
  provider: OAuthProvider;
  profile: OAuthProfile;
  tokens: OAuthTokens;
  /** When set, link the provider to this (signed-in) user instead of signing in. */
  linkToUserId?: string | undefined;
}

/**
 * Resolve the user for an OAuth callback:
 *  1. link mode → attach the provider account to the current user
 *  2. known provider account → that user (tokens refreshed)
 *  3. email already used by another account → LSE-AUTH-005 (no silent merge)
 *  4. otherwise create the user
 */
export async function resolveOAuthUser(
  ctx: AppContext,
  input: ResolveOAuthInput,
): Promise<{ user: User; created: boolean }> {
  const { provider, profile } = input;
  if (!profile.emailVerified || !profile.email) {
    throw new AppError('LSE-AUTH-002', { devMessage: `${provider} account has no verified email` });
  }
  const enc = await encryptTokens(ctx, input.tokens);
  const accountKey = {
    provider_providerAccountId: { provider, providerAccountId: profile.providerAccountId },
  };
  const existingAccount = await ctx.prisma.oAuthAccount.findUnique({
    where: accountKey,
    include: { user: true },
  });

  if (input.linkToUserId) {
    if (existingAccount && existingAccount.userId !== input.linkToUserId) {
      throw new AppError('LSE-AUTH-005', {
        devMessage: `${provider} account already linked to another user`,
      });
    }
    const other = await ctx.prisma.oAuthAccount.findUnique({
      where: { userId_provider: { userId: input.linkToUserId, provider } },
    });
    if (other && other.providerAccountId !== profile.providerAccountId) {
      // Replace the previously linked account of the same provider.
      await ctx.prisma.oAuthAccount.delete({ where: { id: other.id } });
    }
    await ctx.prisma.oAuthAccount.upsert({
      where: accountKey,
      create: {
        userId: input.linkToUserId,
        provider,
        providerAccountId: profile.providerAccountId,
        ...enc,
      },
      update: enc,
    });
    const user = await ctx.prisma.user.update({
      where: { id: input.linkToUserId },
      data: { [providerIdField(provider)]: profile.providerAccountId },
    });
    return { user, created: false };
  }

  if (existingAccount) {
    await ctx.prisma.oAuthAccount.update({ where: { id: existingAccount.id }, data: enc });
    const data: Prisma.UserUpdateInput = {};
    if (!existingAccount.user.avatarUrl && profile.avatarUrl) data.avatarUrl = profile.avatarUrl;
    if (!existingAccount.user.name && profile.name) data.name = profile.name;
    const user = Object.keys(data).length
      ? await ctx.prisma.user.update({ where: { id: existingAccount.userId }, data })
      : existingAccount.user;
    return { user, created: false };
  }

  const byEmail = await ctx.prisma.user.findUnique({ where: { email: profile.email } });
  if (byEmail) {
    throw new AppError('LSE-AUTH-005', {
      devMessage: `email already belongs to a user without a linked ${provider} account`,
    });
  }

  const user = await ctx.prisma.user.create({
    data: {
      email: profile.email,
      name: profile.name,
      avatarUrl: profile.avatarUrl,
      [providerIdField(provider)]: profile.providerAccountId,
      oauthAccounts: { create: { provider, providerAccountId: profile.providerAccountId, ...enc } },
    },
  });
  return { user, created: true };
}

/** DEV ONLY — used by POST /auth/dev-login, which is never mounted in production. */
export async function findOrCreateDevUser(
  ctx: AppContext,
  email: string,
  name?: string,
): Promise<User> {
  return ctx.prisma.user.upsert({
    where: { email },
    create: { email, name: name ?? email.split('@')[0] ?? null },
    update: name ? { name } : {},
  });
}

/** Decrypted GitHub access token for a user, or null if not linked. */
export async function getGithubAccessToken(
  ctx: AppContext,
  userId: string,
): Promise<string | null> {
  const account = await ctx.prisma.oAuthAccount.findUnique({
    where: { userId_provider: { userId, provider: 'github' } },
  });
  if (!account) return null;
  return ctx.crypto.decryptPackedString(account.accessTokenEnc, 'oauth-token');
}
