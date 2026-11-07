/**
 * Personal two-step verification (TOTP + recovery codes, spec §8.20).
 *
 * - The secret is envelope-encrypted (`purpose: 'generic'`, see `ENC_PURPOSE`) and never returned
 *   after enrollment; only `POST /users/me/2fa/enroll` reveals it once.
 * - Recovery codes are shown once and stored as `sha256('recovery:' + normalized)`.
 * - Failed attempts are counted per user in `ctx.kv` (`TWO_FACTOR_MAX_FAILURES` within
 *   `TWO_FACTOR_LOCKOUT_SEC` → LSE-AUTH-008); a success clears the counter.
 * - Codes are replay-protected via `User.totpLastStep`.
 */
import {
  ADMIN_2FA_ROLES,
  RECOVERY_CODE_COUNT,
  TOTP_DEFAULT_ISSUER,
  twoFactorEnrollResponseSchema,
  twoFactorRecoveryCodesResponseSchema,
  twoFactorStatusDtoSchema,
  type TwoFactorEnrollResponse,
  type TwoFactorRecoveryCodesResponse,
  type TwoFactorStatusDto,
} from '@loose/shared';
import type { AuthSession, User } from '@prisma/client';
import type { AppContext } from '../../context';
import { bytes } from '../../lib/crypto';
import { AppError } from '../../lib/errors';
import { publishSessionRevoked } from '../../lib/events/revocations';
import {
  base32Encode,
  generateRecoveryCodes,
  generateTotpSecret,
  hashRecoveryCode,
  otpauthUrl,
  verifyTotp,
} from './totp';

/** Crypto purpose for the TOTP secret (the shared `CryptoPurpose` union has no totp member). */
const ENC_PURPOSE = 'generic' as const;

export const TWO_FACTOR_MAX_FAILURES = 5;
export const TWO_FACTOR_LOCKOUT_SEC = 900;

interface FailureRecord {
  n: number;
  /** Epoch ms when the lockout window ends. */
  until: number;
}

function failureKey(userId: string): string {
  return `2fa:fail:${userId}`;
}

async function readFailures(ctx: AppContext, userId: string): Promise<FailureRecord | null> {
  let raw: string | null;
  try {
    raw = await ctx.kv.get(failureKey(userId));
  } catch {
    return null;
  }
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as FailureRecord;
    if (typeof parsed.n !== 'number' || typeof parsed.until !== 'number') return null;
    return parsed.until <= Date.now() ? null : parsed;
  } catch {
    return null;
  }
}

/** Throws LSE-AUTH-008 while the caller is locked out. */
export async function assertNotLockedOut(ctx: AppContext, userId: string): Promise<void> {
  const rec = await readFailures(ctx, userId);
  if (rec && rec.n >= TWO_FACTOR_MAX_FAILURES) {
    const retryAfter = Math.max(1, Math.ceil((rec.until - Date.now()) / 1000));
    throw new AppError('LSE-AUTH-008', {
      devMessage: 'Too many two-step verification attempts',
      headers: { 'Retry-After': String(retryAfter) },
    });
  }
}

export async function recordFailure(ctx: AppContext, userId: string): Promise<void> {
  const existing = await readFailures(ctx, userId);
  const next: FailureRecord = {
    n: (existing?.n ?? 0) + 1,
    until: existing?.until ?? Date.now() + TWO_FACTOR_LOCKOUT_SEC * 1000,
  };
  const ttl = Math.max(1, Math.ceil((next.until - Date.now()) / 1000));
  await ctx.kv.set(failureKey(userId), JSON.stringify(next), ttl).catch(() => undefined);
}

export async function clearFailures(ctx: AppContext, userId: string): Promise<void> {
  await ctx.kv.del(failureKey(userId)).catch(() => undefined);
}

// ---- status ----------------------------------------------------------------------------------

/** True when any org the user belongs to requires 2FA for their role there. */
export async function twoFactorRequiredByOrg(ctx: AppContext, userId: string): Promise<boolean> {
  if (!ctx.featureFlags.isEnabled('admin_2fa')) return false;
  const row = await ctx.prisma.orgMember.findFirst({
    where: {
      userId,
      role: { in: [...ADMIN_2FA_ROLES] },
      org: { requireAdmin2fa: true },
    },
    select: { id: true },
  });
  return row !== null;
}

export async function twoFactorStatus(
  ctx: AppContext,
  userId: string,
): Promise<TwoFactorStatusDto> {
  const user = await ctx.prisma.user.findUniqueOrThrow({ where: { id: userId } });
  const remaining = user.totpEnabledAt
    ? await ctx.prisma.totpRecoveryCode.count({ where: { userId, usedAt: null } })
    : 0;
  return twoFactorStatusDtoSchema.parse({
    enabled: user.totpEnabledAt !== null,
    enabledAt: user.totpEnabledAt,
    pendingEnrollment: user.totpPendingSecretEnc !== null,
    recoveryCodesRemaining: remaining,
    requiredByOrg: await twoFactorRequiredByOrg(ctx, userId),
  });
}

// ---- enrollment ------------------------------------------------------------------------------

export async function startEnrollment(
  ctx: AppContext,
  user: User,
): Promise<TwoFactorEnrollResponse> {
  if (user.totpEnabledAt) {
    throw new AppError('LSE-CONF-001', {
      devMessage: 'Two-step verification is already enabled',
    });
  }
  const secret = generateTotpSecret();
  await ctx.prisma.user.update({
    where: { id: user.id },
    data: { totpPendingSecretEnc: bytes(await ctx.crypto.encryptPacked(secret, ENC_PURPOSE)) },
  });
  return twoFactorEnrollResponseSchema.parse({
    secret: base32Encode(secret),
    otpauthUrl: otpauthUrl({
      issuer: ctx.env.TOTP_ISSUER || TOTP_DEFAULT_ISSUER,
      account: user.email,
      secret,
    }),
  });
}

async function issueRecoveryCodes(
  ctx: AppContext,
  userId: string,
): Promise<TwoFactorRecoveryCodesResponse> {
  const codes = generateRecoveryCodes(RECOVERY_CODE_COUNT);
  await ctx.prisma.totpRecoveryCode.deleteMany({ where: { userId } });
  await ctx.prisma.totpRecoveryCode.createMany({
    data: codes.map((code) => ({ userId, hash: hashRecoveryCode(code) })),
  });
  return twoFactorRecoveryCodesResponseSchema.parse({ recoveryCodes: codes });
}

/** Finish enrollment: the code must verify against the pending secret. */
export async function activateEnrollment(
  ctx: AppContext,
  user: User,
  code: string,
  session: AuthSession | undefined,
  ip: string | undefined,
): Promise<TwoFactorRecoveryCodesResponse> {
  if (user.totpEnabledAt) {
    throw new AppError('LSE-CONF-001', {
      devMessage: 'Two-step verification is already enabled',
    });
  }
  if (!user.totpPendingSecretEnc) {
    throw new AppError('LSE-VAL-001', { devMessage: 'Start enrollment first' });
  }
  await assertNotLockedOut(ctx, user.id);
  const secret = await ctx.crypto.decryptPacked(user.totpPendingSecretEnc, ENC_PURPOSE);
  const result = verifyTotp(secret, code, { lastStep: null });
  if (!result.ok) {
    await recordFailure(ctx, user.id);
    await ctx.audit.record({
      actorId: user.id,
      action: 'auth.2fa_failed',
      target: user.id,
      meta: { stage: 'activate' },
      ip,
    });
    ctx.metrics.counter('loose_auth_events_total', 'Authentication events', ['event']).inc({
      event: 'mfa_failed',
    });
    throw new AppError('LSE-AUTH-010', { devMessage: 'Verification code did not match' });
  }
  // P10-SEC-008: activation is single-shot. The update only matches while 2FA is still off and
  // the pending secret is the one this request verified against, so two concurrent activations
  // (or one racing a re-enroll) cannot both succeed and issue two sets of recovery codes.
  const activated = await ctx.prisma.user.updateMany({
    where: {
      id: user.id,
      totpEnabledAt: null,
      totpPendingSecretEnc: { equals: user.totpPendingSecretEnc },
    },
    data: {
      totpSecretEnc: user.totpPendingSecretEnc,
      totpPendingSecretEnc: null,
      totpEnabledAt: new Date(),
      totpLastStep: result.step ?? null,
    },
  });
  if (activated.count !== 1) {
    throw new AppError('LSE-AUTH-010', {
      devMessage: 'Enrollment was already completed or restarted by another request',
    });
  }
  const codes = await issueRecoveryCodes(ctx, user.id);
  // The enrolling session is trusted immediately (it just proved possession).
  if (session) await ctx.sessions.markMfaVerified(session.id);
  await clearFailures(ctx, user.id);
  await ctx.audit.record({
    actorId: user.id,
    action: 'auth.2fa_enrolled',
    target: user.id,
    meta: { recoveryCodes: RECOVERY_CODE_COUNT },
    ip,
  });
  return codes;
}

export async function regenerateRecoveryCodes(
  ctx: AppContext,
  user: User,
  code: string,
  ip: string | undefined,
): Promise<TwoFactorRecoveryCodesResponse> {
  await assertCodeValid(ctx, user, code, ip, 'recovery_codes');
  const codes = await issueRecoveryCodes(ctx, user.id);
  await ctx.audit.record({
    actorId: user.id,
    action: 'auth.2fa_recovery_regenerated',
    target: user.id,
    ip,
  });
  return codes;
}

export interface DisableTwoFactorResult {
  /** Rotated cookie for the calling session (null when called without a session). */
  sessionToken: string | null;
  sessionExpiresAt: Date | null;
  /** Other sessions of the user that were signed out. */
  revokedSessions: number;
}

/**
 * Turn 2FA off. P10-SEC-009: this is a credential change. Every *other* session of the user is
 * deleted — otherwise a session parked at the challenge (e.g. a stolen OAuth cookie that could
 * not pass TOTP) would silently become fully authorized — and the calling session is rotated.
 */
export async function disableTwoFactor(
  ctx: AppContext,
  user: User,
  code: string,
  ip: string | undefined,
  session?: AuthSession,
): Promise<DisableTwoFactorResult> {
  if (await twoFactorRequiredByOrg(ctx, user.id)) {
    throw new AppError('LSE-AUTH-012', {
      devMessage: 'An organization you administer requires two-step verification',
      action: null,
    });
  }
  await assertCodeValid(ctx, user, code, ip, 'disable');
  // P10-SEC-011: turning 2FA off, signing out the other sessions and the audit row are one
  // transaction — if the audit append fails, 2FA stays on and no session is touched.
  const others = session ? { userId: user.id, id: { not: session.id } } : { userId: user.id };
  const revokedIds = await ctx.prisma.$transaction(
    async (tx) => {
      await tx.totpRecoveryCode.deleteMany({ where: { userId: user.id } });
      await tx.user.update({
        where: { id: user.id },
        data: {
          totpSecretEnc: null,
          totpPendingSecretEnc: null,
          totpEnabledAt: null,
          totpLastStep: null,
        },
      });
      const doomed = await tx.authSession.findMany({ where: others, select: { id: true } });
      await tx.authSession.deleteMany({ where: { id: { in: doomed.map((s) => s.id) } } });
      await tx.authSession.updateMany({
        where: { userId: user.id },
        data: { mfaVerifiedAt: null },
      });
      await ctx.audit.record(
        {
          actorId: user.id,
          action: 'auth.2fa_disabled',
          target: user.id,
          meta: { revokedSessions: doomed.length },
          ip,
        },
        tx,
      );
      return doomed.map((s) => s.id);
    },
    { maxWait: 10_000, timeout: 15_000 },
  );
  const revokedSessions = revokedIds.length;
  // P10-SEC-003: close the WebSockets of the sessions that were just signed out (after commit).
  await publishSessionRevoked(revokedIds, { userId: user.id, reason: 'session_revoked' });
  const rotated = session ? await ctx.sessions.rotate(session.id) : null;
  return {
    sessionToken: rotated?.token ?? null,
    sessionExpiresAt: rotated?.session.expiresAt ?? null,
    revokedSessions,
  };
}

/** Verify a TOTP code for an already-enrolled user (does not touch the session). */
async function assertCodeValid(
  ctx: AppContext,
  user: User,
  code: string,
  ip: string | undefined,
  stage: string,
): Promise<void> {
  if (!user.totpSecretEnc || !user.totpEnabledAt) {
    throw new AppError('LSE-VAL-001', { devMessage: 'Two-step verification is not enabled' });
  }
  await assertNotLockedOut(ctx, user.id);
  const secret = await ctx.crypto.decryptPacked(user.totpSecretEnc, ENC_PURPOSE);
  const result = verifyTotp(secret, code, { lastStep: user.totpLastStep });
  // P10-SEC-008: consume the step atomically. The check above used the (possibly stale) row
  // the request loaded; the conditional update is the authoritative single-use check, so of two
  // concurrent requests carrying the same code exactly one wins.
  const consumed =
    result.ok && result.step !== undefined
      ? await ctx.prisma.user.updateMany({
          where: {
            id: user.id,
            totpEnabledAt: { not: null },
            OR: [{ totpLastStep: null }, { totpLastStep: { lt: result.step } }],
          },
          data: { totpLastStep: result.step },
        })
      : { count: 0 };
  if (consumed.count !== 1) {
    const replayed = result.replayed === true || result.ok;
    await recordFailure(ctx, user.id);
    await ctx.audit.record({
      actorId: user.id,
      action: 'auth.2fa_failed',
      target: user.id,
      meta: { stage, replayed },
      ip,
    });
    ctx.metrics
      .counter('loose_auth_events_total', 'Authentication events', ['event'])
      .inc({ event: 'mfa_failed' });
    throw new AppError('LSE-AUTH-010', {
      devMessage: replayed
        ? 'Verification code was already used'
        : 'Verification code did not match',
    });
  }
  await clearFailures(ctx, user.id);
}

// ---- challenge (POST /auth/2fa/verify) --------------------------------------------------------

export interface ChallengeInput {
  user: User;
  session: AuthSession;
  code?: string | undefined;
  recoveryCode?: string | undefined;
  ip?: string | undefined;
}

export interface ChallengeResult {
  /** Remaining unused recovery codes when a recovery code was consumed, else null. */
  recoveryCodesRemaining: number | null;
  /** New session cookie value (the session token is rotated after a successful challenge). */
  sessionToken: string;
  sessionExpiresAt: Date;
}

export async function completeChallenge(
  ctx: AppContext,
  input: ChallengeInput,
): Promise<ChallengeResult> {
  const { user, session, ip } = input;
  if (!user.totpEnabledAt || !user.totpSecretEnc) {
    throw new AppError('LSE-VAL-001', { devMessage: 'Two-step verification is not enabled' });
  }
  await assertNotLockedOut(ctx, user.id);

  let recoveryRemaining: number | null = null;
  if (input.recoveryCode) {
    const hash = hashRecoveryCode(input.recoveryCode);
    const row = await ctx.prisma.totpRecoveryCode.findFirst({
      where: { userId: user.id, hash, usedAt: null },
    });
    if (!row) {
      await recordFailure(ctx, user.id);
      await ctx.audit.record({
        actorId: user.id,
        action: 'auth.2fa_failed',
        target: user.id,
        meta: { stage: 'challenge', kind: 'recovery' },
        ip,
      });
      ctx.metrics
        .counter('loose_auth_events_total', 'Authentication events', ['event'])
        .inc({ event: 'mfa_failed' });
      throw new AppError('LSE-AUTH-010', { devMessage: 'Recovery code is not valid' });
    }
    // Single use: the update is conditional on usedAt still being null.
    const consumed = await ctx.prisma.totpRecoveryCode.updateMany({
      where: { id: row.id, usedAt: null },
      data: { usedAt: new Date() },
    });
    if (consumed.count !== 1) {
      throw new AppError('LSE-AUTH-010', { devMessage: 'Recovery code was already used' });
    }
    recoveryRemaining = await ctx.prisma.totpRecoveryCode.count({
      where: { userId: user.id, usedAt: null },
    });
    await ctx.audit.record({
      actorId: user.id,
      action: 'auth.2fa_recovery_used',
      target: user.id,
      meta: { remaining: recoveryRemaining },
      ip,
    });
  } else {
    await assertCodeValid(ctx, user, input.code ?? '', ip, 'challenge');
  }

  await clearFailures(ctx, user.id);
  // Rotate the session token so a pre-challenge cookie cannot be replayed.
  const rotated = await ctx.sessions.rotate(session.id, { mfaVerified: true });
  await ctx.audit.record({
    actorId: user.id,
    action: 'auth.2fa_verified',
    target: user.id,
    meta: { viaRecoveryCode: input.recoveryCode !== undefined },
    ip,
  });
  return {
    recoveryCodesRemaining: recoveryRemaining,
    sessionToken: rotated.token,
    sessionExpiresAt: rotated.session.expiresAt,
  };
}
