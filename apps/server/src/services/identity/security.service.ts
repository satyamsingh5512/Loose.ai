/**
 * Org security settings: IP allowlist and enforced admin 2FA (spec §8.20).
 *
 * Self-lockout protection: an update that would exclude the caller's own IP is refused with
 * LSE-VAL-001 unless the caller passes `confirmLockout: true`. Turning `requireAdmin2fa` on
 * reports how many admins are not enrolled yet (they are challenged on their next org request).
 */
import {
  ADMIN_2FA_ROLES,
  ipAllowed,
  orgSecurityDtoSchema,
  type OrgSecurityDto,
  type UpdateOrgSecurityBody,
} from '@loose/shared';
import type { Organization } from '@prisma/client';
import type { AppContext } from '../../context';
import { AppError } from '../../lib/errors';
import { publishPolicyChanged } from '../../lib/events/revocations';
import type { Actor } from '../org.service';
import { invalidateOrgSecurityCache } from './accessPolicy';

export async function adminsWithoutTwoFactor(ctx: AppContext, orgId: string): Promise<number> {
  return ctx.prisma.orgMember.count({
    where: {
      orgId,
      role: { in: [...ADMIN_2FA_ROLES] },
      user: { totpEnabledAt: null },
    },
  });
}

export async function orgSecurityDto(
  ctx: AppContext,
  org: Organization,
  callerIp: string | undefined,
): Promise<OrgSecurityDto> {
  const list = org.ipAllowlist;
  return orgSecurityDtoSchema.parse({
    ipAllowlistEnabled: org.ipAllowlistEnabled,
    ipAllowlist: list,
    requireAdmin2fa: org.requireAdmin2fa,
    callerIp: callerIp ?? null,
    callerIpAllowed:
      !org.ipAllowlistEnabled || list.length === 0
        ? true
        : callerIp !== undefined && ipAllowed(callerIp, list),
    adminsWithout2fa: await adminsWithoutTwoFactor(ctx, org.id),
  });
}

export async function updateOrgSecurity(
  ctx: AppContext,
  org: Organization,
  actor: Actor,
  body: UpdateOrgSecurityBody,
  callerIp: string | undefined,
): Promise<OrgSecurityDto> {
  const nextEnabled = body.ipAllowlistEnabled ?? org.ipAllowlistEnabled;
  const nextList = body.ipAllowlist ?? org.ipAllowlist;
  if (nextEnabled && nextList.length === 0) {
    throw new AppError('LSE-VAL-001', {
      devMessage: 'an enabled allowlist needs at least one range',
      fields: { ipAllowlist: ['Add at least one IP range before turning the allowlist on'] },
    });
  }
  if (nextEnabled && body.confirmLockout !== true) {
    const allowed = callerIp !== undefined && ipAllowed(callerIp, nextList);
    if (!allowed) {
      throw new AppError('LSE-VAL-001', {
        devMessage: 'the new allowlist would block the caller',
        fields: {
          ipAllowlist: [
            `This would block your current address (${callerIp ?? 'unknown'}). Add it, or confirm the lockout.`,
          ],
        },
      });
    }
  }
  // P10-SEC-011: the policy change and its audit row commit (or roll back) together.
  const updated = await ctx.prisma.$transaction(
    async (tx) => {
      const row = await tx.organization.update({
        where: { id: org.id },
        data: {
          ipAllowlistEnabled: nextEnabled,
          ipAllowlist: nextList,
          requireAdmin2fa: body.requireAdmin2fa ?? org.requireAdmin2fa,
        },
      });
      await ctx.audit.record(
        {
          orgId: org.id,
          actorId: actor.userId,
          action: 'security.update',
          target: org.id,
          meta: {
            ipAllowlistEnabled: row.ipAllowlistEnabled,
            ipAllowlistEntries: row.ipAllowlist.length,
            requireAdmin2fa: row.requireAdmin2fa,
            confirmedLockout: body.confirmLockout === true,
          },
          ip: actor.ip,
        },
        tx,
      );
      return row;
    },
    { maxWait: 10_000, timeout: 15_000 },
  );
  invalidateOrgSecurityCache(ctx, org.id);
  // REAUDIT-006: IP allowlist / admin 2FA changes re-validate live sockets on every instance.
  await publishPolicyChanged(org.id);
  return orgSecurityDto(ctx, updated, callerIp);
}
