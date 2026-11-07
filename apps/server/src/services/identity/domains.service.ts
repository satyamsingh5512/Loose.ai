/**
 * Verified org email domains (spec §8.20). A domain proves ownership with a DNS TXT record
 * (`_loose-verification.<domain>` = `loose-verify=<token>`); only a *verified* domain drives SSO
 * discovery, enforce-SSO and JIT account matching, and a domain may be verified by at most one
 * org (LSE-ORG-011). DNS goes through `ctx.dns` so tests inject a fake resolver.
 */
import {
  domainVerificationRecord,
  DOMAIN_VERIFICATION_VALUE_PREFIX,
  DOMAIN_VERIFICATION_PREFIX,
  MAX_ORG_DOMAINS,
  orgDomainDtoSchema,
  type OrgDomainDto,
} from '@loose/shared';
import { Prisma, type OrgDomain } from '@prisma/client';
import type { AppContext } from '../../context';
import { randomToken, safeEqual } from '../../lib/crypto';
import { AppError } from '../../lib/errors';
import type { Actor } from '../org.service';

export function toOrgDomainDto(row: OrgDomain): OrgDomainDto {
  return orgDomainDtoSchema.parse({
    ...row,
    verified: row.verifiedAt !== null,
    verificationRecord: domainVerificationRecord(row.domain, row.verificationToken),
  });
}

export function emailDomain(email: string): string | null {
  const at = email.lastIndexOf('@');
  if (at < 0) return null;
  const domain = email
    .slice(at + 1)
    .trim()
    .toLowerCase();
  return domain.length > 0 ? domain : null;
}

export async function listOrgDomains(ctx: AppContext, orgId: string): Promise<OrgDomainDto[]> {
  const rows = await ctx.prisma.orgDomain.findMany({
    where: { orgId },
    orderBy: { createdAt: 'asc' },
  });
  return rows.map(toOrgDomainDto);
}

/** Verified domain names of an org (lower-case). */
export async function verifiedDomainNames(ctx: AppContext, orgId: string): Promise<string[]> {
  const rows = await ctx.prisma.orgDomain.findMany({
    where: { orgId, verifiedAt: { not: null } },
    select: { domain: true },
  });
  return rows.map((r) => r.domain);
}

export async function createOrgDomain(
  ctx: AppContext,
  orgId: string,
  actor: Actor,
  domain: string,
): Promise<OrgDomainDto> {
  const count = await ctx.prisma.orgDomain.count({ where: { orgId } });
  if (count >= MAX_ORG_DOMAINS) {
    throw new AppError('LSE-VAL-001', {
      devMessage: `At most ${MAX_ORG_DOMAINS} domains per organization`,
      fields: { domain: [`At most ${MAX_ORG_DOMAINS} domains per organization`] },
    });
  }
  const claimedElsewhere = await ctx.prisma.orgDomain.findFirst({
    where: { domain, verifiedAt: { not: null }, orgId: { not: orgId } },
    select: { id: true },
  });
  if (claimedElsewhere) {
    throw new AppError('LSE-ORG-011', {
      devMessage: 'domain is already verified by another organization',
      fields: { domain: ['This domain is already verified by another organization.'] },
    });
  }
  const existing = await ctx.prisma.orgDomain.findUnique({
    where: { orgId_domain: { orgId, domain } },
  });
  if (existing) return toOrgDomainDto(existing);
  // P10-SEC-011: the claim and its audit row commit together.
  const row = await ctx.prisma.$transaction(
    async (tx) => {
      const created = await tx.orgDomain.create({
        data: { orgId, domain, verificationToken: randomToken(16) },
      });
      await ctx.audit.record(
        {
          orgId,
          actorId: actor.userId,
          action: 'domain.create',
          target: created.id,
          meta: { domain },
          ip: actor.ip,
        },
        tx,
      );
      return created;
    },
    { maxWait: 10_000, timeout: 15_000 },
  );
  return toOrgDomainDto(row);
}

async function txtRecords(ctx: AppContext, name: string): Promise<string[]> {
  try {
    const records = await ctx.dns.resolveTxt(name);
    return records.map((chunks) => chunks.join(''));
  } catch {
    return [];
  }
}

export async function verifyOrgDomain(
  ctx: AppContext,
  orgId: string,
  actor: Actor,
  domainId: string,
): Promise<OrgDomainDto> {
  const row = await ctx.prisma.orgDomain.findFirst({ where: { id: domainId, orgId } });
  if (!row) throw new AppError('LSE-NF-001', { devMessage: 'domain not found' });
  const claimedElsewhere = await ctx.prisma.orgDomain.findFirst({
    where: { domain: row.domain, verifiedAt: { not: null }, orgId: { not: orgId } },
    select: { id: true },
  });
  if (claimedElsewhere) {
    throw new AppError('LSE-ORG-011', {
      devMessage: 'domain is already verified by another organization',
    });
  }
  const expected = `${DOMAIN_VERIFICATION_VALUE_PREFIX}${row.verificationToken}`;
  const found = await txtRecords(ctx, `${DOMAIN_VERIFICATION_PREFIX}.${row.domain}`);
  if (!found.some((value) => safeEqual(value.trim(), expected))) {
    throw new AppError('LSE-ORG-011', {
      devMessage: 'TXT record missing or does not match',
    });
  }
  // P10-SEC-010: the claim is DB-enforced. `verifiedDomain` is unique, so of two concurrent
  // verifications for the same domain exactly one commits; the loser gets LSE-ORG-011.
  let updated: OrgDomain;
  try {
    updated = await ctx.prisma.$transaction(
      async (tx) => {
        const verified = await tx.orgDomain.update({
          where: { id: row.id },
          data: { verifiedAt: new Date(), verifiedDomain: row.domain },
        });
        // P10-SEC-011: no verified domain without its audit row.
        await ctx.audit.record(
          {
            orgId,
            actorId: actor.userId,
            action: 'domain.verify',
            target: row.id,
            meta: { domain: row.domain },
            ip: actor.ip,
          },
          tx,
        );
        return verified;
      },
      { maxWait: 10_000, timeout: 15_000 },
    );
  } catch (err) {
    if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002') {
      throw new AppError('LSE-ORG-011', {
        devMessage: 'domain is already verified by another organization',
      });
    }
    throw err;
  }
  return toOrgDomainDto(updated);
}

export async function deleteOrgDomain(
  ctx: AppContext,
  orgId: string,
  actor: Actor,
  domainId: string,
): Promise<void> {
  const row = await ctx.prisma.orgDomain.findFirst({ where: { id: domainId, orgId } });
  if (!row) throw new AppError('LSE-NF-001', { devMessage: 'domain not found' });
  await ctx.prisma.$transaction(
    async (tx) => {
      await tx.orgDomain.delete({ where: { id: row.id } });
      await ctx.audit.record(
        {
          orgId,
          actorId: actor.userId,
          action: 'domain.delete',
          target: row.id,
          meta: { domain: row.domain },
          ip: actor.ip,
        },
        tx,
      );
    },
    { maxWait: 10_000, timeout: 15_000 },
  );
}
