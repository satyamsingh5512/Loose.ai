/**
 * Shared building blocks of the extension services (skills, commands, MCP servers,
 * subagents, hooks, plugins): the acting member, scope/ownership checks, duplicate-name
 * checks and the SSRF guard used by every server-side outbound call.
 *
 * Lives in its own module so `extensions.service.ts` (skills/commands/MCP) and the
 * Phase 8 services (`subagents`, `hooks`, `plugins`) can share it without import cycles.
 */
import { lookup } from 'node:dns/promises';
import type { OrgMember, Prisma } from '@prisma/client';
import { isAdminRole, type ErrorCode, type OrgPolicy, type WritableExtScope } from '@loose/shared';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';
import { canonicalIpLiteral, isNonPublicAddress } from '../lib/net/ip';

export interface ExtActor {
  userId: string;
  membership: OrgMember;
  ip?: string | undefined;
}

export const json = (v: unknown) => v as Prisma.InputJsonValue;

export function isRecord(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

/** Resources a member may own personally (gated by the org policy). */
export type ExtKind = 'skill' | 'mcp' | 'command' | 'subagent' | 'hook' | 'plugin';

const PERSONAL_LABEL: Readonly<Record<ExtKind, string>> = Object.freeze({
  skill: 'skills',
  mcp: 'MCP servers',
  command: 'commands',
  subagent: 'subagents',
  hook: 'hooks',
  plugin: 'plugins',
});

export function assertCanWrite(
  actor: ExtActor,
  policy: OrgPolicy,
  kind: ExtKind,
  scope: WritableExtScope,
  ownerUserId?: string | null,
) {
  if (actor.membership.role === 'VIEWER') {
    throw new AppError('LSE-ORG-002', { devMessage: 'Viewers cannot manage extensions' });
  }
  if (scope === 'USER') {
    if (ownerUserId && ownerUserId !== actor.userId) {
      throw new AppError('LSE-NF-001', { devMessage: 'Extension not found' });
    }
    const allowed =
      kind === 'mcp'
        ? policy.extensions.allowUserMcp
        : kind === 'skill' || kind === 'subagent'
          ? policy.extensions.allowUserSkills
          : true;
    if (!allowed) {
      throw new AppError('LSE-ORG-002', {
        devMessage: `Personal ${PERSONAL_LABEL[kind]} are disabled by the org policy`,
      });
    }
    return;
  }
  if (!isAdminRole(actor.membership.role)) {
    throw new AppError('LSE-ORG-002', {
      devMessage: 'Only org admins can manage shared extensions',
    });
  }
}

/** ADMIN-only resources (hooks, plugins): org policy, never personal. */
export function assertAdmin(actor: ExtActor, what: string) {
  if (!isAdminRole(actor.membership.role)) {
    throw new AppError('LSE-ORG-002', { devMessage: `Only org admins can manage ${what}` });
  }
}

/** Org rows, project rows of the org, and the caller's own personal rows. */
export function visibleWhere(orgId: string, userId: string, q: { projectId?: string | undefined }) {
  return {
    orgId,
    OR: [
      { scope: 'ORG' as const },
      { scope: 'PROJECT' as const, ...(q.projectId ? { projectId: q.projectId } : {}) },
      { scope: 'USER' as const, userId },
    ],
  };
}

export async function assertProjectInOrg(
  ctx: AppContext,
  orgId: string,
  projectId: string | undefined,
) {
  if (!projectId) return;
  const p = await ctx.prisma.project.findFirst({
    where: { id: projectId, orgId },
    select: { id: true },
  });
  if (!p) throw new AppError('LSE-NF-001', { devMessage: 'Project not found' });
}

export function scopeIds(
  orgId: string,
  actor: ExtActor,
  scope: WritableExtScope,
  projectId?: string,
) {
  return {
    scope,
    orgId,
    projectId: scope === 'PROJECT' ? (projectId ?? null) : null,
    userId: scope === 'USER' ? actor.userId : null,
  };
}

export type ScopeIds = ReturnType<typeof scopeIds>;

export async function assertNameFree(
  find: (where: ScopeIds & { name: string }) => Promise<{ id: string } | null>,
  ids: ScopeIds,
  name: string,
  exceptId?: string,
  code: ErrorCode = 'LSE-EXT-005',
) {
  // Prisma's composite unique treats NULLs as distinct: enforce in the app.
  const row = await find({ ...ids, name });
  if (row && row.id !== exceptId) {
    throw new AppError(code, {
      fields: { name: [`"${name}" already exists in this scope`] },
    });
  }
}

// ---- SSRF guard ----------------------------------------------------------------------------

/**
 * SSRF guard for server-side outbound calls (MCP connection tests, webhook hooks):
 * http(s) only, no loopback / private / link-local targets (literal or resolved).
 * Redirects are never followed by the callers.
 */
export async function assertPublicUrl(raw: string, code: ErrorCode = 'LSE-MCP-004'): Promise<URL> {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new AppError(code, { fields: { url: ['Invalid URL'] } });
  }
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  // P10-SEC-012: one numeric classifier (lib/net/ip.ts) for every SSRF guard in the server.
  const literal = canonicalIpLiteral(host);
  if (
    !/^https?:$/.test(url.protocol) ||
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.internal') ||
    host.endsWith('.local') ||
    (literal !== null && isNonPublicAddress(literal.address))
  ) {
    throw new AppError(code, {
      devMessage: 'Outbound calls only reach public http(s) addresses',
      fields: { url: ['Use a public http(s) address'] },
    });
  }
  if (literal === null) {
    const addrs = await lookup(host, { all: true }).catch(() => []);
    if (addrs.some((a) => isNonPublicAddress(a.address))) {
      throw new AppError(code, {
        devMessage: 'The host resolves to a private address',
        fields: { url: ['Use a public http(s) address'] },
      });
    }
  }
  return url;
}
