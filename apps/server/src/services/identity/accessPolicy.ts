/**
 * Org access policy (spec §8.20: enforced 2FA for admins, SSO enforcement, IP allowlists) —
 * OWNED BY W1. Contract: phase10-design.md §5.1.
 *
 * Call sites (wired by the Phase 10 foundation):
 * - `requireAuth` → `enforceSessionPolicy(ctx, req)`: a user with 2FA enabled must pass the
 *   challenge once per cookie session (LSE-AUTH-012) before touching anything but the
 *   allow-listed auth/profile endpoints.
 * - `requireOrg` and `sessionLifecycle.membershipFor` (session routes, runs, WS joins) →
 *   `enforceOrgAccess(...)`: IP allowlist (LSE-ORG-010) → enforced 2FA (LSE-AUTH-012) →
 *   enforced SSO (LSE-AUTH-006).
 *
 * Every check is skipped for `via: 'internal'` callers (job-driven runs and triggers have no
 * request, no IP and no session). API tokens cannot be *challenged*, so they carry the assurance
 * of the session that minted them (`ApiToken.mfaVerifiedAt`, `ApiToken.ssoConnectionId`) and
 * are checked against the org's current 2FA / SSO policy on every request (P10-SEC-002).
 *
 * The per-org security configuration (SSO connection + verified domains) is cached for
 * `ORG_SECURITY_TTL_MS` per process so the hot path costs at most one extra query every 5 s.
 */
import type { Request } from 'express';
import { ADMIN_2FA_ROLES, API_PREFIX, ipAllowed, type Role } from '@loose/shared';
import type { ApiToken, AuthSession, Organization, OrgMember, User } from '@prisma/client';
import type { AppContext } from '../../context';
import { AppError } from '../../lib/errors';
import { normalizeClientIp } from '../../lib/net/clientIp';
import type { Caller } from '../sessionLifecycle.service';
import { verifiedDomainNames } from './domains.service';
import { getSsoConnection, ssoRequiredFor } from './sso.service';

export interface OrgAccessSubject {
  user: User;
  /** `internal` = no request (job-driven runs / triggers): IP / 2FA / SSO checks do not apply. */
  via: 'session' | 'token' | 'internal';
  authSession?: AuthSession | undefined;
  apiToken?: ApiToken | undefined;
  /** Normalized client IP (`::ffff:` prefix removed). */
  ip?: string | undefined;
  method?: string | undefined;
  path?: string | undefined;
}

export function orgAccessSubjectFromRequest(req: Request): OrgAccessSubject {
  const auth = req.auth;
  if (!auth) throw new Error('orgAccessSubjectFromRequest called before requireAuth');
  return {
    user: auth.user,
    via: auth.via,
    authSession: auth.session,
    apiToken: auth.apiToken,
    ip: normalizeClientIp(req.ip),
    method: req.method,
    path: req.originalUrl.split('?')[0],
  };
}

export function orgAccessSubjectFromCaller(caller: Caller): OrgAccessSubject {
  const via: OrgAccessSubject['via'] = caller.apiToken
    ? 'token'
    : caller.authSession || caller.ip !== undefined
      ? 'session'
      : 'internal';
  return {
    user: caller.user,
    via,
    authSession: caller.authSession,
    apiToken: caller.apiToken,
    ip: normalizeClientIp(caller.ip),
  };
}

// ---- cached per-org security configuration ----------------------------------------------------

export const ORG_SECURITY_TTL_MS = 5_000;

interface OrgSecurityConfig {
  ssoEnabled: boolean;
  ssoEnforce: boolean;
  allowOwnerBypass: boolean;
  /** Id of the org's current SSO connection (sessions/tokens must match it, P10-SEC-002). */
  ssoConnectionId: string | null;
  verifiedDomains: string[];
}

interface CacheEntry {
  expiresAt: number;
  value: OrgSecurityConfig;
}

const cache = new WeakMap<AppContext, Map<string, CacheEntry>>();

function cacheFor(ctx: AppContext): Map<string, CacheEntry> {
  let map = cache.get(ctx);
  if (!map) {
    map = new Map();
    cache.set(ctx, map);
  }
  return map;
}

/** Drop the cached configuration of an org (called after SSO / domain / security changes). */
export function invalidateOrgSecurityCache(ctx: AppContext, orgId?: string): void {
  const map = cache.get(ctx);
  if (!map) return;
  if (orgId === undefined) map.clear();
  else map.delete(orgId);
}

async function orgSecurityConfig(ctx: AppContext, orgId: string): Promise<OrgSecurityConfig> {
  const map = cacheFor(ctx);
  const hit = map.get(orgId);
  if (hit && hit.expiresAt > Date.now()) return hit.value;
  const connection = await getSsoConnection(ctx, orgId);
  const value: OrgSecurityConfig = {
    ssoEnabled: connection?.enabled ?? false,
    ssoEnforce: connection?.enforce ?? false,
    allowOwnerBypass: connection?.allowOwnerBypass ?? true,
    ssoConnectionId: connection?.id ?? null,
    verifiedDomains:
      connection?.enabled && connection.enforce ? await verifiedDomainNames(ctx, orgId) : [],
  };
  map.set(orgId, { expiresAt: Date.now() + ORG_SECURITY_TTL_MS, value });
  return value;
}

// ---- enforcement -----------------------------------------------------------------------------

function authEvent(ctx: AppContext, event: string): void {
  ctx.metrics.counter('loose_auth_events_total', 'Authentication events', ['event']).inc({ event });
}

async function enforceIpAllowlist(
  ctx: AppContext,
  subject: OrgAccessSubject,
  org: Organization,
): Promise<void> {
  if (!org.ipAllowlistEnabled || org.ipAllowlist.length === 0) return;
  if (!ctx.featureFlags.isEnabled('ip_allowlist', org)) return;
  const ip = subject.ip;
  if (ip !== undefined && ipAllowed(ip, org.ipAllowlist)) return;
  authEvent(ctx, 'ip_blocked');
  await ctx.audit.record({
    orgId: org.id,
    actorId: subject.user.id,
    action: 'security.ip_blocked',
    target: org.id,
    meta: { method: subject.method, path: subject.path, via: subject.via },
    ip,
  });
  throw new AppError('LSE-ORG-010', {
    devMessage: `client address ${ip ?? 'unknown'} is not in the organization's IP allowlist`,
  });
}

function enforceAdminTwoFactor(
  ctx: AppContext,
  subject: OrgAccessSubject,
  org: Organization,
  role: Role,
): void {
  if (!org.requireAdmin2fa) return;
  if (!ctx.featureFlags.isEnabled('admin_2fa', org)) return;
  if (!(ADMIN_2FA_ROLES as readonly string[]).includes(role)) return;
  if (!subject.user.totpEnabledAt) {
    throw new AppError('LSE-AUTH-012', {
      devMessage: 'this organization requires two-step verification for admins',
    });
  }
  if (subject.via === 'token') {
    // P10-SEC-002: token callers cannot be challenged interactively, so the token must have been
    // minted by a session that passed the challenge under the user's *current* enrollment.
    // Tokens created before the user enrolled (or before a re-enrollment) are refused until
    // they are re-issued.
    const minted = subject.apiToken?.mfaVerifiedAt ?? null;
    if (!minted || minted.getTime() < subject.user.totpEnabledAt.getTime()) {
      throw new AppError('LSE-AUTH-012', {
        devMessage:
          'this API token was created without two-step verification; create a new token from a verified session',
        action: null,
      });
    }
    return;
  }
  if (subject.via !== 'session') return;
  if (!subject.authSession?.mfaVerifiedAt) {
    throw new AppError('LSE-AUTH-012', {
      devMessage: 'this session has not passed the two-step challenge yet',
    });
  }
}

async function enforceSsoOnly(
  ctx: AppContext,
  subject: OrgAccessSubject,
  org: Organization,
  role: Role,
): Promise<void> {
  if (!ctx.featureFlags.isEnabled('sso_oidc', org)) return;
  if (subject.via !== 'session' && subject.via !== 'token') return;
  const config = await orgSecurityConfig(ctx, org.id);
  const required = ssoRequiredFor(
    {
      enabled: config.ssoEnabled,
      enforce: config.ssoEnforce,
      allowOwnerBypass: config.allowOwnerBypass,
    },
    role,
    subject.user.email,
    config.verifiedDomains,
  );
  if (!required) return;
  // P10-SEC-002: the credential must carry assurance from the org's *current* connection. A
  // session from a deleted/replaced connection, or a PAT minted outside SSO (e.g. before
  // enforcement was switched on), no longer satisfies the policy.
  const active = config.ssoConnectionId;
  if (active !== null) {
    if (
      subject.via === 'session' &&
      subject.authSession?.ssoOrgId === org.id &&
      subject.authSession.ssoConnectionId === active
    ) {
      return;
    }
    if (subject.via === 'token' && subject.apiToken?.ssoConnectionId === active) return;
  }
  authEvent(ctx, 'sso_failed');
  throw new AppError('LSE-AUTH-006', {
    devMessage:
      subject.via === 'token'
        ? 'this organization requires SSO; create a new API token from a session signed in through its identity provider'
        : 'this organization requires signing in through its identity provider',
  });
}

/**
 * Throws LSE-ORG-010 (IP not allowed), LSE-AUTH-012 (2FA required) or LSE-AUTH-006
 * (org requires SSO). `org` may be the row or its id.
 */
export async function enforceOrgAccess(
  ctx: AppContext,
  subject: OrgAccessSubject,
  org: Organization | string,
  membership: OrgMember,
): Promise<void> {
  if (subject.via === 'internal') return;
  const row =
    typeof org === 'string'
      ? await ctx.prisma.organization.findUnique({ where: { id: org } })
      : org;
  if (!row) return;
  await enforceIpAllowlist(ctx, subject, row);
  enforceAdminTwoFactor(ctx, subject, row, membership.role);
  await enforceSsoOnly(ctx, subject, row, membership.role);
}

// ---- session-wide policy ---------------------------------------------------------------------

const ME_PATH = `${API_PREFIX}/users/me`;

/**
 * Paths a user with an unverified session may still reach: the whole auth surface (CSRF token,
 * sign-out, the challenge itself), their own profile and their own 2FA endpoints. Everything
 * else answers LSE-AUTH-012 so the web app can redirect to `/auth/2fa`.
 */
export function isMfaExemptPath(method: string, path: string): boolean {
  if (path.startsWith(`${API_PREFIX}/auth/`)) return true;
  if (path.startsWith(`${ME_PATH}/2fa`)) return true;
  if (path === ME_PATH && method === 'GET') return true;
  if (path === `${API_PREFIX}/feature-flags`) return true;
  return false;
}

/**
 * Session-wide policy after authentication: a user who enabled 2FA must verify every new
 * cookie session. Token requests are not challenged.
 */
export async function enforceSessionPolicy(ctx: AppContext, req: Request): Promise<void> {
  const auth = req.auth;
  if (!auth || auth.via !== 'session' || !auth.session) return;
  if (!auth.user.totpEnabledAt) return;
  if (auth.session.mfaVerifiedAt) return;
  if (!ctx.featureFlags.isEnabled('admin_2fa')) return;
  const path = req.originalUrl.split('?')[0] ?? req.path;
  if (isMfaExemptPath(req.method, path)) return;
  throw new AppError('LSE-AUTH-012', {
    devMessage: 'this session has not passed the two-step challenge yet',
  });
}

/** True when the request's session still needs the 2FA challenge (used by `UserDto`). */
export function sessionNeedsMfa(
  user: Pick<User, 'totpEnabledAt'>,
  session: Pick<AuthSession, 'mfaVerifiedAt'> | undefined,
): boolean {
  if (!user.totpEnabledAt) return false;
  if (!session) return false;
  return session.mfaVerifiedAt === null;
}
