/**
 * WebSocket upgrade authentication (spec §11): `Authorization: Bearer loose_pat_…`
 * (headless) or the `loose_session` cookie. Cookie auth additionally requires
 * `Origin` == APP_URL's origin (cross-site WebSocket hijacking protection).
 */
import type { IncomingMessage } from 'node:http';
import { PAT_PREFIX, SESSION_COOKIE } from '@loose/shared';
import type { AppContext } from '../context';
import { sha256Hex } from '../lib/crypto';
import { AppError } from '../lib/errors';
import { clientIpFromUpgrade } from '../lib/net/clientIp';
import { bearerToken } from '../middleware/requireAuth';
import { loadSessionForParticipant, type Caller } from '../services/sessionLifecycle.service';

export function parseCookieHeader(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i <= 0) continue;
    const k = part.slice(0, i).trim();
    let v = part.slice(i + 1).trim();
    if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
    try {
      out[k] = decodeURIComponent(v);
    } catch {
      out[k] = v;
    }
  }
  return out;
}

export type UpgradeAuthResult =
  | { ok: true; caller: Caller }
  | { ok: false; reason: 'no_credentials' | 'bad_token' | 'bad_origin' | 'bad_session' };

export async function authenticateUpgrade(
  ctx: AppContext,
  req: IncomingMessage,
): Promise<UpgradeAuthResult> {
  // Phase 10: honour TRUST_PROXY like Express' req.ip (IP allowlists).
  const ip = clientIpFromUpgrade(req, ctx.env.TRUST_PROXY);
  const bearer = bearerToken(req.headers.authorization);
  if (bearer !== undefined) {
    if (!bearer.startsWith(PAT_PREFIX)) return { ok: false, reason: 'bad_token' };
    const row = await ctx.prisma.apiToken.findUnique({
      where: { hash: sha256Hex(bearer) },
      include: { user: true },
    });
    if (!row || (row.expiresAt && row.expiresAt.getTime() <= Date.now())) {
      return { ok: false, reason: 'bad_token' };
    }
    const { user, ...apiToken } = row;
    return { ok: true, caller: { user, apiToken, ip } };
  }
  const token = parseCookieHeader(req.headers.cookie)[SESSION_COOKIE];
  if (!token) return { ok: false, reason: 'no_credentials' };
  const origin = req.headers.origin;
  if (!origin || origin !== new URL(ctx.env.APP_URL).origin) {
    return { ok: false, reason: 'bad_origin' };
  }
  const result = await ctx.sessions.validate(token);
  if (!result) return { ok: false, reason: 'bad_session' };
  return { ok: true, caller: { user: result.user, ip, authSession: result.session } };
}

/**
 * P10-SEC-003 / REAUDIT-006: reloads the caller's FULL live credential — user row, cookie
 * session / API token row (including the SSO / 2FA assurance columns `ssoOrgId`,
 * `ssoConnectionId`, `mfaVerifiedAt`) — so an established socket never keeps authorizing with
 * the assurance it had at upgrade time. Returns null when the user, cookie session or API token
 * is gone, expired or no longer belongs to the user. Throws on infrastructure errors (the
 * gateway closes such sockets with 1013).
 */
export async function refreshCaller(
  ctx: AppContext,
  caller: Caller,
  now: number = Date.now(),
): Promise<Caller | null> {
  // A connection always carries one of the two (see `authenticateUpgrade`).
  if (!caller.apiToken && !caller.authSession) return null;
  const [user, apiToken, authSession] = await Promise.all([
    ctx.prisma.user.findUnique({ where: { id: caller.user.id } }),
    caller.apiToken
      ? ctx.prisma.apiToken.findFirst({
          where: { id: caller.apiToken.id, userId: caller.user.id },
        })
      : null,
    caller.authSession
      ? ctx.prisma.authSession.findFirst({
          where: { id: caller.authSession.id, userId: caller.user.id },
        })
      : null,
  ]);
  if (!user) return null;
  if (caller.apiToken && (!apiToken || (apiToken.expiresAt && apiToken.expiresAt.getTime() <= now)))
    return null;
  if (caller.authSession && (!authSession || authSession.expiresAt.getTime() <= now)) return null;
  return {
    user,
    ...(apiToken ? { apiToken } : {}),
    ...(authSession ? { authSession } : {}),
    ...(caller.ip !== undefined ? { ip: caller.ip } : {}),
  };
}

/**
 * Strict boolean form of `refreshCaller`: false when the credential is gone/expired OR its live
 * assurance / scope columns differ from the cached caller (REAUDIT-006: a caller object must not
 * be trusted after the org's IdP or the user's 2FA changed underneath it).
 */
export async function callerStillValid(
  ctx: AppContext,
  caller: Caller,
  now: number = Date.now(),
): Promise<boolean> {
  const fresh = await refreshCaller(ctx, caller, now);
  if (!fresh) return false;
  const time = (d: Date | null | undefined) => d?.getTime() ?? null;
  if (caller.authSession && fresh.authSession) {
    const [a, b] = [caller.authSession, fresh.authSession];
    if (
      a.ssoOrgId !== b.ssoOrgId ||
      a.ssoConnectionId !== b.ssoConnectionId ||
      time(a.mfaVerifiedAt) !== time(b.mfaVerifiedAt)
    )
      return false;
  }
  if (caller.apiToken && fresh.apiToken) {
    const [a, b] = [caller.apiToken, fresh.apiToken];
    if (
      a.orgId !== b.orgId ||
      a.ssoConnectionId !== b.ssoConnectionId ||
      time(a.mfaVerifiedAt) !== time(b.mfaVerifiedAt) ||
      a.scopes.join(' ') !== b.scopes.join(' ')
    )
      return false;
  }
  return time(caller.user.totpEnabledAt) === time(fresh.user.totpEnabledAt);
}

export type WsRevalidation =
  | { state: 'ok'; caller: Caller }
  /** Credential gone/expired or its SSO/2FA assurance no longer satisfies the org: close 4401. */
  | { state: 'revoked'; code: string }
  /** Still signed in, but no longer allowed into the joined session (removed member, IP allowlist): close 4403. */
  | { state: 'forbidden'; code: string };

/**
 * REAUDIT-006: what the gateway runs periodically, before state-changing commands and on every
 * `policy_changed` event. Reloads the full credential (`refreshCaller`) and, for a socket that
 * joined a session, re-runs the same participant + org access policy as HTTP
 * (`loadSessionForParticipant` → `membershipFor` → `enforceOrgAccess`: IP allowlist, enforced
 * admin 2FA, enforced SSO against the org's *current* connection). Throws on non-policy errors.
 */
export async function revalidateWsCaller(
  ctx: AppContext,
  caller: Caller,
  sessionId: string | undefined,
  now: number = Date.now(),
): Promise<WsRevalidation> {
  const fresh = await refreshCaller(ctx, caller, now);
  if (!fresh) return { state: 'revoked', code: 'LSE-WS-001' };
  if (sessionId) {
    try {
      await loadSessionForParticipant(ctx, fresh, sessionId);
    } catch (err) {
      if (!(err instanceof AppError)) throw err;
      // LSE-AUTH-006 (SSO required) / LSE-AUTH-012 (2FA required): the credential no longer
      // carries the assurance the org requires — the user must sign in again.
      if (err.code.startsWith('LSE-AUTH-')) {
        return { state: 'revoked', code: err.code };
      }
      if (err.code.startsWith('LSE-SYS-')) throw err;
      return { state: 'forbidden', code: err.code };
    }
  }
  return { state: 'ok', caller: fresh };
}
