/**
 * Authentication middleware.
 * - `Authorization: Bearer loose_pat_…` → personal API token (LSE-AUTH-007 if bad)
 * - otherwise the `loose_session` cookie → Lucia-style session (LSE-AUTH-001)
 */
import type { Request, RequestHandler, Response } from 'express';
import { PAT_PREFIX, SESSION_COOKIE } from '@loose/shared';
import type { AppContext } from '../context';
import { clearSessionCookie, setSessionCookie } from '../lib/cookies';
import { sha256Hex } from '../lib/crypto';
import { AppError } from '../lib/errors';
import { enforceSessionPolicy } from '../services/identity/accessPolicy';

export interface RequireAuthOptions {
  /** Allow personal API tokens (default true). Token/key management is session-only. */
  allowToken?: boolean;
}

export function bearerToken(header: string | undefined): string | undefined {
  if (!header) return undefined;
  const m = /^Bearer\s+(\S+)\s*$/i.exec(header);
  return m?.[1];
}

/** Attach `req.auth` from the session cookie if it is valid (sliding renewal). */
export async function attachSession(ctx: AppContext, req: Request, res: Response): Promise<void> {
  if (req.auth) return;
  // A request that presents an Authorization header is a token request; never
  // fall back to (or act on) the cookie session for it. This keeps the CSRF
  // exemption for bearer requests from reaching cookie-authenticated actions.
  if (req.headers.authorization) return;
  const token = req.cookies?.[SESSION_COOKIE] as string | undefined;
  if (!token) return;
  const result = await ctx.sessions.validate(token);
  if (!result) {
    clearSessionCookie(res, ctx.env);
    return;
  }
  if (result.fresh) setSessionCookie(res, ctx.env, token, result.session.expiresAt);
  req.auth = { user: result.user, via: 'session', session: result.session };
}

async function attachToken(ctx: AppContext, req: Request, bearer: string): Promise<void> {
  if (!bearer.startsWith(PAT_PREFIX)) {
    throw new AppError('LSE-AUTH-007', { devMessage: 'Unrecognised bearer token format' });
  }
  const row = await ctx.prisma.apiToken.findUnique({
    where: { hash: sha256Hex(bearer) },
    include: { user: true },
  });
  if (!row || (row.expiresAt && row.expiresAt.getTime() <= Date.now())) {
    throw new AppError('LSE-AUTH-007', { devMessage: row ? 'Token expired' : 'Unknown token' });
  }
  // Best-effort; a failure here must not block the request.
  void ctx.prisma.apiToken
    .update({ where: { id: row.id }, data: { lastUsedAt: new Date() } })
    .catch((err: unknown) => ctx.logger.warn({ err }, 'failed to update token lastUsedAt'));
  const { user, ...apiToken } = row;
  req.auth = { user, via: 'token', apiToken };
}

export function requireAuth(ctx: AppContext, opts: RequireAuthOptions = {}): RequestHandler {
  const allowToken = opts.allowToken ?? true;
  return async (req, res, next) => {
    const bearer = bearerToken(req.headers.authorization);
    if (bearer !== undefined) {
      if (!allowToken) {
        throw new AppError('LSE-AUTH-001', {
          devMessage: 'This endpoint requires a browser session; API tokens are not accepted',
        });
      }
      await attachToken(ctx, req, bearer);
      await enforceSessionPolicy(ctx, req);
      return next();
    }
    await attachSession(ctx, req, res);
    if (!req.auth) throw new AppError('LSE-AUTH-001', { devMessage: 'No valid session' });
    // Phase 10 (W1): e.g. users with 2FA must verify each new session (LSE-AUTH-012).
    await enforceSessionPolicy(ctx, req);
    next();
  };
}

/** Like requireAuth but anonymous callers pass through (req.auth undefined). */
export function optionalAuth(ctx: AppContext): RequestHandler {
  return async (req, res, next) => {
    if (bearerToken(req.headers.authorization) === undefined) await attachSession(ctx, req, res);
    next();
  };
}
