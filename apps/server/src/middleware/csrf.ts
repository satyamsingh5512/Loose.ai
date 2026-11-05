/**
 * CSRF protection — signed double-submit cookie.
 * The server issues `loose_csrf = <random>.<hmac(random)>` (readable by JS);
 * state-changing requests must echo it in `x-csrf-token`. Requests carrying a
 * Bearer token are exempt (browsers can't attach that header cross-site
 * without a CORS preflight, which we never grant).
 */
import type { RequestHandler, Response } from 'express';
import { CSRF_COOKIE, CSRF_HEADER, PAT_PREFIX } from '@loose/shared';
import type { Env } from '../config/env';
import { setCsrfCookie } from '../lib/cookies';
import { hmacSha256, randomToken, safeEqual } from '../lib/crypto';
import { AppError } from '../lib/errors';
import { bearerToken } from './requireAuth';

const UNSAFE = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export function createCsrfToken(secret: string): string {
  const nonce = randomToken(24);
  return `${nonce}.${hmacSha256(`csrf:${secret}`, nonce)}`;
}

export function isValidCsrfToken(secret: string, token: unknown): token is string {
  if (typeof token !== 'string') return false;
  const [nonce, sig, extra] = token.split('.');
  if (!nonce || !sig || extra !== undefined) return false;
  return safeEqual(sig, hmacSha256(`csrf:${secret}`, nonce));
}

/** Returns the current valid CSRF token, issuing a new cookie if needed. */
export function ensureCsrfCookie(env: Env, existing: unknown, res: Response): string {
  if (isValidCsrfToken(env.SESSION_SECRET, existing)) return existing;
  const token = createCsrfToken(env.SESSION_SECRET);
  setCsrfCookie(res, env, token);
  return token;
}

export interface CsrfOptions {
  /** Paths (relative to the mount point) that skip the check, e.g. inbound webhooks. */
  exemptPaths?: string[];
}

export function csrfProtection(env: Env, opts: CsrfOptions = {}): RequestHandler {
  const exempt = new Set(opts.exemptPaths ?? []);
  return (req, res, next) => {
    const cookie = req.cookies?.[CSRF_COOKIE] as unknown;
    if (!UNSAFE.has(req.method)) {
      // Issue the cookie on safe requests so the SPA always has one.
      res.locals.csrfToken = ensureCsrfCookie(env, cookie, res);
      return next();
    }
    if (exempt.has(req.path)) return next();
    // Only personal-API-token requests are exempt; cookie sessions are ignored
    // whenever an Authorization header is present (see attachSession).
    if (bearerToken(req.headers.authorization)?.startsWith(PAT_PREFIX)) return next();
    const header = req.get(CSRF_HEADER);
    if (!isValidCsrfToken(env.SESSION_SECRET, cookie) || !safeEqual(header, cookie)) {
      return next(
        new AppError('LSE-AUTH-002', {
          status: 403,
          title: 'Security check failed',
          userMessage: 'Your session security check failed. Reload the page and try again.',
          action: { type: 'retry', label: 'Reload' },
          devMessage: header ? 'CSRF token mismatch' : 'Missing CSRF token header',
        }),
      );
    }
    next();
  };
}
