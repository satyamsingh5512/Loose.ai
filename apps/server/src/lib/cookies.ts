/** Cookie helpers. All auth cookies: SameSite=Lax, Secure in production. */
import type { CookieOptions, Response } from 'express';
import {
  CSRF_COOKIE,
  OAUTH_LINK_COOKIE,
  OAUTH_RETURN_TO_COOKIE,
  OAUTH_STATE_COOKIE,
  OAUTH_STATE_TTL_MS,
  OAUTH_VERIFIER_COOKIE,
  SESSION_COOKIE,
  API_PREFIX,
} from '@loose/shared';
import type { Env } from '../config/env';

type CookieEnv = Pick<Env, 'NODE_ENV'>;

const secure = (env: CookieEnv) => env.NODE_ENV === 'production';

export function sessionCookieOptions(env: CookieEnv, expiresAt: Date): CookieOptions {
  return { httpOnly: true, sameSite: 'lax', secure: secure(env), path: '/', expires: expiresAt };
}

export function setSessionCookie(res: Response, env: CookieEnv, token: string, expiresAt: Date) {
  res.cookie(SESSION_COOKIE, token, sessionCookieOptions(env, expiresAt));
}

export function clearSessionCookie(res: Response, env: CookieEnv) {
  res.clearCookie(SESSION_COOKIE, {
    httpOnly: true,
    sameSite: 'lax',
    secure: secure(env),
    path: '/',
  });
}

/** Readable by JS (double-submit CSRF). */
export function setCsrfCookie(res: Response, env: CookieEnv, token: string) {
  res.cookie(CSRF_COOKIE, token, {
    httpOnly: false,
    sameSite: 'lax',
    secure: secure(env),
    path: '/',
  });
}

const OAUTH_COOKIE_PATH = `${API_PREFIX}/auth`;

export function oauthCookieOptions(env: CookieEnv): CookieOptions {
  return {
    httpOnly: true,
    sameSite: 'lax',
    secure: secure(env),
    path: OAUTH_COOKIE_PATH,
    maxAge: OAUTH_STATE_TTL_MS,
  };
}

export const OAUTH_COOKIES = [
  OAUTH_STATE_COOKIE,
  OAUTH_VERIFIER_COOKIE,
  OAUTH_RETURN_TO_COOKIE,
  OAUTH_LINK_COOKIE,
] as const;

export function clearOAuthCookies(res: Response, env: CookieEnv) {
  for (const name of OAUTH_COOKIES) {
    res.clearCookie(name, {
      httpOnly: true,
      sameSite: 'lax',
      secure: secure(env),
      path: OAUTH_COOKIE_PATH,
    });
  }
}
