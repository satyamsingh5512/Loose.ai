/**
 * Fine-grained API token scopes (spec §8.15). Mount after `requireAuth(ctx)`:
 *
 *   r.post('/', requireAuth(ctx), requireScope('runs:write'), …)
 *
 * Cookie (browser) sessions are not scoped and always pass. Token requests must carry EVERY
 * listed scope, else LSE-ORG-002 (same code the existing session/org token checks use).
 * Scopes do not imply each other (`runs:write` does not grant `runs:read`).
 */
import type { RequestHandler } from 'express';
import type { ApiToken } from '@prisma/client';
import type { ApiTokenScope } from '@loose/shared';
import { AppError } from '../lib/errors';

type Scoped = Pick<ApiToken, 'scopes'>;

export function tokenHasScopes(token: Scoped, needed: readonly ApiTokenScope[]): boolean {
  return needed.every((s) => token.scopes.includes(s));
}

function missingScopeError(token: Scoped, needed: readonly ApiTokenScope[]): AppError {
  const missing = needed.filter((s) => !token.scopes.includes(s));
  return new AppError('LSE-ORG-002', {
    devMessage: `API token lacks ${missing.join(', ')}`,
  });
}

/** Service-level check for code paths that are not behind a route (e.g. runs.service). */
export function assertScopes(
  caller: { apiToken?: Scoped | undefined },
  ...needed: ApiTokenScope[]
): void {
  const token = caller.apiToken;
  if (token && !tokenHasScopes(token, needed)) throw missingScopeError(token, needed);
}

export function requireScope(...needed: [ApiTokenScope, ...ApiTokenScope[]]): RequestHandler {
  return (req, _res, next) => {
    const token = req.auth?.apiToken;
    if (token && !tokenHasScopes(token, needed)) throw missingScopeError(token, needed);
    next();
  };
}
