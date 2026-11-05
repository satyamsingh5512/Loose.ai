/** Auth routes (spec §10.1): OAuth, session info, logout, dev login. */
import { Router, type Request, type Response } from 'express';
import { z } from 'zod';
import {
  devLoginBodySchema,
  logoutBodySchema,
  OAUTH_LINK_COOKIE,
  OAUTH_RETURN_TO_COOKIE,
  OAUTH_STATE_COOKIE,
  OAUTH_VERIFIER_COOKIE,
  oauthCallbackQuerySchema,
  oauthProviderParamsSchema,
  oauthStartQuerySchema,
  isSafeReturnTo,
  type DevLoginBody,
  type ErrorCode,
  type LogoutBody,
  type OAuthCallbackQuery,
  type OAuthProvider,
  type OAuthStartQuery,
} from '@loose/shared';
import type { User } from '@prisma/client';
import { isDevLoginEnabled } from '../config/env';
import type { AppContext } from '../context';
import {
  clearOAuthCookies,
  clearSessionCookie,
  oauthCookieOptions,
  setSessionCookie,
} from '../lib/cookies';
import { randomToken, safeEqual } from '../lib/crypto';
import { AppError, isAppError } from '../lib/errors';
import type { RateLimiters } from '../middleware/rateLimit';
import { attachSession, requireAuth } from '../middleware/requireAuth';
import { authUser } from '../middleware/requireOrg';
import { queryOf, validate } from '../middleware/validate';
import type { OAuthClients } from '../services/oauth.service';
import { findOrCreateDevUser, getUserDto, resolveOAuthUser } from '../services/user.service';

const authSessionDtoSchema = z.object({
  id: z.string(),
  current: z.boolean(),
  ip: z.string().nullable(),
  userAgent: z.string().nullable(),
  createdAt: z.date().transform((d) => d.toISOString()),
  expiresAt: z.date().transform((d) => d.toISOString()),
});

export async function startSession(ctx: AppContext, req: Request, res: Response, user: User) {
  const { token, session } = await ctx.sessions.create(user.id, {
    ip: req.ip,
    userAgent: req.get('user-agent'),
  });
  setSessionCookie(res, ctx.env, token, session.expiresAt);
  await ctx.audit.record({ actorId: user.id, action: 'auth.sign_in', target: user.id, ip: req.ip });
  return session;
}

export function authRouter(ctx: AppContext, limiters: RateLimiters, oauth: OAuthClients): Router {
  const r = Router();
  const appUrl = ctx.env.APP_URL.replace(/\/$/, '');

  r.get('/csrf', (_req, res) => {
    res.json({ data: { csrfToken: res.locals.csrfToken as string } });
  });

  r.get('/me', requireAuth(ctx), async (req, res) => {
    // Phase 10: `session` fills `mfaRequired` (this session still needs the 2FA challenge).
    res.json({ data: await getUserDto(ctx, authUser(req).id, { session: req.auth?.session }) });
  });

  r.get('/sessions', requireAuth(ctx, { allowToken: false }), async (req, res) => {
    const user = authUser(req);
    const rows = await ctx.sessions.listForUser(user.id);
    const currentId = req.auth?.session?.id;
    res.json({
      data: rows.map((s) =>
        authSessionDtoSchema.parse({ ...s, id: s.id.slice(0, 16), current: s.id === currentId }),
      ),
      nextCursor: null,
    });
  });

  r.post('/logout', validate({ body: logoutBodySchema }), async (req, res) => {
    await attachSession(ctx, req, res);
    const body = req.body as LogoutBody;
    const auth = req.auth;
    if (auth?.session) {
      if (body.all) await ctx.sessions.invalidateAllForUser(auth.user.id);
      else await ctx.sessions.invalidate(auth.session.id);
      await ctx.audit.record({
        actorId: auth.user.id,
        action: body.all ? 'auth.sign_out_all' : 'auth.sign_out',
        target: auth.user.id,
        ip: req.ip,
      });
    }
    clearSessionCookie(res, ctx.env);
    res.json({ data: { ok: true } });
  });

  r.post('/logout-all', requireAuth(ctx, { allowToken: false }), async (req, res) => {
    const user = authUser(req);
    await ctx.sessions.invalidateAllForUser(user.id);
    await ctx.audit.record({
      actorId: user.id,
      action: 'auth.sign_out_all',
      target: user.id,
      ip: req.ip,
    });
    clearSessionCookie(res, ctx.env);
    res.json({ data: { ok: true } });
  });

  // ------------------------------------------------------------------------
  // DEV ONLY. There are no OAuth credentials in local development, so this
  // route signs in (creating if needed) any email. It is mounted ONLY when
  // NODE_ENV !== 'production' AND DEV_LOGIN_ENABLED === 'true'. A test asserts
  // it is absent (404) in production.
  // ------------------------------------------------------------------------
  if (isDevLoginEnabled(ctx.env)) {
    r.post(
      '/dev-login',
      limiters.auth,
      validate({ body: devLoginBodySchema }),
      async (req, res) => {
        const body = req.body as DevLoginBody;
        const user = await findOrCreateDevUser(ctx, body.email, body.name);
        await startSession(ctx, req, res, user);
        res.json({ data: await getUserDto(ctx, user.id) });
      },
    );
  }

  // ---- OAuth start ------------------------------------------------------------
  r.get(
    '/:provider',
    limiters.auth,
    validate({ params: oauthProviderParamsSchema, query: oauthStartQuerySchema }),
    async (req, res) => {
      const provider = req.params.provider as OAuthProvider;
      const client = oauth[provider];
      if (!client) {
        throw new AppError('LSE-AUTH-004', { devMessage: `${provider} provider not configured` });
      }
      const q = queryOf<OAuthStartQuery>(req);
      const cookieOpts = oauthCookieOptions(ctx.env);
      if (q.link) {
        await attachSession(ctx, req, res);
        if (!req.auth) {
          res.redirect(302, `${appUrl}/auth/callback/${provider}?error=LSE-AUTH-001`);
          return;
        }
        res.cookie(OAUTH_LINK_COOKIE, req.auth.user.id, cookieOpts);
      } else {
        res.clearCookie(OAUTH_LINK_COOKIE, { ...cookieOpts, maxAge: undefined });
      }
      const state = randomToken(32);
      const verifier = client.usesPkce ? randomToken(32) : undefined;
      res.cookie(OAUTH_STATE_COOKIE, state, cookieOpts);
      if (verifier) res.cookie(OAUTH_VERIFIER_COOKIE, verifier, cookieOpts);
      res.cookie(OAUTH_RETURN_TO_COOKIE, q.returnTo ?? '/', cookieOpts);
      res.redirect(302, client.authorizationUrl(state, verifier).toString());
    },
  );

  // ---- OAuth callback -------------------------------------------------------------
  r.get(
    '/:provider/callback',
    limiters.auth,
    validate({ params: oauthProviderParamsSchema }),
    async (req, res) => {
      const provider = req.params.provider as OAuthProvider;
      const fail = (code: ErrorCode, devMessage: string) => {
        ctx.logger.warn(
          { requestId: req.requestId, provider, code, devMessage },
          'oauth callback failed',
        );
        clearOAuthCookies(res, ctx.env);
        res.redirect(302, `${appUrl}/auth/callback/${provider}?error=${code}`);
      };
      const client = oauth[provider];
      if (!client) return fail('LSE-AUTH-004', `${provider} provider not configured`);

      const parsed = oauthCallbackQuerySchema.safeParse(req.query);
      if (!parsed.success) return fail('LSE-AUTH-002', 'malformed callback query');
      const q: OAuthCallbackQuery = parsed.data;
      const cookies = (req.cookies ?? {}) as Record<string, string | undefined>;

      if (q.error) {
        return fail(
          q.error === 'access_denied' ? 'LSE-AUTH-003' : 'LSE-AUTH-004',
          `provider error ${q.error}`,
        );
      }
      if (!q.state || !safeEqual(q.state, cookies[OAUTH_STATE_COOKIE])) {
        return fail('LSE-AUTH-002', 'state mismatch');
      }
      if (!q.code) return fail('LSE-AUTH-002', 'missing code');
      const verifier = cookies[OAUTH_VERIFIER_COOKIE];
      if (client.usesPkce && !verifier) return fail('LSE-AUTH-002', 'missing PKCE verifier');
      const returnToRaw = cookies[OAUTH_RETURN_TO_COOKIE];
      const returnTo = isSafeReturnTo(returnToRaw) ? returnToRaw : '/';

      let linkToUserId: string | undefined;
      const linkCookie = cookies[OAUTH_LINK_COOKIE];
      if (linkCookie) {
        await attachSession(ctx, req, res);
        if (!req.auth || req.auth.user.id !== linkCookie) {
          return fail('LSE-AUTH-002', 'link flow without matching session');
        }
        linkToUserId = req.auth.user.id;
      }

      try {
        const tokens = await client.exchangeCode(q.code, verifier);
        const profile = await client.fetchProfile(tokens);
        const { user } = await resolveOAuthUser(ctx, { provider, profile, tokens, linkToUserId });
        if (!linkToUserId) await startSession(ctx, req, res, user);
        clearOAuthCookies(res, ctx.env);
        res.redirect(302, `${appUrl}${returnTo}`);
      } catch (err) {
        if (isAppError(err) && err.code.startsWith('LSE-AUTH-'))
          return fail(err.code, err.devMessage ?? err.code);
        ctx.logger.error({ err, requestId: req.requestId }, 'oauth callback error');
        return fail('LSE-AUTH-004', 'unexpected error');
      }
    },
  );

  return r;
}
