/**
 * Identity routes (Phase 10, spec §8.20) — OWNED BY W1. Contract: phase10-design.md §5.2.
 *
 * - `/api/v1/scim/v2/*`   SCIM 2.0, mounted before cookies/CSRF (bearer tokens, scim+json)
 * - `/auth/sso/*`         OIDC sign-in (discover, start, callback; SAML behind `sso_saml`)
 * - `/auth/2fa/verify`    two-step challenge for the current cookie session
 * - `/users/me/2fa/*`     personal TOTP enrollment / recovery codes
 * - `/orgs/:orgId/identity/*` SSO connection, verified domains, SCIM tokens, security settings
 *
 * All admin surfaces are session-only (`allowToken: false`): a leaked read-only PAT must not be
 * able to read or change an org's identity configuration.
 */
import express, {
  Router,
  type Express,
  type Request,
  type RequestHandler,
  type Response,
} from 'express';
import {
  API_PREFIX,
  OAUTH_RETURN_TO_COOKIE,
  SCIM_BASE_PATH,
  SCIM_CONTENT_TYPE,
  SESSION_COOKIE,
  SSO_NONCE_COOKIE,
  SSO_ORG_COOKIE,
  SSO_STATE_COOKIE,
  SSO_VERIFIER_COOKIE,
  createOrgDomainBodySchema,
  createScimTokenBodySchema,
  isSafeReturnTo,
  resourceIdParamsSchema,
  ssoDiscoverQuerySchema,
  ssoParamsSchema,
  ssoStartQuerySchema,
  ssoCallbackQuerySchema,
  twoFactorCodeBodySchema,
  twoFactorVerifyBodySchema,
  twoFactorVerifyResponseSchema,
  updateOrgSecurityBodySchema,
  upsertSsoConnectionBodySchema,
  type CreateOrgDomainBody,
  type CreateScimTokenBody,
  type ErrorCode,
  type SsoCallbackQuery,
  type SsoDiscoverQuery,
  type SsoStartQuery,
  type TwoFactorCodeBody,
  type TwoFactorVerifyBody,
  type UpdateOrgSecurityBody,
  type UpsertSsoConnectionBody,
} from '@loose/shared';
import type { Organization, ScimToken } from '@prisma/client';
import type { AppContext } from '../context';
import { oauthCookieOptions, setSessionCookie } from '../lib/cookies';
import { AppError, isAppError } from '../lib/errors';
import { publishPolicyChanged } from '../lib/events/revocations';
import { requireFeature } from '../lib/featureFlags';
import { normalizeClientIp } from '../lib/net/clientIp';
import { idempotency } from '../middleware/idempotency';
import type { RateLimiters } from '../middleware/rateLimit';
import { requireAuth } from '../middleware/requireAuth';
import { authUser, orgOf, requireRole } from '../middleware/requireOrg';
import { queryOf, validate } from '../middleware/validate';
import { invalidateOrgSecurityCache } from '../services/identity/accessPolicy';
import {
  createOrgDomain,
  deleteOrgDomain,
  listOrgDomains,
  verifyOrgDomain,
} from '../services/identity/domains.service';
import {
  assertScimWritable,
  authenticateScim,
  resourceTypes,
  schemas,
  scimCreateGroup,
  scimCreateUser,
  scimDeleteGroup,
  scimDeleteUser,
  scimFindGroup,
  scimFindUser,
  scimGroupResource,
  scimListGroups,
  scimListResponse,
  scimListUsers,
  scimMemberIds,
  scimPatchGroup,
  scimPatchUser,
  scimReplaceGroup,
  scimReplaceUser,
  scimUserResource,
  serviceProviderConfig,
  ScimError,
  createScimToken,
  listScimTokens,
  revokeScimToken,
  type ScimGroupRow,
} from '../services/identity/scim.service';
import { orgSecurityDto, updateOrgSecurity } from '../services/identity/security.service';
import {
  beginSso,
  completeSso,
  deleteSsoConnection,
  discoverSso,
  getSsoConnectionDto,
  testSsoConnection,
  upsertSsoConnection,
} from '../services/identity/sso.service';
import {
  activateEnrollment,
  completeChallenge,
  disableTwoFactor,
  regenerateRecoveryCodes,
  startEnrollment,
  twoFactorStatus,
} from '../services/identity/twoFactor.service';
import type { Actor } from '../services/org.service';

const SCIM_BODY_LIMIT = '1mb';

function actorOf(req: Request): Actor {
  return { userId: authUser(req).id, role: orgOf(req).membership.role, ip: clientIp(req) };
}

function clientIp(req: Request): string | undefined {
  return normalizeClientIp(req.ip);
}

// ---------------------------------------------------------------------------------------------
// SCIM 2.0
// ---------------------------------------------------------------------------------------------

interface ScimLocals {
  token: ScimToken;
  org: Organization;
}

function scimAuthOf(res: Response): ScimLocals {
  const scim = res.locals.scim as ScimLocals | undefined;
  if (!scim) throw new ScimError(401, 'Unauthenticated.', undefined, 'LSE-AUTH-007');
  return scim;
}

function sendScim(res: Response, status: number, body: Record<string, unknown>): void {
  res.status(status).type(SCIM_CONTENT_TYPE).send(JSON.stringify(body));
}

function scimBody(req: Request): Record<string, unknown> {
  const body = req.body as unknown;
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new ScimError(400, 'A JSON object body is required.', 'invalidSyntax', 'LSE-VAL-001');
  }
  return body as Record<string, unknown>;
}

/** Wrap an async SCIM handler so rejections reach the SCIM error middleware. */
function scimHandler(fn: (req: Request, res: Response) => Promise<void>): RequestHandler {
  return (req, res, next) => {
    fn(req, res).catch(next);
  };
}

/** `/api/v1/scim/v2/*` — mounted BEFORE cookies/CSRF (bearer SCIM tokens, scim+json bodies). */
export function mountIdentityRawRoutes(app: Express, ctx: AppContext): void {
  const scim = Router();
  scim.use(
    express.json({
      // Okta sends `application/scim+json`, Entra ID plain `application/json`.
      type: [SCIM_CONTENT_TYPE, 'application/json'],
      limit: SCIM_BODY_LIMIT,
    }),
  );
  scim.use((req, res, next) => {
    authenticateScim(ctx, req.headers.authorization)
      .then((auth) => {
        assertScimWritable(auth.org, req.method);
        res.locals.scim = auth;
        next();
      })
      .catch(next);
  });

  scim.get(
    '/ServiceProviderConfig',
    scimHandler(async (_req, res) => {
      sendScim(res, 200, serviceProviderConfig(ctx));
    }),
  );
  scim.get(
    '/ResourceTypes',
    scimHandler(async (_req, res) => {
      sendScim(res, 200, resourceTypes(ctx));
    }),
  );
  scim.get(
    '/Schemas',
    scimHandler(async (_req, res) => {
      sendScim(res, 200, schemas());
    }),
  );

  // ---- Users ---------------------------------------------------------------------------
  scim.get(
    '/Users',
    scimHandler(async (req, res) => {
      const { org } = scimAuthOf(res);
      const { rows, total, startIndex } = await scimListUsers(ctx, org.id, req.query);
      sendScim(
        res,
        200,
        scimListResponse(
          rows.map((r) => scimUserResource(ctx, r)),
          total,
          startIndex,
        ),
      );
    }),
  );

  scim.post(
    '/Users',
    scimHandler(async (req, res) => {
      const { org } = scimAuthOf(res);
      const row = await scimCreateUser(ctx, org, scimBody(req));
      const resource = scimUserResource(ctx, row);
      const meta = resource.meta as { location?: string } | undefined;
      if (meta?.location) res.setHeader('Location', meta.location);
      sendScim(res, 201, resource);
    }),
  );

  scim.get(
    '/Users/:id',
    scimHandler(async (req, res) => {
      const { org } = scimAuthOf(res);
      sendScim(
        res,
        200,
        scimUserResource(ctx, await scimFindUser(ctx, org.id, req.params.id as string)),
      );
    }),
  );

  scim.put(
    '/Users/:id',
    scimHandler(async (req, res) => {
      const { org } = scimAuthOf(res);
      const row = await scimReplaceUser(ctx, org, req.params.id as string, scimBody(req));
      sendScim(res, 200, scimUserResource(ctx, row));
    }),
  );

  scim.patch(
    '/Users/:id',
    scimHandler(async (req, res) => {
      const { org } = scimAuthOf(res);
      const row = await scimPatchUser(ctx, org, req.params.id as string, scimBody(req));
      sendScim(res, 200, scimUserResource(ctx, row));
    }),
  );

  scim.delete(
    '/Users/:id',
    scimHandler(async (req, res) => {
      const { org } = scimAuthOf(res);
      await scimDeleteUser(ctx, org, req.params.id as string);
      res.status(204).end();
    }),
  );

  // ---- Groups --------------------------------------------------------------------------
  const renderGroup = async (org: Organization, row: ScimGroupRow) =>
    scimGroupResource(
      ctx,
      row,
      await scimMemberIds(
        ctx,
        org.id,
        row.members.map((m) => m.userId),
      ),
    );

  scim.get(
    '/Groups',
    scimHandler(async (req, res) => {
      const { org } = scimAuthOf(res);
      const { rows, total, startIndex } = await scimListGroups(ctx, org.id, req.query);
      const ids = await scimMemberIds(
        ctx,
        org.id,
        rows.flatMap((r) => r.members.map((m) => m.userId)),
      );
      sendScim(
        res,
        200,
        scimListResponse(
          rows.map((r) => scimGroupResource(ctx, r, ids)),
          total,
          startIndex,
        ),
      );
    }),
  );

  scim.post(
    '/Groups',
    scimHandler(async (req, res) => {
      const { org } = scimAuthOf(res);
      const row = await scimCreateGroup(ctx, org, scimBody(req));
      sendScim(res, 201, await renderGroup(org, row));
    }),
  );

  scim.get(
    '/Groups/:id',
    scimHandler(async (req, res) => {
      const { org } = scimAuthOf(res);
      sendScim(
        res,
        200,
        await renderGroup(org, await scimFindGroup(ctx, org.id, req.params.id as string)),
      );
    }),
  );

  scim.put(
    '/Groups/:id',
    scimHandler(async (req, res) => {
      const { org } = scimAuthOf(res);
      sendScim(
        res,
        200,
        await renderGroup(
          org,
          await scimReplaceGroup(ctx, org, req.params.id as string, scimBody(req)),
        ),
      );
    }),
  );

  scim.patch(
    '/Groups/:id',
    scimHandler(async (req, res) => {
      const { org } = scimAuthOf(res);
      sendScim(
        res,
        200,
        await renderGroup(
          org,
          await scimPatchGroup(ctx, org, req.params.id as string, scimBody(req)),
        ),
      );
    }),
  );

  scim.delete(
    '/Groups/:id',
    scimHandler(async (req, res) => {
      const { org } = scimAuthOf(res);
      await scimDeleteGroup(ctx, org, req.params.id as string);
      res.status(204).end();
    }),
  );

  scim.use((req, res) => {
    sendScim(res, 404, new ScimError(404, `No SCIM route for ${req.method} ${req.path}`).toBody());
  });

  // RFC 7644 error bodies (the global §16.2 envelope would confuse SCIM clients).
  scim.use(((err, req, res, next) => {
    if (res.headersSent) return next(err);
    const bodyParser = err as { type?: unknown; status?: unknown };
    const scimErr =
      err instanceof ScimError
        ? err
        : isAppError(err)
          ? new ScimError(err.status, err.userMessage, undefined, err.code)
          : typeof bodyParser.type === 'string' && typeof bodyParser.status === 'number'
            ? new ScimError(
                bodyParser.status < 500 ? bodyParser.status : 400,
                'The request body could not be parsed as SCIM JSON.',
                'invalidSyntax',
                'LSE-VAL-001',
              )
            : null;
    if (scimErr) {
      if (scimErr.looseCode) res.setHeader('x-loose-error-code', scimErr.looseCode);
      ctx.logger.warn(
        { requestId: req.requestId, status: scimErr.status, code: scimErr.looseCode },
        'scim request rejected',
      );
      sendScim(res, scimErr.status, scimErr.toBody());
      return;
    }
    ctx.logger.error({ err, requestId: req.requestId }, 'scim request failed');
    sendScim(res, 500, new ScimError(500, 'Internal error.', undefined, 'LSE-SYS-001').toBody());
  }) as express.ErrorRequestHandler);

  app.use(`${API_PREFIX}${SCIM_BASE_PATH}`, scim);
}

// ---------------------------------------------------------------------------------------------
// SSO + 2FA
// ---------------------------------------------------------------------------------------------

const SSO_COOKIES = [
  SSO_STATE_COOKIE,
  SSO_NONCE_COOKIE,
  SSO_VERIFIER_COOKIE,
  SSO_ORG_COOKIE,
] as const;

function clearSsoCookies(res: Response, ctx: AppContext): void {
  const opts = { ...oauthCookieOptions(ctx.env), maxAge: undefined };
  for (const name of [...SSO_COOKIES, OAUTH_RETURN_TO_COOKIE]) res.clearCookie(name, opts);
}

function cookiesOf(req: Request): Record<string, string | undefined> {
  return (req.cookies ?? {}) as Record<string, string | undefined>;
}

/** `/auth/sso/*`, `/auth/2fa/*`, `/users/me/2fa/*` — mounted before `/auth` and `/users`. */
export function mountIdentityApiRoutes(api: Router, ctx: AppContext, limiters: RateLimiters): void {
  const appUrl = ctx.env.APP_URL.replace(/\/$/, '');
  const sessionOnly = requireAuth(ctx, { allowToken: false });

  // ---- SSO ------------------------------------------------------------------------------
  const sso = Router();

  sso.get(
    '/discover',
    limiters.auth,
    validate({ query: ssoDiscoverQuerySchema }),
    async (req, res) => {
      const q = queryOf<SsoDiscoverQuery>(req);
      res.json({ data: await discoverSso(ctx, q.email) });
    },
  );

  sso.get(
    '/:orgSlug/start',
    limiters.auth,
    requireFeature(ctx, 'sso_oidc'),
    validate({ params: ssoParamsSchema, query: ssoStartQuerySchema }),
    async (req, res) => {
      const { orgSlug } = req.params as { orgSlug: string };
      const q = queryOf<SsoStartQuery>(req);
      const started = await beginSso(ctx, orgSlug);
      const opts = oauthCookieOptions(ctx.env);
      res.cookie(SSO_STATE_COOKIE, started.state, opts);
      res.cookie(SSO_NONCE_COOKIE, started.nonce, opts);
      res.cookie(SSO_VERIFIER_COOKIE, started.verifier, opts);
      res.cookie(SSO_ORG_COOKIE, started.orgId, opts);
      res.cookie(OAUTH_RETURN_TO_COOKIE, q.returnTo ?? '/', opts);
      res.redirect(302, started.url);
    },
  );

  sso.get(
    '/:orgSlug/callback',
    limiters.auth,
    requireFeature(ctx, 'sso_oidc'),
    validate({ params: ssoParamsSchema }),
    async (req, res) => {
      const { orgSlug } = req.params as { orgSlug: string };
      const cookies = cookiesOf(req);
      const fail = async (code: ErrorCode, devMessage: string) => {
        ctx.logger.warn(
          { requestId: req.requestId, orgSlug, code, devMessage },
          'sso callback failed',
        );
        ctx.metrics
          .counter('loose_auth_events_total', 'Authentication events', ['event'])
          .inc({ event: 'sso_failed' });
        await ctx.audit.record({
          action: 'auth.sso_sign_in_failed',
          target: orgSlug,
          meta: { code },
          ip: clientIp(req),
        });
        clearSsoCookies(res, ctx);
        res.redirect(302, `${appUrl}/auth/callback/sso?error=${code}`);
      };

      const parsed = ssoCallbackQuerySchema.safeParse(req.query);
      if (!parsed.success) return fail('LSE-AUTH-002', 'malformed callback query');
      const q: SsoCallbackQuery = parsed.data;
      if (q.error) {
        return fail(
          q.error === 'access_denied' ? 'LSE-AUTH-003' : 'LSE-AUTH-004',
          `identity provider error ${q.error}`,
        );
      }
      const returnToRaw = cookies[OAUTH_RETURN_TO_COOKIE];
      const returnTo = isSafeReturnTo(returnToRaw) ? returnToRaw : '/';
      try {
        const result = await completeSso(ctx, {
          orgSlug,
          code: q.code,
          state: q.state,
          cookies: {
            state: cookies[SSO_STATE_COOKIE],
            nonce: cookies[SSO_NONCE_COOKIE],
            verifier: cookies[SSO_VERIFIER_COOKIE],
            orgId: cookies[SSO_ORG_COOKIE],
          },
          ip: clientIp(req),
          userAgent: req.get('user-agent'),
          sessionToken: cookies[SESSION_COOKIE],
        });
        clearSsoCookies(res, ctx);
        setSessionCookie(res, ctx.env, result.token, result.session.expiresAt);
        res.redirect(302, `${appUrl}${returnTo}`);
      } catch (err) {
        if (
          isAppError(err) &&
          (err.code.startsWith('LSE-AUTH-') ||
            err.code.startsWith('LSE-ORG-') ||
            // A fail-closed audit append (e.g. JIT membership) rolled the sign-in back (P10-SEC-011).
            err.code === 'LSE-SYS-001')
        ) {
          return fail(err.code, err.devMessage ?? err.code);
        }
        ctx.logger.error({ err, requestId: req.requestId }, 'sso callback error');
        return fail('LSE-AUTH-004', 'unexpected error');
      }
    },
  );

  // SAML stays behind `sso_saml` (off): never hand-roll XML-DSig (phase10-design.md §1).
  sso.post('/:orgSlug/saml/acs', requireFeature(ctx, 'sso_saml'), () => {
    throw new AppError('LSE-SYS-007', { devMessage: 'SAML sign-in is not available' });
  });

  api.use('/auth/sso', sso);

  // ---- 2FA challenge --------------------------------------------------------------------
  const challenge = Router();
  challenge.post(
    '/verify',
    limiters.auth,
    requireFeature(ctx, 'admin_2fa'),
    sessionOnly,
    validate({ body: twoFactorVerifyBodySchema }),
    async (req, res) => {
      const auth = req.auth;
      if (!auth?.session) throw new AppError('LSE-AUTH-001', { devMessage: 'no cookie session' });
      const body = req.body as TwoFactorVerifyBody;
      const result = await completeChallenge(ctx, {
        user: auth.user,
        session: auth.session,
        code: 'code' in body ? body.code : undefined,
        recoveryCode: 'recoveryCode' in body ? body.recoveryCode : undefined,
        ip: clientIp(req),
      });
      setSessionCookie(res, ctx.env, result.sessionToken, result.sessionExpiresAt);
      res.json({
        data: twoFactorVerifyResponseSchema.parse({
          verified: true,
          recoveryCodesRemaining: result.recoveryCodesRemaining,
        }),
      });
    },
  );
  api.use('/auth/2fa', challenge);

  // ---- personal 2FA --------------------------------------------------------------------
  const me2fa = Router();
  me2fa.use(requireFeature(ctx, 'admin_2fa'), sessionOnly);

  me2fa.get('/', async (req, res) => {
    res.json({ data: await twoFactorStatus(ctx, authUser(req).id) });
  });

  me2fa.post('/enroll', limiters.auth, async (req, res) => {
    res.json({ data: await startEnrollment(ctx, authUser(req)) });
  });

  me2fa.post(
    '/activate',
    limiters.auth,
    validate({ body: twoFactorCodeBodySchema }),
    async (req, res) => {
      const data = await activateEnrollment(
        ctx,
        authUser(req),
        (req.body as TwoFactorCodeBody).code,
        req.auth?.session,
        clientIp(req),
      );
      res.json({ data });
    },
  );

  me2fa.post(
    '/disable',
    limiters.auth,
    validate({ body: twoFactorCodeBodySchema }),
    async (req, res) => {
      const result = await disableTwoFactor(
        ctx,
        authUser(req),
        (req.body as TwoFactorCodeBody).code,
        clientIp(req),
        req.auth?.session,
      );
      // P10-SEC-009: the calling session was rotated; every other session was signed out.
      if (result.sessionToken && result.sessionExpiresAt) {
        setSessionCookie(res, ctx.env, result.sessionToken, result.sessionExpiresAt);
      }
      res.status(204).end();
    },
  );

  me2fa.post(
    '/recovery-codes',
    limiters.auth,
    validate({ body: twoFactorCodeBodySchema }),
    async (req, res) => {
      const data = await regenerateRecoveryCodes(
        ctx,
        authUser(req),
        (req.body as TwoFactorCodeBody).code,
        clientIp(req),
      );
      res.json({ data });
    },
  );

  api.use('/users/me/2fa', me2fa);
}

// ---------------------------------------------------------------------------------------------
// org identity settings
// ---------------------------------------------------------------------------------------------

/**
 * The org router already authenticated the caller; this only refuses API tokens (the identity
 * surface must never be reachable with a read-only PAT, even one with `org:read`).
 */
const sessionOnlyGuard: RequestHandler = (req, _res, next) => {
  if (req.auth?.via === 'token') {
    throw new AppError('LSE-AUTH-001', {
      devMessage: 'Identity settings require a browser session; API tokens are not accepted',
    });
  }
  next();
};

/** `/orgs/:orgId/identity/*` — inside the org router (requireAuth + requireOrg already ran). */
export function mountIdentityOrgRoutes(org: Router, ctx: AppContext): void {
  const r = Router({ mergeParams: true });
  // Identity configuration is admin-only AND session-only (never a read-only PAT).
  r.use(requireRole('ADMIN'), sessionOnlyGuard);
  const owner = requireRole('OWNER');

  // ---- SSO connection ------------------------------------------------------------------
  r.get('/sso', requireFeature(ctx, 'sso_oidc'), async (req, res) => {
    res.json({ data: await getSsoConnectionDto(ctx, orgOf(req).org) });
  });

  r.put(
    '/sso',
    owner,
    requireFeature(ctx, 'sso_oidc'),
    validate({ body: upsertSsoConnectionBodySchema }),
    async (req, res) => {
      const dto = await upsertSsoConnection(
        ctx,
        orgOf(req).org,
        actorOf(req),
        req.body as UpsertSsoConnectionBody,
      );
      invalidateOrgSecurityCache(ctx, orgOf(req).org.id);
      res.json({ data: dto });
    },
  );

  r.delete('/sso', owner, requireFeature(ctx, 'sso_oidc'), async (req, res) => {
    await deleteSsoConnection(ctx, orgOf(req).org, actorOf(req));
    invalidateOrgSecurityCache(ctx, orgOf(req).org.id);
    res.status(204).end();
  });

  r.post('/sso/test', owner, requireFeature(ctx, 'sso_oidc'), async (req, res) => {
    res.json({ data: await testSsoConnection(ctx, orgOf(req).org) });
  });

  // ---- verified domains ----------------------------------------------------------------
  r.get('/domains', async (req, res) => {
    res.json({ data: await listOrgDomains(ctx, orgOf(req).org.id), nextCursor: null });
  });

  r.post(
    '/domains',
    idempotency(ctx),
    validate({ body: createOrgDomainBodySchema }),
    async (req, res) => {
      const dto = await createOrgDomain(
        ctx,
        orgOf(req).org.id,
        actorOf(req),
        (req.body as CreateOrgDomainBody).domain,
      );
      res.status(201).json({ data: dto });
    },
  );

  r.post('/domains/:id/verify', validate({ params: resourceIdParamsSchema }), async (req, res) => {
    const dto = await verifyOrgDomain(
      ctx,
      orgOf(req).org.id,
      actorOf(req),
      req.params.id as string,
    );
    invalidateOrgSecurityCache(ctx, orgOf(req).org.id);
    // REAUDIT-006: verified domains decide who enforce-SSO applies to.
    await publishPolicyChanged(orgOf(req).org.id);
    res.json({ data: dto });
  });

  r.delete('/domains/:id', validate({ params: resourceIdParamsSchema }), async (req, res) => {
    await deleteOrgDomain(ctx, orgOf(req).org.id, actorOf(req), req.params.id as string);
    invalidateOrgSecurityCache(ctx, orgOf(req).org.id);
    await publishPolicyChanged(orgOf(req).org.id); // REAUDIT-006
    res.status(204).end();
  });

  // ---- SCIM tokens ---------------------------------------------------------------------
  r.get('/scim-tokens', owner, requireFeature(ctx, 'scim'), async (req, res) => {
    res.json({ data: await listScimTokens(ctx, orgOf(req).org.id), nextCursor: null });
  });

  r.post(
    '/scim-tokens',
    owner,
    requireFeature(ctx, 'scim'),
    idempotency(ctx),
    validate({ body: createScimTokenBodySchema }),
    async (req, res) => {
      const body = req.body as CreateScimTokenBody;
      const dto = await createScimToken(
        ctx,
        orgOf(req).org.id,
        actorOf(req),
        body.name,
        body.expiresInDays,
      );
      res.status(201).json({ data: dto });
    },
  );

  r.delete(
    '/scim-tokens/:id',
    owner,
    requireFeature(ctx, 'scim'),
    validate({ params: resourceIdParamsSchema }),
    async (req, res) => {
      await revokeScimToken(ctx, orgOf(req).org.id, actorOf(req), req.params.id as string);
      res.status(204).end();
    },
  );

  // ---- security settings ---------------------------------------------------------------
  r.get('/security', async (req, res) => {
    res.json({ data: await orgSecurityDto(ctx, orgOf(req).org, clientIp(req)) });
  });

  r.put('/security', owner, validate({ body: updateOrgSecurityBodySchema }), async (req, res) => {
    const dto = await updateOrgSecurity(
      ctx,
      orgOf(req).org,
      actorOf(req),
      req.body as UpdateOrgSecurityBody,
      clientIp(req),
    );
    res.json({ data: dto });
  });

  org.use('/identity', r);
}
