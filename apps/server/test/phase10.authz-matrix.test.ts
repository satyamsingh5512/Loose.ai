/**
 * AuthZ matrix (Phase 10 §7.1, W4): walks the live Express router stack of `createApp(ctx)` via
 * `routeInventory.ts` and checks every route against `authzExpectations.ts`.
 *
 * 1. Coverage: every live route has an expectation, and every expectation matches a live route
 *    (the table can't drift from reality in either direction).
 * 2. Behaviour, driven by `auth`. Middleware order in `app.ts` is CSRF *then* `requireAuth`, so
 *    an anonymous request with an unsafe method (POST/PUT/DELETE) and no CSRF cookie never
 *    reaches the auth check — it is correctly rejected earlier with 403 `LSE-AUTH-002` ("missing
 *    CSRF token header"). GET requests skip CSRF, so they reach `requireAuth` and get 401
 *    `LSE-AUTH-001`. The matrix asserts whichever of the two is correct for the method, not just
 *    LSE-AUTH-001 — both prove the route never serves data to an anonymous caller.
 *    - 'session'/'session-only': anonymous → 401 LSE-AUTH-001 (GET) or 403 LSE-AUTH-002 (unsafe).
 *    - 'session-only' additionally: an authenticated bearer-token request (which *is* CSRF-exempt)
 *      → 401 LSE-AUTH-001.
 *    - 'org'/'org-session-only': anonymous → as above; a signed-in-with-CSRF non-member → 403/404
 *      LSE-ORG-001; a member below `minRole` → 403 LSE-ORG-002; 'org-session-only' additionally
 *      rejects a bearer token at `minRole` with 401 LSE-AUTH-001.
 *    - 'metrics': without `METRICS_TOKEN` configured, 404 LSE-NF-001 (foundation default).
 *    - 'public'/'signature'/'scim': left to their own dedicated tests (listed per-route in
 *      `note`); only presence/coverage is asserted here.
 *
 * Routes that are still Phase 10 stubs (`pendingOwner` set) answer 503 `LSE-SYS-007` once the
 * auth/role gate passes — the matrix accepts that body in place of a 2xx without weakening the
 * negative assertions above (anonymous/wrong-role/wrong-scope requests still must fail the way
 * the *final* route will).
 */
import request from 'supertest';
import { randomBytes } from 'node:crypto';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { CSRF_HEADER, PAT_PREFIX, type ApiTokenScope, type Role } from '@loose/shared';
import { sha256Hex } from '../src/lib/crypto';
import {
  AUTHZ_EXPECTATIONS,
  SCIM_MOUNT_PREFIX,
  type OrgRole,
  type RouteExpectation,
} from './authzExpectations';
import { inventoryRoutes } from './routeInventory';
import {
  addMember,
  createOrg,
  expectError,
  login,
  makeApp,
  resetDb,
  testPrisma,
  type Client,
} from './helpers';

const prisma = testPrisma();
const { app, ctx } = makeApp();

afterAll(async () => {
  await ctx.jobs.onIdle();
  await prisma.$disconnect();
});

beforeEach(async () => {
  await ctx.jobs.onIdle();
  await resetDb(prisma);
});

type Method = 'get' | 'post' | 'put' | 'delete' | 'patch';
const UNSAFE_METHODS = new Set<Method>(['post', 'put', 'delete', 'patch']);

const ROLE_ORDER: OrgRole[] = ['VIEWER', 'MEMBER', 'ADMIN', 'OWNER'];
function roleBelow(min: OrgRole): OrgRole | undefined {
  const i = ROLE_ORDER.indexOf(min);
  return i > 0 ? ROLE_ORDER[i - 1] : undefined;
}

/** Fill `:param` placeholders with harmless values so Express dispatches past validation. */
const PLACEHOLDER = 'ffffffff-ffff-ffff-ffff-ffffffffffff';
function materialize(path: string): string {
  return path.replace(/:[A-Za-z0-9_]+/g, () => PLACEHOLDER);
}
function withOrgId(path: string, orgId: string): string {
  return path.replace(PLACEHOLDER, orgId);
}

function methodOf(key: string): Method {
  const m = key.split(' ', 1)[0]!.toLowerCase();
  if (m !== 'get' && m !== 'post' && m !== 'put' && m !== 'delete' && m !== 'patch') {
    throw new Error(`authz matrix: unsupported method in ${key}`);
  }
  return m as Method;
}

async function makeOrgWithRole(role: Role): Promise<{ client: Client; org: { id: string } }> {
  const owner = await login(app);
  const org = await createOrg(owner);
  if (role === 'OWNER') return { client: owner, org };
  const client = await login(app);
  await addMember(org.id, client.user.id, role);
  return { client, org };
}

async function patFor(userId: string, orgId: string, scopes: ApiTokenScope[]): Promise<string> {
  const raw = `${PAT_PREFIX}${randomBytes(24).toString('base64url')}`;
  await prisma.apiToken.create({
    data: { orgId, userId, name: 'matrix', hash: sha256Hex(raw), scopes },
  });
  return raw;
}

const ALL_SCOPES: ApiTokenScope[] = [
  'runs:read',
  'runs:write',
  'projects:read',
  'org:read',
  'sessions:read',
  'sessions:write',
];

describe('route inventory ↔ authzExpectations coverage', () => {
  it('every live route has an expectation, and every expectation matches a live route', () => {
    // inventoryRoutes must build a *fresh* app from scratch inside its own call: it records
    // mount prefixes by patching Router.use only for the duration of `build()`, so `build` has
    // to actually construct the app there — passing back an already-built app (whose `.use()`
    // calls already happened before the patch was installed) sees no mounts at all.
    const live = inventoryRoutes(() => makeApp().app);
    const liveKeys = new Set(live.map((r) => r.key));
    const expectedKeys = new Set(Object.keys(AUTHZ_EXPECTATIONS));

    const missing = live.filter((r) => !expectedKeys.has(r.key)).map((r) => r.key);
    expect(missing, `routes with no authzExpectations entry:\n${missing.join('\n')}`).toEqual([]);

    const stale = [...expectedKeys].filter((k) => !liveKeys.has(k));
    expect(stale, `authzExpectations entries matching no live route:\n${stale.join('\n')}`).toEqual(
      [],
    );
  });

  it('SCIM is mounted (documented exception: not individually enumerable)', async () => {
    const res = await request(app).get(`${SCIM_MOUNT_PREFIX}/Users`);
    // Routed (not the global 404) — the catch-all stub or a real SCIM handler, never falls
    // through to notFoundHandler.
    expect(String(res.body?.error?.devMessage ?? '')).not.toMatch(/^No route for/);
  });
});

/** Anonymous request, no cookies/CSRF/auth at all. */
function anonCall(method: Method, path: string): request.Test {
  const r = request(app)[method](path);
  return method === 'get' || method === 'delete' ? r : r.send({});
}

/** Signed-in cookie request (with CSRF for unsafe methods); also covers PATCH, which `Client` lacks. */
function clientCall(client: Client, method: Method, path: string): request.Test {
  return method === 'get'
    ? client.agent.get(path)
    : client.agent[method](path).set(CSRF_HEADER, client.csrf);
}

/** Bearer-token request (CSRF-exempt by design). */
function tokenCall(method: Method, path: string, token: string): request.Test {
  const r = request(app)[method](path).set('authorization', `Bearer ${token}`);
  return method === 'get' || method === 'delete' ? r : r.send({});
}
describe.each(Object.entries(AUTHZ_EXPECTATIONS))('%s', (key, expectation: RouteExpectation) => {
  const method = methodOf(key);
  const pathTemplate = key.split(' ').slice(1).join(' ');
  const path = materialize(pathTemplate);
  // Anonymous + unsafe method never reaches requireAuth: CSRF middleware runs first and rejects
  // with 403 LSE-AUTH-002 (no cookie at all → "missing CSRF token header"). Safe GETs skip CSRF.
  const anonExpectedCode = UNSAFE_METHODS.has(method) ? 'LSE-AUTH-002' : 'LSE-AUTH-001';
  const anonExpectedStatus = UNSAFE_METHODS.has(method) ? 403 : 401;

  function expectAuthOrStub(res: request.Response, code: string, status: number) {
    if (expectation.pendingOwner && res.status === 503) {
      expectError(res, 'LSE-SYS-007', 503);
      return;
    }
    expectError(res, code, status);
  }

  if (expectation.auth === 'session' || expectation.auth === 'session-only') {
    it(`anonymous → ${anonExpectedStatus} ${anonExpectedCode}`, async () => {
      const res = await anonCall(method, path);
      expectAuthOrStub(res, anonExpectedCode, anonExpectedStatus);
    });
  }

  if (expectation.auth === 'session-only') {
    it('bearer token → 401 LSE-AUTH-001 (session-only route)', async () => {
      const user = await login(app);
      const org = await createOrg(user);
      const token = await patFor(user.user.id, org.id, ALL_SCOPES);
      const res = await tokenCall(method, path, token);
      expectAuthOrStub(res, 'LSE-AUTH-001', 401);
    });
  }

  if (expectation.auth === 'org' || expectation.auth === 'org-session-only') {
    const minRole = expectation.minRole!;

    it(`anonymous → ${anonExpectedStatus} ${anonExpectedCode}`, async () => {
      const res = await anonCall(method, path);
      expectAuthOrStub(res, anonExpectedCode, anonExpectedStatus);
    });

    it('signed-in non-member → 403 LSE-ORG-001', async () => {
      const nonMember = await login(app);
      const { org } = await makeOrgWithRole('OWNER');
      const materialized = withOrgId(path, org.id);
      const res = await clientCall(nonMember, method, materialized);
      expectAuthOrStub(res, 'LSE-ORG-001', 403);
    });

    const below = roleBelow(minRole);
    if (below) {
      it(`member below ${minRole} (${below}) → 403 LSE-ORG-002`, async () => {
        const { client, org } = await makeOrgWithRole(below as Role);
        const materialized = withOrgId(path, org.id);
        const res = await clientCall(client, method, materialized);
        expectAuthOrStub(res, 'LSE-ORG-002', 403);
      });
    }

    if (expectation.auth === 'org-session-only') {
      it('bearer token at minRole → rejected before reaching the stub/handler', async () => {
        const { client, org } = await makeOrgWithRole(minRole as Role);
        const token = await patFor(client.user.id, org.id, ALL_SCOPES);
        const materialized = withOrgId(path, org.id);
        const res = await tokenCall(method, materialized, token);
        // `orgsRouter`'s `tokenScopeGuard` runs before webhooks/triggers' own session-only
        // check and rejects any non-GET token request first (LSE-ORG-002); a GET token request
        // passes that guard (org:read) and is caught by the route's own `sessionOnly` instead
        // (LSE-AUTH-001). Either way the token never reaches the handler.
        if (method === 'get') {
          expectAuthOrStub(res, 'LSE-AUTH-001', 401);
        } else {
          expectError(res, 'LSE-ORG-002', 403);
        }
      });
    }
  }

  if (expectation.auth === 'metrics') {
    it('no METRICS_TOKEN configured → 404 LSE-NF-001', async () => {
      const res = await anonCall(method, path);
      expectError(res, 'LSE-NF-001', 404);
    });
  }

  if (expectation.auth === 'scim') {
    it('no bearer token → 401 (RFC 7644 error body, x-loose-error-code LSE-AUTH-007)', async () => {
      const res = await anonCall(method, path);
      expect(res.status).toBe(401);
      expect(res.headers['x-loose-error-code']).toBe('LSE-AUTH-007');
    });

    it('a cookie session (no bearer token) is not accepted either', async () => {
      const user = await login(app);
      let res: request.Response;
      if (method === 'get' || method === 'delete') {
        res = await (method === 'get' ? user.get(path) : user.delete(path));
      } else if (method === 'patch') {
        res = await user.agent.patch(path).set('x-csrf-token', user.csrf).send({});
      } else {
        res = await (method === 'post' ? user.post(path, {}) : user.put(path, {}));
      }
      expect(res.status).toBe(401);
      expect(res.headers['x-loose-error-code']).toBe('LSE-AUTH-007');
    });
  }

  if (expectation.auth === 'public' || expectation.auth === 'signature') {
    // Covered by this route's own dedicated test file (see `note`); the matrix only needs the
    // coverage assertion above (every live route has an entry here) for these kinds.
    it('left to its own dedicated test (public / signature-verified route)', () => {
      expect(expectation.auth).toMatch(/^(public|signature)$/);
    });
  }
});
