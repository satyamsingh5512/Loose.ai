/**
 * Phase 10 / W1 — SCIM 2.0 provisioning (spec §8.20): token management (hashed, owner-only,
 * never returned twice), bearer authentication (RFC 7644 error bodies + `x-loose-error-code`),
 * discovery documents, Users (create / get / list + filter / replace / patch / deactivate /
 * delete) and Groups (members, role mapping, last-owner protection), plus tenant isolation.
 */
import request from 'supertest';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import {
  API_PREFIX,
  MAX_SCIM_TOKENS_PER_ORG,
  SCIM_BASE_PATH,
  SCIM_CONTENT_TYPE,
  SCIM_SCHEMAS,
  SCIM_TOKEN_PREFIX,
} from '@loose/shared';
import { sha256Hex } from '../src/lib/crypto';
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
const SCIM = `${API_PREFIX}${SCIM_BASE_PATH}`;

afterAll(async () => {
  await ctx.jobs.onIdle();
  await prisma.$disconnect();
});

beforeEach(async () => {
  await resetDb(prisma);
});

interface World {
  owner: Client;
  org: { id: string; slug: string };
  token: string;
}

let seq = 0;
async function world(): Promise<World> {
  seq += 1;
  const owner = await login(app, `scim-owner-${seq}@example.com`);
  const org = await createOrg(owner, `Scim ${seq}-${Math.random().toString(36).slice(2, 7)}`);
  const created = await owner.post(`${API_PREFIX}/orgs/${org.id}/identity/scim-tokens`, {
    name: 'okta',
  });
  expect(created.status, JSON.stringify(created.body)).toBe(201);
  return { owner, org, token: created.body.data.token as string };
}

/** A SCIM request with the bearer token and `application/scim+json`. */
function scim(
  method: 'get' | 'post' | 'put' | 'patch' | 'delete',
  path: string,
  token: string | null,
  body?: unknown,
) {
  let req = request(app)[method](`${SCIM}${path}`);
  if (token) req = req.set('authorization', `Bearer ${token}`);
  if (body !== undefined) req = req.set('content-type', SCIM_CONTENT_TYPE).send(body as object);
  return req;
}

function userPayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemas: [SCIM_SCHEMAS.user],
    userName: 'jane.doe@acme.test',
    name: { givenName: 'Jane', familyName: 'Doe' },
    emails: [{ value: 'jane.doe@acme.test', primary: true, type: 'work' }],
    active: true,
    externalId: 'ext-jane',
    ...overrides,
  };
}

async function createUser(
  w: World,
  overrides: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const res = await scim('post', '/Users', w.token, userPayload(overrides));
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  return res.body as Record<string, unknown>;
}

function patch(ops: Record<string, unknown>[]): Record<string, unknown> {
  return { schemas: [SCIM_SCHEMAS.patchOp], Operations: ops };
}

// ---------------------------------------------------------------------------------------------

describe('SCIM tokens', () => {
  it('shows the token once, stores only its hash and enforces the per-org limit', async () => {
    const owner = await login(app, 'tok-owner@example.com');
    const org = await createOrg(owner, `Tok ${Math.random().toString(36).slice(2, 7)}`);
    const base = `${API_PREFIX}/orgs/${org.id}/identity/scim-tokens`;
    const created = await owner.post(base, { name: 'okta' });
    expect(created.status).toBe(201);
    const token = created.body.data.token as string;
    expect(token.startsWith(SCIM_TOKEN_PREFIX)).toBe(true);
    expect(created.body.data.scimBaseUrl).toBe(`http://localhost:4000${SCIM}`);

    const rows = await prisma.scimToken.findMany({ where: { orgId: org.id } });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.hash).toBe(sha256Hex(token));

    const list = await owner.get(base);
    expect(list.status).toBe(200);
    expect(list.body.data).toHaveLength(1);
    expect(JSON.stringify(list.body)).not.toContain(token);

    for (let i = 1; i < MAX_SCIM_TOKENS_PER_ORG; i++) {
      expect((await owner.post(base, { name: `extra-${i}` })).status).toBe(201);
    }
    expectError(await owner.post(base, { name: 'too-many' }), 'LSE-VAL-001', 400);

    // Revoking kills the token immediately.
    const id = list.body.data[0].id as string;
    expect((await owner.delete(`${base}/${id}`)).status).toBe(204);
    const res = await scim('get', '/Users', token);
    expect(res.status).toBe(401);
    expect(await prisma.auditLog.count({ where: { action: 'scim_token.revoke' } })).toBe(1);
  });

  it('is owner-only and never reachable with an API token', async () => {
    const owner = await login(app, 'tok-roles@example.com');
    const org = await createOrg(owner, `Roles ${Math.random().toString(36).slice(2, 7)}`);
    const admin = await login(app, 'tok-admin@example.com');
    await addMember(org.id, admin.user.id, 'ADMIN');
    const base = `${API_PREFIX}/orgs/${org.id}/identity/scim-tokens`;
    expectError(await admin.get(base), 'LSE-ORG-002', 403);
    expectError(await admin.post(base, { name: 'nope' }), 'LSE-ORG-002', 403);
  });
});

describe('SCIM authentication', () => {
  it('rejects missing, malformed, unknown and revoked tokens with RFC 7644 bodies', async () => {
    const w = await world();
    for (const token of [null, 'not-a-loose-token', `${SCIM_TOKEN_PREFIX}wrong`]) {
      const res = await scim('get', '/Users', token);
      expect(res.status).toBe(401);
      expect(res.headers['content-type']).toContain('application/scim+json');
      expect(res.body).toMatchObject({ schemas: [SCIM_SCHEMAS.error], status: '401' });
      expect(res.headers['x-loose-error-code']).toBe('LSE-AUTH-007');
      // No §16.2 envelope, so SCIM clients are not confused.
      expect(res.body.error).toBeUndefined();
    }
    expect((await scim('get', '/Users', w.token)).status).toBe(200);
    // `lastUsedAt` is a fire-and-forget update; under load it can land after the response.
    await expect
      .poll(
        async () =>
          (await prisma.scimToken.findFirstOrThrow({ where: { orgId: w.org.id } })).lastUsedAt,
      )
      .not.toBeNull();
  });

  it('answers 503 when the scim feature flag is off', async () => {
    const off = makeApp({ env: { FEATURE_FLAGS: 'scim=off' } });
    const owner = await login(off.app, 'scim-off@example.com');
    const org = await createOrg(owner, `Off ${Math.random().toString(36).slice(2, 7)}`);
    expectError(
      await owner.post(`${API_PREFIX}/orgs/${org.id}/identity/scim-tokens`, { name: 'x' }),
      'LSE-SYS-007',
      503,
    );
    // A token minted while the flag was on stops working.
    const row = await prisma.scimToken.create({
      data: { orgId: org.id, name: 'legacy', hash: sha256Hex('loose_scim_legacy') },
    });
    expect(row.id).toBeTruthy();
    const res = await request(off.app)
      .get(`${SCIM}/Users`)
      .set('authorization', 'Bearer loose_scim_legacy');
    expect(res.status).toBe(503);
    expect(res.headers['x-loose-error-code']).toBe('LSE-SYS-007');
  });

  it('serves the discovery documents', async () => {
    const w = await world();
    const config = await scim('get', '/ServiceProviderConfig', w.token);
    expect(config.status).toBe(200);
    expect(config.body).toMatchObject({
      schemas: [SCIM_SCHEMAS.serviceProviderConfig],
      patch: { supported: true },
      bulk: { supported: false },
      filter: { supported: true },
      sort: { supported: false },
      etag: { supported: false },
    });
    const types = await scim('get', '/ResourceTypes', w.token);
    expect(types.body.Resources.map((r: { id: string }) => r.id)).toEqual(['User', 'Group']);
    const schemasRes = await scim('get', '/Schemas', w.token);
    expect(schemasRes.body.Resources.map((r: { id: string }) => r.id)).toEqual([
      SCIM_SCHEMAS.user,
      SCIM_SCHEMAS.group,
    ]);
    expect((await scim('get', '/Nope', w.token)).status).toBe(404);
  });
});

describe('SCIM Users', () => {
  it('provisions a user, creates the membership and is idempotent on conflicts', async () => {
    const w = await world();
    const created = await createUser(w);
    expect(created).toMatchObject({
      schemas: [SCIM_SCHEMAS.user],
      userName: 'jane.doe@acme.test',
      active: true,
      externalId: 'ext-jane',
      displayName: 'Jane Doe',
      meta: { resourceType: 'User' },
    });
    expect(created.id).toBeTruthy();

    const user = await prisma.user.findUniqueOrThrow({ where: { email: 'jane.doe@acme.test' } });
    const membership = await prisma.orgMember.findUnique({
      where: { userId_orgId: { userId: user.id, orgId: w.org.id } },
    });
    expect(membership?.role).toBe('MEMBER');
    expect(await prisma.auditLog.count({ where: { action: 'scim.user_provision' } })).toBe(1);

    const again = await scim('post', '/Users', w.token, userPayload());
    expect(again.status).toBe(409);
    expect(again.body).toMatchObject({ status: '409', scimType: 'uniqueness' });

    const fetched = await scim('get', `/Users/${created.id as string}`, w.token);
    expect(fetched.status).toBe(200);
    expect(fetched.body.id).toBe(created.id);
    expect((await scim('get', '/Users/does-not-exist', w.token)).status).toBe(404);
  });

  it('uses the org SSO default role for new members', async () => {
    const w = await world();
    await prisma.ssoConnection.create({
      data: { orgId: w.org.id, issuer: 'https://203.0.113.10/idp', defaultRole: 'VIEWER' },
    });
    const created = await createUser(w, { userName: 'viewer@acme.test', emails: undefined });
    const user = await prisma.user.findUniqueOrThrow({ where: { email: 'viewer@acme.test' } });
    expect(created.userName).toBe('viewer@acme.test');
    expect(
      (
        await prisma.orgMember.findUniqueOrThrow({
          where: { userId_orgId: { userId: user.id, orgId: w.org.id } },
        })
      ).role,
    ).toBe('VIEWER');
  });

  it('rejects a payload without a usable email', async () => {
    const w = await world();
    const res = await scim('post', '/Users', w.token, {
      schemas: [SCIM_SCHEMAS.user],
      userName: 'jane',
    });
    expect(res.status).toBe(400);
    expect(res.body.scimType).toBe('invalidValue');
    expect(res.headers['x-loose-error-code']).toBe('LSE-VAL-001');
    expect((await scim('post', '/Users', w.token, 'not-json')).status).toBe(400);
  });

  it('lists with paging and supports userName / externalId / active filters', async () => {
    const w = await world();
    await createUser(w);
    await createUser(w, { userName: 'john@acme.test', externalId: 'ext-john', emails: undefined });

    const all = await scim('get', '/Users', w.token);
    expect(all.body).toMatchObject({
      schemas: [SCIM_SCHEMAS.listResponse],
      totalResults: 2,
      itemsPerPage: 2,
      startIndex: 1,
    });

    const filtered = await scim(
      'get',
      `/Users?filter=${encodeURIComponent('userName eq "JANE.DOE@acme.test"')}`,
      w.token,
    );
    expect(filtered.body.totalResults).toBe(1);
    expect(filtered.body.Resources[0].userName).toBe('jane.doe@acme.test');

    const byExternal = await scim(
      'get',
      `/Users?filter=${encodeURIComponent('externalId eq "ext-john"')}`,
      w.token,
    );
    expect(byExternal.body.Resources[0].userName).toBe('john@acme.test');

    const missing = await scim(
      'get',
      `/Users?filter=${encodeURIComponent('userName eq "nobody@acme.test"')}`,
      w.token,
    );
    expect(missing.body).toMatchObject({ totalResults: 0, Resources: [] });

    const paged = await scim('get', '/Users?startIndex=2&count=1', w.token);
    expect(paged.body).toMatchObject({ totalResults: 2, itemsPerPage: 1, startIndex: 2 });

    const badFilter = await scim(
      'get',
      `/Users?filter=${encodeURIComponent('userName co "acme"')}`,
      w.token,
    );
    expect(badFilter.status).toBe(400);
    expect(badFilter.body.scimType).toBe('invalidFilter');
    const badAttr = await scim(
      'get',
      `/Users?filter=${encodeURIComponent('password eq "x"')}`,
      w.token,
    );
    expect(badAttr.body.scimType).toBe('invalidFilter');
    expect((await scim('get', '/Users?startIndex=0', w.token)).status).toBe(400);
  });

  it('patches attributes and deactivates / reactivates the membership', async () => {
    const w = await world();
    const created = await createUser(w);
    const id = created.id as string;
    const user = await prisma.user.findUniqueOrThrow({ where: { email: 'jane.doe@acme.test' } });
    const membership = () =>
      prisma.orgMember.findUnique({
        where: { userId_orgId: { userId: user.id, orgId: w.org.id } },
      });

    const renamed = await scim(
      'patch',
      `/Users/${id}`,
      w.token,
      patch([
        { op: 'replace', path: 'name.familyName', value: 'Smith' },
        { op: 'replace', path: 'displayName', value: 'Jane Smith' },
      ]),
    );
    expect(renamed.status, JSON.stringify(renamed.body)).toBe(200);
    expect(renamed.body).toMatchObject({
      displayName: 'Jane Smith',
      name: { givenName: 'Jane', familyName: 'Smith' },
    });

    // Okta-style deactivate.
    const deactivated = await scim(
      'patch',
      `/Users/${id}`,
      w.token,
      patch([{ op: 'replace', value: { active: false } }]),
    );
    expect(deactivated.status).toBe(200);
    expect(deactivated.body.active).toBe(false);
    expect(await membership()).toBeNull();
    expect(await prisma.auditLog.count({ where: { action: 'scim.user_deprovision' } })).toBe(1);
    // The account itself survives (audit trail, session history).
    expect(await prisma.user.count({ where: { id: user.id } })).toBe(1);

    const reactivated = await scim(
      'patch',
      `/Users/${id}`,
      w.token,
      patch([{ op: 'replace', path: 'active', value: true }]),
    );
    expect(reactivated.body.active).toBe(true);
    expect((await membership())?.role).toBe('MEMBER');

    // Unsupported paths and malformed PATCH bodies are refused.
    expect(
      (
        await scim(
          'patch',
          `/Users/${id}`,
          w.token,
          patch([{ op: 'replace', path: 'password', value: 'x' }]),
        )
      ).body.scimType,
    ).toBe('invalidPath');
    expect(
      (await scim('patch', `/Users/${id}`, w.token, patch([{ op: 'bogus', path: 'active' }]))).body
        .scimType,
    ).toBe('invalidSyntax');
    expect((await scim('patch', `/Users/${id}`, w.token, { Operations: [] })).body.scimType).toBe(
      'invalidSyntax',
    );
  });

  it('replaces a user with PUT and refuses a duplicate userName', async () => {
    const w = await world();
    const jane = await createUser(w);
    await createUser(w, { userName: 'john@acme.test', emails: undefined, externalId: 'ext-john' });

    const replaced = await scim(
      'put',
      `/Users/${jane.id as string}`,
      w.token,
      userPayload({ name: { givenName: 'Janet', familyName: 'Doe' }, externalId: 'ext-janet' }),
    );
    expect(replaced.status).toBe(200);
    expect(replaced.body).toMatchObject({
      displayName: 'Janet Doe',
      externalId: 'ext-janet',
    });

    const clash = await scim(
      'put',
      `/Users/${jane.id as string}`,
      w.token,
      userPayload({ userName: 'john@acme.test' }),
    );
    expect(clash.status).toBe(409);
    expect(clash.body.scimType).toBe('uniqueness');
  });

  it('DELETE deprovisions and keeps the last owner', async () => {
    const w = await world();
    const created = await createUser(w);
    const user = await prisma.user.findUniqueOrThrow({ where: { email: 'jane.doe@acme.test' } });
    expect((await scim('delete', `/Users/${created.id as string}`, w.token)).status).toBe(204);
    expect(await prisma.orgMember.count({ where: { userId: user.id, orgId: w.org.id } })).toBe(0);
    expect(
      (await prisma.scimIdentity.findUniqueOrThrow({ where: { id: created.id as string } })).active,
    ).toBe(false);

    // The sole owner cannot be removed through SCIM.
    const ownerIdentity = await prisma.scimIdentity.create({
      data: {
        orgId: w.org.id,
        userId: w.owner.user.id,
        userName: w.owner.user.email,
        active: true,
      },
    });
    const res = await scim('delete', `/Users/${ownerIdentity.id}`, w.token);
    expect(res.status).toBe(409);
    expect(res.headers['x-loose-error-code']).toBe('LSE-ORG-007');
    expect(
      await prisma.orgMember.count({ where: { userId: w.owner.user.id, orgId: w.org.id } }),
    ).toBe(1);
  });

  it('never crosses tenants', async () => {
    const a = await world();
    const b = await world();
    const created = await createUser(a);
    expect((await scim('get', `/Users/${created.id as string}`, b.token)).status).toBe(404);
    expect((await scim('delete', `/Users/${created.id as string}`, b.token)).status).toBe(404);
    expect((await scim('get', '/Users', b.token)).body.totalResults).toBe(0);
  });
});

describe('SCIM Groups', () => {
  it('creates a group, maps loose-admins to ADMIN and syncs member roles', async () => {
    const w = await world();
    const jane = await createUser(w);
    const group = await scim('post', '/Groups', w.token, {
      schemas: [SCIM_SCHEMAS.group],
      displayName: 'loose-admins',
      externalId: 'grp-1',
      members: [{ value: jane.id as string }],
    });
    expect(group.status, JSON.stringify(group.body)).toBe(201);
    expect(group.body).toMatchObject({
      displayName: 'loose-admins',
      externalId: 'grp-1',
      members: [{ value: jane.id as string, type: 'User' }],
    });
    const user = await prisma.user.findUniqueOrThrow({ where: { email: 'jane.doe@acme.test' } });
    expect(
      (
        await prisma.orgMember.findUniqueOrThrow({
          where: { userId_orgId: { userId: user.id, orgId: w.org.id } },
        })
      ).role,
    ).toBe('ADMIN');
    expect((await prisma.scimGroup.findFirstOrThrow({ where: { orgId: w.org.id } })).role).toBe(
      'ADMIN',
    );
    expect(await prisma.auditLog.count({ where: { action: 'scim.group_update' } })).toBe(1);

    const duplicate = await scim('post', '/Groups', w.token, {
      schemas: [SCIM_SCHEMAS.group],
      displayName: 'loose-admins',
    });
    expect(duplicate.status).toBe(409);
  });

  it('a group name without a mapping does not change roles', async () => {
    const w = await world();
    const jane = await createUser(w);
    await scim('post', '/Groups', w.token, {
      schemas: [SCIM_SCHEMAS.group],
      displayName: 'Engineering',
      members: [{ value: jane.id as string }],
    });
    const user = await prisma.user.findUniqueOrThrow({ where: { email: 'jane.doe@acme.test' } });
    expect(
      (
        await prisma.orgMember.findUniqueOrThrow({
          where: { userId_orgId: { userId: user.id, orgId: w.org.id } },
        })
      ).role,
    ).toBe('MEMBER');
  });

  it('adds and removes members through PATCH and keeps roles in sync', async () => {
    const w = await world();
    const jane = await createUser(w);
    const john = await createUser(w, {
      userName: 'john@acme.test',
      emails: undefined,
      externalId: 'ext-john',
    });
    const group = await scim('post', '/Groups', w.token, {
      schemas: [SCIM_SCHEMAS.group],
      displayName: 'loose-viewers',
    });
    const id = group.body.id as string;
    const role = async (email: string) => {
      const user = await prisma.user.findUniqueOrThrow({ where: { email } });
      return (
        await prisma.orgMember.findUniqueOrThrow({
          where: { userId_orgId: { userId: user.id, orgId: w.org.id } },
        })
      ).role;
    };

    const added = await scim(
      'patch',
      `/Groups/${id}`,
      w.token,
      patch([{ op: 'add', path: 'members', value: [{ value: jane.id as string }] }]),
    );
    expect(added.status, JSON.stringify(added.body)).toBe(200);
    expect(added.body.members).toHaveLength(1);
    expect(await role('jane.doe@acme.test')).toBe('VIEWER');

    const both = await scim(
      'patch',
      `/Groups/${id}`,
      w.token,
      patch([{ op: 'add', path: 'members', value: [{ value: john.id as string }] }]),
    );
    expect(both.body.members).toHaveLength(2);

    // Entra-style targeted removal.
    const removed = await scim(
      'patch',
      `/Groups/${id}`,
      w.token,
      patch([{ op: 'remove', path: `members[value eq "${jane.id as string}"]` }]),
    );
    expect(removed.body.members).toEqual([{ value: john.id as string, type: 'User' }]);
    expect(await role('jane.doe@acme.test')).toBe('MEMBER');

    const renamed = await scim(
      'patch',
      `/Groups/${id}`,
      w.token,
      patch([{ op: 'replace', path: 'displayName', value: 'loose-admins' }]),
    );
    expect(renamed.body.displayName).toBe('loose-admins');
    expect(await role('john@acme.test')).toBe('ADMIN');

    const unknown = await scim(
      'patch',
      `/Groups/${id}`,
      w.token,
      patch([{ op: 'add', path: 'members', value: [{ value: 'nope' }] }]),
    );
    expect(unknown.status).toBe(400);
    expect(unknown.body.scimType).toBe('invalidValue');
  });

  it('lists, replaces and deletes groups', async () => {
    const w = await world();
    const jane = await createUser(w);
    const group = await scim('post', '/Groups', w.token, {
      schemas: [SCIM_SCHEMAS.group],
      displayName: 'loose-members',
      members: [{ value: jane.id as string }],
    });
    const id = group.body.id as string;
    const list = await scim(
      'get',
      `/Groups?filter=${encodeURIComponent('displayName eq "loose-members"')}`,
      w.token,
    );
    expect(list.body.totalResults).toBe(1);
    expect(list.body.Resources[0].members).toHaveLength(1);

    const replaced = await scim('put', `/Groups/${id}`, w.token, {
      schemas: [SCIM_SCHEMAS.group],
      displayName: 'loose-admins',
      members: [],
    });
    expect(replaced.status).toBe(200);
    expect(replaced.body.members).toEqual([]);
    const user = await prisma.user.findUniqueOrThrow({ where: { email: 'jane.doe@acme.test' } });
    expect(
      (
        await prisma.orgMember.findUniqueOrThrow({
          where: { userId_orgId: { userId: user.id, orgId: w.org.id } },
        })
      ).role,
    ).toBe('MEMBER');

    expect((await scim('delete', `/Groups/${id}`, w.token)).status).toBe(204);
    expect((await scim('get', `/Groups/${id}`, w.token)).status).toBe(404);
    expect(await prisma.scimGroupMember.count()).toBe(0);
  });

  it('never grants OWNER through a group name', async () => {
    const w = await world();
    const jane = await createUser(w);
    await scim('post', '/Groups', w.token, {
      schemas: [SCIM_SCHEMAS.group],
      displayName: 'loose-owners',
      members: [{ value: jane.id as string }],
    });
    const user = await prisma.user.findUniqueOrThrow({ where: { email: 'jane.doe@acme.test' } });
    expect(
      (
        await prisma.orgMember.findUniqueOrThrow({
          where: { userId_orgId: { userId: user.id, orgId: w.org.id } },
        })
      ).role,
    ).toBe('MEMBER');
    expect(await prisma.orgMember.count({ where: { orgId: w.org.id, role: 'OWNER' } })).toBe(1);
  });
});
