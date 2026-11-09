import request from 'supertest';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { DEFAULT_ORG_POLICY, IDEMPOTENCY_HEADER, PAT_PREFIX } from '@loose/shared';
import { sha256Hex } from '../src/lib/crypto';
import { MemoryKvStore } from '../src/lib/redis';
import {
  addMember,
  createOrg,
  expectError,
  login,
  makeApp,
  resetDb,
  testPrisma,
  uniqueEmail,
} from './helpers';

const prisma = testPrisma();
const { app } = makeApp();

beforeEach(() => resetDb());
afterAll(() => prisma.$disconnect());

describe('organizations', () => {
  it('create → creator is OWNER; list; get; derived slug is de-duplicated', async () => {
    const c = await login(app);
    const a = await createOrg(c, 'Acme Inc.');
    expect(a).toMatchObject({
      name: 'Acme Inc.',
      slug: 'acme-inc',
      role: 'OWNER',
      hasGithubApp: false,
    });
    const b = await createOrg(c, 'Acme Inc');
    expect(b.slug).toBe('acme-inc-2');
    const list = await c.get('/api/v1/orgs');
    expect(list.body).toMatchObject({ nextCursor: null });
    expect(list.body.data.map((o: { slug: string }) => o.slug)).toEqual(['acme-inc', 'acme-inc-2']);
    expect((await c.get(`/api/v1/orgs/${a.id}`)).body.data.role).toBe('OWNER');
    const policy = await c.get(`/api/v1/orgs/${a.id}/policy`);
    expect(policy.body.data).toEqual(DEFAULT_ORG_POLICY);
  });

  it('explicit slug already taken → LSE-ORG-004 (create and update)', async () => {
    const c = await login(app);
    await c.post('/api/v1/orgs', { name: 'One', slug: 'taken-slug' });
    expectError(
      await c.post('/api/v1/orgs', { name: 'Two', slug: 'taken-slug' }),
      'LSE-ORG-004',
      409,
    );
    const two = await createOrg(c, 'Two');
    expectError(await c.put(`/api/v1/orgs/${two.id}`, { slug: 'taken-slug' }), 'LSE-ORG-004', 409);
    const ok = await c.put(`/api/v1/orgs/${two.id}`, { name: 'Two Renamed', slug: 'two-renamed' });
    expect(ok.body.data).toMatchObject({ name: 'Two Renamed', slug: 'two-renamed' });
  });

  it('unknown org → LSE-ORG-003; not a member → LSE-ORG-001', async () => {
    const owner = await login(app);
    const outsider = await login(app);
    const org = await createOrg(owner);
    expectError(await outsider.get('/api/v1/orgs/doesnotexist123'), 'LSE-ORG-003', 404);
    expectError(await outsider.get(`/api/v1/orgs/${org.id}`), 'LSE-ORG-001', 403);
  });

  it('there is no immediate org delete; deletion only goes through the confirmed grace-period flow', async () => {
    const c = await login(app);
    const org = await createOrg(c);
    expectError(await c.delete(`/api/v1/orgs/${org.id}`), 'LSE-NF-001', 404);
    expect(await prisma.organization.count()).toBe(1);
    expect(await prisma.orgMember.count()).toBe(1);
  });

  it('policy update is validated and audited', async () => {
    const c = await login(app);
    const org = await createOrg(c);
    const body = {
      lockedModes: { MEMBER: 'SIMPLE' },
      commitToMainEnabled: true,
      retentionDays: { transcripts: 30, screenshots: 7 },
    };
    const res = await c.put(`/api/v1/orgs/${org.id}/policy`, body);
    expect(res.status).toBe(200);
    expect(res.body.data).toEqual({
      ...DEFAULT_ORG_POLICY,
      ...body,
      // Phase 10 retention fields omitted from the body take their defaults.
      retentionDays: { ...DEFAULT_ORG_POLICY.retentionDays, ...body.retentionDays },
      requireGithubApp: false,
    });
    expect((await c.get(`/api/v1/orgs/${org.id}/policy`)).body.data.commitToMainEnabled).toBe(true);
    expectError(
      await c.put(`/api/v1/orgs/${org.id}/policy`, { retentionDays: { transcripts: 0 } }),
      'LSE-VAL-001',
      400,
    );
  });

  it('audit log lists org events newest first with cursor pagination', async () => {
    const c = await login(app);
    const org = await createOrg(c);
    for (let i = 0; i < 3; i++) await c.put(`/api/v1/orgs/${org.id}`, { name: `Name ${i}` });
    const page1 = await c.get(`/api/v1/orgs/${org.id}/audit-log?limit=2`);
    expect(page1.status).toBe(200);
    expect(page1.body.data).toHaveLength(2);
    expect(page1.body.data[0]).toMatchObject({ action: 'org.update', actor: { id: c.user.id } });
    expect(page1.body.nextCursor).toEqual(expect.any(String));
    const page2 = await c.get(
      `/api/v1/orgs/${org.id}/audit-log?limit=2&cursor=${page1.body.nextCursor}`,
    );
    expect(page2.body.data).toHaveLength(2);
    expect(page2.body.data[1].action).toBe('org.create');
    expect(page2.body.nextCursor).toBeNull();
    const filtered = await c.get(`/api/v1/orgs/${org.id}/audit-log?action=org.create`);
    expect(filtered.body.data).toHaveLength(1);
  });
});

describe('members & owner protection', () => {
  it('cannot demote or remove the last OWNER (LSE-ORG-007)', async () => {
    const owner = await login(app);
    const org = await createOrg(owner);
    const url = `/api/v1/orgs/${org.id}/members/${owner.user.id}`;
    expectError(await owner.put(url, { role: 'ADMIN' }), 'LSE-ORG-007', 409);
    expectError(await owner.delete(url), 'LSE-ORG-007', 409);
    // With a second owner, demotion works.
    const second = await login(app);
    await addMember(org.id, second.user.id, 'MEMBER');
    expect(
      (await owner.put(`/api/v1/orgs/${org.id}/members/${second.user.id}`, { role: 'OWNER' }))
        .status,
    ).toBe(200);
    const demoted = await owner.put(url, { role: 'ADMIN' });
    expect(demoted.status).toBe(200);
    expect(demoted.body.data.role).toBe('ADMIN');
    expectError(
      await second.delete(`/api/v1/orgs/${org.id}/members/${second.user.id}`),
      'LSE-ORG-007',
      409,
    );
  });

  it('only an OWNER can grant OWNER or modify/remove an owner', async () => {
    const owner = await login(app);
    const org = await createOrg(owner);
    const admin = await login(app);
    const member = await login(app);
    await addMember(org.id, admin.user.id, 'ADMIN');
    await addMember(org.id, member.user.id, 'MEMBER');
    const base = `/api/v1/orgs/${org.id}/members`;
    expectError(
      await admin.put(`${base}/${member.user.id}`, { role: 'OWNER' }),
      'LSE-ORG-002',
      403,
    );
    expectError(
      await admin.put(`${base}/${owner.user.id}`, { role: 'MEMBER' }),
      'LSE-ORG-002',
      403,
    );
    expectError(await admin.delete(`${base}/${owner.user.id}`), 'LSE-ORG-002', 403);
    // Admins can manage non-owners.
    const res = await admin.put(`${base}/${member.user.id}`, {
      role: 'VIEWER',
      lockedMode: 'SIMPLE',
    });
    expect(res.body.data).toMatchObject({
      role: 'VIEWER',
      lockedMode: 'SIMPLE',
      user: { email: member.user.email },
    });
    const audit = await prisma.auditLog.findFirstOrThrow({
      where: { action: 'member.role_change', target: member.user.id },
    });
    expect(audit.meta).toMatchObject({ from: { role: 'MEMBER' }, to: { role: 'VIEWER' } });
  });

  it('members list paginates; any member may leave', async () => {
    const owner = await login(app);
    const org = await createOrg(owner);
    const users = [];
    for (let i = 0; i < 3; i++) {
      const u = await login(app);
      await addMember(org.id, u.user.id, 'MEMBER');
      users.push(u);
    }
    const p1 = await owner.get(`/api/v1/orgs/${org.id}/members?limit=2`);
    expect(p1.body.data).toHaveLength(2);
    const p2 = await owner.get(
      `/api/v1/orgs/${org.id}/members?limit=2&cursor=${p1.body.nextCursor}`,
    );
    expect(p2.body.data).toHaveLength(2);
    expect(p2.body.nextCursor).toBeNull();
    const leaver = users[0]!;
    expect((await leaver.delete(`/api/v1/orgs/${org.id}/members/${leaver.user.id}`)).status).toBe(
      204,
    );
    expectError(await leaver.get(`/api/v1/orgs/${org.id}`), 'LSE-ORG-001', 403);
    expectError(
      await users[1]!.delete(`/api/v1/orgs/${org.id}/members/${users[2]!.user.id}`),
      'LSE-ORG-002',
      403,
    );
    expectError(await owner.get(`/api/v1/orgs/${org.id}/members/nosuchuser`), 'LSE-NF-001', 404);
  });
});

describe('invites', () => {
  it('email invite: create → preview → accept → member with role; single use', async () => {
    const admin = await login(app);
    const org = await createOrg(admin, 'Invite Co');
    const email = uniqueEmail('invitee');
    const created = await admin.post(`/api/v1/orgs/${org.id}/invites`, {
      email: email.toUpperCase(),
      role: 'MEMBER',
    });
    expect(created.status).toBe(201);
    const { token, url } = created.body.data as { token: string; url: string };
    expect(created.body.data).toMatchObject({
      email,
      role: 'MEMBER',
      kind: 'email',
      status: 'pending',
    });
    expect(url).toBe(`http://localhost:5173/invite/${token}`);
    // Only the hash is stored.
    const row = await prisma.orgInvite.findFirstOrThrow({ where: { orgId: org.id } });
    expect(row.token).toBe(sha256Hex(token));
    expect(row.token).not.toBe(token);
    // Listing never shows the token.
    const list = await admin.get(`/api/v1/orgs/${org.id}/invites`);
    expect(JSON.stringify(list.body)).not.toContain(token);
    expect(JSON.stringify(list.body)).not.toContain(row.token);

    const preview = await request(app).get(`/api/v1/orgs/invites/${token}`);
    expect(preview.status).toBe(200);
    expect(preview.body.data).toMatchObject({
      orgName: 'Invite Co',
      role: 'MEMBER',
      emailBound: true,
    });
    expect(JSON.stringify(preview.body)).not.toContain(email);

    const invitee = await login(app, email);
    const accepted = await invitee.post(`/api/v1/orgs/invites/${token}/accept`);
    expect(accepted.status).toBe(200);
    expect(accepted.body.data).toMatchObject({
      alreadyMember: false,
      org: { id: org.id, role: 'MEMBER' },
    });
    expect((await invitee.get(`/api/v1/orgs/${org.id}`)).body.data.role).toBe('MEMBER');

    // Accepting again as the same user is idempotent.
    const again = await invitee.post(`/api/v1/orgs/invites/${token}/accept`);
    expect(again.body.data).toMatchObject({ alreadyMember: true });
    // Single use: nobody else can use it (even with the same email casing rules).
    const other = await login(app);
    expectError(await other.post(`/api/v1/orgs/invites/${token}/accept`), 'LSE-ORG-005', 410);
    expectError(await request(app).get(`/api/v1/orgs/invites/${token}`), 'LSE-ORG-005', 410);
    const listed = await admin.get(`/api/v1/orgs/${org.id}/invites`);
    expect(listed.body.data[0].status).toBe('accepted');
  });

  it('email mismatch → LSE-ORG-006', async () => {
    const admin = await login(app);
    const org = await createOrg(admin);
    const { token } = (
      await admin.post(`/api/v1/orgs/${org.id}/invites`, {
        email: uniqueEmail('a'),
        role: 'VIEWER',
      })
    ).body.data;
    const wrong = await login(app);
    expectError(await wrong.post(`/api/v1/orgs/invites/${token}/accept`), 'LSE-ORG-006', 403);
    expect(await prisma.orgMember.count({ where: { orgId: org.id } })).toBe(1);
  });

  it('link invite is multi-use until revoked', async () => {
    const admin = await login(app);
    const org = await createOrg(admin);
    const created = await admin.post(`/api/v1/orgs/${org.id}/invites`, { role: 'VIEWER' });
    expect(created.body.data).toMatchObject({ kind: 'link', email: null });
    const { token, id } = created.body.data;
    const u1 = await login(app);
    const u2 = await login(app);
    expect((await u1.post(`/api/v1/orgs/invites/${token}/accept`)).body.data.org.role).toBe(
      'VIEWER',
    );
    expect((await u2.post(`/api/v1/orgs/invites/${token}/accept`)).body.data.org.role).toBe(
      'VIEWER',
    );

    expect((await admin.delete(`/api/v1/orgs/${org.id}/invites/${id}`)).status).toBe(204);
    const u3 = await login(app);
    expectError(await u3.post(`/api/v1/orgs/invites/${token}/accept`), 'LSE-ORG-005', 410);
    const list = await admin.get(`/api/v1/orgs/${org.id}/invites`);
    expect(list.body.data[0].status).toBe('revoked');
    const actions = (await prisma.auditLog.findMany({ where: { orgId: org.id } })).map(
      (a) => a.action,
    );
    expect(actions).toEqual(
      expect.arrayContaining(['invite.create', 'invite.accept', 'invite.revoke']),
    );
  });

  it('expired invite → LSE-ORG-005', async () => {
    const admin = await login(app);
    const org = await createOrg(admin);
    const { token } = (
      await admin.post(`/api/v1/orgs/${org.id}/invites`, { role: 'MEMBER', expiresInDays: 1 })
    ).body.data;
    await prisma.orgInvite.updateMany({ data: { expiresAt: new Date(Date.now() - 1000) } });
    const u = await login(app);
    expectError(await u.post(`/api/v1/orgs/invites/${token}/accept`), 'LSE-ORG-005', 410);
    expectError(await request(app).get(`/api/v1/orgs/invites/${token}`), 'LSE-ORG-005', 410);
  });

  it('unknown token → LSE-NF-001; OWNER role cannot be invited', async () => {
    const admin = await login(app);
    const org = await createOrg(admin);
    expectError(
      await admin.post(`/api/v1/orgs/invites/${'x'.repeat(43)}/accept`),
      'LSE-NF-001',
      404,
    );
    expectError(
      await admin.post(`/api/v1/orgs/${org.id}/invites`, { role: 'OWNER' }),
      'LSE-VAL-001',
      400,
    );
  });

  it("can't revoke another org's invite", async () => {
    const a = await login(app);
    const orgA = await createOrg(a);
    const orgB = await createOrg(a);
    const { id } = (await a.post(`/api/v1/orgs/${orgB.id}/invites`, { role: 'MEMBER' })).body.data;
    expectError(await a.delete(`/api/v1/orgs/${orgA.id}/invites/${id}`), 'LSE-NF-001', 404);
  });
});

describe('tenant isolation', () => {
  it("a member of org A can't read org B's members, invites, projects, policy or audit log", async () => {
    const ownerA = await login(app);
    const ownerB = await login(app);
    const orgA = await createOrg(ownerA);
    const orgB = await createOrg(ownerB);
    await ownerB.post(`/api/v1/orgs/${orgB.id}/invites`, { role: 'MEMBER' });
    const projectB = await prisma.project.create({
      data: {
        orgId: orgB.id,
        name: 'B secret project',
        githubRepoFullName: 'b/repo',
        githubRepoUrl: 'https://github.com/b/repo',
        defaultBranch: 'main',
        envVarsEnc: new Uint8Array([1]),
        templateStatus: 'READY',
      },
    });
    for (const path of [
      '',
      '/members',
      '/invites',
      '/projects',
      `/projects/${projectB.id}`,
      '/policy',
      '/audit-log',
    ]) {
      expectError(await ownerA.get(`/api/v1/orgs/${orgB.id}${path}`), 'LSE-ORG-001', 403);
    }
    // Using A's orgId with B's project id must not leak it either.
    expectError(
      await ownerA.get(`/api/v1/orgs/${orgA.id}/projects/${projectB.id}`),
      'LSE-NF-001',
      404,
    );
    expectError(
      await ownerA.put(`/api/v1/orgs/${orgA.id}/projects/${projectB.id}`, { name: 'pwn' }),
      'LSE-NF-001',
      404,
    );
    expectError(
      await ownerA.delete(`/api/v1/orgs/${orgA.id}/projects/${projectB.id}`),
      'LSE-NF-001',
      404,
    );
    expectError(
      await ownerA.get(`/api/v1/orgs/${orgA.id}/members/${ownerB.user.id}`),
      'LSE-NF-001',
      404,
    );
    expect((await ownerA.get(`/api/v1/orgs/${orgA.id}/projects`)).body.data).toEqual([]);
    expect((await ownerA.get('/api/v1/orgs')).body.data.map((o: { id: string }) => o.id)).toEqual([
      orgA.id,
    ]);
    expect((await prisma.project.findUniqueOrThrow({ where: { id: projectB.id } })).name).toBe(
      'B secret project',
    );
  });
});

describe('idempotency', () => {
  it('same key + same body replays; different body → LSE-VAL-004', async () => {
    const c = await login(app);
    const first = await c
      .post('/api/v1/orgs', { name: 'Idem Org' })
      .set(IDEMPOTENCY_HEADER, 'key-123');
    expect(first.status).toBe(201);
    const replay = await c
      .post('/api/v1/orgs', { name: 'Idem Org' })
      .set(IDEMPOTENCY_HEADER, 'key-123');
    expect(replay.status).toBe(201);
    expect(replay.headers['idempotent-replayed']).toBe('true');
    expect(replay.body).toEqual(first.body);
    expect(await prisma.organization.count()).toBe(1);

    const conflict = await c
      .post('/api/v1/orgs', { name: 'Other Org' })
      .set(IDEMPOTENCY_HEADER, 'key-123');
    expectError(conflict, 'LSE-VAL-004', 409);
    expect(await prisma.organization.count()).toBe(1);

    // Keys are scoped per user.
    const other = await login(app);
    const theirs = await other
      .post('/api/v1/orgs', { name: 'Idem Org' })
      .set(IDEMPOTENCY_HEADER, 'key-123');
    expect(theirs.status).toBe(201);
    expect(theirs.headers['idempotent-replayed']).toBeUndefined();
    expect(await prisma.organization.count()).toBe(2);
  });

  it('failed requests are not stored; invalid keys are rejected', async () => {
    const c = await login(app);
    expectError(
      await c.post('/api/v1/orgs', { name: '' }).set(IDEMPOTENCY_HEADER, 'k2'),
      'LSE-VAL-001',
      400,
    );
    expect(
      (await c.post('/api/v1/orgs', { name: 'Fixed' }).set(IDEMPOTENCY_HEADER, 'k2')).status,
    ).toBe(201);
    expectError(
      await c.post('/api/v1/orgs', { name: 'X' }).set(IDEMPOTENCY_HEADER, 'bad key!'),
      'LSE-VAL-001',
      400,
    );
  });

  it('replays one-time secrets (invite token) without storing them in plaintext', async () => {
    const stored: string[] = [];
    class RecordingKv extends MemoryKvStore {
      override async set(key: string, value: string, ttl: number) {
        stored.push(value);
        return super.set(key, value, ttl);
      }
    }
    const { app: app2 } = makeApp({ context: { kv: new RecordingKv() } });
    const c = await login(app2);
    const org = await createOrg(c);
    const first = await c
      .post(`/api/v1/orgs/${org.id}/invites`, { role: 'MEMBER' })
      .set(IDEMPOTENCY_HEADER, 'inv-1');
    const replay = await c
      .post(`/api/v1/orgs/${org.id}/invites`, { role: 'MEMBER' })
      .set(IDEMPOTENCY_HEADER, 'inv-1');
    expect(replay.headers['idempotent-replayed']).toBe('true');
    expect(replay.body.data.token).toBe(first.body.data.token);
    expect(await prisma.orgInvite.count()).toBe(1);
    expect(stored.length).toBeGreaterThan(0);
    for (const v of stored) expect(v).not.toContain(first.body.data.token as string);
  });
});

describe('personal API tokens', () => {
  it('create (raw shown once) → Bearer auth works → delete revokes', async () => {
    const c = await login(app);
    const org = await createOrg(c);
    const created = await c.post('/api/v1/users/me/tokens', {
      orgId: org.id,
      name: 'CI',
      scopes: ['org:read', 'projects:read'],
      expiresInDays: 30,
    });
    expect(created.status).toBe(201);
    const token = created.body.data.token as string;
    expect(token.startsWith(PAT_PREFIX)).toBe(true);
    expect(await prisma.apiToken.count({ where: { hash: sha256Hex(token) } })).toBe(1);
    const list = await c.get('/api/v1/users/me/tokens');
    expect(JSON.stringify(list.body)).not.toContain(token);
    expect(JSON.stringify(list.body)).not.toContain(sha256Hex(token));

    const me = await request(app).get('/api/v1/auth/me').set('Authorization', `Bearer ${token}`);
    expect(me.status).toBe(200);
    expect(me.body.data.id).toBe(c.user.id);
    expect(
      (await request(app).get(`/api/v1/orgs/${org.id}`).set('Authorization', `Bearer ${token}`))
        .status,
    ).toBe(200);
    expect((await prisma.apiToken.findFirstOrThrow()).lastUsedAt).not.toBeNull();

    // Bearer requests skip CSRF but tokens can't mint credentials or write.
    expectError(
      await request(app)
        .post('/api/v1/users/me/tokens')
        .set('Authorization', `Bearer ${token}`)
        .send({ orgId: org.id, name: 'x', scopes: ['org:read'] }),
      'LSE-AUTH-001',
      401,
    );
    expectError(
      await request(app)
        .put(`/api/v1/orgs/${org.id}`)
        .set('Authorization', `Bearer ${token}`)
        .send({ name: 'x' }),
      'LSE-ORG-002',
      403,
    );
    // Tokens are bound to their org.
    const otherOrg = await createOrg(c);
    expectError(
      await request(app).get(`/api/v1/orgs/${otherOrg.id}`).set('Authorization', `Bearer ${token}`),
      'LSE-ORG-001',
      403,
    );

    expect((await c.delete(`/api/v1/users/me/tokens/${created.body.data.id}`)).status).toBe(204);
    expectError(
      await request(app).get('/api/v1/auth/me').set('Authorization', `Bearer ${token}`),
      'LSE-AUTH-007',
      401,
    );
  });

  it('invalid / malformed / expired PAT → LSE-AUTH-007', async () => {
    expectError(
      await request(app).get('/api/v1/auth/me').set('Authorization', `Bearer ${PAT_PREFIX}nope`),
      'LSE-AUTH-007',
      401,
    );
    expectError(
      await request(app).get('/api/v1/auth/me').set('Authorization', 'Bearer something-else'),
      'LSE-AUTH-007',
      401,
    );
    const c = await login(app);
    const org = await createOrg(c);
    const { token } = (
      await c.post('/api/v1/users/me/tokens', { orgId: org.id, name: 'old', scopes: ['org:read'] })
    ).body.data;
    await prisma.apiToken.updateMany({ data: { expiresAt: new Date(Date.now() - 1000) } });
    expectError(
      await request(app).get('/api/v1/auth/me').set('Authorization', `Bearer ${token}`),
      'LSE-AUTH-007',
      401,
    );
  });

  it('token for an org you are not in → LSE-ORG-001 / unknown org → LSE-ORG-003', async () => {
    const a = await login(app);
    const b = await login(app);
    const orgB = await createOrg(b);
    expectError(
      await a.post('/api/v1/users/me/tokens', { orgId: orgB.id, name: 'x', scopes: ['org:read'] }),
      'LSE-ORG-001',
      403,
    );
    expectError(
      await a.post('/api/v1/users/me/tokens', { orgId: 'nope', name: 'x', scopes: ['org:read'] }),
      'LSE-ORG-003',
      404,
    );
  });

  it('removing a member deletes their tokens for that org', async () => {
    const owner = await login(app);
    const org = await createOrg(owner);
    const m = await login(app);
    await addMember(org.id, m.user.id, 'MEMBER');
    const { token } = (
      await m.post('/api/v1/users/me/tokens', { orgId: org.id, name: 't', scopes: ['org:read'] })
    ).body.data;
    expect((await owner.delete(`/api/v1/orgs/${org.id}/members/${m.user.id}`)).status).toBe(204);
    expectError(
      await request(app).get('/api/v1/auth/me').set('Authorization', `Bearer ${token}`),
      'LSE-AUTH-007',
      401,
    );
  });
});
