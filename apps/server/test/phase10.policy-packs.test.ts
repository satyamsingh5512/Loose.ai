/**
 * Phase 10 (W2): policy packs — built-ins, org-defined packs (CRUD), applying them to project
 * guardrails (tighten-only merge, copy-on-apply, atomic, audited) and the role matrix.
 */
import request from 'supertest';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { BUILTIN_POLICY_PACKS, applyPolicyPack, builtinPolicyPackId } from '@loose/shared';
import { addMember, createOrg, expectError, login, makeApp, resetDb, testPrisma } from './helpers';
import { createReadyProject } from './sessionHelpers';

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

const base = (orgId: string, path = '') => `/api/v1/orgs/${orgId}/policy-packs${path}`;

async function setup() {
  const owner = await login(app);
  const org = await createOrg(owner);
  const admin = await login(app);
  await addMember(org.id, admin.user.id, 'ADMIN');
  const member = await login(app);
  await addMember(org.id, member.user.id, 'MEMBER');
  const viewer = await login(app);
  await addMember(org.id, viewer.user.id, 'VIEWER');
  return { owner, admin, member, viewer, org };
}

const project = (orgId: string, over: Record<string, unknown> = {}) =>
  createReadyProject(ctx, orgId, {
    allowedFilePatterns: ['src/**'],
    deniedFilePatterns: ['secrets/**'],
    commandPolicy: { allow: ['npm test'], deny: ['rm -rf *'] },
    approvalGates: { dependencies: false, migrations: false, deletes: true },
    networkAllowlist: ['registry.npmjs.org'],
    maxBudgetUsd: 5,
    maxSessionDurationMin: 90,
    planMode: 'OFF',
    ...over,
  });

const guardrails = async (id: string) => {
  const p = await prisma.project.findUniqueOrThrow({ where: { id } });
  return {
    allowed: p.allowedFilePatterns,
    denied: p.deniedFilePatterns,
    commands: p.commandPolicy,
    gates: p.approvalGates,
    network: p.networkAllowlist,
    budget: Number(p.maxBudgetUsd),
    minutes: p.maxSessionDurationMin,
    plan: p.planMode,
    applied: p.appliedPolicyPacks as {
      packId: string;
      slug: string;
      version: number;
      appliedById: string;
    }[],
  };
};

describe('listing and reading', () => {
  it('lists the four built-in packs (read-only, ids builtin:<slug>) plus org packs', async () => {
    const { admin, org } = await setup();
    const custom = await admin.post(base(org.id), {
      name: 'Docs only',
      rules: { allowedFilePatterns: ['docs/**'] },
    });
    const res = await admin.get(base(org.id));
    expect(res.status).toBe(200);
    expect(res.body.nextCursor).toBeNull();
    const packs = res.body.data as {
      id: string;
      builtin: boolean;
      slug: string;
      appliedProjectCount: number;
    }[];
    expect(packs.filter((p) => p.builtin).map((p) => p.id)).toEqual(
      BUILTIN_POLICY_PACKS.map((b) => builtinPolicyPackId(b.slug)),
    );
    expect(packs.filter((p) => p.builtin).every((p) => p.appliedProjectCount === 0)).toBe(true);
    expect(packs.find((p) => !p.builtin)).toMatchObject({
      id: custom.body.data.id,
      slug: 'docs-only',
    });
    expect(BUILTIN_POLICY_PACKS.map((b) => b.slug).sort()).toEqual([
      'marketing-site-only',
      'no-dependency-changes',
      'protect-infrastructure',
      'strict-review',
    ]);
  });

  it("reads a built-in or custom pack; unknown ids and other orgs' packs are LSE-NF-001", async () => {
    const a = await setup();
    const b = await setup();
    const mine = await a.admin.post(base(a.org.id), { name: 'Mine', rules: { maxBudgetUsd: 1 } });
    const builtin = await a.admin.get(base(a.org.id, '/builtin:strict-review'));
    expect(builtin.body.data).toMatchObject({
      id: 'builtin:strict-review',
      builtin: true,
      orgId: null,
      createdAt: null,
      rules: { planMode: 'ALWAYS' },
    });
    expect((await a.admin.get(base(a.org.id, `/${mine.body.data.id}`))).body.data.name).toBe(
      'Mine',
    );
    expectError(await a.admin.get(base(a.org.id, '/builtin:nope')), 'LSE-NF-001', 404);
    expectError(await a.admin.get(base(a.org.id, '/unknownid123')), 'LSE-NF-001', 404);
    expectError(await b.admin.get(base(b.org.id, `/${mine.body.data.id}`)), 'LSE-NF-001', 404);
  });
});

describe('authorization', () => {
  it('ADMIN+ only: members, viewers and outsiders are refused, tokens cannot write', async () => {
    const { owner, admin, member, viewer, org } = await setup();
    const body = { name: 'X pack', rules: { maxBudgetUsd: 2 } };
    for (const c of [owner, admin]) expect((await c.get(base(org.id))).status).toBe(200);
    for (const c of [member, viewer]) {
      expectError(await c.get(base(org.id)), 'LSE-ORG-002', 403);
      expectError(await c.post(base(org.id), body), 'LSE-ORG-002', 403);
      expectError(
        await c.put(base(org.id, '/builtin:strict-review'), { name: 'n' }),
        'LSE-ORG-002',
        403,
      );
      expectError(await c.delete(base(org.id, '/abc')), 'LSE-ORG-002', 403);
      expectError(
        await c.post(base(org.id, '/builtin:strict-review/apply'), { projectIds: ['x'] }),
        'LSE-ORG-002',
        403,
      );
    }
    const outsider = await login(app);
    expectError(await outsider.get(base(org.id)), 'LSE-ORG-001', 403);
    expectError(await request(app).get(base(org.id)), 'LSE-AUTH-001', 401);

    const minted = await admin.post('/api/v1/users/me/tokens', {
      orgId: org.id,
      name: 'ci',
      scopes: ['org:read'],
    });
    const bearer = `Bearer ${minted.body.data.token as string}`;
    expect((await request(app).get(base(org.id)).set('Authorization', bearer)).status).toBe(200);
    expectError(
      await request(app).post(base(org.id)).set('Authorization', bearer).send(body),
      'LSE-ORG-002',
      403,
    );
  });

  it('is switched off by the policy_packs flag (LSE-SYS-007)', async () => {
    const off = makeApp({ env: { FEATURE_FLAGS: 'policy_packs=off' } });
    const owner = await login(off.app);
    const org = await createOrg(owner);
    expectError(await owner.get(base(org.id)), 'LSE-SYS-007', 503);
    await off.ctx.jobs.onIdle();
  });
});

describe('creating, updating, deleting org packs', () => {
  it('creates a pack (slug from the name or given), audits it and supports Idempotency-Key', async () => {
    const { admin, org } = await setup();
    const rules = { deniedFilePatterns: ['infra/**'], approvalGates: { migrations: true } };
    const first = await admin
      .post(base(org.id), { name: 'No Infra!', description: 'keep out', rules })
      .set('Idempotency-Key', 'k1');
    expect(first.status).toBe(201);
    expect(first.body.data).toMatchObject({
      builtin: false,
      orgId: org.id,
      slug: 'no-infra',
      name: 'No Infra!',
      description: 'keep out',
      version: 1,
      rules,
      appliedProjectCount: 0,
    });
    const replay = await admin
      .post(base(org.id), { name: 'No Infra!', description: 'keep out', rules })
      .set('Idempotency-Key', 'k1');
    expect(replay.headers['idempotent-replayed']).toBe('true');
    expect(await prisma.policyPack.count()).toBe(1);

    const explicit = await admin.post(base(org.id), {
      name: 'Other',
      slug: 'custom-slug',
      rules: { maxBudgetUsd: 3 },
    });
    expect(explicit.body.data.slug).toBe('custom-slug');

    const entry = await prisma.auditLog.findFirstOrThrow({
      where: { orgId: org.id, action: 'policy_pack.create' },
      orderBy: { createdAt: 'asc' },
    });
    expect(entry).toMatchObject({ actorId: admin.user.id, target: first.body.data.id });
    expect(entry.meta).toMatchObject({ slug: 'no-infra', rules });
  });

  it('rejects invalid input (LSE-VAL-001): empty/unknown/bad rules, bad slug, duplicates, built-in slugs', async () => {
    const { admin, org } = await setup();
    const ok = { name: 'Valid', rules: { maxBudgetUsd: 2 } };
    for (const bad of [
      { name: '', rules: { maxBudgetUsd: 2 } },
      { name: 'No rules', rules: {} },
      { name: 'Unknown', rules: { somethingElse: true } },
      { name: 'Neg', rules: { maxBudgetUsd: -1 } },
      { name: 'Huge', rules: { maxBudgetUsd: 5000 } },
      { name: 'Short', rules: { maxSessionDurationMin: 1 } },
      { name: 'Host', rules: { networkAllowlist: ['not a host!'] } },
      { name: 'Plan', rules: { planMode: 'SOMETIMES' } },
      { name: 'Slug', slug: 'Bad Slug', rules: { maxBudgetUsd: 2 } },
      { name: 'Slug2', slug: 'ab', rules: { maxBudgetUsd: 2 } },
      { rules: { maxBudgetUsd: 2 } },
      { ...ok, extra: 1 },
    ]) {
      expectError(await admin.post(base(org.id), bad), 'LSE-VAL-001', 400);
    }
    expect((await admin.post(base(org.id), ok)).status).toBe(201);
    const dup = await admin.post(base(org.id), ok);
    expectError(dup, 'LSE-VAL-001', 400);
    expect(dup.body.error.fields.slug).toBeDefined();
    const builtinClash = await admin.post(base(org.id), {
      name: 'Strict review',
      rules: { maxBudgetUsd: 1 },
    });
    expectError(builtinClash, 'LSE-VAL-001', 400);
    // the same slug in a different org is fine
    const other = await setup();
    expect((await other.admin.post(base(other.org.id), ok)).status).toBe(201);
  });

  it('updates metadata without a version bump, rules with one; audits the change', async () => {
    const { admin, org } = await setup();
    const created = await admin.post(base(org.id), { name: 'P', rules: { maxBudgetUsd: 4 } });
    const id = created.body.data.id as string;
    const renamed = await admin.put(base(org.id, `/${id}`), { name: 'Renamed', description: 'd' });
    expect(renamed.body.data).toMatchObject({
      name: 'Renamed',
      description: 'd',
      version: 1,
      slug: 'p-org',
    });
    const reruled = await admin.put(base(org.id, `/${id}`), {
      rules: { maxBudgetUsd: 2, planMode: 'ALWAYS' },
    });
    expect(reruled.body.data).toMatchObject({
      version: 2,
      rules: { maxBudgetUsd: 2, planMode: 'ALWAYS' },
    });
    const entry = await prisma.auditLog.findFirstOrThrow({
      where: { orgId: org.id, action: 'policy_pack.update' },
      orderBy: { createdAt: 'desc' },
    });
    expect(entry.meta).toMatchObject({
      version: { from: 1, to: 2 },
      rules: { before: { maxBudgetUsd: 4 }, after: { maxBudgetUsd: 2 } },
    });
    expectError(await admin.put(base(org.id, `/${id}`), {}), 'LSE-VAL-001', 400);
    expectError(await admin.put(base(org.id, `/${id}`), { rules: {} }), 'LSE-VAL-001', 400);
    expectError(await admin.put(base(org.id, '/missing'), { name: 'x' }), 'LSE-NF-001', 404);
  });

  it("deletes org packs (audited); built-ins are read-only; other orgs' packs are not reachable", async () => {
    const a = await setup();
    const b = await setup();
    const created = await a.admin.post(base(a.org.id), {
      name: 'Temp',
      rules: { maxBudgetUsd: 1 },
    });
    const id = created.body.data.id as string;
    expectError(await b.admin.delete(base(b.org.id, `/${id}`)), 'LSE-NF-001', 404);
    expectError(await b.admin.put(base(b.org.id, `/${id}`), { name: 'hijack' }), 'LSE-NF-001', 404);
    expectError(await a.admin.delete(base(a.org.id, '/builtin:strict-review')), 'LSE-VAL-001', 400);
    expectError(
      await a.admin.put(base(a.org.id, '/builtin:strict-review'), { name: 'x' }),
      'LSE-VAL-001',
      400,
    );
    expect((await a.admin.delete(base(a.org.id, `/${id}`))).status).toBe(204);
    expect(await prisma.policyPack.count()).toBe(0);
    expectError(await a.admin.delete(base(a.org.id, `/${id}`)), 'LSE-NF-001', 404);
    expect(
      await prisma.auditLog.count({ where: { orgId: a.org.id, action: 'policy_pack.delete' } }),
    ).toBe(1);
  });
});

describe('applying packs to projects', () => {
  it('merges a built-in pack into the guardrails and records it on the project', async () => {
    const { admin, org } = await setup();
    const p = await project(org.id);
    const res = await admin.post(base(org.id, '/builtin:no-dependency-changes/apply'), {
      projectIds: [p.id],
    });
    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({ packId: 'builtin:no-dependency-changes', version: 1 });
    expect(res.body.data.applied).toHaveLength(1);
    expect(res.body.data.applied[0].projectId).toBe(p.id);
    expect(res.body.data.applied[0].changed.sort()).toEqual([
      'approvalGates',
      'commandPolicy',
      'deniedFilePatterns',
    ]);

    const g = await guardrails(p.id);
    expect(g.denied).toEqual(
      expect.arrayContaining(['secrets/**', '**/package.json', '**/bun.lock']),
    );
    expect(g.denied[0]).toBe('secrets/**'); // existing entries kept, in place
    expect((g.commands as { deny: string[]; allow: string[] }).deny).toEqual(
      expect.arrayContaining(['rm -rf *', 'npm install*']),
    );
    expect((g.commands as { allow: string[] }).allow).toEqual(['npm test']); // not set by the pack → kept
    expect(g.gates).toMatchObject({ dependencies: true, migrations: false, deletes: true });
    expect(g.allowed).toEqual(['src/**']);
    expect(g.applied).toHaveLength(1);
    expect(g.applied[0]).toMatchObject({
      packId: 'builtin:no-dependency-changes',
      slug: 'no-dependency-changes',
      version: 1,
      appliedById: admin.user.id,
    });

    // visible through the project API
    const dto = await admin.get(`/api/v1/orgs/${org.id}/projects/${p.id}`);
    expect(dto.body.data.appliedPolicyPacks[0]).toMatchObject({
      slug: 'no-dependency-changes',
      name: 'No dependency changes',
    });
    expect(dto.body.data.deniedFilePatterns).toContain('**/package.json');
  });

  it('only ever tightens: budgets/durations take the minimum, plan mode the strictest, gates stay on', async () => {
    const { admin, org } = await setup();
    const loose = await project(org.id); // budget 5, 90 min, plan OFF, deps gate off
    const tight = await project(org.id, {
      maxBudgetUsd: 1,
      maxSessionDurationMin: 30,
      planMode: 'ALWAYS',
      approvalGates: { dependencies: true, migrations: true, deletes: true },
    });
    const res = await admin.post(base(org.id, '/builtin:strict-review/apply'), {
      projectIds: [loose.id, tight.id],
    });
    expect(res.body.data.applied.map((a: { projectId: string }) => a.projectId)).toEqual([
      loose.id,
      tight.id,
    ]);
    expect(res.body.data.applied[0].changed.sort()).toEqual([
      'approvalGates',
      'maxBudgetUsd',
      'maxSessionDurationMin',
      'planMode',
    ]);
    expect(res.body.data.applied[1].changed).toEqual([]);

    expect(await guardrails(loose.id)).toMatchObject({
      budget: 2,
      minutes: 60,
      plan: 'ALWAYS',
      gates: { dependencies: true, migrations: true, deletes: true },
    });
    expect(await guardrails(tight.id)).toMatchObject({ budget: 1, minutes: 30, plan: 'ALWAYS' });
  });

  it('replaces allowed patterns / allow-lists / network allow-list when a pack sets them (marketing pack)', async () => {
    const { admin, org } = await setup();
    const p = await project(org.id);
    await admin.post(base(org.id, '/builtin:marketing-site-only/apply'), { projectIds: [p.id] });
    const g = await guardrails(p.id);
    expect(g.allowed).not.toContain('src/**');
    expect(g.allowed).toEqual(expect.arrayContaining(['**/*.md', 'content/**', 'public/**']));
    expect(g.denied).toEqual(
      expect.arrayContaining(['secrets/**', '**/package.json', '.github/**', '**/.env']),
    );
    expect(g.gates).toMatchObject({ dependencies: true, migrations: true, deletes: true });
    expect(g.network).toEqual(['registry.npmjs.org']); // untouched: pack doesn't set it

    const custom = await admin.post(base(org.id), {
      name: 'Net',
      rules: {
        networkAllowlist: ['api.example.com', '*.cdn.example.com'],
        commandPolicy: { allow: ['pnpm test'] },
      },
    });
    await admin.post(base(org.id, `/${custom.body.data.id}/apply`), { projectIds: [p.id] });
    expect(await guardrails(p.id)).toMatchObject({
      network: ['api.example.com', '*.cdn.example.com'],
      commands: { allow: ['pnpm test'], deny: ['rm -rf *'] },
    });
  });

  it('matches the pure merge in @loose/shared for every built-in pack', async () => {
    const { admin, org } = await setup();
    for (const b of BUILTIN_POLICY_PACKS) {
      const p = await project(org.id);
      const before = await prisma.project.findUniqueOrThrow({ where: { id: p.id } });
      await admin.post(base(org.id, `/${builtinPolicyPackId(b.slug)}/apply`), {
        projectIds: [p.id],
      });
      const expected = applyPolicyPack(
        {
          allowedFilePatterns: before.allowedFilePatterns,
          deniedFilePatterns: before.deniedFilePatterns,
          commandPolicy: before.commandPolicy as { allow: string[]; deny: string[] },
          approvalGates: before.approvalGates as {
            dependencies: boolean;
            migrations: boolean;
            deletes: boolean;
          },
          networkAllowlist: before.networkAllowlist,
          maxBudgetUsd: Number(before.maxBudgetUsd),
          maxSessionDurationMin: before.maxSessionDurationMin,
          planMode: before.planMode as 'OFF',
        },
        b.rules,
      ).guardrails;
      const after = await guardrails(p.id);
      expect(after.allowed, b.slug).toEqual(expected.allowedFilePatterns);
      expect(after.denied, b.slug).toEqual(expected.deniedFilePatterns);
      expect(after.commands, b.slug).toEqual(expected.commandPolicy);
      expect(after.gates, b.slug).toEqual(expected.approvalGates);
      expect(after.budget, b.slug).toBe(expected.maxBudgetUsd);
      expect(after.minutes, b.slug).toBe(expected.maxSessionDurationMin);
      expect(after.plan, b.slug).toBe(expected.planMode);
    }
  });

  it("re-applying replaces the pack's entry (no duplicates) and reports no changes; packs accumulate", async () => {
    const { admin, org } = await setup();
    const p = await project(org.id);
    const url = (slug: string) => base(org.id, `/builtin:${slug}/apply`);
    await admin.post(url('strict-review'), { projectIds: [p.id] });
    const again = await admin.post(url('strict-review'), { projectIds: [p.id] });
    expect(again.body.data.applied[0].changed).toEqual([]);
    await admin.post(url('protect-infrastructure'), { projectIds: [p.id] });
    const g = await guardrails(p.id);
    expect(g.applied.map((a) => a.packId)).toEqual([
      'builtin:strict-review',
      'builtin:protect-infrastructure',
    ]);
    const listed = (await admin.get(base(org.id))).body.data as {
      id: string;
      appliedProjectCount: number;
    }[];
    expect(listed.find((x) => x.id === 'builtin:strict-review')?.appliedProjectCount).toBe(1);
    expect(listed.find((x) => x.id === 'builtin:marketing-site-only')?.appliedProjectCount).toBe(0);
  });

  it('is copy-on-apply: later edits of a pack do not touch projects until it is applied again', async () => {
    const { admin, org } = await setup();
    const p = await project(org.id);
    const created = await admin.post(base(org.id), { name: 'Budget', rules: { maxBudgetUsd: 3 } });
    const id = created.body.data.id as string;
    await admin.post(base(org.id, `/${id}/apply`), { projectIds: [p.id] });
    expect(await guardrails(p.id)).toMatchObject({ budget: 3 });
    await admin.put(base(org.id, `/${id}`), { rules: { maxBudgetUsd: 1 } });
    const stale = await guardrails(p.id);
    expect(stale.budget).toBe(3);
    expect(stale.applied[0]).toMatchObject({ packId: id, version: 1 });
    const res = await admin.post(base(org.id, `/${id}/apply`), { projectIds: [p.id] });
    expect(res.body.data.version).toBe(2);
    expect(await guardrails(p.id)).toMatchObject({ budget: 1 });
    expect((await guardrails(p.id)).applied).toHaveLength(1);
    // deleting the pack leaves the project's guardrails and history alone
    await admin.delete(base(org.id, `/${id}`));
    expect(await guardrails(p.id)).toMatchObject({ budget: 1 });
  });

  it('is atomic and tenant-safe: a foreign or unknown project fails the whole request', async () => {
    const a = await setup();
    const b = await setup();
    const mine = await project(a.org.id);
    const foreign = await project(b.org.id);
    for (const ids of [[mine.id, foreign.id], [foreign.id], [mine.id, 'ghost-project-id']]) {
      expectError(
        await a.admin.post(base(a.org.id, '/builtin:strict-review/apply'), { projectIds: ids }),
        'LSE-NF-001',
        404,
      );
    }
    expect(await guardrails(mine.id)).toMatchObject({ plan: 'OFF', budget: 5, applied: [] });
    expect(await guardrails(foreign.id)).toMatchObject({ plan: 'OFF', applied: [] });
    expect(await prisma.auditLog.count({ where: { action: 'policy_pack.apply' } })).toBe(0);
    // another org's custom pack can't be applied here either
    const theirPack = await b.admin.post(base(b.org.id), {
      name: 'Theirs',
      rules: { maxBudgetUsd: 1 },
    });
    expectError(
      await a.admin.post(base(a.org.id, `/${theirPack.body.data.id}/apply`), {
        projectIds: [mine.id],
      }),
      'LSE-NF-001',
      404,
    );
    expectError(
      await a.admin.post(base(a.org.id, '/builtin:ghost/apply'), { projectIds: [mine.id] }),
      'LSE-NF-001',
      404,
    );
  });

  it('validates the project list (LSE-VAL-001) and audits applications', async () => {
    const { admin, org } = await setup();
    const p = await project(org.id);
    const url = base(org.id, '/builtin:strict-review/apply');
    expectError(await admin.post(url, { projectIds: [] }), 'LSE-VAL-001', 400);
    expectError(await admin.post(url, { projectIds: [p.id, p.id] }), 'LSE-VAL-001', 400);
    expectError(await admin.post(url, {}), 'LSE-VAL-001', 400);
    expectError(await admin.post(url, { projectIds: [p.id], extra: true }), 'LSE-VAL-001', 400);
    await admin.post(url, { projectIds: [p.id] });
    const entry = await prisma.auditLog.findFirstOrThrow({
      where: { orgId: org.id, action: 'policy_pack.apply' },
    });
    expect(entry).toMatchObject({ actorId: admin.user.id, target: 'builtin:strict-review' });
    expect(entry.meta).toMatchObject({
      slug: 'strict-review',
      version: 1,
      projects: [{ projectId: p.id, changed: expect.arrayContaining(['planMode']) }],
    });
  });
});
