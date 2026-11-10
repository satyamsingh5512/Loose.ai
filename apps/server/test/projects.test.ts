import { createHmac } from 'node:crypto';
import { http, HttpResponse } from 'msw';
import request from 'supertest';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { decryptProjectEnv } from '../src/services/project.service';
import {
  addMember,
  createMswServer,
  createOrg,
  expectError,
  GITHUB_API,
  githubRepoHandler,
  githubRepoJson,
  linkGithub,
  login,
  makeApp,
  onUnhandled,
  resetDb,
  TEST_SECRETS,
  testPrisma,
} from './helpers';

const server = createMswServer();
const prisma = testPrisma();
const { app, ctx } = makeApp();

beforeAll(() => server.listen({ onUnhandledRequest: onUnhandled }));
afterEach(() => server.resetHandlers());
afterAll(async () => {
  server.close();
  await prisma.$disconnect();
});
beforeEach(() => resetDb());

const SECRET_VALUE = 'postgres://user:hunter2-very-secret@db/app';

async function adminWithGithub() {
  const admin = await login(app);
  await linkGithub(ctx, admin.user.id);
  const org = await createOrg(admin);
  return { admin, org };
}

describe('projects', () => {
  it('create validates the repo via GitHub and never returns env var values', async () => {
    const { admin, org } = await adminWithGithub();
    let authHeader = '';
    server.use(
      http.get(`${GITHUB_API}/repos/acme/web`, ({ request: req }) => {
        authHeader = req.headers.get('authorization') ?? '';
        return HttpResponse.json(githubRepoJson('Acme/web', { default_branch: 'develop' }));
      }),
    );
    const res = await admin.post(`/api/v1/orgs/${org.id}/projects`, {
      name: 'Web',
      githubRepoFullName: 'acme/web',
      envVars: { DATABASE_URL: SECRET_VALUE, PUBLIC_FLAG: 'on' },
      secretEnvVars: ['DATABASE_URL'],
      requiredServices: ['postgresql', 'redis'],
      portMap: [{ name: 'web', port: 3000, public: true }],
    });
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    expect(authHeader).toMatch(/^(token|bearer) gho_/i);
    const p = res.body.data;
    expect(p).toMatchObject({
      name: 'Web',
      githubRepoFullName: 'Acme/web',
      githubRepoUrl: 'https://github.com/Acme/web',
      defaultBranch: 'develop',
      templateStatus: 'PENDING',
      maxBudgetUsd: 5,
      maxSessionDurationMin: 60,
      approvalGates: { dependencies: true, migrations: true, deletes: true },
      envVarNames: [
        { name: 'DATABASE_URL', secret: true },
        { name: 'PUBLIC_FLAG', secret: false },
      ],
      hasMemory: false,
    });
    const responses = [
      res,
      await admin.get(`/api/v1/orgs/${org.id}/projects`),
      await admin.get(`/api/v1/orgs/${org.id}/projects/${p.id}`),
    ];
    for (const r of responses) {
      const text = JSON.stringify(r.body);
      expect(text).not.toContain('hunter2');
      expect(text).not.toContain('"on"');
      expect(text).not.toContain('envVarsEnc');
    }
    const row = await prisma.project.findUniqueOrThrow({ where: { id: p.id } });
    expect(Buffer.from(row.envVarsEnc).toString('latin1')).not.toContain('hunter2');
    expect(await decryptProjectEnv(ctx, row)).toEqual({
      DATABASE_URL: SECRET_VALUE,
      PUBLIC_FLAG: 'on',
    });
    const audit = await prisma.auditLog.findFirstOrThrow({ where: { action: 'project.create' } });
    expect(JSON.stringify(audit.meta)).not.toContain('hunter2');
  });

  it('repo not found on GitHub → LSE-GH-003; nothing created', async () => {
    const { admin, org } = await adminWithGithub();
    server.use(
      http.get(`${GITHUB_API}/repos/acme/missing`, () =>
        HttpResponse.json({ message: 'Not Found' }, { status: 404 }),
      ),
    );
    const res = await admin.post(`/api/v1/orgs/${org.id}/projects`, {
      name: 'X',
      githubRepoFullName: 'acme/missing',
    });
    expectError(res, 'LSE-GH-003', 404);
    expect(await prisma.project.count()).toBe(0);
  });

  it('admin without a linked GitHub account → LSE-GH-001 with reconnect action', async () => {
    const admin = await login(app);
    const org = await createOrg(admin);
    const res = await admin.post(`/api/v1/orgs/${org.id}/projects`, {
      name: 'X',
      githubRepoFullName: 'acme/web',
    });
    expectError(res, 'LSE-GH-001', 401);
    expect(res.body.error.action).toMatchObject({ href: '/api/v1/auth/github?link=1' });
  });

  it('validation: secretEnvVars must exist in envVars; unknown fields rejected', async () => {
    const { admin, org } = await adminWithGithub();
    const res = await admin.post(`/api/v1/orgs/${org.id}/projects`, {
      name: 'X',
      githubRepoFullName: 'acme/web',
      envVars: { A: '1' },
      secretEnvVars: ['B'],
    });
    expectError(res, 'LSE-VAL-001', 400);
    expect(res.body.error.fields['secretEnvVars.0']).toBeDefined();
    expectError(
      await admin.post(`/api/v1/orgs/${org.id}/projects`, {
        name: 'X',
        githubRepoFullName: 'acme/web',
        requiredServices: ['oracle'],
      }),
      'LSE-VAL-001',
      400,
    );
  });

  it('update merges env vars (null deletes) and keeps secret flags; repo is immutable', async () => {
    const { admin, org } = await adminWithGithub();
    server.use(githubRepoHandler('acme/web'));
    const created = await admin.post(`/api/v1/orgs/${org.id}/projects`, {
      name: 'Web',
      githubRepoFullName: 'acme/web',
      envVars: { A: 'secret-a', B: 'b' },
      secretEnvVars: ['A'],
    });
    const id = created.body.data.id as string;
    const url = `/api/v1/orgs/${org.id}/projects/${id}`;
    const res = await admin.put(url, {
      envVars: { B: null, C: 'c-value' },
      maxBudgetUsd: 12.5,
      healthCheck: { path: '/health', port: 3000 },
    });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.data.envVarNames).toEqual([
      { name: 'A', secret: true },
      { name: 'C', secret: false },
    ]);
    expect(res.body.data).toMatchObject({
      maxBudgetUsd: 12.5,
      healthCheck: { path: '/health', port: 3000, timeoutSec: 60 },
    });
    expect(
      await decryptProjectEnv(ctx, await prisma.project.findUniqueOrThrow({ where: { id } })),
    ).toEqual({ A: 'secret-a', C: 'c-value' });

    const flags = await admin.put(url, { secretEnvVars: ['C'], healthCheck: null });
    expect(flags.body.data.envVarNames).toEqual([
      { name: 'A', secret: false },
      { name: 'C', secret: true },
    ]);
    expect(flags.body.data.healthCheck).toBeNull();
    expectError(await admin.put(url, { secretEnvVars: ['NOPE'] }), 'LSE-VAL-001', 400);
    expectError(await admin.put(url, { githubRepoFullName: 'other/repo' }), 'LSE-VAL-001', 400);
    expectError(await admin.put(url, {}), 'LSE-VAL-001', 400);
    expect(JSON.stringify(flags.body)).not.toContain('secret-a');
  });

  it('members and viewers only see READY projects; admins see all', async () => {
    const { admin, org } = await adminWithGithub();
    server.use(githubRepoHandler('acme/one'), githubRepoHandler('acme/two'));
    const pending = (
      await admin.post(`/api/v1/orgs/${org.id}/projects`, {
        name: 'Pending',
        githubRepoFullName: 'acme/one',
      })
    ).body.data;
    const ready = (
      await admin.post(`/api/v1/orgs/${org.id}/projects`, {
        name: 'Ready',
        githubRepoFullName: 'acme/two',
      })
    ).body.data;
    await prisma.project.update({ where: { id: ready.id }, data: { templateStatus: 'READY' } });

    expect((await admin.get(`/api/v1/orgs/${org.id}/projects`)).body.data).toHaveLength(2);
    for (const role of ['MEMBER', 'VIEWER'] as const) {
      const u = await login(app);
      await addMember(org.id, u.user.id, role);
      const list = await u.get(`/api/v1/orgs/${org.id}/projects`);
      expect(list.body.data.map((p: { name: string }) => p.name)).toEqual(['Ready']);
      expect((await u.get(`/api/v1/orgs/${org.id}/projects/${ready.id}`)).status).toBe(200);
      expectError(await u.get(`/api/v1/orgs/${org.id}/projects/${pending.id}`), 'LSE-NF-001', 404);
    }
  });

  it('memory GET/PUT and delete', async () => {
    const { admin, org } = await adminWithGithub();
    server.use(githubRepoHandler('acme/web'));
    const id = (
      await admin.post(`/api/v1/orgs/${org.id}/projects`, {
        name: 'Web',
        githubRepoFullName: 'acme/web',
      })
    ).body.data.id;
    const url = `/api/v1/orgs/${org.id}/projects/${id}`;
    expect((await admin.get(`${url}/memory`)).body.data).toEqual({
      looseMd: null,
      componentLabels: {},
    });
    const put = await admin.put(`${url}/memory`, {
      looseMd: '# Project',
      componentLabels: { 'src/billing/**': 'Billing' },
    });
    expect(put.body.data).toEqual({
      looseMd: '# Project',
      componentLabels: { 'src/billing/**': 'Billing' },
    });
    expect((await admin.get(url)).body.data.hasMemory).toBe(true);
    const b64 = (t: string) => Buffer.from(t).toString('base64');
    const files: Record<string, string> = {
      'package.json': JSON.stringify({
        scripts: { dev: 'vite', build: 'vite build', test: 'vitest' },
        dependencies: { react: '18.0.0', stripe: '1.0.0' },
        devDependencies: { vite: '7.0.0', typescript: '5.0.0' },
      }),
      'README.md': '# Web',
      'AGENTS.md': '- Use tabs.\n- Never edit generated files.',
    };
    server.use(
      http.get(`${GITHUB_API}/repos/acme/web/git/trees/main`, () =>
        HttpResponse.json({
          tree: [
            ...Object.keys(files).map((path) => ({ path, type: 'blob' })),
            { path: 'pnpm-lock.yaml', type: 'blob' },
            { path: 'src', type: 'tree' },
            { path: 'src/components', type: 'tree' },
            { path: 'src/components/pricing', type: 'tree' },
            { path: 'src/payments', type: 'tree' },
          ],
        }),
      ),
      http.get(`${GITHUB_API}/repos/acme/web/contents/:path`, ({ params }) => {
        const content = files[params.path as string];
        return content === undefined
          ? HttpResponse.json({ message: 'Not Found' }, { status: 404 })
          : HttpResponse.json({ type: 'file', content: b64(content) });
      }),
    );
    const gen = await admin.post(`${url}/memory/generate`);
    expect(gen.status, JSON.stringify(gen.body)).toBe(200);
    const draft = gen.body.data.draft as string;
    expect(draft).toContain('- React');
    expect(draft).toContain('- Stripe');
    expect(draft).toContain('`pnpm run dev`');
    expect(draft).toContain("From the repository's AGENTS.md:");
    expect(draft).toContain('`src/payments/`');
    expect(gen.body.data.sources).toEqual(['package.json', 'README.md', 'AGENTS.md']);
    expect(gen.body.data.componentLabels).toEqual({
      'src/components/pricing/**': 'the pricing',
      'src/billing/**': 'Billing',
    });
    // Nothing is saved by generating a draft.
    expect((await admin.get(`${url}/memory`)).body.data.looseMd).toBe('# Project');
    expect((await admin.delete(url)).status).toBe(204);
    expectError(await admin.get(url), 'LSE-NF-001', 404);
    const actions = (await prisma.auditLog.findMany({ where: { target: id } })).map(
      (a) => a.action,
    );
    expect(actions).toEqual(
      expect.arrayContaining(['project.create', 'project.update', 'project.delete']),
    );
  });

  it('list paginates with cursor', async () => {
    const { admin, org } = await adminWithGithub();
    server.use(githubRepoHandler('acme/web'));
    for (let i = 0; i < 3; i++)
      await admin.post(`/api/v1/orgs/${org.id}/projects`, {
        name: `P${i}`,
        githubRepoFullName: 'acme/web',
      });
    const p1 = await admin.get(`/api/v1/orgs/${org.id}/projects?limit=2`);
    expect(p1.body.data).toHaveLength(2);
    const p2 = await admin.get(
      `/api/v1/orgs/${org.id}/projects?limit=2&cursor=${p1.body.nextCursor}`,
    );
    expect(p2.body.data).toHaveLength(1);
    expect(p2.body.nextCursor).toBeNull();
  });
});

describe('github routes', () => {
  it('GET /github/repos without a linked account → LSE-GH-001', async () => {
    const c = await login(app);
    const res = await c.get('/api/v1/github/repos');
    expectError(res, 'LSE-GH-001', 401);
    expect(res.body.error.action).toEqual({
      type: 'link',
      label: 'Connect GitHub',
      href: '/api/v1/auth/github?link=1',
    });
  });

  it('lists repos with page-number cursors and filters by q', async () => {
    const c = await login(app);
    await linkGithub(ctx, c.user.id);
    server.use(
      http.get(`${GITHUB_API}/user/repos`, ({ request: req }) => {
        const page = new URL(req.url).searchParams.get('page') ?? '1';
        const headers: Record<string, string> =
          page === '1' ? { link: `<${GITHUB_API}/user/repos?page=2>; rel="next"` } : {};
        const repos =
          page === '1'
            ? [githubRepoJson('acme/web'), githubRepoJson('acme/api')]
            : [githubRepoJson('acme/docs')];
        return HttpResponse.json(repos, { headers });
      }),
    );
    const p1 = await c.get('/api/v1/github/repos?limit=2');
    expect(p1.status).toBe(200);
    expect(p1.body.data.map((r: { fullName: string }) => r.fullName)).toEqual([
      'acme/web',
      'acme/api',
    ]);
    expect(p1.body.data[0]).toMatchObject({
      owner: 'acme',
      name: 'web',
      private: true,
      defaultBranch: 'main',
    });
    expect(p1.body.nextCursor).toBe('2');
    const p2 = await c.get('/api/v1/github/repos?limit=2&cursor=2');
    expect(p2.body).toMatchObject({ nextCursor: null, data: [{ fullName: 'acme/docs' }] });
    const filtered = await c.get('/api/v1/github/repos?q=API');
    expect(filtered.body.data.map((r: { fullName: string }) => r.fullName)).toEqual(['acme/api']);
    expectError(await c.get('/api/v1/github/repos?cursor=0'), 'LSE-VAL-001', 400);
  });

  it.each([
    [401, {}, 'LSE-GH-001', 401],
    [403, {}, 'LSE-GH-002', 403],
    [
      403,
      {
        'x-ratelimit-remaining': '0',
        'x-ratelimit-reset': String(Math.floor(Date.now() / 1000) + 30),
      },
      'LSE-GH-010',
      429,
    ],
    [403, { 'retry-after': '60' }, 'LSE-GH-009', 403],
    [429, {}, 'LSE-GH-010', 429],
    [404, {}, 'LSE-GH-003', 404],
    [502, {}, 'LSE-GH-011', 502],
  ])('GitHub %i %j → %s', async (status, headers, code, httpStatus) => {
    const c = await login(app);
    await linkGithub(ctx, c.user.id);
    server.use(
      http.get(`${GITHUB_API}/repos/acme/web`, () =>
        HttpResponse.json(
          { message: 'nope' },
          { status, headers: headers as Record<string, string> },
        ),
      ),
    );
    const res = await c.get('/api/v1/github/repos/acme/web');
    expectError(res, code, httpStatus);
    expect(JSON.stringify(res.body)).not.toContain('gho_');
  });

  it('GET /github/repos/:owner/:repo returns the repo', async () => {
    const c = await login(app);
    await linkGithub(ctx, c.user.id);
    server.use(githubRepoHandler('acme/web'));
    const res = await c.get('/api/v1/github/repos/acme/web');
    expect(res.body.data).toMatchObject({
      fullName: 'acme/web',
      htmlUrl: 'https://github.com/acme/web',
    });
  });
});

describe('github webhook', () => {
  const payload = JSON.stringify({ action: 'opened', number: 1 });
  const sign = (body: string, secret = TEST_SECRETS.GITHUB_WEBHOOK_SECRET) =>
    `sha256=${createHmac('sha256', secret).update(body).digest('hex')}`;

  it('valid signature → 202 (no auth or CSRF needed)', async () => {
    const res = await request(app)
      .post('/api/v1/github/webhook')
      .set('content-type', 'application/json')
      .set('x-github-event', 'pull_request')
      .set('x-hub-signature-256', sign(payload))
      .send(payload);
    expect(res.status).toBe(202);
    expect(res.body).toEqual({ data: { received: true, handled: false } });
  });

  it('invalid / missing / wrong-secret signature → 400 LSE-GH-014', async () => {
    for (const sig of [
      undefined,
      'sha256=deadbeef',
      sign(payload, 'wrong-secret'),
      sign(`${payload} `),
    ]) {
      const r = request(app).post('/api/v1/github/webhook').set('content-type', 'application/json');
      if (sig) r.set('x-hub-signature-256', sig);
      expectError(await r.send(payload), 'LSE-GH-014', 400);
    }
  });

  it('no webhook secret configured → LSE-GH-014', async () => {
    const { app: bare } = makeApp({ env: { GITHUB_WEBHOOK_SECRET: undefined } });
    const res = await request(bare)
      .post('/api/v1/github/webhook')
      .set('x-hub-signature-256', sign(payload))
      .send(payload);
    expectError(res, 'LSE-GH-014', 400);
  });
});
