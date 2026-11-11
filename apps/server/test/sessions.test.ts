/** Phase 4: session preflight, provisioning (FakeSandboxProvider), recover, artifacts, isolation. */
import { randomBytes } from 'node:crypto';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { PAT_PREFIX, parseRunnerConfig, type ServerMessage } from '@loose/shared';
import { sha256Hex } from '../src/lib/crypto';
import { AppError } from '../src/lib/errors';
import { saveArtifact, stopSession } from '../src/services/sessionLifecycle.service';
import type { SessionReadyContext } from '../src/services/sessionRuntime';
import {
  addMember,
  createMswServer,
  createOrg,
  expectError,
  linkGithub,
  login,
  makeApp,
  onUnhandled,
  resetDb,
  testPrisma,
  type Client,
} from './helpers';
import {
  addApiKey,
  createReadyProject,
  DUMMY_ANTHROPIC_KEY,
  fakeSandbox,
  settle,
} from './sessionHelpers';

const server = createMswServer();
const prisma = testPrisma();
const { app, ctx } = makeApp();
const fake = fakeSandbox(ctx);

const DB_PASSWORD = 'pg-secret-password-123';
const GH_TOKEN = 'gho_sessiontesttoken0000000000000001';

beforeAll(() => server.listen({ onUnhandledRequest: onUnhandled }));
afterEach(() => server.resetHandlers());
afterAll(async () => {
  await ctx.jobs.onIdle();
  server.close();
  await prisma.$disconnect();
});
beforeEach(async () => {
  await ctx.jobs.onIdle();
  fake.reset();
  await resetDb();
});

interface World {
  admin: Client;
  member: Client;
  org: { id: string };
  project: Awaited<ReturnType<typeof createReadyProject>>;
}

async function world(projectExtra: Parameters<typeof createReadyProject>[2] = {}): Promise<World> {
  const admin = await login(app);
  await linkGithub(ctx, admin.user.id);
  const org = await createOrg(admin);
  const member = await login(app, undefined, 'Mia Member');
  await addMember(org.id, member.user.id, 'MEMBER');
  await linkGithub(ctx, member.user.id, GH_TOKEN);
  await addApiKey(ctx, member.user.id);
  const project = await createReadyProject(ctx, org.id, {
    env: {
      DATABASE_URL: `postgres://app:${DB_PASSWORD}@localhost/app`,
      VITE_API_URL: 'http://localhost:4000',
    },
    startupCommands: ['npm ci', 'npm run migrate', 'npm run dev'],
    portMap: [
      { name: 'web', port: 5173, public: true, envVar: 'APP_URL' },
      { name: 'api', port: 4000, public: false, envVar: 'VITE_API_URL' },
    ],
    healthCheck: { path: '/health', port: 4000, timeoutSec: 1 },
    contextInstructions: 'Use tabs.',
    ...projectExtra,
  });
  return { admin, member, org, project };
}

function events(sessionId: string): Promise<ServerMessage[]> {
  return ctx.sessionEvents.replay(sessionId, 0).then((r) => r.events);
}

async function start(client: Client, projectId: string, body: object = {}) {
  const res = await client.post('/api/v1/sessions', { projectId, ...body });
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  return res.body.data as { id: string; status: string; branchName: string };
}

async function setPolicy(orgId: string, policy: object) {
  await prisma.organization.update({ where: { id: orgId }, data: { policy } });
}

describe('provisioning', () => {
  it('QUEUED → RUNNING: clone, branch, .env with public URLs, runner config, startup, health, preview', async () => {
    const { member, project, org } = await world();
    const ready: SessionReadyContext[] = [];
    const off = ctx.sessionHooks.register({ onSessionReady: async (c) => void ready.push(c) });
    try {
      const created = await start(member, project.id);
      expect(created.status).toBe('QUEUED');
      expect(created.branchName).toBe(`loose/session-${created.id}`);
      const s = await settle(ctx, created.id);
      expect(s.status).toBe('RUNNING');
      const sbx = fake.last()!;
      expect(s.sandboxId).toBe(sbx.id);
      expect(sbx.templateId).toBe('tpl-ready-1');
      expect(sbx.createOpts.metadata).toMatchObject({
        sessionId: s.id,
        projectId: project.id,
        orgId: org.id,
      });
      expect(s.previewUrl).toBe(`https://5173-${sbx.id}.fake.sandbox`);
      expect(s.idleSince).toBeInstanceOf(Date);

      // .env: project vars + resolved public URLs (port/URL wiring).
      const env = sbx.files.get('/home/user/workspace/.env')!;
      expect(env).toContain(`APP_URL="https://5173-${sbx.id}.fake.sandbox"`);
      expect(env).toContain(`VITE_API_URL="https://4000-${sbx.id}.fake.sandbox"`);
      expect(env).toContain(`CORS_ORIGIN="https://5173-${sbx.id}.fake.sandbox"`);
      expect(env).toContain(`DATABASE_URL="postgres://app:${DB_PASSWORD}@localhost/app"`);

      // Runner config: valid, no secrets.
      const cfgRaw = sbx.files.get('/home/user/.loose/config.json')!;
      const cfg = parseRunnerConfig(cfgRaw);
      expect(cfg.ok).toBe(true);
      expect(cfg.ok && cfg.config).toMatchObject({
        sessionId: s.id,
        workspaceDir: '/home/user/workspace',
        model: 'claude-sonnet-4-5',
        mock: true,
        systemPrompt: { projectContext: 'Use tabs.' },
      });
      expect(cfgRaw).not.toContain(DB_PASSWORD);
      expect(cfgRaw).not.toContain(DUMMY_ANTHROPIC_KEY);
      expect(cfgRaw).not.toContain(GH_TOKEN);

      // Git: token only via env, never in the command line.
      const lines = sbx.commandLines();
      const clone = sbx.commands.find((c) => c.cmd.startsWith('git clone'))!;
      expect(clone.cmd).toContain("'https://github.com/acme/web.git'");
      expect(clone.cmd).not.toContain(GH_TOKEN);
      expect(
        Buffer.from(clone.opts.envs!.GIT_CONFIG_VALUE_0!.split(' ').at(-1)!, 'base64').toString(),
      ).toBe(`x-access-token:${GH_TOKEN}`);
      expect(lines.some((l) => l.includes('.git/info/exclude'))).toBe(true);
      expect(lines).toContain(`git checkout -b 'loose/session-${s.id}'`);
      const i = (c: string) => lines.indexOf(c);
      expect(i('npm ci')).toBeLessThan(i('npm run migrate'));
      expect(sbx.commands.find((c) => c.cmd === 'npm run dev')?.background).toBe(true);
      expect(sbx.commands.find((c) => c.cmd === 'npm ci')?.opts.envs?.APP_URL).toBe(s.previewUrl);
      expect(lines.some((l) => l.includes('http://127.0.0.1:4000/health'))).toBe(true);

      // Events + runtime + hooks.
      const evs = await events(s.id);
      const steps = evs
        .filter((e) => e.type === 'session_status')
        .map((e) => (e.payload as { step?: string }).step);
      expect(steps).toEqual(
        expect.arrayContaining([
          'provisioning',
          'cloning',
          'branching',
          'writing_env',
          'installing',
          'starting_app',
          'health_check',
          'ready',
        ]),
      );
      expect(evs.map((e) => e.seq)).toEqual(evs.map((_, k) => k + 1));
      expect(evs.some((e) => e.type === 'preview_updated')).toBe(true);
      expect(ctx.sessionRuntime.get(s.id)?.sandbox.id).toBe(sbx.id);
      expect(ready).toHaveLength(1);
      expect(ready[0]!.runnerLaunch).toMatchObject({
        command: 'node /sandbox-agent/runner/dist/cli.js',
        envs: { LOOSE_STATE_DIR: '/home/user/.loose', LOOSE_RUNNER_MOCK: '1' },
      });
      expect(ready[0]!.recovered).toBe(false);

      const dto = (await member.get(`/api/v1/sessions/${s.id}`)).body.data;
      expect(dto).toMatchObject({
        status: 'RUNNING',
        agentState: 'idle',
        projectName: 'Web',
        orgId: org.id,
        userName: 'Mia Member',
        budgetUsd: 5,
        totalCostUsd: 0,
        maxSessionDurationMin: 60,
      });
      expect(dto.sandboxId).toBeUndefined();
      expect(
        await prisma.auditLog.findFirst({ where: { action: 'session.start', target: s.id } }),
      ).not.toBeNull();
    } finally {
      off();
    }
  });

  it('LSE-GH-004: an existing remote branch gets a suffix', async () => {
    const { member, project } = await world();
    fake.onCommand(/^git ls-remote/, (cmd) => ({
      exitCode: /'loose\/session-[a-z0-9]+'$/.test(cmd) ? 0 : 2,
    }));
    const created = await start(member, project.id);
    const s = await settle(ctx, created.id);
    expect(s.status).toBe('RUNNING');
    expect(s.branchName).toBe(`loose/session-${s.id}-2`);
    expect(fake.last()!.commandLines()).toContain(`git checkout -b 'loose/session-${s.id}-2'`);
  });

  const failures: [string, string, () => void][] = [
    [
      'LSE-SBX-001',
      'no sandbox capacity (after retries)',
      () => void fake.failNextCreate('capacity', 4),
    ],
    ['LSE-SBX-002', 'sandbox fails to start', () => void fake.failNextCreate('start_failed')],
    [
      'LSE-SBX-003',
      'clone fails',
      () =>
        void fake.onCommand(/^git clone/, () => ({
          exitCode: 128,
          stderr: 'fatal: repository not found',
        })),
    ],
    [
      'LSE-SBX-004',
      'a startup command fails',
      () =>
        void fake.onCommand('npm run migrate', () => ({
          exitCode: 1,
          stderr: `error: password ${DB_PASSWORD} rejected`,
        })),
    ],
    [
      'LSE-SBX-005',
      'health check never passes',
      () => void fake.onCommand(/^node -e/, () => ({ exitCode: 1 })),
    ],
  ];
  for (const [code, what, script] of failures) {
    it(`${code}: ${what} → ERRORED, sandbox killed, error + session_ended events`, async () => {
      const { member, project } = await world();
      script();
      const created = await start(member, project.id);
      const s = await settle(ctx, created.id);
      expect(s).toMatchObject({ status: 'ERRORED', errorCode: code, sandboxId: null });
      expect(s.endedAt).toBeInstanceOf(Date);
      for (const sbx of fake.sandboxes.values()) expect(sbx.killed).toBe(true);
      expect(ctx.sessionRuntime.get(s.id)).toBeUndefined();
      const evs = await events(s.id);
      const err = evs.find((e) => e.type === 'error');
      expect((err?.payload as { error: { code: string } }).error.code).toBe(code);
      expect(evs.at(-1)?.type).toBe('session_ended');
      expect(JSON.stringify(evs)).not.toContain(DB_PASSWORD);
      const dto = (await member.get(`/api/v1/sessions/${s.id}`)).body.data;
      expect(dto).toMatchObject({ status: 'ERRORED', errorCode: code });
    });
  }

  it('the app process crashing during startup → LSE-SBX-004', async () => {
    const { member, project } = await world();
    fake.onBackground('npm run dev', (proc) => {
      proc.emitStderr('Error: Cannot find module');
      proc.exit(1);
    });
    fake.onCommand(/^node -e/, () => ({ exitCode: 1 }));
    const s = await settle(ctx, (await start(member, project.id)).id);
    expect(s).toMatchObject({ status: 'ERRORED', errorCode: 'LSE-SBX-004' });
  });

  it('an orchestrator onSessionReady failure → ERRORED with its code', async () => {
    const { member, project } = await world();
    const off = ctx.sessionHooks.register({
      onSessionReady: async () => {
        throw new AppError('LSE-AGT-001', { devMessage: 'runner did not start' });
      },
    });
    try {
      const s = await settle(ctx, (await start(member, project.id)).id);
      expect(s).toMatchObject({ status: 'ERRORED', errorCode: 'LSE-AGT-001', sandboxId: null });
    } finally {
      off();
    }
  });

  it('DEV_GIT_REMOTE_OVERRIDE replaces github.com (non-production)', async () => {
    const { app: app2, ctx: ctx2 } = makeApp({
      env: { DEV_GIT_REMOTE_OVERRIDE: '/tmp/remotes/{owner}/{repo}.git' },
    });
    const fake2 = fakeSandbox(ctx2);
    const admin = await login(app2);
    const org = await createOrg(admin);
    await addApiKey(ctx2, admin.user.id); // no GitHub link needed with the override
    const project = await createReadyProject(ctx2, org.id);
    const res = await admin.post('/api/v1/sessions', { projectId: project.id });
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    await ctx2.jobs.onIdle();
    const clone = fake2
      .last()!
      .commandLines()
      .find((c) => c.startsWith('git clone'));
    expect(clone).toContain("'/tmp/remotes/acme/web.git'");
  });
});

describe('preflight', () => {
  it('LSE-TPL-001 when the project has no READY template', async () => {
    const { member, org } = await world();
    const p = await createReadyProject(ctx, org.id, {
      templateStatus: 'BUILDING',
      e2bTemplateId: null,
    });
    expectError(await member.post('/api/v1/sessions', { projectId: p.id }), 'LSE-TPL-001', 409);
  });

  it('LSE-KEY-001 without a key, LSE-KEY-003 with only an invalid key', async () => {
    const { admin, project } = await world();
    expectError(
      await admin.post('/api/v1/sessions', { projectId: project.id }),
      'LSE-KEY-001',
      400,
    );
    await addApiKey(ctx, admin.user.id, 'INVALID');
    expectError(
      await admin.post('/api/v1/sessions', { projectId: project.id }),
      'LSE-KEY-003',
      401,
    );
  });

  it('LSE-KEY-013 for an unknown model; dated snapshots resolve', async () => {
    const { member, project } = await world();
    expectError(
      await member.post('/api/v1/sessions', { projectId: project.id, model: 'gpt-4o' }),
      'LSE-KEY-013',
      400,
    );
    const s = await start(member, project.id, { model: 'claude-haiku-4-5-20251001' });
    expect((await settle(ctx, s.id)).model).toBe('claude-haiku-4-5');
  });

  it('LSE-KEY-012 when org, user or key monthly budgets are used up', async () => {
    const { member, project, org } = await world();
    const s = await start(member, project.id);
    await settle(ctx, s.id);
    await prisma.usageEvent.create({
      data: {
        sessionId: s.id,
        orgId: org.id,
        userId: member.user.id,
        model: 'claude-sonnet-4-5',
        tokensIn: 1,
        tokensOut: 1,
        cacheRead: 0,
        costUsd: 2,
      },
    });
    await setPolicy(org.id, { budgets: { orgMonthlyUsd: 1 } });
    expectError(
      await member.post('/api/v1/sessions', { projectId: project.id }),
      'LSE-KEY-012',
      402,
    );
    await setPolicy(org.id, { budgets: { userMonthlyUsd: 2 } });
    expectError(
      await member.post('/api/v1/sessions', { projectId: project.id }),
      'LSE-KEY-012',
      402,
    );
    await setPolicy(org.id, {});
    await prisma.apiKey.updateMany({
      where: { userId: member.user.id },
      data: { monthlyLimitUsd: 1.5 },
    });
    expectError(
      await member.post('/api/v1/sessions', { projectId: project.id }),
      'LSE-KEY-012',
      402,
    );
  });

  it('LSE-SBX-011 per-user and LSE-RATE-002 per-org concurrency caps', async () => {
    const { member, admin, project, org } = await world();
    await addApiKey(ctx, admin.user.id);
    await setPolicy(org.id, { maxConcurrentSessionsPerUser: 1, maxConcurrentSessionsPerOrg: 2 });
    await start(member, project.id);
    expectError(
      await member.post('/api/v1/sessions', { projectId: project.id }),
      'LSE-SBX-011',
      429,
    );
    await start(admin, project.id);
    const third = await login(app);
    await addMember(org.id, third.user.id, 'MEMBER');
    await linkGithub(ctx, third.user.id);
    await addApiKey(ctx, third.user.id);
    expectError(
      await third.post('/api/v1/sessions', { projectId: project.id }),
      'LSE-RATE-002',
      429,
    );
    await ctx.jobs.onIdle();
  });

  it('viewers are denied; non-members and other orgs see "not found"', async () => {
    const { project, org } = await world();
    const viewer = await login(app);
    await addMember(org.id, viewer.user.id, 'VIEWER');
    await addApiKey(ctx, viewer.user.id);
    expectError(
      await viewer.post('/api/v1/sessions', { projectId: project.id }),
      'LSE-ORG-002',
      403,
    );
    const outsider = await login(app);
    await addApiKey(ctx, outsider.user.id);
    expectError(
      await outsider.post('/api/v1/sessions', { projectId: project.id }),
      'LSE-NF-001',
      404,
    );
    // A member of another org gets the same answer as a stranger.
    const { member } = await world();
    expectError(
      await member.post('/api/v1/sessions', { projectId: project.id }),
      'LSE-NF-001',
      404,
    );
  });

  it('forkFrom an unknown session → LSE-NF-001; locked modes override the requested mode', async () => {
    const { member, project, org } = await world();
    // Phase 9 implements forking (see phase9.fork.test.ts); an unknown parent is "not found".
    expectError(
      await member.post('/api/v1/sessions', { projectId: project.id, forkFrom: 'cabc' }),
      'LSE-NF-001',
      404,
    );
    await setPolicy(org.id, { lockedModes: { MEMBER: 'SIMPLE' } });
    const s = await start(member, project.id, { mode: 'PRO' });
    expect((await settle(ctx, s.id)).mode).toBe('SIMPLE');
  });

  it('warns about other active sessions on the same project', async () => {
    const { member, admin, project } = await world();
    await addApiKey(ctx, admin.user.id);
    const first = await start(member, project.id);
    const second = await start(admin, project.id);
    const evs = await events(second.id);
    const warn = evs.find((e) => e.type === 'conflict_warning');
    expect(warn?.payload).toMatchObject({ otherSessionId: first.id, otherUserName: 'Mia Member' });
    await ctx.jobs.onIdle();
  });

  it('POST /sessions is rate limited per user (LSE-RATE-001)', async () => {
    const { app: app2, ctx: ctx2 } = makeApp({ env: { RATE_LIMIT_SESSION_CREATE_MAX: '1' } });
    const admin = await login(app2);
    const org = await createOrg(admin);
    const project = await createReadyProject(ctx2, org.id, {
      e2bTemplateId: null,
      templateStatus: 'PENDING',
    });
    expectError(
      await admin.post('/api/v1/sessions', { projectId: project.id }),
      'LSE-TPL-001',
      409,
    );
    expectError(
      await admin.post('/api/v1/sessions', { projectId: project.id }),
      'LSE-RATE-001',
      429,
    );
  });
});

describe('recover from WIP', () => {
  it('pause pushes refs/loose/wip/<id>; recover re-provisions from it', async () => {
    const { member, project } = await world();
    const ready: SessionReadyContext[] = [];
    const off = ctx.sessionHooks.register({ onSessionReady: async (c) => void ready.push(c) });
    try {
      const s = await settle(ctx, (await start(member, project.id)).id);
      const first = fake.last()!;
      expect(await stopSession(ctx, s.id, { to: 'PAUSED', reason: 'stopped', pushWip: true })).toBe(
        true,
      );
      const paused = await prisma.session.findUniqueOrThrow({ where: { id: s.id } });
      expect(paused).toMatchObject({
        status: 'PAUSED',
        wipRef: `refs/loose/wip/${s.id}`,
        sandboxId: null,
      });
      expect(first.killed).toBe(true);
      const push = first.commands.find((c) => c.cmd.includes('git push'))!;
      expect(push.cmd).toContain(`"$commit:refs/loose/wip/${s.id}"`);
      expect(push.cmd).toContain('commit-tree');
      expect(push.cmd).not.toContain(GH_TOKEN);

      const rec = await member.post(`/api/v1/sessions/${s.id}/recover`);
      expect(rec.status, JSON.stringify(rec.body)).toBe(202);
      expect(rec.body.data.status).toBe('QUEUED');
      const after = await settle(ctx, s.id);
      expect(after.status).toBe('RUNNING');
      const second = fake.last()!;
      expect(second.id).not.toBe(first.id);
      const lines = second.commandLines();
      expect(lines).toContain(
        `git fetch --no-tags origin '+refs/loose/wip/${s.id}:refs/loose/wip'`,
      );
      expect(
        lines.some(
          (l) => l.includes(`checkout -q -B 'loose/session-${s.id}'`) && l.includes('read-tree'),
        ),
      ).toBe(true);
      expect(lines.some((l) => l.startsWith('git checkout -b'))).toBe(false);
      expect(ready.at(-1)?.recovered).toBe(true);
      expect(
        await prisma.auditLog.findFirst({ where: { action: 'session.recover', target: s.id } }),
      ).not.toBeNull();
    } finally {
      off();
    }
  });

  it('recover is only for ERRORED/TIMED_OUT/PAUSED sessions', async () => {
    const { member, project } = await world();
    const s = await settle(ctx, (await start(member, project.id)).id);
    expectError(await member.post(`/api/v1/sessions/${s.id}/recover`), 'LSE-CONF-001', 409);
  });

  it('a session that failed to provision can be recovered (fresh branch, no WIP)', async () => {
    const { member, project } = await world();
    fake.failNextCreate('start_failed');
    const s = await settle(ctx, (await start(member, project.id)).id);
    expect(s.errorCode).toBe('LSE-SBX-002');
    expect((await member.post(`/api/v1/sessions/${s.id}/recover`)).status).toBe(202);
    const after = await settle(ctx, s.id);
    expect(after.status).toBe('RUNNING');
    expect(after.errorCode).toBeNull();
  });
});

describe('artifacts', () => {
  it('auth-checked list and content; other members and outsiders are denied', async () => {
    const { member, admin, project, org } = await world();
    const s = await start(member, project.id);
    await settle(ctx, s.id);
    const png = Buffer.from('89504e470d0a1a0a0000000d49484452', 'hex');
    const art = await saveArtifact(ctx, {
      sessionId: s.id,
      kind: 'screenshot',
      data: png,
      contentType: 'image/png',
      meta: { viewport: 'desktop', phase: 'after' },
    });
    expect(art.url).toBe(`/api/v1/sessions/${s.id}/artifacts/${art.id}/content`);

    const list = await member.get(`/api/v1/sessions/${s.id}/artifacts`);
    expect(list.status).toBe(200);
    expect(list.body.data).toEqual([
      expect.objectContaining({ id: art.id, kind: 'screenshot', url: art.url }),
    ]);
    expect(JSON.stringify(list.body)).not.toContain('storageKey');

    const content = await member
      .get(art.url)
      .buffer(true)
      .parse((r, cb) => {
        const chunks: Buffer[] = [];
        r.on('data', (c: Buffer) => chunks.push(c));
        r.on('end', () => cb(null, Buffer.concat(chunks)));
      });
    expect(content.status).toBe(200);
    expect(content.headers['content-type']).toBe('image/png');
    expect(content.headers['content-security-policy']).toContain('sandbox');
    expect(Buffer.compare(content.body as Buffer, png)).toBe(0);
    expect((await admin.get(art.url)).status).toBe(200);

    const other = await login(app);
    await addMember(org.id, other.user.id, 'MEMBER');
    expectError(await other.get(art.url), 'LSE-ORG-002', 403);
    expectError(await other.get(`/api/v1/sessions/${s.id}/artifacts`), 'LSE-ORG-002', 403);
    const outsider = await login(app);
    expectError(await outsider.get(art.url), 'LSE-NF-001', 404);
    // An artifact id from another session does not resolve.
    const s2 = await start(member, project.id);
    await settle(ctx, s2.id);
    expectError(
      await member.get(`/api/v1/sessions/${s2.id}/artifacts/${art.id}/content`),
      'LSE-NF-001',
      404,
    );
    expectError(
      await member.get(`/api/v1/sessions/${s.id}/artifacts/cnope/content`),
      'LSE-NF-001',
      404,
    );
  });
});

describe('tenant isolation & listing', () => {
  async function pat(userId: string, orgId: string, scopes: string[]) {
    const raw = `${PAT_PREFIX}${randomBytes(24).toString('base64url')}`;
    await prisma.apiToken.create({
      data: { orgId, userId, name: 't', hash: sha256Hex(raw), scopes },
    });
    return raw;
  }

  it('sessions of another org are invisible (REST, list, PAT)', async () => {
    const a = await world();
    const sa = await settle(ctx, (await start(a.member, a.project.id)).id);
    const b = await world();
    const sb = await settle(ctx, (await start(b.member, b.project.id)).id);

    expectError(await b.admin.get(`/api/v1/sessions/${sa.id}`), 'LSE-NF-001', 404);
    expectError(await b.admin.post(`/api/v1/sessions/${sa.id}/recover`), 'LSE-NF-001', 404);
    expectError(await b.admin.get(`/api/v1/orgs/${a.org.id}/sessions`), 'LSE-ORG-001', 403);
    const listB = await b.admin.get(`/api/v1/orgs/${b.org.id}/sessions`);
    expect(listB.body.data.map((s: { id: string }) => s.id)).toEqual([sb.id]);
    expectError(
      await b.admin.post('/api/v1/sessions', { projectId: a.project.id }),
      'LSE-NF-001',
      404,
    );

    // A PAT bound to org B cannot read org A's session even for a user in both orgs.
    await addMember(a.org.id, b.admin.user.id, 'ADMIN');
    const tokenB = await pat(b.admin.user.id, b.org.id, ['sessions:read']);
    const viaToken = await b.admin.agent
      .get(`/api/v1/sessions/${sa.id}`)
      .set('authorization', `Bearer ${tokenB}`);
    expectError(viaToken, 'LSE-NF-001', 404);
    const ownViaToken = await b.admin.agent
      .get(`/api/v1/sessions/${sb.id}`)
      .set('authorization', `Bearer ${tokenB}`);
    expect(ownViaToken.status).toBe(200);
  });

  it('PAT scopes: sessions:read for GET, sessions:write for POST', async () => {
    const { member, project, org } = await world();
    const s = await settle(ctx, (await start(member, project.id)).id);
    const noScope = await pat(member.user.id, org.id, ['org:read']);
    const read = await pat(member.user.id, org.id, ['sessions:read']);
    const get = (t: string) =>
      member.agent.get(`/api/v1/sessions/${s.id}`).set('authorization', `Bearer ${t}`);
    expectError(await get(noScope), 'LSE-ORG-002', 403);
    expect((await get(read)).status).toBe(200);
    const post = await member.agent
      .post('/api/v1/sessions')
      .set('authorization', `Bearer ${read}`)
      .send({ projectId: project.id });
    expectError(post, 'LSE-ORG-002', 403);
    const list = await member.agent
      .get(`/api/v1/orgs/${org.id}/sessions`)
      .set('authorization', `Bearer ${read}`);
    expect(list.status).toBe(200);
  });

  it('members list their own sessions; admins list all with filters; cursor pagination', async () => {
    const { member, admin, project, org } = await world();
    await addApiKey(ctx, admin.user.id);
    const m1 = await settle(ctx, (await start(member, project.id)).id);
    const a1 = await settle(ctx, (await start(admin, project.id)).id);
    await prisma.session.update({
      where: { id: m1.id },
      data: { status: 'COMPLETED', outcome: 'DISCARDED' },
    });

    const mine = await member.get(`/api/v1/orgs/${org.id}/sessions?userId=${admin.user.id}`);
    expect(mine.body.data.map((s: { id: string }) => s.id)).toEqual([m1.id]);
    const all = await admin.get(`/api/v1/orgs/${org.id}/sessions`);
    expect(all.body.data.map((s: { id: string }) => s.id).sort()).toEqual([m1.id, a1.id].sort());
    const done = await admin.get(
      `/api/v1/orgs/${org.id}/sessions?status=COMPLETED&outcome=DISCARDED`,
    );
    expect(done.body.data.map((s: { id: string }) => s.id)).toEqual([m1.id]);
    const byUser = await admin.get(
      `/api/v1/orgs/${org.id}/sessions?userId=${admin.user.id}&projectId=${project.id}`,
    );
    expect(byUser.body.data.map((s: { id: string }) => s.id)).toEqual([a1.id]);
    const page1 = await admin.get(`/api/v1/orgs/${org.id}/sessions?limit=1`);
    expect(page1.body.data).toHaveLength(1);
    const page2 = await admin.get(
      `/api/v1/orgs/${org.id}/sessions?limit=1&cursor=${page1.body.nextCursor}`,
    );
    expect(page2.body.data).toHaveLength(1);
    expect(page2.body.data[0].id).not.toBe(page1.body.data[0].id);
    const viewer = await login(app);
    await addMember(org.id, viewer.user.id, 'VIEWER');
    expectError(await viewer.get(`/api/v1/orgs/${org.id}/sessions`), 'LSE-ORG-002', 403);
  });

  it('active-sessions hides other users’ preview URLs from members', async () => {
    const { member, admin, project, org } = await world();
    await addApiKey(ctx, admin.user.id);
    const a1 = await settle(ctx, (await start(admin, project.id)).id);
    const m1 = await settle(ctx, (await start(member, project.id)).id);
    const res = await member.get(`/api/v1/orgs/${org.id}/projects/${project.id}/active-sessions`);
    expect(res.status).toBe(200);
    const byId = Object.fromEntries(res.body.data.map((s: { id: string }) => [s.id, s]));
    expect(byId[a1.id].previewUrl).toBeNull();
    expect(byId[m1.id].previewUrl).toBe(m1.previewUrl);
    const asAdmin = await admin.get(
      `/api/v1/orgs/${org.id}/projects/${project.id}/active-sessions`,
    );
    expect(asAdmin.body.data.every((s: { previewUrl: string | null }) => s.previewUrl)).toBe(true);
  });
});
