/** Phase 3: template builds (lifecycle, blue/green, SSE logs) and smoke tests. */
import { randomBytes } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { http, HttpResponse } from 'msw';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { PAT_PREFIX } from '@loose/shared';
import { sha256Hex } from '../src/lib/crypto';
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
import { addApiKey, createReadyProject, fakeBuilder, fakeSandbox } from './sessionHelpers';

const server = createMswServer();
const prisma = testPrisma();
const { app, ctx } = makeApp();
const fake = fakeSandbox(ctx);
const builder = fakeBuilder(ctx);

const SECRET = 'hunter2-super-secret-db-password';

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
  builder.reset();
  await resetDb();
});

function gate() {
  let open!: () => void;
  const promise = new Promise<void>((r) => (open = r));
  return { promise, open };
}

async function setup(extra: Parameters<typeof createReadyProject>[2] = {}) {
  const admin = await login(app);
  await linkGithub(ctx, admin.user.id);
  const org = await createOrg(admin);
  const project = await createReadyProject(ctx, org.id, {
    templateStatus: 'PENDING',
    templateVersion: 0,
    e2bTemplateId: null,
    env: { DATABASE_URL: `postgres://app:${SECRET}@db/app` },
    ...extra,
  });
  const base = `/api/v1/orgs/${org.id}/projects/${project.id}`;
  return { admin, org, project, base };
}

describe('template build lifecycle', () => {
  it('PENDING → BUILDING → READY; version bump, template id, audit', async () => {
    const { admin, base, project } = await setup();
    builder.enqueue({
      logs: ['step 1/3 apt-get install', 'step 2/3 npm install'],
      templateId: 'tpl-new-1',
    });
    const res = await admin.post(`${base}/build-template`);
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(res.body.data).toMatchObject({
      status: 'BUILDING',
      version: 0,
      templateId: null,
      error: null,
    });
    await ctx.jobs.onIdle();

    const st = await admin.get(`${base}/template-status`);
    expect(st.status).toBe(200);
    expect(st.body.data).toMatchObject({
      status: 'READY',
      version: 1,
      templateId: 'tpl-new-1',
      error: null,
    });
    expect(st.body.data.buildFinishedAt).toEqual(expect.any(String));
    expect(builder.specs[0]?.name).toBe(`loose-${project.id.toLowerCase()}-v1`);
    const actions = (await prisma.auditLog.findMany({ where: { target: project.id } })).map(
      (a) => a.action,
    );
    expect(actions).toContain('template.build');
    // A member now sees the project.
    const p = await prisma.project.findUniqueOrThrow({ where: { id: project.id } });
    expect(p.templateStatus).toBe('READY');
  });

  it('failure → FAILED with LSE-TPL-002 and a sanitized log tail', async () => {
    const { admin, base, project } = await setup();
    builder.enqueue({
      logs: [
        `npm ERR! could not connect to postgres://app:${SECRET}@db/app`,
        'npm ERR! token sk-ant-api03-abcdefghijklmnop1234 rejected',
        'npm ERR! code ELIFECYCLE',
      ],
      error: { kind: 'user', message: `install step failed (password ${SECRET})` },
    });
    expect((await admin.post(`${base}/build-template`)).status).toBe(202);
    await ctx.jobs.onIdle();
    const st = (await admin.get(`${base}/template-status`)).body.data;
    expect(st.status).toBe('FAILED');
    expect(st.error.code).toBe('LSE-TPL-002');
    const blob = JSON.stringify(st);
    expect(blob).not.toContain(SECRET);
    expect(blob).not.toContain('sk-ant-api03-abcdefghijklmnop1234');
    expect(st.error.logTail.join('\n')).toContain('[REDACTED]');
    expect(st.error.logTail.join('\n')).toContain('code ELIFECYCLE');
    expect(st.error.message).toContain('[REDACTED]');
    const proj = (await admin.get(base)).body.data;
    expect(proj.templateStatus).toBe('FAILED');
    expect(proj.templateError).toMatch(/couldn't install/i);
    const actions = (await prisma.auditLog.findMany({ where: { target: project.id } })).map(
      (a) => a.action,
    );
    expect(actions).toContain('template.build_failed');
    // Stored logs are scrubbed too.
    const lines = (await ctx.templateLogs.read(project.id)).map((l) => l.line).join('\n');
    expect(lines).not.toContain(SECRET);
  });

  it('retries once on infra errors; a second infra error fails the build', async () => {
    const { admin, base } = await setup();
    builder.enqueue(
      { error: { kind: 'infra', message: 'e2b 502' } },
      { templateId: 'tpl-after-retry' },
    );
    await admin.post(`${base}/build-template`);
    await ctx.jobs.onIdle();
    expect((await admin.get(`${base}/template-status`)).body.data).toMatchObject({
      status: 'READY',
      templateId: 'tpl-after-retry',
    });
    expect(builder.specs).toHaveLength(2);

    builder.enqueue(
      { error: { kind: 'infra', message: 'x' } },
      { error: { kind: 'infra', message: 'y' } },
    );
    await admin.post(`${base}/build-template`);
    await ctx.jobs.onIdle();
    const st = (await admin.get(`${base}/template-status`)).body.data;
    expect(st).toMatchObject({ status: 'FAILED', templateId: 'tpl-after-retry' });
    expect(st.error.code).toBe('LSE-TPL-002');
  });

  it('unsupported service → LSE-TPL-003 without calling the builder; timeouts → LSE-TPL-004', async () => {
    const { admin, base } = await setup({ requiredServices: ['mongodb'] });
    await admin.post(`${base}/build-template`);
    await ctx.jobs.onIdle();
    const st = (await admin.get(`${base}/template-status`)).body.data;
    expect(st.status).toBe('FAILED');
    expect(st.error.code).toBe('LSE-TPL-003');
    expect(builder.specs).toHaveLength(0);

    const two = await setup();
    builder.enqueue({ error: { kind: 'timeout', message: 'took too long' } });
    await two.admin.post(`${two.base}/build-template`);
    await ctx.jobs.onIdle();
    expect((await two.admin.get(`${two.base}/template-status`)).body.data.error.code).toBe(
      'LSE-TPL-004',
    );
  });

  it('already building → 409 LSE-TPL-007', async () => {
    const { admin, base } = await setup();
    const g = gate();
    builder.enqueue({ gate: g.promise });
    expect((await admin.post(`${base}/build-template`)).status).toBe(202);
    expectError(await admin.post(`${base}/build-template`), 'LSE-TPL-007', 409);
    g.open();
    await ctx.jobs.onIdle();
    expect((await admin.get(`${base}/template-status`)).body.data.status).toBe('READY');
    // Not building any more → a rebuild is accepted again.
    expect((await admin.post(`${base}/build-template`)).status).toBe(202);
    await ctx.jobs.onIdle();
  });

  it('blue/green: the previous template stays active during and after a failed rebuild', async () => {
    const { admin, org, base, project } = await setup({
      templateStatus: 'READY',
      templateVersion: 1,
      e2bTemplateId: 'tpl-old',
    });
    const member = await login(app);
    await addMember(org.id, member.user.id, 'MEMBER');
    await linkGithub(ctx, member.user.id);
    await addApiKey(ctx, member.user.id);

    const g = gate();
    builder.enqueue({ gate: g.promise, error: { kind: 'user', message: 'broken deps' } });
    await admin.post(`${base}/build-template`);
    expect((await admin.get(`${base}/template-status`)).body.data).toMatchObject({
      status: 'BUILDING',
      templateId: 'tpl-old',
    });
    // Members still see the project and can start sessions on the old template.
    const list = await member.get(`/api/v1/orgs/${org.id}/projects`);
    expect(list.body.data.map((p: { id: string }) => p.id)).toContain(project.id);
    const started = await member.post('/api/v1/sessions', { projectId: project.id });
    expect(started.status, JSON.stringify(started.body)).toBe(201);

    g.open();
    await ctx.jobs.onIdle();
    expect(fake.createCalls.map((c) => c.templateId)).toContain('tpl-old');
    let st = (await admin.get(`${base}/template-status`)).body.data;
    expect(st).toMatchObject({ status: 'FAILED', templateId: 'tpl-old', version: 1 });

    builder.enqueue({ templateId: 'tpl-new' });
    await admin.post(`${base}/build-template`);
    await ctx.jobs.onIdle();
    st = (await admin.get(`${base}/template-status`)).body.data;
    expect(st).toMatchObject({ status: 'READY', templateId: 'tpl-new', version: 2 });
    const row = await prisma.project.findUniqueOrThrow({ where: { id: project.id } });
    expect(row.previousTemplateId).toBe('tpl-old');
  });

  it('build-template is idempotent with an Idempotency-Key', async () => {
    const { admin, base } = await setup();
    const g = gate();
    builder.enqueue({ gate: g.promise });
    const a = await admin.post(`${base}/build-template`).set('Idempotency-Key', 'build-1');
    const b = await admin.post(`${base}/build-template`).set('Idempotency-Key', 'build-1');
    expect(a.status).toBe(202);
    expect(b.status).toBe(202);
    expect(b.headers['idempotent-replayed']).toBe('true');
    g.open();
    await ctx.jobs.onIdle();
    expect(builder.specs).toHaveLength(1);
  });
});

function parseSse(text: string) {
  return text
    .split('\n\n')
    .filter((b) => b.trim() && !b.startsWith(':'))
    .map((block) => {
      const ev: { id?: string; event?: string; data?: unknown } = {};
      for (const line of block.split('\n')) {
        const i = line.indexOf(': ');
        const k = line.slice(0, i);
        const v = line.slice(i + 2);
        if (k === 'id') ev.id = v;
        if (k === 'event') ev.event = v;
        if (k === 'data') ev.data = JSON.parse(v);
      }
      return ev;
    });
}

async function patFor(userId: string, orgId: string) {
  const raw = `${PAT_PREFIX}${randomBytes(24).toString('base64url')}`;
  await prisma.apiToken.create({
    data: {
      orgId,
      userId,
      name: 'sse',
      hash: sha256Hex(raw),
      scopes: ['projects:read', 'org:read'],
    },
  });
  return raw;
}

describe('template logs SSE', () => {
  it('replays buffered lines, the status and `end` for a finished build; honours Last-Event-ID', async () => {
    const { admin, base } = await setup();
    builder.enqueue({ logs: ['line A', 'line B'] });
    await admin.post(`${base}/build-template`);
    await ctx.jobs.onIdle();
    const res = await admin
      .get(`${base}/template-logs`)
      .buffer(true)
      .parse((r, cb) => {
        let t = '';
        r.on('data', (c: Buffer) => (t += c.toString()));
        r.on('end', () => cb(null, t));
      });
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/text\/event-stream/);
    const events = parseSse(res.body as string);
    const logs = events
      .filter((e) => e.event === 'log')
      .map((e) => (e.data as { line: string }).line);
    expect(logs).toEqual(expect.arrayContaining(['line A', 'line B']));
    expect(events.filter((e) => e.event === 'status').at(-1)?.data).toMatchObject({
      status: 'READY',
    });
    expect(events.at(-1)?.event).toBe('end');

    const lineB = events.find(
      (e) => e.event === 'log' && (e.data as { line: string }).line === 'line B',
    );
    const again = await admin
      .get(`${base}/template-logs`)
      .set('Last-Event-ID', lineB!.id!)
      .buffer(true)
      .parse((r, cb) => {
        let t = '';
        r.on('data', (c: Buffer) => (t += c.toString()));
        r.on('end', () => cb(null, t));
      });
    const after = parseSse(again.body as string).filter((e) => e.event === 'log');
    expect(after.every((e) => Number(e.id) > Number(lineB!.id))).toBe(true);
    expect(after.map((e) => (e.data as { line: string }).line)).not.toContain('line A');
  });

  it('streams live lines and ends when the build finishes', async () => {
    const { admin, org, base } = await setup();
    const g = gate();
    builder.enqueue({ logs: ['early line'], gate: g.promise, logsAfterGate: ['late line'] });
    await admin.post(`${base}/build-template`);
    const token = await patFor(admin.user.id, org.id);
    const srv = app.listen(0);
    try {
      const { port } = srv.address() as AddressInfo;
      const res = await fetch(`http://127.0.0.1:${port}${base}/template-logs`, {
        headers: { authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(10_000),
      });
      expect(res.status).toBe(200);
      const reader = res.body!.getReader();
      let text = '';
      let released = false;
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        text += new TextDecoder().decode(value);
        if (!released && text.includes('event: status')) {
          released = true;
          g.open();
        }
      }
      const events = parseSse(text);
      const lines = events
        .filter((e) => e.event === 'log')
        .map((e) => (e.data as { line: string }).line);
      expect(lines).toEqual(expect.arrayContaining(['early line', 'late line']));
      const statuses = events
        .filter((e) => e.event === 'status')
        .map((e) => (e.data as { status: string }).status);
      expect(statuses[0]).toBe('BUILDING');
      expect(statuses.at(-1)).toBe('READY');
      expect(events.at(-1)?.event).toBe('end');
    } finally {
      g.open();
      await new Promise<void>((r) => srv.close(() => r()));
      await ctx.jobs.onIdle();
    }
  });
});

describe('smoke test', () => {
  const previewOk = () =>
    server.use(
      http.get(/\.fake\.sandbox\/?$/, () => new HttpResponse('<html>ok</html>', { status: 200 })),
    );

  async function smokeSetup(extra: Parameters<typeof createReadyProject>[2] = {}) {
    return setup({
      templateStatus: 'READY',
      e2bTemplateId: 'tpl-smoke',
      startupCommands: ['npm ci', 'npm run dev'],
      portMap: [{ name: 'web', port: 3000, public: true, envVar: 'APP_URL' }],
      healthCheck: { path: '/health', port: 3000, timeoutSec: 1 },
      ...extra,
    });
  }

  it('passes: clone, startup, health check and preview; sandbox is killed', async () => {
    const { admin, base, project } = await smokeSetup();
    previewOk();
    const res = await admin.post(`${base}/smoke-test`);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.data).toMatchObject({ status: 'PASSED', failedStep: null });
    const sbx = fake.last()!;
    expect(sbx.templateId).toBe('tpl-smoke');
    expect(sbx.killed).toBe(true);
    expect(sbx.commands.find((c) => c.background)?.cmd).toBe('npm run dev');
    expect(sbx.commandLines().some((c) => c.startsWith('git clone'))).toBe(true);
    expect(sbx.files.get('/home/user/workspace/.env')).toContain(
      `APP_URL="https://3000-${sbx.id}.fake.sandbox"`,
    );
    const st = (await admin.get(`${base}/template-status`)).body.data;
    expect(st.smokeTest).toMatchObject({ status: 'PASSED', failedStep: null });
    const audit = await prisma.auditLog.findFirst({
      where: { target: project.id, action: 'template.smoke_test' },
    });
    expect(audit?.meta).toMatchObject({ status: 'PASSED' });
  });

  it('fails at the health check → LSE-TPL-006 with failedStep', async () => {
    const { admin, base } = await smokeSetup();
    fake.onCommand(/^node -e/, () => ({ exitCode: 1 }));
    const res = await admin.post(`${base}/smoke-test`);
    expectError(res, 'LSE-TPL-006', 500);
    expect(res.body.error.fields.failedStep).toEqual(['health_check']);
    expect(fake.last()!.killed).toBe(true);
    const st = (await admin.get(`${base}/template-status`)).body.data;
    expect(st.smokeTest).toMatchObject({ status: 'FAILED', failedStep: 'health_check' });
  });

  it('fails at a startup command; output is scrubbed', async () => {
    const { admin, base } = await smokeSetup();
    fake.onCommand('npm ci', () => ({ exitCode: 1, stderr: `npm ERR! auth ${SECRET}` }));
    const res = await admin.post(`${base}/smoke-test`);
    expectError(res, 'LSE-TPL-006', 500);
    expect(res.body.error.fields.failedStep).toEqual(['startup_commands']);
    expect(JSON.stringify(res.body)).not.toContain(SECRET);
  });

  it('fails at the preview when the public URL errors', async () => {
    const { admin, base } = await smokeSetup();
    server.use(http.get(/\.fake\.sandbox\/?$/, () => new HttpResponse('down', { status: 502 })));
    const res = await admin.post(`${base}/smoke-test`);
    expectError(res, 'LSE-TPL-006', 500);
    expect(res.body.error.fields.failedStep).toEqual(['preview']);
  });

  it('needs a built template (LSE-TPL-001) and runs one at a time (LSE-TPL-007)', async () => {
    const { admin, base } = await setup();
    expectError(await admin.post(`${base}/smoke-test`), 'LSE-TPL-001', 409);
    const s = await smokeSetup();
    await ctx.kv.set(`smoke:${s.project.id}`, '1', 60);
    expectError(await s.admin.post(`${s.base}/smoke-test`), 'LSE-TPL-007', 409);
  });

  it('members cannot build or smoke-test (admin only)', async () => {
    const { org, base } = await smokeSetup();
    const member: Client = await login(app);
    await addMember(org.id, member.user.id, 'MEMBER');
    expectError(await member.post(`${base}/build-template`), 'LSE-ORG-002', 403);
    expectError(await member.post(`${base}/smoke-test`), 'LSE-ORG-002', 403);
    expectError(await member.get(`${base}/template-logs`), 'LSE-ORG-002', 403);
  });
});
