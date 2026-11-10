/**
 * Phase 8 (agent side — "hooks enforce policies server-side"): the `hook_request` /
 * `hook_response` round-trip with webhook handlers (allow / deny / fail open / fail
 * closed), `UserPromptSubmit` hooks evaluated by the server before a turn, the post-turn
 * re-validation of `block_paths`, SessionStart / SessionEnd / Notification hooks, context
 * usage audiences, attachments, click-to-select and per-subagent usage attribution.
 */
import { http, HttpResponse, type RequestHandler } from 'msw';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import {
  CSRF_HEADER,
  HOOK_SIGNATURE_HEADER,
  MAX_ATTACHMENT_BYTES,
  type ChatMessageMetadata,
} from '@loose/shared';
import {
  busEvents,
  FakeGit,
  installFakeRunner,
  lastSandbox,
  mswFetch,
  playTurn,
  waitFor,
  type FakeRunner,
  type RunnerScript,
} from './agentHelpers';
import {
  addMember,
  createOrg,
  expectError,
  linkGithub,
  login,
  makeApp,
  resetDb,
  testPrisma,
  type Client,
} from './helpers';
import { addApiKey, createReadyProject, fakeSandbox, settle } from './sessionHelpers';

const prisma = testPrisma();
const handlers: { current: RequestHandler[] } = { current: [] };
const { app, ctx } = makeApp({ context: { fetch: mswFetch(handlers) } });
const fake = fakeSandbox(ctx);
const script: { current: RunnerScript } = { current: () => undefined };
let runners: FakeRunner[] = [];
let git: FakeGit;

afterAll(async () => {
  await ctx.agent.idle();
  await ctx.jobs.onIdle();
  await prisma.$disconnect();
});

beforeEach(async () => {
  await ctx.agent.shutdownAll();
  await ctx.jobs.onIdle();
  fake.reset();
  runners = installFakeRunner(fake, script);
  git = new FakeGit().install(fake);
  handlers.current = [];
  script.current = (cmd, r) => {
    if (cmd.type === 'user_message') playTurn(r);
  };
  await resetDb();
});

// ---- helpers -------------------------------------------------------------------------------

const base = (orgId: string) => `/api/v1/orgs/${orgId}`;
const WEBHOOK_URL = 'https://hooks.example.test/loose';
const HOOK_SECRET = 'hook-secret-value-0123456789';
const PNG = Buffer.from('89504e470d0a1a0a0000000d49484452', 'hex');

interface WebhookSeen {
  events: string[];
  payloads: Record<string, unknown>[];
  signatures: (string | null)[];
}

/** `reply(payload)` decides what the webhook answers for each call. */
function webhook(reply: (p: Record<string, unknown>) => Response | Promise<Response>): WebhookSeen {
  const seen: WebhookSeen = { events: [], payloads: [], signatures: [] };
  handlers.current = [
    http.post(WEBHOOK_URL, async ({ request: req }) => {
      const body = (await req.json()) as Record<string, unknown>;
      seen.payloads.push(body);
      seen.events.push(String(body.event));
      seen.signatures.push(req.headers.get(HOOK_SIGNATURE_HEADER));
      return reply(body);
    }),
  ];
  return seen;
}

interface World {
  owner: Client;
  admin: Client;
  orgId: string;
  projectId: string;
  sessionId: string;
  runner: FakeRunner;
}

async function world(
  opts: {
    mode?: 'SIMPLE' | 'PRO';
    project?: Record<string, unknown>;
    setup?: (a: { admin: Client; orgId: string; projectId: string }) => Promise<void>;
  } = {},
): Promise<World> {
  const admin = await login(app, undefined, 'Ada Admin');
  const org = await createOrg(admin);
  const owner = await login(app, undefined, 'Mo Member');
  await addMember(org.id, owner.user.id, 'MEMBER');
  await linkGithub(ctx, owner.user.id);
  await addApiKey(ctx, owner.user.id);
  const project = await createReadyProject(ctx, org.id, {
    componentLabels: { 'src/components/Header*': 'the site header' },
    portMap: [{ name: 'web', port: 3000, public: true }],
    ...opts.project,
  });
  await opts.setup?.({ admin, orgId: org.id, projectId: project.id });
  const res = await owner.post('/api/v1/sessions', {
    projectId: project.id,
    mode: opts.mode ?? 'PRO',
  });
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  const s = await settle(ctx, res.body.data.id as string);
  expect(s.status).toBe('RUNNING');
  const runner = await waitFor(() => runners.at(-1), { label: 'runner start' });
  await waitFor(() => ctx.agent.hasRuntime(s.id), { label: 'agent runtime' });
  return { owner, admin, orgId: org.id, projectId: project.id, sessionId: s.id, runner };
}

const send = (c: Client, sessionId: string, content: string, extra: object = {}) =>
  c.post(`/api/v1/sessions/${sessionId}/messages`, { content, ...extra });

async function turnDone(sessionId: string, n = 1) {
  await waitFor(
    async () =>
      (await prisma.chatMessage.count({
        where: { sessionId, role: 'ASSISTANT', rawContent: { path: ['pending'], equals: false } },
      })) >= n,
    { label: `turn ${n} complete` },
  );
  await ctx.agent.idle(sessionId);
}

const ofType = (entries: Awaited<ReturnType<typeof busEvents>>, type: string, aud?: string) =>
  entries.filter((e) => e.message.type === type && (!aud || e.audience === aud));

const errorCodes = (entries: Awaited<ReturnType<typeof busEvents>>) =>
  ofType(entries, 'error').map(
    (e) => (e.message.payload as { error: { code: string } }).error.code,
  );

function httpHook(body: Record<string, unknown> = {}) {
  return {
    scope: 'ORG' as const,
    name: 'Review service',
    event: 'PreToolUse',
    handler: { type: 'http', url: WEBHOOK_URL, secret: HOOK_SECRET },
    ...body,
  };
}

// ---- hook_request / hook_response ----------------------------------------------------------

describe('server-side hook decisions', () => {
  it('answers a hook_request with the webhook decision and audits it', async () => {
    const w = await world({
      setup: async ({ admin, orgId }) => {
        const res = await admin.post(`${base(orgId)}/hooks`, httpHook({ matcher: 'Edit|Write' }));
        expect(res.status, JSON.stringify(res.body)).toBe(201);
      },
    });
    const seen = webhook((p) =>
      HttpResponse.json(
        p.toolName === 'Write'
          ? { decision: 'deny', reason: 'Writing new files is frozen' }
          : { decision: 'allow' },
      ),
    );
    // The config tells the runner which events the server owns.
    const sbx = lastSandbox(ctx);
    const config = JSON.parse(sbx.files.get(`${sbx.paths.state}/config.json`)!) as {
      serverHookEvents: string[];
      hooks: unknown[];
    };
    expect(config.serverHookEvents).toEqual(['PreToolUse']);
    expect(config.hooks).toEqual([]);

    w.runner.emit('hook_request', {
      id: 'hr-1',
      event: 'PreToolUse',
      payload: {
        event: 'PreToolUse',
        sessionId: w.sessionId,
        toolName: 'Edit',
        toolInput: { file_path: 'src/components/Header.tsx' },
        filePaths: ['src/components/Header.tsx'],
      },
    });
    await waitFor(() => w.runner.of('hook_response').length === 1, {
      label: 'allow response',
      timeoutMs: 15_000,
    });
    expect(w.runner.of('hook_response')[0]!.data).toMatchObject({
      id: 'hr-1',
      decision: 'allow',
    });

    w.runner.emit('hook_request', {
      id: 'hr-2',
      event: 'PreToolUse',
      payload: {
        event: 'PreToolUse',
        sessionId: w.sessionId,
        toolName: 'Write',
        filePaths: ['infra/main.tf'],
      },
    });
    await waitFor(() => w.runner.of('hook_response').length === 2, {
      label: 'deny response',
      timeoutMs: 15_000,
    });
    expect(w.runner.of('hook_response')[1]!.data).toMatchObject({
      id: 'hr-2',
      decision: 'deny',
      reason: 'Writing new files is frozen',
    });
    await ctx.agent.idle(w.sessionId);

    // Every call is signed and carries the session context the server owns.
    expect(seen.events).toEqual(['PreToolUse', 'PreToolUse']);
    expect(seen.signatures.every((s) => s?.startsWith('sha256='))).toBe(true);
    expect(seen.payloads[0]).toMatchObject({
      sessionId: w.sessionId,
      projectId: w.projectId,
      orgId: w.orgId,
    });

    // Both decisions are audited and shown in the Pro timeline.
    const audits = await prisma.auditLog.findMany({
      where: { orgId: w.orgId, action: 'hook.decision' },
      orderBy: { createdAt: 'asc' },
    });
    expect(audits).toHaveLength(2);
    expect(audits.map((a) => (a.meta as { decision: string }).decision)).toEqual(['allow', 'deny']);
    expect(audits[1]!.meta).toMatchObject({
      name: 'Review service',
      event: 'PreToolUse',
      handler: 'http',
      toolName: 'Write',
      sessionId: w.sessionId,
    });
    const entries = await busEvents(ctx, w.sessionId);
    const hookEvents = ofType(entries, 'hook_event', 'pro');
    expect(hookEvents).toHaveLength(2);
    expect(hookEvents[1]!.message.payload).toMatchObject({
      name: 'Review service',
      decision: 'deny',
      handler: 'http',
      toolName: 'Write',
    });
    expect(ofType(entries, 'hook_event', 'simple')).toHaveLength(0);
    expect(errorCodes(entries)).toContain('LSE-AGT-005');
    const row = await prisma.hook.findFirstOrThrow({ where: { orgId: w.orgId } });
    expect(row.lastDecision).toBe('deny');
  });

  it('fails closed on a webhook timeout and open when the hook says so', async () => {
    const w = await world({
      setup: async ({ admin, orgId }) => {
        expect((await admin.post(`${base(orgId)}/hooks`, httpHook({ timeoutSec: 1 }))).status).toBe(
          201,
        );
      },
    });
    webhook(async () => {
      await new Promise((r) => setTimeout(r, 2500));
      return HttpResponse.json({ decision: 'allow' });
    });
    w.runner.emit('hook_request', {
      id: 'slow-1',
      event: 'PreToolUse',
      payload: { event: 'PreToolUse', sessionId: w.sessionId, toolName: 'Edit' },
    });
    await waitFor(() => w.runner.of('hook_response').length === 1, {
      label: 'timeout response',
      timeoutMs: 20_000,
    });
    expect(w.runner.of('hook_response')[0]!.data).toMatchObject({ decision: 'deny' });
    expect(w.runner.of('hook_response')[0]!.data.reason).toContain('could not run');
    await ctx.agent.idle(w.sessionId);
    const entries = await busEvents(ctx, w.sessionId);
    expect(errorCodes(entries)).toContain('LSE-AGT-014');
    expect(
      (ofType(entries, 'hook_event', 'pro')[0]!.message.payload as { errorCode?: string })
        .errorCode,
    ).toBe('LSE-AGT-014');
    const audit = await prisma.auditLog.findFirstOrThrow({
      where: { orgId: w.orgId, action: 'hook.decision' },
    });
    expect(audit.meta).toMatchObject({ decision: 'deny', errorCode: 'LSE-AGT-014' });

    // The same failure with failMode: open lets the agent continue.
    await resetDb();
    const open = await world({
      setup: async ({ admin, orgId }) => {
        expect(
          (
            await admin.post(
              `${base(orgId)}/hooks`,
              httpHook({ failMode: 'open', timeoutSec: 1, event: 'PostToolUse' }),
            )
          ).status,
        ).toBe(201);
      },
    });
    webhook(() => new HttpResponse(null, { status: 500 }));
    open.runner.emit('hook_request', {
      id: 'open-1',
      event: 'PostToolUse',
      payload: { event: 'PostToolUse', sessionId: open.sessionId, toolName: 'Edit' },
    });
    await waitFor(() => open.runner.of('hook_response').length === 1, {
      label: 'open response',
      timeoutMs: 15_000,
    });
    expect(open.runner.of('hook_response')[0]!.data).toMatchObject({ decision: 'allow' });
    await ctx.agent.idle(open.sessionId);
  });

  it('merges several hooks: deny wins over modify and ask', async () => {
    const w = await world({
      setup: async ({ admin, orgId }) => {
        expect((await admin.post(`${base(orgId)}/hooks`, httpHook())).status).toBe(201);
        expect(
          (
            await admin.post(
              `${base(orgId)}/hooks`,
              httpHook({ name: 'Second service', handler: { type: 'http', url: WEBHOOK_URL } }),
            )
          ).status,
        ).toBe(201);
      },
    });
    let n = 0;
    webhook(() =>
      HttpResponse.json(
        (n += 1) === 1
          ? { decision: 'modify', updatedInput: { file_path: 'src/Safe.tsx' } }
          : { decision: 'deny', reason: 'No' },
      ),
    );
    w.runner.emit('hook_request', {
      id: 'merge-1',
      event: 'PreToolUse',
      payload: { event: 'PreToolUse', sessionId: w.sessionId, toolName: 'Edit' },
    });
    await waitFor(() => w.runner.of('hook_response').length === 1, {
      label: 'merged response',
      timeoutMs: 15_000,
    });
    expect(w.runner.of('hook_response')[0]!.data).toMatchObject({ decision: 'deny', reason: 'No' });
    await ctx.agent.idle(w.sessionId);
    expect(
      await prisma.auditLog.count({ where: { orgId: w.orgId, action: 'hook.decision' } }),
    ).toBe(2);
  });

  it('audits the hooks the runner evaluated itself', async () => {
    const w = await world({
      setup: async ({ admin, orgId }) => {
        const res = await admin.post(`${base(orgId)}/hooks`, {
          scope: 'ORG',
          name: 'Protect infra',
          event: 'PreToolUse',
          matcher: 'Edit|Write',
          handler: { type: 'builtin', action: 'block_paths', config: { paths: ['infra/**'] } },
        });
        expect(res.status, JSON.stringify(res.body)).toBe(201);
      },
    });
    const hook = await prisma.hook.findFirstOrThrow({ where: { orgId: w.orgId } });
    w.runner.emit('hook_result', {
      hookId: hook.id,
      event: 'PreToolUse',
      decision: 'deny',
      reason: 'infra/main.tf is off-limits in this project',
      handler: 'builtin',
      action: 'block_paths',
      toolName: 'Edit',
      durationMs: 3,
    });
    await waitFor(
      async () =>
        (await prisma.auditLog.count({ where: { orgId: w.orgId, action: 'hook.decision' } })) === 1,
      { label: 'runner hook audited' },
    );
    const audit = await prisma.auditLog.findFirstOrThrow({
      where: { orgId: w.orgId, action: 'hook.decision' },
    });
    expect(audit.meta).toMatchObject({
      name: 'Protect infra',
      handler: 'builtin',
      action: 'block_paths',
      decision: 'deny',
      source: 'runner',
    });
    await ctx.agent.idle(w.sessionId);
    expect((await prisma.hook.findUniqueOrThrow({ where: { id: hook.id } })).lastDecision).toBe(
      'deny',
    );
    const pro = ofType(await busEvents(ctx, w.sessionId), 'hook_event', 'pro');
    expect(pro).toHaveLength(1);
    expect(pro[0]!.message.payload).toMatchObject({ handler: 'builtin', decision: 'deny' });
  });
});

// ---- UserPromptSubmit ----------------------------------------------------------------------

describe('UserPromptSubmit hooks', () => {
  it('denies a message (LSE-AGT-005) and rewrites a prompt on modify', async () => {
    const w = await world({
      setup: async ({ admin, orgId }) => {
        expect(
          (await admin.post(`${base(orgId)}/hooks`, httpHook({ event: 'UserPromptSubmit' })))
            .status,
        ).toBe(201);
      },
    });
    webhook((p) =>
      HttpResponse.json(
        String(p.prompt).includes('production')
          ? { decision: 'deny', reason: 'Production changes need a ticket' }
          : {
              decision: 'modify',
              updatedPrompt: `${String(p.prompt)}\n\n(House style: British spelling.)`,
            },
      ),
    );

    const denied = await send(w.owner, w.sessionId, 'Deploy this to production now');
    expectError(denied, 'LSE-AGT-005', 403);
    expect(denied.body.error.userMessage).toBe('Production changes need a ticket');
    // Nothing was persisted or sent to the agent.
    expect(await prisma.chatMessage.count({ where: { sessionId: w.sessionId } })).toBe(0);
    expect(w.runner.of('user_message')).toHaveLength(0);

    const ok = await send(w.owner, w.sessionId, 'Make the title red');
    expect(ok.status, JSON.stringify(ok.body)).toBe(202);
    await turnDone(w.sessionId);
    const sent = w.runner.of('user_message')[0]!.data;
    expect(sent.text).toContain('Make the title red');
    expect(sent.text).toContain('British spelling');
    // The chat still shows exactly what the user typed.
    const userMsg = await prisma.chatMessage.findFirstOrThrow({
      where: { sessionId: w.sessionId, role: 'USER' },
    });
    expect(userMsg.content).toBe('Make the title red');
    const audits = await prisma.auditLog.findMany({
      where: { orgId: w.orgId, action: 'hook.decision' },
      orderBy: { createdAt: 'asc' },
    });
    expect(audits.map((a) => (a.meta as { decision: string }).decision)).toEqual([
      'deny',
      'modify',
    ]);
  });
});

// ---- post-turn block_paths -----------------------------------------------------------------

describe('post-turn block_paths enforcement', () => {
  it('reverts files a hook forbids and reports LSE-AGT-004', async () => {
    const w = await world({
      setup: async ({ admin, orgId }) => {
        const res = await admin.post(`${base(orgId)}/hooks`, {
          scope: 'ORG',
          name: 'Protect infra',
          event: 'PreToolUse',
          matcher: 'Edit|Write',
          handler: {
            type: 'builtin',
            action: 'block_paths',
            config: { paths: ['infra/**'], message: 'Infrastructure is off-limits' },
          },
        });
        expect(res.status, JSON.stringify(res.body)).toBe(201);
      },
    });
    git.set('src/components/Header.tsx').set('infra/main.tf');
    script.current = (cmd, r) => {
      if (cmd.type === 'user_message')
        playTurn(r, { files: ['src/components/Header.tsx', 'infra/main.tf'] });
    };
    expect((await send(w.owner, w.sessionId, 'Tidy everything up')).status).toBe(202);
    await turnDone(w.sessionId);

    // The blocked file was reverted; the allowed one survives.
    expect([...git.files.keys()]).toEqual(['src/components/Header.tsx']);
    const sbx = lastSandbox(ctx);
    expect(sbx.commands.some((c) => c.cmd.includes("checkout -q HEAD -- 'infra/main.tf'"))).toBe(
      true,
    );
    const entries = await busEvents(ctx, w.sessionId);
    expect(errorCodes(entries)).toContain('LSE-AGT-004');
    const hookEvent = ofType(entries, 'hook_event', 'pro').at(-1)!;
    expect(hookEvent.message.payload).toMatchObject({
      name: 'Protect infra',
      decision: 'deny',
      handler: 'builtin',
    });
    const audit = await prisma.auditLog.findFirstOrThrow({
      where: { orgId: w.orgId, action: 'hook.decision' },
    });
    expect(audit.meta).toMatchObject({
      source: 'post_turn',
      decision: 'deny',
      reason: 'Infrastructure is off-limits',
      files: ['infra/main.tf'],
    });
    // The change summary only mentions the file that was kept.
    const msg = await prisma.chatMessage.findFirstOrThrow({
      where: { sessionId: w.sessionId, role: 'ASSISTANT' },
    });
    expect((msg.metadata as { filesChanged: string[] }).filesChanged).toEqual([
      'src/components/Header.tsx',
    ]);
  });
});

// ---- lifecycle hooks -----------------------------------------------------------------------

describe('lifecycle hooks', () => {
  it('calls the webhook on SessionStart and SessionEnd', async () => {
    const seen = webhook(() => HttpResponse.json({ decision: 'allow' }));
    const w = await world({
      setup: async ({ admin, orgId }) => {
        for (const event of ['SessionStart', 'SessionEnd'] as const) {
          const res = await admin.post(
            `${base(orgId)}/hooks`,
            httpHook({ name: `On ${event}`, event, failMode: 'open' }),
          );
          expect(res.status, JSON.stringify(res.body)).toBe(201);
        }
      },
    });
    await waitFor(() => seen.events.includes('SessionStart'), {
      label: 'SessionStart webhook',
      timeoutMs: 15_000,
    });
    expect(seen.payloads[0]).toMatchObject({
      event: 'SessionStart',
      sessionId: w.sessionId,
      projectId: w.projectId,
      orgId: w.orgId,
    });
    await ctx.agent.idle(w.sessionId);

    await ctx.agent.shutdownAll();
    await waitFor(() => seen.events.includes('SessionEnd'), {
      label: 'SessionEnd webhook',
      timeoutMs: 15_000,
    });
    const end = seen.payloads.find((p) => p.event === 'SessionEnd')!;
    expect(end).toMatchObject({ sessionId: w.sessionId });
    expect((end.context as { reason: string }).reason).toBe('stopped');
    expect(
      await prisma.auditLog.count({ where: { orgId: w.orgId, action: 'hook.decision' } }),
    ).toBeGreaterThanOrEqual(2);
  });

  it('notifies on a created pull request', async () => {
    const w = await world({
      setup: async ({ admin, orgId }) => {
        expect(
          (
            await admin.post(
              `${base(orgId)}/hooks`,
              httpHook({ name: 'Notify', event: 'Notification', failMode: 'open' }),
            )
          ).status,
        ).toBe(201);
      },
    });
    git.set('src/components/Header.tsx');
    const seen = webhook(() => HttpResponse.json({ decision: 'allow' }));
    handlers.current = [
      ...handlers.current,
      http.get('https://api.github.com/repos/acme/web', () =>
        HttpResponse.json({
          id: 1,
          full_name: 'acme/web',
          name: 'web',
          owner: { login: 'acme' },
          private: true,
          default_branch: 'main',
          html_url: 'https://github.com/acme/web',
        }),
      ),
      http.get('https://api.github.com/repos/acme/web/pulls', () => HttpResponse.json([])),
      http.post('https://api.github.com/repos/acme/web/pulls', () =>
        HttpResponse.json(
          { number: 42, html_url: 'https://github.com/acme/web/pull/42', draft: false },
          { status: 201 },
        ),
      ),
    ];
    const pr = await w.admin.post(`/api/v1/sessions/${w.sessionId}/create-pr`, {});
    expect(pr.status, JSON.stringify(pr.body)).toBe(200);
    await waitFor(() => seen.events.includes('Notification'), {
      label: 'Notification webhook',
      timeoutMs: 15_000,
    });
    const payload = seen.payloads.find((p) => p.event === 'Notification')!;
    expect(payload.message).toContain('pull request');
    expect((payload.context as { prUrl: string }).prUrl).toBe(
      'https://github.com/acme/web/pull/42',
    );
  });
});

// ---- context management --------------------------------------------------------------------

describe('context usage', () => {
  it('is Pro-only below 90% and reaches Simple viewers on warnings and compaction', async () => {
    const w = await world();
    w.runner.emit('context_usage', { usedTokens: 50_000, contextWindow: 200_000, percent: 25 });
    w.runner.emit('context_usage', { usedTokens: 184_000, contextWindow: 200_000, percent: 92 });
    w.runner.emit('context_usage', {
      usedTokens: 40_000,
      contextWindow: 200_000,
      percent: 20,
      compacted: true,
      trigger: 'auto',
    });
    await waitFor(
      async () => ofType(await busEvents(ctx, w.sessionId), 'context_update', 'pro').length === 3,
      { label: 'context updates' },
    );
    await ctx.agent.idle(w.sessionId);
    const entries = await busEvents(ctx, w.sessionId);
    const pro = ofType(entries, 'context_update', 'pro');
    expect(pro.map((e) => (e.message.payload as { percent: number }).percent)).toEqual([
      25, 92, 20,
    ]);
    expect(pro[0]!.message.payload).toMatchObject({
      usedTokens: 50_000,
      contextWindow: 200_000,
    });
    expect((pro[1]!.message.payload as { event?: string }).event).toBe('warning');
    expect(pro[2]!.message.payload).toMatchObject({ event: 'compacted', trigger: 'auto' });
    const simple = ofType(entries, 'context_update', 'simple');
    expect(simple.map((e) => (e.message.payload as { percent: number }).percent)).toEqual([92, 20]);
    // Compaction is explained in plain language.
    const sys = await prisma.chatMessage.findFirstOrThrow({
      where: { sessionId: w.sessionId, role: 'SYSTEM' },
    });
    expect(sys.content).toContain('summarised');
  });
});

// ---- attachments & inspection --------------------------------------------------------------

function upload(
  c: Client,
  sessionId: string,
  contentType: string,
  data: Buffer,
  name = 'shot.png',
) {
  return c.agent
    .post(`/api/v1/sessions/${sessionId}/attachments`)
    .set(CSRF_HEADER, c.csrf)
    .set('Content-Type', contentType)
    .set('x-file-name', name)
    .send(data);
}

describe('attachments', () => {
  it('stores an upload as an artifact and sends it to the runner', async () => {
    const w = await world();
    const res = await upload(w.owner, w.sessionId, 'image/png', PNG);
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    expect(res.body.data).toMatchObject({
      kind: 'attachment',
      name: 'shot.png',
      mimeType: 'image/png',
      size: PNG.length,
    });
    const artifactId = res.body.data.id as string;
    expect(res.body.data.url).toBe(
      `/api/v1/sessions/${w.sessionId}/artifacts/${artifactId}/content`,
    );
    const artifact = await prisma.artifact.findUniqueOrThrow({ where: { id: artifactId } });
    expect(artifact.kind).toBe('attachment');
    expect(artifact.meta).toMatchObject({ name: 'shot.png', mimeType: 'image/png' });
    // It is readable through the normal artifact route.
    const content = await w.owner.get(
      `/api/v1/sessions/${w.sessionId}/artifacts/${artifactId}/content`,
    );
    expect(content.status).toBe(200);
    expect(content.headers['content-type']).toContain('image/png');

    // The header is percent-encoded by the browser client (header values are ASCII-only).
    const encoded = await upload(
      w.owner,
      w.sessionId,
      'image/png',
      PNG,
      encodeURIComponent('my “logo” (1).png'),
    );
    expect(encoded.status, JSON.stringify(encoded.body)).toBe(201);
    expect(encoded.body.data.name).toBe('my “logo” (1).png');

    const sent = await send(w.owner, w.sessionId, 'Make it look like this', {
      attachments: [
        { kind: 'image', name: 'shot.png', id: artifactId, mimeType: 'image/png' },
        { kind: 'element', name: 'button', label: 'the “Sign up” button', selector: '#signup' },
      ],
    });
    expect(sent.status, JSON.stringify(sent.body)).toBe(202);
    await turnDone(w.sessionId);
    const msg = w.runner.of('user_message')[0]!.data;
    expect(msg.attachments).toEqual([
      {
        kind: 'image',
        name: 'shot.png',
        mimeType: 'image/png',
        dataBase64: PNG.toString('base64'),
      },
      {
        kind: 'element',
        name: 'button',
        label: 'the “Sign up” button',
        selector: '#signup',
      },
    ]);
    // The element context is spelled out for the agent.
    expect(msg.text).toContain('<selected_elements>');
    expect(msg.text).toContain('the “Sign up” button');
    expect(msg.text).toContain('#signup');

    // The chat message keeps the attachments, and Simple viewers never see the selector.
    const listed = await w.owner.get(`/api/v1/sessions/${w.sessionId}/messages`);
    expect(listed.status, JSON.stringify(listed.body)).toBe(200);
    const user = (listed.body.data as { role: string; metadata: ChatMessageMetadata }[]).find(
      (m) => m.role === 'USER',
    );
    expect(user?.metadata.attachments).toHaveLength(2);
    expect(user?.metadata.attachments?.[0]).toMatchObject({ kind: 'image', id: artifactId });
    expect(user?.metadata.attachments?.[1]).toMatchObject({ selector: '#signup' });
    const entries = await busEvents(ctx, w.sessionId);
    const simple = ofType(entries, 'chat_message', 'simple').map(
      (e) => (e.message.payload as { message: { metadata: ChatMessageMetadata } }).message,
    );
    expect(simple.length).toBeGreaterThan(0);
    expect(JSON.stringify(simple)).not.toContain('#signup');
    expect(JSON.stringify(simple)).toContain('the “Sign up” button');
    expect(
      JSON.stringify(
        ofType(entries, 'chat_message', 'pro').map((e) => e.message.payload as unknown),
      ),
    ).toContain('#signup');
  });

  it('refuses unsupported types and over-sized bodies with LSE-AGT-009', async () => {
    const w = await world();
    expectError(
      await upload(w.owner, w.sessionId, 'text/plain', Buffer.from('hello'), 'notes.txt'),
      'LSE-AGT-009',
      400,
    );
    expectError(
      await upload(w.owner, w.sessionId, 'image/png', Buffer.alloc(0)),
      'LSE-AGT-009',
      400,
    );
    const big = Buffer.alloc(MAX_ATTACHMENT_BYTES + 1024, 1);
    expectError(await upload(w.owner, w.sessionId, 'image/png', big), 'LSE-AGT-009', 400);
    expect(await prisma.artifact.count({ where: { sessionId: w.sessionId } })).toBe(0);
    // A PDF is accepted and handed over as a document block.
    const pdf = await upload(
      w.owner,
      w.sessionId,
      'application/pdf',
      Buffer.from('%PDF-1.7\n'),
      'spec.pdf',
    );
    expect(pdf.status, JSON.stringify(pdf.body)).toBe(201);
    await send(w.owner, w.sessionId, 'Follow this spec', {
      attachments: [
        {
          kind: 'file',
          name: 'spec.pdf',
          id: pdf.body.data.id as string,
          mimeType: 'application/pdf',
        },
      ],
    });
    await turnDone(w.sessionId);
    expect(w.runner.of('user_message')[0]!.data.attachments?.[0]).toMatchObject({
      kind: 'document',
      mimeType: 'application/pdf',
    });
  });
});

describe('click-to-select', () => {
  it('returns a Simple-safe label, the selector in Pro and a cropped artifact', async () => {
    script.current = (cmd, r) => {
      if (cmd.type === 'inspect')
        r.emit('inspect_result', {
          requestId: cmd.data.requestId,
          ok: true,
          selector: '#hero > button.signup',
          tagName: 'BUTTON',
          text: 'Sign up',
          rect: { x: 100, y: 200, width: 120, height: 40 },
          pngBase64: PNG.toString('base64'),
        });
      if (cmd.type === 'user_message') playTurn(r);
    };
    const w = await world();
    const res = await w.owner.post(`/api/v1/sessions/${w.sessionId}/inspect`, { x: 120, y: 210 });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.data).toMatchObject({
      ok: true,
      selector: '#hero > button.signup',
      label: 'the “Sign up” button',
      tagName: 'BUTTON',
      rect: { x: 100, y: 200, width: 120, height: 40 },
    });
    const sent = w.runner.of('inspect')[0]!.data;
    expect(sent).toMatchObject({ x: 120, y: 210, viewport: 'desktop' });
    expect(sent.url).toBeTruthy();
    const artifact = await prisma.artifact.findUniqueOrThrow({
      where: { id: res.body.data.artifactId as string },
    });
    expect(artifact.kind).toBe('element');
    expect(artifact.meta).toMatchObject({ label: 'the “Sign up” button', tagName: 'BUTTON' });

    // Simple viewers never receive the selector.
    expect(
      (
        await w.owner.post(`/api/v1/sessions/${w.sessionId}/commands`, {
          command: 'mode',
          args: 'simple',
        })
      ).status,
    ).toBe(200);
    const simple = await w.owner.post(`/api/v1/sessions/${w.sessionId}/inspect`, {
      x: 10,
      y: 10,
    });
    expect(simple.status, JSON.stringify(simple.body)).toBe(200);
    expect(simple.body.data.selector).toBeNull();
    expect(simple.body.data.label).toBe('the “Sign up” button');
  });

  it('reports a failed inspection without throwing', async () => {
    script.current = (cmd, r) => {
      if (cmd.type === 'inspect')
        r.emit('inspect_result', {
          requestId: cmd.data.requestId,
          ok: false,
          error: 'no element at that point',
        });
      if (cmd.type === 'user_message') playTurn(r);
    };
    const w = await world();
    const res = await w.owner.post(`/api/v1/sessions/${w.sessionId}/inspect`, { x: 1, y: 1 });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.data).toMatchObject({
      ok: false,
      selector: null,
      artifactId: null,
      error: { code: 'LSE-AGT-001' },
    });
    expect(res.body.data.label).toContain('element');
  });
});

// ---- usage attribution ---------------------------------------------------------------------

describe('usage', () => {
  it('attributes cost per subagent and reports the cache hit ratio', async () => {
    const w = await world();
    script.current = (cmd, r) => {
      if (cmd.type !== 'user_message') return;
      r.emit('usage', {
        in: 1000,
        out: 200,
        cacheRead: 3000,
        costUsd: 0.01,
        model: 'claude-sonnet-4-5',
        subagent: 'code-reviewer',
      });
      playTurn(r, { usage: { in: 500, out: 100, costUsd: 0.02 } });
    };
    expect((await send(w.owner, w.sessionId, 'Review my change')).status).toBe(202);
    await turnDone(w.sessionId);
    const events = await prisma.usageEvent.findMany({
      where: { sessionId: w.sessionId },
      orderBy: { createdAt: 'asc' },
    });
    expect(events.map((e) => e.subagent)).toEqual(['code-reviewer', null]);
    // The delegation is also recorded on the assistant message (Pro-only chips).
    const assistant = await prisma.chatMessage.findFirstOrThrow({
      where: { sessionId: w.sessionId, role: 'ASSISTANT' },
      orderBy: { createdAt: 'desc' },
    });
    expect(assistant.metadata).toMatchObject({ subagents: ['code-reviewer'] });

    const usage = await w.admin.get(`${base(w.orgId)}/usage`);
    expect(usage.status, JSON.stringify(usage.body)).toBe(200);
    const bySubagent = usage.body.data.bySubagent as {
      subagent: string | null;
      costUsd: number;
      calls: number;
    }[];
    expect(bySubagent).toHaveLength(2);
    expect(bySubagent.find((r) => r.subagent === 'code-reviewer')).toMatchObject({
      costUsd: 0.01,
      calls: 1,
    });
    expect(bySubagent.find((r) => r.subagent === null)).toMatchObject({ calls: 1 });
    // cacheRead / (tokensIn + cacheRead) = 12000 / (1500 + 12000)
    expect(usage.body.data.cacheHitRatio).toBeCloseTo(12_000 / 13_500, 5);
  });
});

// ---- per-viewport screenshots ---------------------------------------------------------------

describe('per-viewport screenshots', () => {
  it('captures before/after shots for every viewport the project enables', async () => {
    const shot = makeApp({ env: { AGENT_SCREENSHOTS: 'true' } });
    const shotFake = fakeSandbox(shot.ctx);
    const shotScript: { current: RunnerScript } = {
      current: (cmd, r) => {
        if (cmd.type === 'screenshot')
          r.emit('screenshot_result', {
            requestId: cmd.data.requestId,
            ok: true,
            pngBase64: PNG.toString('base64'),
            width: 1280,
            height: 800,
          });
        if (cmd.type === 'user_message') playTurn(r, { files: ['src/components/Header.tsx'] });
      },
    };
    installFakeRunner(shotFake, shotScript);
    new FakeGit().set('src/components/Header.tsx').install(shotFake);
    const admin = await login(shot.app);
    const org = await createOrg(admin);
    await linkGithub(shot.ctx, admin.user.id);
    await addApiKey(shot.ctx, admin.user.id);
    const project = await createReadyProject(shot.ctx, org.id, {
      portMap: [{ name: 'web', port: 3000, public: true }],
      screenshotViewports: ['desktop', 'mobile'],
    });
    const res = await admin.post('/api/v1/sessions', { projectId: project.id, mode: 'PRO' });
    const s = await settle(shot.ctx, res.body.data.id as string);
    expect(s.status).toBe('RUNNING');
    await waitFor(() => shot.ctx.agent.hasRuntime(s.id), { label: 'runtime' });
    await admin.post(`/api/v1/sessions/${s.id}/messages`, { content: 'make the title red' });
    await waitFor(async () => (await prisma.artifact.count({ where: { sessionId: s.id } })) === 4, {
      label: 'four screenshots',
    });
    await shot.ctx.agent.idle(s.id);
    const arts = await prisma.artifact.findMany({
      where: { sessionId: s.id },
      orderBy: { createdAt: 'asc' },
    });
    expect(
      arts.map((a) => {
        const m = a.meta as { phase: string; viewport: string };
        return `${m.phase}:${m.viewport}`;
      }),
    ).toEqual(['before:desktop', 'before:mobile', 'after:desktop', 'after:mobile']);
    const summary = (await shot.ctx.sessionEvents.replay(s.id, 0)).entries.find(
      (e) => e.message.type === 'change_summary',
    )!;
    const screenshots = (
      summary.message.payload as { screenshots: { viewport: string; before?: string }[] }
    ).screenshots;
    expect(screenshots.map((x) => x.viewport)).toEqual(['desktop', 'mobile']);
    expect(screenshots.every((x) => x.before)).toBe(true);
    await shot.ctx.agent.shutdownAll();
  });
});
