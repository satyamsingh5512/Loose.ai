/**
 * Phase 8 (extensibility — REST surface): subagents (built-ins + CRUD + validation),
 * hooks (CRUD, recipes, encrypted webhook secrets that are never returned, the test
 * endpoint with a signed MSW webhook and the SSRF guard), plugins (publish, validate,
 * install / update / rollback / uninstall, LSE-EXT-007 conflicts, MCP credential
 * fill-in) and the delivery of all of it into the sandbox runner config.
 */
import { createHmac } from 'node:crypto';
import { http, HttpResponse, type RequestHandler } from 'msw';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import {
  BUILTIN_SUBAGENTS,
  HOOK_EVENT_HEADER,
  HOOK_RECIPES,
  HOOK_SIGNATURE_HEADER,
  MCP_SECRET_ENV_PREFIX,
  type HookPayload,
  type RunnerConfig,
} from '@loose/shared';
import {
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
  new FakeGit().install(fake);
  handlers.current = [];
  script.current = (cmd, r) => {
    if (cmd.type === 'user_message') playTurn(r);
  };
  await resetDb();
});

// ---- helpers -------------------------------------------------------------------------------

const base = (orgId: string) => `/api/v1/orgs/${orgId}`;
const names = (rows: { name: string }[]) => rows.map((r) => r.name);

async function orgAdmin(): Promise<{ admin: Client; orgId: string }> {
  const admin = await login(app, undefined, 'Ada Admin');
  const org = await createOrg(admin);
  return { admin, orgId: org.id };
}

async function joinOrg(orgId: string, role: 'ADMIN' | 'MEMBER' | 'VIEWER' = 'MEMBER') {
  const c = await login(app, undefined, `Mo ${role}`);
  await addMember(orgId, c.user.id, role);
  return c;
}

function subagentMd(name: string, description: string, opts: { tools?: string[] } = {}): string {
  return [
    '---',
    `name: ${name}`,
    `description: ${JSON.stringify(description)}`,
    ...(opts.tools ? [`tools: [${opts.tools.join(', ')}]`] : []),
    '---',
    '',
    'Do the thing carefully.',
    '',
  ].join('\n');
}

const SECURITY_REVIEWER = subagentMd('security-reviewer', 'Reviews changes for security bugs.', {
  tools: ['Read', 'Grep'],
});

// ---- subagents -----------------------------------------------------------------------------

describe('subagents', () => {
  it('lists the built-ins and creates an ORG subagent', async () => {
    const { admin, orgId } = await orgAdmin();
    expect(BUILTIN_SUBAGENTS).toHaveLength(4);
    const list = await admin.get(`${base(orgId)}/subagents`);
    expect(list.status, JSON.stringify(list.body)).toBe(200);
    const builtins = list.body.data as { id: string; builtin: boolean; scope: string }[];
    expect(builtins).toHaveLength(4);
    expect(builtins.every((s) => s.builtin && s.scope === 'BUILTIN')).toBe(true);
    expect(builtins.map((s) => s.id)).toContain('builtin:code-reviewer');
    expect(names(list.body.data as { name: string }[])).toEqual([
      'code-reviewer',
      'test-runner',
      'ui-designer',
      'researcher',
    ]);

    const res = await admin.post(`${base(orgId)}/subagents`, {
      scope: 'ORG',
      definition: SECURITY_REVIEWER,
    });
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    expect(res.body.data).toMatchObject({
      name: 'security-reviewer',
      description: 'Reviews changes for security bugs.',
      tools: ['Read', 'Grep'],
      scope: 'ORG',
      orgId,
      builtin: false,
      model: null,
      permissionMode: null,
    });
    const row = await prisma.subagent.findFirstOrThrow({ where: { orgId } });
    expect(row.meta).toMatchObject({ description: 'Reviews changes for security bugs.' });
    const audit = await prisma.auditLog.findFirstOrThrow({
      where: { orgId, action: 'subagent.create' },
    });
    expect(audit.meta).toMatchObject({ name: 'security-reviewer', scope: 'ORG' });
    expect((await admin.get(`${base(orgId)}/subagents`)).body.data).toHaveLength(5);

    const builtin = await admin.get(`${base(orgId)}/subagents/builtin:code-reviewer`);
    expect(builtin.status).toBe(200);
    expect(builtin.body.data).toMatchObject({ builtin: true, permissionMode: 'plan' });
    expectError(await admin.get(`${base(orgId)}/subagents/builtin:nope`), 'LSE-NF-001', 404);
  });

  it('rejects invalid definitions, duplicate names and renames', async () => {
    const { admin, orgId } = await orgAdmin();
    const invalid = await admin.post(`${base(orgId)}/subagents`, {
      scope: 'ORG',
      definition: '# No frontmatter here\n',
    });
    expectError(invalid, 'LSE-EXT-001', 400);
    expect(invalid.body.error.fields.definition.join(' ')).toContain('frontmatter');

    const created = await admin.post(`${base(orgId)}/subagents`, {
      scope: 'ORG',
      definition: SECURITY_REVIEWER,
    });
    expect(created.status).toBe(201);
    expectError(
      await admin.post(`${base(orgId)}/subagents`, { scope: 'ORG', definition: SECURITY_REVIEWER }),
      'LSE-EXT-005',
      409,
    );

    const id = created.body.data.id as string;
    const renamed = await admin.put(`${base(orgId)}/subagents/${id}`, {
      definition: subagentMd('other-name', 'Something else.'),
    });
    expectError(renamed, 'LSE-EXT-001', 400);
    expect(renamed.body.error.fields.definition.join(' ')).toContain('must stay');

    const updated = await admin.put(`${base(orgId)}/subagents/${id}`, {
      definition: subagentMd('security-reviewer', 'Reviews changes for security problems.'),
    });
    expect(updated.status, JSON.stringify(updated.body)).toBe(200);
    expect(updated.body.data.description).toBe('Reviews changes for security problems.');
    expect(updated.body.data.tools).toEqual([]);

    expect((await admin.delete(`${base(orgId)}/subagents/${id}`)).status).toBe(204);
    expect(await prisma.subagent.count({ where: { orgId } })).toBe(0);
    expect(await prisma.auditLog.count({ where: { orgId, action: 'subagent.delete' } })).toBe(1);
  });

  it('members may own personal subagents but not shared ones', async () => {
    const { admin, orgId } = await orgAdmin();
    const member = await joinOrg(orgId);
    expectError(
      await member.post(`${base(orgId)}/subagents`, {
        scope: 'ORG',
        definition: SECURITY_REVIEWER,
      }),
      'LSE-ORG-002',
      403,
    );
    const mine = await member.post(`${base(orgId)}/subagents`, {
      scope: 'USER',
      definition: SECURITY_REVIEWER,
    });
    expect(mine.status, JSON.stringify(mine.body)).toBe(201);
    expect(mine.body.data).toMatchObject({ scope: 'USER', userId: member.user.id });
    expectError(
      await admin.get(`${base(orgId)}/subagents/${mine.body.data.id}`),
      'LSE-NF-001',
      404,
    );
    expect(
      (
        await admin.put(`${base(orgId)}/policy`, {
          extensions: { allowUserSkills: false },
        })
      ).status,
    ).toBe(200);
    const other = await joinOrg(orgId);
    expectError(
      await other.post(`${base(orgId)}/subagents`, {
        scope: 'USER',
        definition: SECURITY_REVIEWER,
      }),
      'LSE-ORG-002',
      403,
    );
  });

  it('can be switched off per project', async () => {
    const { admin, orgId } = await orgAdmin();
    const project = await createReadyProject(ctx, orgId);
    const url = `${base(orgId)}/projects/${project.id}/extensions`;
    const before = await admin.get(url);
    expect(before.status, JSON.stringify(before.body)).toBe(200);
    const subagents = before.body.data.subagents as {
      name: string;
      enabled: boolean;
      inherited: boolean;
      override: boolean | null;
    }[];
    expect(subagents).toHaveLength(4);
    expect(subagents.find((s) => s.name === 'code-reviewer')).toMatchObject({
      enabled: true,
      inherited: true,
      override: null,
    });

    const off = await admin.put(url, { subagents: { 'code-reviewer': false } });
    expect(off.status, JSON.stringify(off.body)).toBe(200);
    expect(
      (off.body.data.subagents as { name: string; enabled: boolean }[]).find(
        (s) => s.name === 'code-reviewer',
      ),
    ).toMatchObject({ enabled: false, override: false });
    expect(
      (await prisma.project.findUniqueOrThrow({ where: { id: project.id } })).extensionOverrides,
    ).toMatchObject({ subagents: { 'code-reviewer': false } });
    const audit = await prisma.auditLog.findFirstOrThrow({
      where: { orgId, action: 'project.extensions_update' },
    });
    expect(audit.meta).toMatchObject({ subagents: ['code-reviewer'] });
  });
});

// ---- hooks ---------------------------------------------------------------------------------

const WEBHOOK_URL = 'https://hooks.example.test/loose';
const SLACK_URL = 'https://hooks.slack.example.test/services/T0/B0/xyz';
const HOOK_SECRET = 'hook-secret-value-0123456789';

interface WebhookSeen {
  bodies: string[];
  signatures: (string | null)[];
  events: (string | null)[];
}

function webhookHandlers(
  reply: unknown | null,
  opts: { status?: number; delayMs?: number } = {},
): WebhookSeen {
  const seen: WebhookSeen = { bodies: [], signatures: [], events: [] };
  handlers.current = [
    http.post(WEBHOOK_URL, async ({ request: req }) => {
      seen.bodies.push(await req.text());
      seen.signatures.push(req.headers.get(HOOK_SIGNATURE_HEADER));
      seen.events.push(req.headers.get(HOOK_EVENT_HEADER));
      if (opts.delayMs) await new Promise((r) => setTimeout(r, opts.delayMs));
      if (opts.status && opts.status >= 300) return new HttpResponse(null, { status: opts.status });
      return reply === null
        ? new HttpResponse(null, { status: 204 })
        : HttpResponse.json(reply, { status: opts.status ?? 200 });
    }),
    http.post(SLACK_URL, async ({ request: req }) => {
      seen.bodies.push(await req.text());
      return HttpResponse.json({ ok: true });
    }),
  ];
  return seen;
}

const createHook = (client: Client, orgId: string, body: object) =>
  client.post(`${base(orgId)}/hooks`, body);

describe('hooks', () => {
  it('creates a built-in hook, lists recipes and validates definitions', async () => {
    const { admin, orgId } = await orgAdmin();
    const recipes = await admin.get(`${base(orgId)}/hooks/recipes`);
    expect(recipes.status, JSON.stringify(recipes.body)).toBe(200);
    expect((recipes.body.data as { id: string }[]).map((r) => r.id)).toEqual(
      HOOK_RECIPES.map((r) => r.id),
    );

    const res = await createHook(admin, orgId, {
      scope: 'ORG',
      name: 'Protect infrastructure',
      event: 'PreToolUse',
      matcher: 'Edit|Write',
      handler: { type: 'builtin', action: 'block_paths', config: { paths: ['infra/**'] } },
      recipe: 'block-paths',
    });
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    expect(res.body.data).toMatchObject({
      name: 'Protect infrastructure',
      event: 'PreToolUse',
      matcher: 'Edit|Write',
      scope: 'ORG',
      failMode: 'closed',
      timeoutSec: 10,
      enabled: true,
      recipe: 'block-paths',
      handler: { type: 'builtin', action: 'block_paths', config: { paths: ['infra/**'] } },
    });
    const audit = await prisma.auditLog.findFirstOrThrow({
      where: { orgId, action: 'hook.create' },
    });
    expect(audit.meta).toMatchObject({ handler: 'builtin', action: 'block_paths' });

    // Non-blocking events default to fail-open.
    const stop = await createHook(admin, orgId, {
      scope: 'ORG',
      name: 'Run checks',
      event: 'Stop',
      handler: { type: 'builtin', action: 'run_checks', config: { commands: ['npm test'] } },
    });
    expect(stop.status, JSON.stringify(stop.body)).toBe(201);
    expect(stop.body.data.failMode).toBe('open');

    // Missing required config / unknown event / bad matcher / denied command.
    expectError(
      await createHook(admin, orgId, {
        scope: 'ORG',
        name: 'Broken',
        event: 'PreToolUse',
        handler: { type: 'builtin', action: 'block_paths', config: {} },
      }),
      'LSE-VAL-001',
      400,
    );
    expectError(
      await createHook(admin, orgId, {
        scope: 'ORG',
        name: 'Bad matcher',
        event: 'PreToolUse',
        matcher: '([',
        handler: { type: 'command', command: 'node check.js' },
      }),
      'LSE-VAL-001',
      400,
    );
    const dangerous = await createHook(admin, orgId, {
      scope: 'ORG',
      name: 'Dangerous',
      event: 'PreToolUse',
      handler: { type: 'command', command: 'rm -rf /' },
    });
    expectError(dangerous, 'LSE-EXT-006', 400);
    expect(dangerous.body.error.fields.handler.join(' ')).toContain('not allowed');

    expectError(
      await createHook(admin, orgId, {
        scope: 'ORG',
        name: 'Protect infrastructure',
        event: 'PreToolUse',
        handler: { type: 'builtin', action: 'block_dangerous_commands', config: {} },
      }),
      'LSE-EXT-005',
      409,
    );

    const member = await joinOrg(orgId);
    expect((await member.get(`${base(orgId)}/hooks`)).status).toBe(200);
    expectError(
      await createHook(member, orgId, {
        scope: 'ORG',
        name: 'Member hook',
        event: 'Stop',
        handler: { type: 'builtin', action: 'run_checks', config: { commands: ['npm test'] } },
      }),
      'LSE-ORG-002',
      403,
    );
  });

  it('stores webhook secrets encrypted and never returns them', async () => {
    const { admin, orgId } = await orgAdmin();
    const res = await createHook(admin, orgId, {
      scope: 'ORG',
      name: 'Review service',
      event: 'PreToolUse',
      handler: { type: 'http', url: WEBHOOK_URL, secret: HOOK_SECRET },
    });
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    expect(res.body.data.handler).toEqual({
      type: 'http',
      url: WEBHOOK_URL,
      hasSecret: true,
    });
    expect(JSON.stringify(res.body)).not.toContain(HOOK_SECRET);
    const id = res.body.data.id as string;
    expect(JSON.stringify((await admin.get(`${base(orgId)}/hooks/${id}`)).body)).not.toContain(
      HOOK_SECRET,
    );
    expect(JSON.stringify((await admin.get(`${base(orgId)}/hooks`)).body)).not.toContain(
      HOOK_SECRET,
    );
    const row = await prisma.hook.findUniqueOrThrow({ where: { id } });
    expect(row.secretEnc).toBeTruthy();
    expect(Buffer.from(row.secretEnc!).toString('utf8')).not.toContain(HOOK_SECRET);
    expect(JSON.stringify(row.handler)).not.toContain(HOOK_SECRET);
    expect(JSON.stringify(await prisma.auditLog.findMany({ where: { orgId } }))).not.toContain(
      HOOK_SECRET,
    );

    // notify_slack keeps its webhook URL out of the API surface too.
    const slack = await createHook(admin, orgId, {
      scope: 'ORG',
      name: 'Tell Slack',
      event: 'Notification',
      handler: {
        type: 'builtin',
        action: 'notify_slack',
        config: { webhookUrl: SLACK_URL, text: '{message}' },
      },
    });
    expect(slack.status, JSON.stringify(slack.body)).toBe(201);
    expect(slack.body.data.handler.config).toEqual({ text: '{message}', hasWebhookUrl: true });
    expect(JSON.stringify(slack.body)).not.toContain(SLACK_URL);

    const off = await admin.put(`${base(orgId)}/hooks/${id}`, { enabled: false, name: 'Paused' });
    expect(off.status, JSON.stringify(off.body)).toBe(200);
    expect(off.body.data).toMatchObject({ enabled: false, name: 'Paused' });
    expect(off.body.data.handler.hasSecret).toBe(true);

    // Re-sending the handler without the (unreadable) secret keeps the stored one…
    const rotated = await admin.put(`${base(orgId)}/hooks/${id}`, {
      handler: { type: 'http', url: `${WEBHOOK_URL}/v2` },
    });
    expect(rotated.status, JSON.stringify(rotated.body)).toBe(200);
    expect(rotated.body.data.handler).toEqual({
      type: 'http',
      url: `${WEBHOOK_URL}/v2`,
      hasSecret: true,
    });
    const kept = await prisma.hook.findUniqueOrThrow({ where: { id } });
    expect(kept.secretEnc).toBeTruthy();
    // …and the Slack webhook URL survives an unrelated update of a notify_slack hook.
    const slackOff = await admin.put(`${base(orgId)}/hooks/${slack.body.data.id}`, {
      enabled: false,
    });
    expect(slackOff.status, JSON.stringify(slackOff.body)).toBe(200);
    expect(slackOff.body.data.handler.config).toEqual({
      text: '{message}',
      hasWebhookUrl: true,
    });
    expect(JSON.stringify(slackOff.body)).not.toContain(SLACK_URL);
    // Switching to another handler type drops the old secret.
    const replaced = await admin.put(`${base(orgId)}/hooks/${id}`, {
      handler: { type: 'command', command: 'echo hi' },
    });
    expect(replaced.status, JSON.stringify(replaced.body)).toBe(200);
    expect(await prisma.hook.findUniqueOrThrow({ where: { id } })).toMatchObject({
      secretEnc: null,
    });

    expect((await admin.delete(`${base(orgId)}/hooks/${id}`)).status).toBe(204);
    expect(await prisma.auditLog.count({ where: { orgId, action: 'hook.delete' } })).toBe(1);
  });

  it('tests a webhook hook: signed call, decision, failure and the SSRF guard', async () => {
    const { admin, orgId } = await orgAdmin();
    const id = (
      await createHook(admin, orgId, {
        scope: 'ORG',
        name: 'Review service',
        event: 'PreToolUse',
        matcher: 'Edit|Write',
        handler: { type: 'http', url: WEBHOOK_URL, secret: HOOK_SECRET },
      })
    ).body.data.id as string;

    const seen = webhookHandlers({ decision: 'deny', reason: 'Not during the freeze' });
    const res = await admin.post(`${base(orgId)}/hooks/${id}/test`);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.data).toMatchObject({
      ok: true,
      decision: { decision: 'deny', reason: 'Not during the freeze' },
      status: 200,
      error: null,
      note: null,
    });
    expect(res.body.data.latencyMs).toBeGreaterThanOrEqual(0);
    // The sample payload for PreToolUse carries the tool and its input.
    const payload = res.body.data.payload as HookPayload;
    expect(payload).toMatchObject({ event: 'PreToolUse', toolName: 'Edit' });
    expect(seen.events[0]).toBe('PreToolUse');
    expect(seen.bodies[0]).toBe(JSON.stringify(payload));
    // The signature is a plain HMAC-SHA256 of the exact body.
    expect(seen.signatures[0]).toBe(
      `sha256=${createHmac('sha256', HOOK_SECRET).update(seen.bodies[0]!, 'utf8').digest('hex')}`,
    );
    const row = await prisma.hook.findUniqueOrThrow({ where: { id } });
    expect(row.lastDecision).toBe('deny');
    expect(row.lastRunAt).toBeTruthy();
    const audit = await prisma.auditLog.findFirstOrThrow({
      where: { orgId, action: 'hook.test' },
    });
    expect(audit.meta).toMatchObject({ decision: 'deny', ok: true });

    // A custom payload is passed through unchanged.
    webhookHandlers({ decision: 'allow' });
    const custom = await admin.post(`${base(orgId)}/hooks/${id}/test`, {
      payload: { event: 'PreToolUse', sessionId: 'ses_custom', toolName: 'Write' },
    });
    expect(custom.status, JSON.stringify(custom.body)).toBe(200);
    expect(custom.body.data.payload).toMatchObject({ sessionId: 'ses_custom' });

    // A 500 is a hook failure → LSE-AGT-014, fail-closed means deny.
    webhookHandlers(null, { status: 500 });
    const failed = await admin.post(`${base(orgId)}/hooks/${id}/test`);
    expect(failed.status).toBe(200);
    expect(failed.body.data).toMatchObject({
      ok: false,
      status: 500,
      decision: { decision: 'deny' },
      error: { code: 'LSE-AGT-014' },
    });
    expect((await prisma.hook.findUniqueOrThrow({ where: { id } })).lastError).toContain(
      'LSE-AGT-014',
    );

    // Private / loopback targets are refused outright.
    for (const url of ['http://localhost:9999/hook', 'http://10.1.2.3/hook']) {
      const priv = await createHook(admin, orgId, {
        scope: 'ORG',
        name: `priv-${url.includes('localhost') ? 'local' : 'ip'}`,
        event: 'Stop',
        handler: { type: 'http', url },
      });
      expect(priv.status, JSON.stringify(priv.body)).toBe(201);
      const blocked = await admin.post(`${base(orgId)}/hooks/${priv.body.data.id}/test`);
      expectError(blocked, 'LSE-EXT-006', 400);
      expect(blocked.body.error.fields.url[0]).toContain('public');
    }
  });

  it('tests built-in and command hooks without leaving the server', async () => {
    const { admin, orgId } = await orgAdmin();
    const blockPaths = (
      await createHook(admin, orgId, {
        scope: 'ORG',
        name: 'Protect infra',
        event: 'PreToolUse',
        handler: { type: 'builtin', action: 'block_paths', config: { paths: ['infra/**'] } },
      })
    ).body.data.id as string;
    const deny = await admin.post(`${base(orgId)}/hooks/${blockPaths}/test`, {
      payload: {
        event: 'PreToolUse',
        sessionId: 'ses_x',
        toolName: 'Edit',
        filePaths: ['infra/main.tf'],
      },
    });
    expect(deny.status, JSON.stringify(deny.body)).toBe(200);
    expect(deny.body.data).toMatchObject({ ok: true, decision: { decision: 'deny' } });
    const allow = await admin.post(`${base(orgId)}/hooks/${blockPaths}/test`, {
      payload: {
        event: 'PreToolUse',
        sessionId: 'ses_x',
        toolName: 'Edit',
        filePaths: ['src/Header.tsx'],
      },
    });
    expect(allow.body.data.decision).toEqual({ decision: 'allow' });

    const slack = (
      await createHook(admin, orgId, {
        scope: 'ORG',
        name: 'Tell Slack',
        event: 'Notification',
        handler: {
          type: 'builtin',
          action: 'notify_slack',
          config: { webhookUrl: SLACK_URL, text: 'loose: {message}' },
        },
      })
    ).body.data.id as string;
    const seen = webhookHandlers({ ok: true });
    const posted = await admin.post(`${base(orgId)}/hooks/${slack}/test`);
    expect(posted.status, JSON.stringify(posted.body)).toBe(200);
    expect(posted.body.data).toMatchObject({ ok: true, decision: { decision: 'allow' } });
    expect(seen.bodies.at(-1)).toContain('loose: A pull request was created');

    const command = (
      await createHook(admin, orgId, {
        scope: 'ORG',
        name: 'Lint hook',
        event: 'PostToolUse',
        handler: { type: 'command', command: 'npm run lint' },
      })
    ).body.data.id as string;
    const note = await admin.post(`${base(orgId)}/hooks/${command}/test`);
    expect(note.status, JSON.stringify(note.body)).toBe(200);
    expect(note.body.data).toMatchObject({ ok: true, decision: null, latencyMs: null });
    expect(note.body.data.note).toContain('sandbox');
  });
});

// ---- plugins -------------------------------------------------------------------------------

const PLUGIN_SKILL = [
  '---',
  'name: release-notes',
  'description: Write release notes for the current changes.',
  '---',
  '',
  'Group entries by Added / Changed / Fixed.',
  '',
].join('\n');

function manifest(over: Record<string, unknown> = {}) {
  return {
    name: 'acme-pack',
    version: '1.0.0',
    title: 'Acme pack',
    description: 'Acme house style.',
    author: 'Acme',
    skills: [{ files: [{ path: 'SKILL.md', content: PLUGIN_SKILL }] }],
    commands: [{ name: 'acme-notes', body: 'Write notes for $ARGUMENTS.' }],
    subagents: [{ definition: subagentMd('acme-reviewer', 'Reviews against the Acme style.') }],
    hooks: [
      {
        name: 'Acme protects infra',
        event: 'PreToolUse',
        matcher: 'Edit|Write',
        handler: { type: 'builtin', action: 'block_paths', config: { paths: ['infra/**'] } },
      },
    ],
    mcpServers: [
      {
        name: 'acme-api',
        transport: 'HTTP',
        url: 'https://mcp.acme.example.test/mcp',
        credentials: [
          {
            key: 'Authorization',
            kind: 'header',
            label: 'Acme API token',
            prefix: 'Bearer ',
            required: true,
          },
        ],
        approvalTools: ['create_ticket'],
      },
    ],
    ...over,
  };
}

const ACME_TOKEN = 'acme_token_0123456789abcdef';

describe('plugins', () => {
  it('publishes a plugin, lists it and validates manifests', async () => {
    const { admin, orgId } = await orgAdmin();
    const res = await admin.post(`${base(orgId)}/plugins`, { manifest: manifest() });
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    expect(res.body.data).toMatchObject({
      name: 'acme-pack',
      title: 'Acme pack',
      version: '1.0.0',
      author: 'Acme',
      installCount: 0,
      contents: {
        skills: ['release-notes'],
        commands: ['acme-notes'],
        subagents: ['acme-reviewer'],
        mcpServers: ['acme-api'],
        hooks: 1,
      },
    });
    const id = res.body.data.id as string;
    expect(await prisma.pluginVersion.count({ where: { pluginId: id } })).toBe(1);
    expect(
      (await prisma.auditLog.findFirstOrThrow({ where: { orgId, action: 'plugin.create' } })).meta,
    ).toMatchObject({ name: 'acme-pack', version: '1.0.0' });

    expectError(
      await admin.post(`${base(orgId)}/plugins`, { manifest: manifest() }),
      'LSE-EXT-005',
      409,
    );
    expectError(
      await admin.post(`${base(orgId)}/plugins`, {
        manifest: { name: 'bad name!', version: '1' },
      }),
      'LSE-VAL-001',
      400,
    );

    const detail = await admin.get(`${base(orgId)}/plugins/${id}`);
    expect(detail.status, JSON.stringify(detail.body)).toBe(200);
    expect(detail.body.data.versions).toHaveLength(1);
    expect(detail.body.data.credentials).toEqual([
      {
        server: 'acme-api',
        fields: [
          {
            key: 'Authorization',
            kind: 'header',
            label: 'Acme API token',
            prefix: 'Bearer ',
            required: true,
          },
        ],
      },
    ]);
    expect(detail.body.data.manifest.name).toBe('acme-pack');

    const v2 = await admin.post(`${base(orgId)}/plugins/${id}/versions`, {
      manifest: manifest({ version: '1.1.0' }),
    });
    expect(v2.status, JSON.stringify(v2.body)).toBe(201);
    expect(v2.body.data.version).toBe('1.1.0');
    expect((await admin.get(`${base(orgId)}/plugins/${id}`)).body.data.version).toBe('1.1.0');
    expectError(
      await admin.post(`${base(orgId)}/plugins/${id}/versions`, {
        manifest: manifest({ version: '1.1.0' }),
      }),
      'LSE-EXT-007',
      409,
    );
    expectError(
      await admin.post(`${base(orgId)}/plugins/${id}/versions`, {
        manifest: manifest({ name: 'other-pack', version: '2.0.0' }),
      }),
      'LSE-EXT-007',
      409,
    );

    const valid = await admin.post(`${base(orgId)}/plugins/validate`, {
      manifest: manifest({ name: 'fresh-pack', version: '0.1.0' }),
    });
    expect(valid.status, JSON.stringify(valid.body)).toBe(200);
    expect(valid.body.data).toMatchObject({ valid: true, name: 'fresh-pack', version: '0.1.0' });
    const bad = await admin.post(`${base(orgId)}/plugins/validate`, {
      manifest: { name: 'x-pack', version: '1.0.0', subagents: [{ definition: 'nope' }] },
    });
    expect(bad.status).toBe(200);
    expect(bad.body.data.valid).toBe(false);
    expect((bad.body.data.issues as { code: string }[]).map((i) => i.code)).toContain(
      'LSE-EXT-001',
    );

    expect((await admin.delete(`${base(orgId)}/plugins/${id}`)).status).toBe(204);
    expect(await prisma.plugin.count({ where: { orgId } })).toBe(0);
  });

  it('installs into a project, updates, rolls back and uninstalls', async () => {
    const { admin, orgId } = await orgAdmin();
    const project = await createReadyProject(ctx, orgId);
    const id = (await admin.post(`${base(orgId)}/plugins`, { manifest: manifest() })).body.data
      .id as string;
    await admin.post(`${base(orgId)}/plugins/${id}/versions`, {
      manifest: manifest({ version: '2.0.0' }),
    });

    const install = await admin.post(`${base(orgId)}/plugins/${id}/install`, {
      projectId: project.id,
      version: '1.0.0',
      credentials: { 'acme-api': { Authorization: ACME_TOKEN } },
    });
    expect(install.status, JSON.stringify(install.body)).toBe(201);
    expect(install.body.data).toMatchObject({
      pluginName: 'acme-pack',
      projectId: project.id,
      version: '1.0.0',
      latestVersion: '2.0.0',
      updateAvailable: true,
      enabled: true,
      credentialKeys: ['acme-api.Authorization'],
      warnings: [],
    });
    expect(JSON.stringify(install.body)).not.toContain(ACME_TOKEN);
    const row = await prisma.pluginInstall.findFirstOrThrow({ where: { pluginId: id } });
    expect(row.credentialsEnc).toBeTruthy();
    expect(Buffer.from(row.credentialsEnc!).toString('utf8')).not.toContain(ACME_TOKEN);
    expect(JSON.stringify(await prisma.auditLog.findMany({ where: { orgId } }))).not.toContain(
      ACME_TOKEN,
    );
    expect(
      (await prisma.auditLog.findFirstOrThrow({ where: { orgId, action: 'plugin.install' } })).meta,
    ).toMatchObject({ name: 'acme-pack', version: '1.0.0' });

    // Installing twice is a conflict.
    expectError(
      await admin.post(`${base(orgId)}/plugins/${id}/install`, { projectId: project.id }),
      'LSE-EXT-007',
      409,
    );

    // The project list shows the install state.
    const list = await admin.get(`${base(orgId)}/plugins?projectId=${project.id}`);
    expect(list.status).toBe(200);
    expect(list.body.data[0]).toMatchObject({
      installCount: 1,
      install: { version: '1.0.0', enabled: true, updateAvailable: true },
    });

    const updated = await admin.put(`${base(orgId)}/plugins/${id}/install`, {
      projectId: project.id,
      version: '2.0.0',
    });
    expect(updated.status, JSON.stringify(updated.body)).toBe(200);
    expect(updated.body.data).toMatchObject({ version: '2.0.0', updateAvailable: false });
    expect(
      (await prisma.auditLog.findFirstOrThrow({ where: { orgId, action: 'plugin.update' } })).meta,
    ).toMatchObject({ from: '1.0.0', to: '2.0.0' });

    const rolled = await admin.put(`${base(orgId)}/plugins/${id}/install`, {
      projectId: project.id,
      version: '1.0.0',
    });
    expect(rolled.status, JSON.stringify(rolled.body)).toBe(200);
    expect(rolled.body.data.version).toBe('1.0.0');
    expect(
      (await prisma.auditLog.findFirstOrThrow({ where: { orgId, action: 'plugin.rollback' } }))
        .meta,
    ).toMatchObject({ from: '2.0.0', to: '1.0.0' });

    expectError(
      await admin.put(`${base(orgId)}/plugins/${id}/install`, {
        projectId: project.id,
        version: '9.9.9',
      }),
      'LSE-NF-001',
      404,
    );

    // The project extensions page shows the plugin's hooks and subagents.
    const ext = await admin.get(`${base(orgId)}/projects/${project.id}/extensions`);
    expect(ext.status, JSON.stringify(ext.body)).toBe(200);
    expect(ext.body.data.plugins).toHaveLength(1);
    expect(
      (ext.body.data.hooks as { name: string; pluginName: string | null }[]).map((h) => [
        h.name,
        h.pluginName,
      ]),
    ).toEqual([['Acme protects infra', 'acme-pack']]);
    expect(
      (ext.body.data.subagents as { name: string; pluginName?: string | null }[]).find(
        (s) => s.name === 'acme-reviewer',
      ),
    ).toMatchObject({ pluginName: 'acme-pack' });

    expect(
      (await admin.delete(`${base(orgId)}/plugins/${id}/install?projectId=${project.id}`)).status,
    ).toBe(204);
    expect(await prisma.pluginInstall.count()).toBe(0);
    expect(await prisma.auditLog.count({ where: { orgId, action: 'plugin.uninstall' } })).toBe(1);
  });

  it('reports conflicts, dependencies and missing credentials (LSE-EXT-007)', async () => {
    const { admin, orgId } = await orgAdmin();
    const project = await createReadyProject(ctx, orgId);
    // An existing org command with the same name as the plugin's.
    expect(
      (
        await admin.post(`${base(orgId)}/commands`, {
          scope: 'ORG',
          name: 'acme-notes',
          body: 'Mine.',
        })
      ).status,
    ).toBe(201);
    const id = (await admin.post(`${base(orgId)}/plugins`, { manifest: manifest() })).body.data
      .id as string;

    const clash = await admin.post(`${base(orgId)}/plugins/${id}/install`, {
      projectId: project.id,
      credentials: { 'acme-api': { Authorization: ACME_TOKEN } },
    });
    expectError(clash, 'LSE-EXT-007', 409);
    expect(clash.body.error.fields.manifest.join(' ')).toContain('acme-notes');

    const check = await admin.post(`${base(orgId)}/plugins/validate`, {
      manifest: manifest(),
      projectId: project.id,
    });
    expect(check.status).toBe(200);
    expect(check.body.data.valid).toBe(false);
    expect(
      (check.body.data.conflicts as { kind: string; name: string }[]).map((c) => c.kind),
    ).toContain('command');

    // A missing dependency blocks the install.
    const dep = (
      await admin.post(`${base(orgId)}/plugins`, {
        manifest: {
          name: 'needs-base',
          version: '1.0.0',
          description: 'Needs the base pack.',
          dependencies: { 'base-pack': '1.0.0' },
          commands: [{ name: 'needs-base-cmd', body: 'Do it.' }],
        },
      })
    ).body.data.id as string;
    const missing = await admin.post(`${base(orgId)}/plugins/${dep}/install`, {
      projectId: project.id,
    });
    expectError(missing, 'LSE-EXT-007', 409);
    expect(missing.body.error.fields.manifest.join(' ')).toContain('base-pack');

    // Missing MCP credentials only warn: the connection is skipped.
    const noCreds = (
      await admin.post(`${base(orgId)}/plugins`, {
        manifest: manifest({ name: 'creds-pack', commands: [], skills: [], subagents: [] }),
      })
    ).body.data.id as string;
    const installed = await admin.post(`${base(orgId)}/plugins/${noCreds}/install`, {
      projectId: project.id,
    });
    expect(installed.status, JSON.stringify(installed.body)).toBe(201);
    expect((installed.body.data.warnings as string[]).join(' ')).toContain('acme-api');
    expect(installed.body.data.credentialKeys).toEqual([]);

    const filled = await admin.put(`${base(orgId)}/plugins/${noCreds}/install`, {
      projectId: project.id,
      credentials: { 'acme-api': { Authorization: ACME_TOKEN } },
    });
    expect(filled.status, JSON.stringify(filled.body)).toBe(200);
    expect(filled.body.data.warnings).toEqual([]);
    expect(filled.body.data.credentialKeys).toEqual(['acme-api.Authorization']);
  });
});

// ---- delivery into the sandbox --------------------------------------------------------------

interface World {
  owner: Client;
  admin: Client;
  orgId: string;
  projectId: string;
  sessionId: string;
  runner: FakeRunner;
}

async function world(
  setup?: (a: { admin: Client; orgId: string; projectId: string }) => Promise<void>,
  projectExtra: Record<string, unknown> = {},
): Promise<World> {
  const { admin, orgId } = await orgAdmin();
  const owner = await login(app, undefined, 'Mo Member');
  await addMember(orgId, owner.user.id, 'MEMBER');
  await linkGithub(ctx, owner.user.id);
  await addApiKey(ctx, owner.user.id);
  const project = await createReadyProject(ctx, orgId, projectExtra);
  await setup?.({ admin, orgId, projectId: project.id });
  const res = await owner.post('/api/v1/sessions', { projectId: project.id, mode: 'PRO' });
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  const s = await settle(ctx, res.body.data.id as string);
  expect(s.status).toBe('RUNNING');
  const runner = await waitFor(() => runners.at(-1), { label: 'runner start' });
  await waitFor(() => ctx.agent.hasRuntime(s.id), { label: 'agent runtime' });
  return { owner, admin, orgId, projectId: project.id, sessionId: s.id, runner };
}

function configOf(): RunnerConfig {
  const sbx = lastSandbox(ctx);
  const raw = sbx.files.get(`${sbx.paths.state}/config.json`);
  expect(raw, 'config.json written').toBeDefined();
  return JSON.parse(raw!) as RunnerConfig;
}

describe('delivery into the runner config', () => {
  it('writes subagents, local hooks, server hook events and the context settings', async () => {
    const w = await world(
      async ({ admin, orgId, projectId }) => {
        await admin.post(`${base(orgId)}/subagents`, {
          scope: 'ORG',
          definition: SECURITY_REVIEWER,
        });
        // Local handlers reach the runner…
        await createHook(admin, orgId, {
          scope: 'PROJECT',
          projectId,
          name: 'Protect infra',
          event: 'PreToolUse',
          matcher: 'Edit|Write',
          handler: { type: 'builtin', action: 'block_paths', config: { paths: ['infra/**'] } },
        });
        await createHook(admin, orgId, {
          scope: 'ORG',
          name: 'Format after edits',
          event: 'PostToolUse',
          handler: { type: 'builtin', action: 'auto_format', config: { command: 'npm run fmt' } },
        });
        // …webhook + Slack handlers never do.
        await createHook(admin, orgId, {
          scope: 'ORG',
          name: 'Review service',
          event: 'PreToolUse',
          handler: { type: 'http', url: WEBHOOK_URL, secret: HOOK_SECRET },
          timeoutSec: 20,
        });
        await createHook(admin, orgId, {
          scope: 'ORG',
          name: 'Tell Slack',
          event: 'Notification',
          handler: {
            type: 'builtin',
            action: 'notify_slack',
            config: { webhookUrl: SLACK_URL, text: '{message}' },
          },
        });
        // A disabled hook is not delivered at all.
        const paused = await createHook(admin, orgId, {
          scope: 'ORG',
          name: 'Paused checks',
          event: 'Stop',
          handler: { type: 'builtin', action: 'run_checks', config: { commands: ['npm test'] } },
        });
        await admin.put(`${base(orgId)}/hooks/${paused.body.data.id}`, { enabled: false });
        await admin.put(`${base(orgId)}/projects/${projectId}/extensions`, {
          subagents: { researcher: false },
        });
      },
      { autoCompactPercent: 65, screenshotViewports: ['desktop', 'mobile'] },
    );

    const config = configOf();
    expect(config.subagents.map((s) => s.name).sort()).toEqual([
      'code-reviewer',
      'security-reviewer',
      'test-runner',
      'ui-designer',
    ]);
    const reviewer = config.subagents.find((s) => s.name === 'security-reviewer');
    expect(reviewer).toMatchObject({
      description: 'Reviews changes for security bugs.',
      tools: ['Read', 'Grep'],
    });
    expect(reviewer!.prompt).toContain('Do the thing carefully.');
    expect(reviewer!.prompt).not.toContain('---');

    expect(config.hooks.map((h) => [h.name, h.event])).toEqual([
      ['Format after edits', 'PostToolUse'],
      ['Protect infra', 'PreToolUse'],
    ]);
    expect(config.hooks[1]).toMatchObject({
      matcher: 'Edit|Write',
      failMode: 'closed',
      handler: { type: 'builtin', action: 'block_paths', config: { paths: ['infra/**'] } },
    });
    // No webhook URL, Slack URL or secret ever reaches the sandbox.
    const raw = JSON.stringify(config);
    expect(raw).not.toContain(HOOK_SECRET);
    expect(raw).not.toContain(WEBHOOK_URL);
    expect(raw).not.toContain(SLACK_URL);
    expect(raw).not.toContain('notify_slack');
    expect(config.serverHookEvents.sort()).toEqual(['Notification', 'PreToolUse']);
    expect(config.serverHookTimeoutMs).toBe(22_000);
    expect(config.serverHookFailMode).toBe('closed');
    expect(config.autoCompactPercent).toBe(65);
    expect(config.screenshotViewports).toEqual(['desktop', 'mobile']);
    expect(w.runner.of('user_message')).toHaveLength(0);
  });

  it('delivers the contents of an installed plugin', async () => {
    let pluginId = '';
    const w = await world(async ({ admin, orgId, projectId }) => {
      pluginId = (await admin.post(`${base(orgId)}/plugins`, { manifest: manifest() })).body.data
        .id as string;
      const install = await admin.post(`${base(orgId)}/plugins/${pluginId}/install`, {
        projectId,
        credentials: { 'acme-api': { Authorization: ACME_TOKEN } },
      });
      expect(install.status, JSON.stringify(install.body)).toBe(201);
    });

    const sbx = lastSandbox(ctx);
    const config = configOf();
    expect(config.skills).toContain('release-notes');
    expect(config.subagents.map((s) => s.name)).toContain('acme-reviewer');
    expect(config.hooks.map((h) => h.name)).toContain('Acme protects infra');
    expect(config.mcpServers.map((m) => m.name)).toContain('acme-api');
    const mcp = config.mcpServers.find((m) => m.name === 'acme-api')!;
    expect(mcp.headers.Authorization).toBe(`\${${MCP_SECRET_ENV_PREFIX}0}`);
    expect(mcp.toolPolicy.tools).toEqual({ create_ticket: 'approval' });
    expect(JSON.stringify(config)).not.toContain(ACME_TOKEN);
    // The plugin's skill is written into the local plugin dir, outside the repository.
    expect(sbx.files.get(`${sbx.paths.state}/plugin/skills/release-notes/SKILL.md`)).toBe(
      PLUGIN_SKILL,
    );
    // The credential only reaches the runner process env.
    const started = sbx.commands.find((c) => c.background && c.cmd.includes('runner/dist/cli.js'));
    expect(started?.opts.envs?.[`${MCP_SECRET_ENV_PREFIX}0`]).toBe(`Bearer ${ACME_TOKEN}`);
    // The plugin's custom command is available in the session palette.
    const palette = await w.owner.get(`/api/v1/sessions/${w.sessionId}/commands`);
    expect(palette.status, JSON.stringify(palette.body)).toBe(200);
    expect(names(palette.body.data.commands as { name: string }[])).toContain('acme-notes');
  });
});
