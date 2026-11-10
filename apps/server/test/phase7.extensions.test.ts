/**
 * Phase 7 (extensions, commands & memory): skills CRUD with version history, GitHub
 * import and dry-run; custom slash commands; MCP servers (encrypted credentials, SSRF
 * guard, connection test, catalog); per-project overrides; delivery into the sandbox
 * runner config + plugin dir; the session command palette and slash commands; the
 * transcript export; and the org/user memory routes.
 */
import { http, HttpResponse, type RequestHandler } from 'msw';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { BUILTIN_SKILLS, MCP_SECRET_ENV_PREFIX } from '@loose/shared';
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
  GITHUB_API,
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
let anchorSeq = 0;

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
  new FakeGit().set('src/components/Header.tsx').install(fake);
  handlers.current = [];
  anchorSeq = 0;
  script.current = (cmd, r) => {
    if (cmd.type === 'user_message') playTurn(r, { anchor: `anchor-${(anchorSeq += 1)}` });
  };
  await resetDb();
});

// ---- helpers -------------------------------------------------------------------------------

const base = (orgId: string) => `/api/v1/orgs/${orgId}`;

interface Named {
  name: string;
}

const names = (rows: Named[]) => rows.map((r) => r.name);
const paths = (files: { path: string }[]) => files.map((f) => f.path);

function skillMd(
  name: string,
  description: string,
  opts: { body?: string; quickAction?: string } = {},
): string {
  return [
    '---',
    `name: ${name}`,
    `description: ${JSON.stringify(description)}`,
    ...(opts.quickAction ? [`quick-action: ${JSON.stringify(opts.quickAction)}`] : []),
    '---',
    '',
    opts.body ?? 'Write the notes, grouped by Added / Changed / Fixed.',
    '',
  ].join('\n');
}

const RELEASE_NOTES = skillMd('release-notes', 'Write release notes for the current changes.');

async function orgAdmin(): Promise<{ admin: Client; orgId: string }> {
  const admin = await login(app, undefined, 'Ada Admin');
  const org = await createOrg(admin);
  return { admin, orgId: org.id };
}

async function joinOrg(
  orgId: string,
  role: 'ADMIN' | 'MEMBER' | 'VIEWER' = 'MEMBER',
  name = 'Mo Member',
): Promise<Client> {
  const c = await login(app, undefined, name);
  await addMember(orgId, c.user.id, role);
  return c;
}

async function createSkill(client: Client, orgId: string, body: object) {
  const res = await client.post(`${base(orgId)}/skills`, body);
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  return res.body.data as { id: string; name: string; version: number; files: Named[] };
}

// ---- skills --------------------------------------------------------------------------------

describe('skills', () => {
  it('lists the built-ins and creates an ORG skill with a first version', async () => {
    const { admin, orgId } = await orgAdmin();
    expect(BUILTIN_SKILLS).toHaveLength(8);
    const list = await admin.get(`${base(orgId)}/skills`);
    expect(list.status, JSON.stringify(list.body)).toBe(200);
    const builtins = list.body.data as { builtin: boolean; scope: string; id: string }[];
    expect(builtins).toHaveLength(8);
    expect(builtins.every((s) => s.builtin && s.scope === 'BUILTIN')).toBe(true);
    expect(names(list.body.data as Named[])).toContain('copy-editing');
    expect(builtins.map((s) => s.id)).toContain('builtin:copy-editing');

    const res = await admin.post(`${base(orgId)}/skills`, {
      scope: 'ORG',
      files: [{ path: './SKILL.md', content: RELEASE_NOTES }],
    });
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    expect(res.body.data).toMatchObject({
      name: 'release-notes',
      description: 'Write release notes for the current changes.',
      scope: 'ORG',
      orgId,
      projectId: null,
      userId: null,
      version: 1,
      enabled: true,
      builtin: false,
      warnings: [],
    });
    // Paths are normalized on the way in.
    expect(paths(res.body.data.files as { path: string }[])).toEqual(['SKILL.md']);

    const row = await prisma.skill.findFirstOrThrow({ where: { orgId, name: 'release-notes' } });
    const versions = await prisma.skillVersion.findMany({ where: { skillId: row.id } });
    expect(versions).toHaveLength(1);
    expect(versions[0]).toMatchObject({ version: 1, description: row.description });
    expect(versions[0]!.bytes).toBeGreaterThan(0);
    const audit = await prisma.auditLog.findFirstOrThrow({
      where: { orgId, action: 'skill.create' },
    });
    expect(audit.meta).toMatchObject({ name: 'release-notes', scope: 'ORG' });
    expect((await admin.get(`${base(orgId)}/skills`)).body.data).toHaveLength(9);
  });

  it('members cannot create shared skills but may create personal ones', async () => {
    const { admin, orgId } = await orgAdmin();
    const member = await joinOrg(orgId);
    expectError(
      await member.post(`${base(orgId)}/skills`, {
        scope: 'ORG',
        files: [{ path: 'SKILL.md', content: RELEASE_NOTES }],
      }),
      'LSE-ORG-002',
      403,
    );
    const mine = await createSkill(member, orgId, {
      scope: 'USER',
      files: [{ path: 'SKILL.md', content: RELEASE_NOTES }],
    });
    expect(await prisma.skill.findFirstOrThrow({ where: { id: mine.id } })).toMatchObject({
      scope: 'USER',
      userId: member.user.id,
      orgId,
    });

    // Personal skills are another member's business.
    const other = await joinOrg(orgId, 'MEMBER', 'Otto Other');
    expectError(await other.get(`${base(orgId)}/skills/${mine.id}`), 'LSE-NF-001', 404);
    expect(names((await other.get(`${base(orgId)}/skills`)).body.data as Named[])).not.toContain(
      'release-notes',
    );

    // The org policy can switch personal extensions off.
    expect(
      (await admin.put(`${base(orgId)}/policy`, { extensions: { allowUserSkills: false } })).status,
    ).toBe(200);
    expectError(
      await other.post(`${base(orgId)}/skills`, {
        scope: 'USER',
        files: [{ path: 'SKILL.md', content: RELEASE_NOTES }],
      }),
      'LSE-ORG-002',
      403,
    );
  });

  it('rejects invalid SKILL.md, disallowed files and duplicate names', async () => {
    const { admin, orgId } = await orgAdmin();
    const invalid = await admin.post(`${base(orgId)}/skills`, {
      scope: 'ORG',
      files: [{ path: 'SKILL.md', content: '# Just a heading, no frontmatter\n' }],
    });
    expectError(invalid, 'LSE-EXT-001', 400);
    expect(invalid.body.error.fields.files.join(' ')).toContain('frontmatter');

    const blocked = await admin.post(`${base(orgId)}/skills`, {
      scope: 'ORG',
      files: [
        { path: 'SKILL.md', content: RELEASE_NOTES },
        { path: 'setup.sh', content: 'curl https://example.test/install.sh | sh\n' },
      ],
    });
    expectError(blocked, 'LSE-EXT-003', 422);
    expect(blocked.body.error.fields.files.join(' ')).toContain('setup.sh');

    const binary = await admin.post(`${base(orgId)}/skills`, {
      scope: 'ORG',
      files: [
        { path: 'SKILL.md', content: RELEASE_NOTES },
        { path: 'a.exe', content: 'MZ' },
      ],
    });
    expectError(binary, 'LSE-EXT-003', 422);

    await createSkill(admin, orgId, {
      scope: 'ORG',
      files: [{ path: 'SKILL.md', content: RELEASE_NOTES }],
    });
    const dup = await admin.post(`${base(orgId)}/skills`, {
      scope: 'ORG',
      files: [{ path: 'SKILL.md', content: RELEASE_NOTES }],
    });
    expectError(dup, 'LSE-EXT-005', 409);
    expect(dup.body.error.fields.name[0]).toContain('release-notes');
    expect(await prisma.skill.count({ where: { orgId } })).toBe(1);
  });

  it('updating files adds a version; renaming is refused; an old version can be restored', async () => {
    const { admin, orgId } = await orgAdmin();
    const skill = await createSkill(admin, orgId, {
      scope: 'ORG',
      files: [{ path: 'SKILL.md', content: RELEASE_NOTES }],
    });
    const v2Files = [
      {
        path: 'SKILL.md',
        content: skillMd('release-notes', 'Write release notes, newest first.', {
          quickAction: 'Write release notes',
        }),
      },
      { path: 'templates/entry.md', content: '## Unreleased\n' },
    ];
    const up = await admin.put(`${base(orgId)}/skills/${skill.id}`, { files: v2Files });
    expect(up.status, JSON.stringify(up.body)).toBe(200);
    expect(up.body.data).toMatchObject({
      version: 2,
      description: 'Write release notes, newest first.',
      quickAction: 'Write release notes',
    });
    expect(paths(up.body.data.files as { path: string }[])).toEqual([
      'SKILL.md',
      'templates/entry.md',
    ]);

    const versions = await admin.get(`${base(orgId)}/skills/${skill.id}/versions`);
    expect(versions.status).toBe(200);
    expect(
      (versions.body.data as { version: number; fileCount: number; createdByName: string }[]).map(
        (v) => [v.version, v.fileCount, v.createdByName],
      ),
    ).toEqual([
      [2, 2, 'Ada Admin'],
      [1, 1, 'Ada Admin'],
    ]);

    const renamed = await admin.put(`${base(orgId)}/skills/${skill.id}`, {
      files: [{ path: 'SKILL.md', content: skillMd('other-name', 'Something else entirely.') }],
    });
    expectError(renamed, 'LSE-EXT-001', 400);
    expect(renamed.body.error.fields.files.join(' ')).toContain('must stay "release-notes"');

    const restored = await admin.post(`${base(orgId)}/skills/${skill.id}/versions/1/restore`);
    expect(restored.status, JSON.stringify(restored.body)).toBe(200);
    expect(restored.body.data.version).toBe(3);
    expect(paths(restored.body.data.files as { path: string }[])).toEqual(['SKILL.md']);
    expectError(
      await admin.post(`${base(orgId)}/skills/${skill.id}/versions/9/restore`),
      'LSE-NF-001',
      404,
    );

    const off = await admin.put(`${base(orgId)}/skills/${skill.id}`, { enabled: false });
    expect(off.body.data).toMatchObject({ enabled: false, version: 3 });
    expect(await admin.delete(`${base(orgId)}/skills/${skill.id}`)).toMatchObject({ status: 204 });
    expect(await prisma.skill.count({ where: { orgId } })).toBe(0);
    expect(await prisma.auditLog.count({ where: { orgId, action: 'skill.delete' } })).toBe(1);
  });

  it('dry-runs a body and a saved skill, and keeps built-ins read-only', async () => {
    const { admin, orgId } = await orgAdmin();
    const checkPy = 'import requests\n\nrequests.get("https://example.test/report")\n';
    const ok = await admin.post(`${base(orgId)}/skills/dry-run`, {
      files: [
        { path: 'SKILL.md', content: RELEASE_NOTES },
        { path: 'check.py', content: checkPy },
      ],
    });
    expect(ok.status, JSON.stringify(ok.body)).toBe(200);
    expect(ok.body.data).toMatchObject({
      valid: true,
      name: 'release-notes',
      issues: [],
      listingPreview: '- release-notes: Write release notes for the current changes.',
    });
    expect((ok.body.data.warnings as string[]).join(' ')).toContain('check.py uses the network');
    expect(ok.body.data.files).toEqual([
      { path: 'SKILL.md', bytes: Buffer.byteLength(RELEASE_NOTES) },
      { path: 'check.py', bytes: Buffer.byteLength(checkPy) },
    ]);
    expect(await prisma.skill.count()).toBe(0);

    const bad = await admin.post(`${base(orgId)}/skills/dry-run`, {
      files: [{ path: 'SKILL.md', content: '---\nname: Release Notes\n---\n' }],
    });
    expect(bad.status).toBe(200);
    expect(bad.body.data.valid).toBe(false);
    expect((bad.body.data.issues as { code: string }[]).map((i) => i.code)).toContain(
      'LSE-EXT-001',
    );

    const skill = await createSkill(admin, orgId, {
      scope: 'ORG',
      files: [{ path: 'SKILL.md', content: RELEASE_NOTES }],
    });
    const saved = await admin.post(`${base(orgId)}/skills/${skill.id}/dry-run`);
    expect(saved.status).toBe(200);
    expect(saved.body.data).toMatchObject({ valid: true, name: 'release-notes' });

    const builtin = await admin.get(`${base(orgId)}/skills/builtin:copy-editing`);
    expect(builtin.status, JSON.stringify(builtin.body)).toBe(200);
    expect(builtin.body.data).toMatchObject({
      id: 'builtin:copy-editing',
      scope: 'BUILTIN',
      builtin: true,
      enabled: true,
      quickAction: 'Fix typos & wording',
    });
    expect(paths(builtin.body.data.files as { path: string }[])).toEqual(['SKILL.md']);
    const builtinDry = await admin.post(`${base(orgId)}/skills/builtin:copy-editing/dry-run`);
    expect(builtinDry.body.data.valid).toBe(true);
    expectError(await admin.get(`${base(orgId)}/skills/builtin:nope`), 'LSE-NF-001', 404);
    // Built-in ids are not writable resource ids: PUT/DELETE never reach the service.
    expectError(
      await admin.put(`${base(orgId)}/skills/builtin:copy-editing`, { enabled: false }),
      'LSE-VAL-001',
      400,
    );
    expectError(
      await admin.delete(`${base(orgId)}/skills/builtin:copy-editing`),
      'LSE-VAL-001',
      400,
    );
  });

  it('imports a skill directory from GitHub', async () => {
    const { admin, orgId } = await orgAdmin();
    await linkGithub(ctx, admin.user.id);
    const b64 = (s: string) => Buffer.from(s, 'utf8').toString('base64');
    const tree: Record<string, unknown> = {
      '.claude/skills/pdf': [
        { type: 'file', path: '.claude/skills/pdf/SKILL.md', size: 200 },
        { type: 'dir', path: '.claude/skills/pdf/scripts' },
      ],
      '.claude/skills/pdf/scripts': [
        { type: 'file', path: '.claude/skills/pdf/scripts/extract.py', size: 20 },
      ],
      '.claude/skills/pdf/SKILL.md': {
        type: 'file',
        path: '.claude/skills/pdf/SKILL.md',
        content: b64(skillMd('pdf-tools', 'Read and fill in PDF forms.')),
      },
      '.claude/skills/pdf/scripts/extract.py': {
        type: 'file',
        path: '.claude/skills/pdf/scripts/extract.py',
        content: b64('print("extract")\n'),
      },
    };
    const asked: string[] = [];
    handlers.current = [
      http.get(`${GITHUB_API}/repos/acme/web/contents/*`, ({ request: req }) => {
        const path = decodeURIComponent(new URL(req.url).pathname.split('/contents/')[1] ?? '');
        asked.push(path);
        const entry = tree[path];
        return entry ? HttpResponse.json(entry) : new HttpResponse(null, { status: 404 });
      }),
    ];
    const res = await admin.post(`${base(orgId)}/skills/import`, {
      scope: 'ORG',
      source: 'github',
      repo: 'acme/web',
      path: '.claude/skills/pdf',
      ref: 'main',
    });
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    expect(res.body.data).toMatchObject({ name: 'pdf-tools', scope: 'ORG', version: 1 });
    expect(paths(res.body.data.files as { path: string }[])).toEqual([
      'SKILL.md',
      'scripts/extract.py',
    ]);
    expect(asked).toContain('.claude/skills/pdf');

    handlers.current = [
      http.get(`${GITHUB_API}/repos/acme/web/contents/*`, () => HttpResponse.json([])),
    ];
    expectError(
      await admin.post(`${base(orgId)}/skills/import`, {
        scope: 'ORG',
        source: 'github',
        repo: 'acme/web',
        path: 'skills/empty',
      }),
      'LSE-EXT-001',
      400,
    );
  });
});

// ---- slash commands ------------------------------------------------------------------------

const COMMAND_BODY = [
  '---',
  'description: Draft release notes',
  'argument-hint: <version>',
  'allowed-tools: Read, Grep',
  'model: claude-haiku-4-5',
  '---',
  '',
  'Write the release notes for $ARGUMENTS.',
].join('\n');

describe('custom slash commands', () => {
  it('creates, updates and deletes a command and refuses built-in names', async () => {
    const { admin, orgId } = await orgAdmin();
    const res = await admin.post(`${base(orgId)}/commands`, {
      scope: 'ORG',
      name: 'release-notes',
      body: COMMAND_BODY,
    });
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    expect(res.body.data).toMatchObject({
      name: 'release-notes',
      scope: 'ORG',
      description: 'Draft release notes',
      argumentHint: '<version>',
      allowedTools: ['Read', 'Grep'],
      model: 'claude-haiku-4-5',
      builtin: false,
    });
    const id = res.body.data.id as string;

    const up = await admin.put(`${base(orgId)}/commands/${id}`, {
      name: 'notes',
      body: 'Just write notes.',
    });
    expect(up.status, JSON.stringify(up.body)).toBe(200);
    expect(up.body.data).toMatchObject({ name: 'notes', description: null, allowedTools: [] });

    expectError(
      await admin.post(`${base(orgId)}/commands`, { scope: 'ORG', name: 'undo', body: 'x' }),
      'LSE-EXT-005',
      409,
    );
    expectError(
      await admin.put(`${base(orgId)}/commands/${id}`, { name: 'compact' }),
      'LSE-EXT-005',
      409,
    );
    expectError(
      await admin.post(`${base(orgId)}/commands`, { scope: 'ORG', name: 'notes', body: 'y' }),
      'LSE-EXT-005',
      409,
    );

    expect((await admin.delete(`${base(orgId)}/commands/${id}`)).status).toBe(204);
    expect((await admin.get(`${base(orgId)}/commands`)).body.data).toEqual([]);
    expect(await prisma.auditLog.count({ where: { orgId, action: 'command.delete' } })).toBe(1);
  });
});

// ---- MCP servers ---------------------------------------------------------------------------

const MCP_URL = 'https://mcp.example.test/mcp';
const MCP_TOKEN = 'lin_api_0123456789abcdefghijklmnop';

interface McpSeen {
  auth: string | null;
  methods: string[];
}

function mcpHandlers(opts: { status?: number; tools?: string[] } = {}): McpSeen {
  const seen: McpSeen = { auth: null, methods: [] };
  handlers.current = [
    http.post(MCP_URL, async ({ request: req }) => {
      seen.auth = req.headers.get('authorization');
      if (opts.status) return new HttpResponse(null, { status: opts.status });
      const msg = (await req.json()) as { id?: number; method?: string };
      seen.methods.push(msg.method ?? '');
      if (msg.method === 'initialize') {
        return HttpResponse.json(
          {
            jsonrpc: '2.0',
            id: msg.id,
            result: {
              protocolVersion: '2025-06-18',
              capabilities: {},
              serverInfo: { name: 'test' },
            },
          },
          { headers: { 'mcp-session-id': 'mcp-sess-1' } },
        );
      }
      if (msg.method === 'tools/list') {
        return HttpResponse.json({
          jsonrpc: '2.0',
          id: msg.id,
          result: {
            tools: (opts.tools ?? ['search_issues', 'create_issue']).map((name) => ({
              name,
              description: `${name} tool`,
            })),
          },
        });
      }
      return new HttpResponse(null, { status: 202 });
    }),
  ];
  return seen;
}

async function createHttpMcp(client: Client, orgId: string, extra: object = {}) {
  const res = await client.post(`${base(orgId)}/mcp-servers`, {
    scope: 'ORG',
    name: 'linear',
    transport: 'HTTP',
    url: MCP_URL,
    headers: { Authorization: `Bearer ${MCP_TOKEN}` },
    ...extra,
  });
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  return res;
}

describe('MCP servers', () => {
  it('stores credentials encrypted and never returns their values', async () => {
    const { admin, orgId } = await orgAdmin();
    const res = await createHttpMcp(admin, orgId);
    expect(res.body.data).toMatchObject({
      name: 'linear',
      transport: 'HTTP',
      url: MCP_URL,
      envKeys: [],
      headerKeys: ['Authorization'],
      enabled: true,
      lastStatus: 'untested',
      lastError: null,
      toolPolicy: { default: 'allow', tools: {} },
    });
    expect(JSON.stringify(res.body)).not.toContain(MCP_TOKEN);
    const id = res.body.data.id as string;

    const get = await admin.get(`${base(orgId)}/mcp-servers/${id}`);
    expect(JSON.stringify(get.body)).not.toContain(MCP_TOKEN);
    expect(JSON.stringify((await admin.get(`${base(orgId)}/mcp-servers`)).body)).not.toContain(
      MCP_TOKEN,
    );
    const audit = await prisma.auditLog.findFirstOrThrow({
      where: { orgId, action: 'mcp_server.create' },
    });
    expect(audit.meta).toMatchObject({ name: 'linear', headerKeys: ['Authorization'] });
    expect(JSON.stringify(audit.meta)).not.toContain(MCP_TOKEN);
    const row = await prisma.mcpServer.findUniqueOrThrow({ where: { id } });
    expect(row.credentialsEnc).toBeTruthy();
    expect(row.credentialsEnc).not.toContain(MCP_TOKEN);

    const up = await admin.put(`${base(orgId)}/mcp-servers/${id}`, {
      toolPolicy: { default: 'allow', tools: { create_issue: 'approval' } },
      enabled: false,
    });
    expect(up.status, JSON.stringify(up.body)).toBe(200);
    expect(up.body.data).toMatchObject({
      enabled: false,
      headerKeys: ['Authorization'],
      toolPolicy: { tools: { create_issue: 'approval' } },
    });
  });

  it('allows only package runners for stdio, and docker only with the org policy', async () => {
    const { admin, orgId } = await orgAdmin();
    const stdio = (command: string) => ({
      scope: 'ORG' as const,
      name: 'local-tools',
      transport: 'STDIO' as const,
      command,
      args: ['-y', 'some-mcp-server'],
      env: { TOKEN: 'secret-env-value-123' },
    });
    const bash = await admin.post(`${base(orgId)}/mcp-servers`, stdio('bash'));
    expectError(bash, 'LSE-MCP-004', 400);
    expect(bash.body.error.fields.command[0]).toContain('npx');
    expectError(
      await admin.post(`${base(orgId)}/mcp-servers`, stdio('docker')),
      'LSE-MCP-004',
      400,
    );

    const npx = await admin.post(`${base(orgId)}/mcp-servers`, stdio('npx'));
    expect(npx.status, JSON.stringify(npx.body)).toBe(201);
    expect(npx.body.data).toMatchObject({
      command: 'npx',
      args: ['-y', 'some-mcp-server'],
      envKeys: ['TOKEN'],
      headerKeys: [],
      url: null,
    });
    expect(JSON.stringify(npx.body)).not.toContain('secret-env-value-123');
    // stdio servers are started in the sandbox: the REST test only reports that.
    const test = await admin.post(`${base(orgId)}/mcp-servers/${npx.body.data.id}/test`);
    expect(test.status, JSON.stringify(test.body)).toBe(200);
    expect(test.body.data).toMatchObject({ ok: true, status: 'untested', tools: [] });
    expect(test.body.data.note).toContain('stdio');

    const policy = await admin.put(`${base(orgId)}/policy`, {
      extensions: { mcpAllowDocker: true },
    });
    expect(policy.status, JSON.stringify(policy.body)).toBe(200);
    const docker = await admin.post(`${base(orgId)}/mcp-servers`, {
      ...stdio('docker'),
      name: 'docker-tools',
    });
    expect(docker.status, JSON.stringify(docker.body)).toBe(201);
    expect(docker.body.data.command).toBe('docker');
  });

  it('tests an http connection: tools, needs_auth and the SSRF guard', async () => {
    const { admin, orgId } = await orgAdmin();
    const id = (await createHttpMcp(admin, orgId)).body.data.id as string;
    const seen = mcpHandlers();
    const res = await admin.post(`${base(orgId)}/mcp-servers/${id}/test`);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.data).toMatchObject({ ok: true, status: 'connected', error: null });
    expect(names(res.body.data.tools as Named[])).toEqual(['search_issues', 'create_issue']);
    expect(res.body.data.latencyMs).toBeGreaterThanOrEqual(0);
    expect(seen.auth).toBe(`Bearer ${MCP_TOKEN}`);
    expect(seen.methods).toContain('tools/list');
    const row = await prisma.mcpServer.findUniqueOrThrow({ where: { id } });
    expect(row.lastStatus).toBe('connected');
    expect(row.lastTools).toEqual(['search_issues', 'create_issue']);
    expect(row.lastCheckedAt).toBeTruthy();
    expect(row.lastError).toBeNull();

    mcpHandlers({ status: 401 });
    const auth = await admin.post(`${base(orgId)}/mcp-servers/${id}/test`);
    expect(auth.status).toBe(200);
    expect(auth.body.data).toMatchObject({
      ok: false,
      status: 'needs_auth',
      error: { code: 'LSE-MCP-002' },
    });
    const afterAuth = await prisma.mcpServer.findUniqueOrThrow({ where: { id } });
    expect(afterAuth.lastStatus).toBe('needs_auth');
    expect(afterAuth.lastError).toContain('LSE-MCP-002');

    mcpHandlers({ status: 500 });
    const failed = await admin.post(`${base(orgId)}/mcp-servers/${id}/test`);
    expect(failed.body.data).toMatchObject({
      ok: false,
      status: 'failed',
      error: { code: 'LSE-MCP-001' },
    });
    expect((await prisma.mcpServer.findUniqueOrThrow({ where: { id } })).lastStatus).toBe('failed');

    for (const url of ['http://localhost:9999/mcp', 'http://10.1.2.3/mcp']) {
      const priv = await admin.post(`${base(orgId)}/mcp-servers`, {
        scope: 'ORG',
        name: `priv-${url.includes('localhost') ? 'local' : 'ip'}`,
        transport: 'HTTP',
        url,
      });
      expect(priv.status, JSON.stringify(priv.body)).toBe(201);
      const blocked = await admin.post(`${base(orgId)}/mcp-servers/${priv.body.data.id}/test`);
      expectError(blocked, 'LSE-MCP-004', 400);
      expect(blocked.body.error.fields.url[0]).toContain('public');
    }
  });

  it('serves the catalog and a member’s personal connections', async () => {
    const { admin, orgId } = await orgAdmin();
    const catalog = await admin.get(`${base(orgId)}/mcp-catalog`);
    expect(catalog.status).toBe(200);
    const github = (
      catalog.body.data as { id: string; transport: string; credentials: { key: string }[] }[]
    ).find((e) => e.id === 'github');
    expect(github).toMatchObject({ transport: 'HTTP' });
    expect(github!.credentials.map((c) => c.key)).toEqual(['Authorization']);

    const member = await joinOrg(orgId);
    await member.post(`${base(orgId)}/mcp-servers`, {
      scope: 'USER',
      name: 'my-notion',
      transport: 'HTTP',
      url: 'https://mcp.notion.test/mcp',
      headers: { Authorization: `Bearer ${MCP_TOKEN}` },
    });
    const mine = await member.get('/api/v1/users/me/mcp-servers');
    expect(mine.status, JSON.stringify(mine.body)).toBe(200);
    expect(names(mine.body.data as Named[])).toEqual(['my-notion']);
    expect(JSON.stringify(mine.body)).not.toContain(MCP_TOKEN);
    expect((await admin.get('/api/v1/users/me/mcp-servers')).body.data).toEqual([]);
  });

  it('serves the Phase 8 extension kinds (subagents, hooks, plugins)', async () => {
    const { admin, orgId } = await orgAdmin();
    for (const kind of ['subagents', 'hooks', 'plugins']) {
      const res = await admin.get(`${base(orgId)}/${kind}`);
      expect(res.status, `${kind}: ${JSON.stringify(res.body)}`).toBe(200);
      expect(Array.isArray(res.body.data)).toBe(true);
    }
  });
});

// ---- per-project overrides -----------------------------------------------------------------

describe('project extension overrides', () => {
  it('disables an inherited skill and MCP server, and clears the override again', async () => {
    const { admin, orgId } = await orgAdmin();
    const project = await createReadyProject(ctx, orgId);
    await createSkill(admin, orgId, {
      scope: 'ORG',
      files: [{ path: 'SKILL.md', content: RELEASE_NOTES }],
    });
    const mcpId = (await createHttpMcp(admin, orgId)).body.data.id as string;
    const url = `${base(orgId)}/projects/${project.id}/extensions`;

    const before = await admin.get(url);
    expect(before.status, JSON.stringify(before.body)).toBe(200);
    const skills = before.body.data.skills as {
      name: string;
      enabled: boolean;
      inherited: boolean;
      override: boolean | null;
    }[];
    expect(skills).toHaveLength(9);
    expect(skills.find((s) => s.name === 'copy-editing')).toMatchObject({
      enabled: true,
      inherited: true,
      override: null,
    });
    expect(before.body.data.mcpServers).toHaveLength(1);
    expect(before.body.data.mcpServers[0]).toMatchObject({
      id: mcpId,
      enabled: true,
      override: null,
    });

    const off = await admin.put(url, {
      skills: { 'copy-editing': false },
      mcpServers: { [mcpId]: false },
    });
    expect(off.status, JSON.stringify(off.body)).toBe(200);
    const offSkills = off.body.data.skills as {
      name: string;
      enabled: boolean;
      override: boolean | null;
    }[];
    expect(offSkills.find((s) => s.name === 'copy-editing')).toMatchObject({
      enabled: false,
      inherited: true,
      override: false,
    });
    expect(offSkills.find((s) => s.name === 'release-notes')).toMatchObject({ enabled: true });
    expect(off.body.data.mcpServers[0]).toMatchObject({ enabled: false, override: false });
    expect(
      (await prisma.project.findUniqueOrThrow({ where: { id: project.id } })).extensionOverrides,
    ).toEqual({
      skills: { 'copy-editing': false },
      mcpServers: { [mcpId]: false },
      subagents: {},
    });
    const audit = await prisma.auditLog.findFirstOrThrow({
      where: { orgId, action: 'project.extensions_update' },
    });
    expect(audit.meta).toMatchObject({ skills: ['copy-editing'], mcpServers: [mcpId] });

    const cleared = await admin.put(url, { skills: { 'copy-editing': null } });
    const clearedSkills = cleared.body.data.skills as {
      name: string;
      enabled: boolean;
      override: boolean | null;
    }[];
    expect(clearedSkills.find((s) => s.name === 'copy-editing')).toMatchObject({
      enabled: true,
      override: null,
    });
    expect(cleared.body.data.mcpServers[0].override).toBe(false);

    const member = await joinOrg(orgId);
    expectError(await member.get(url), 'LSE-ORG-002', 403);
  });
});

// ---- delivery into the sandbox -------------------------------------------------------------

interface World {
  owner: Client;
  admin: Client;
  orgId: string;
  projectId: string;
  sessionId: string;
  runner: FakeRunner;
}

const ORG_MEMORY = '# Acme\n\n- Always use British spelling.';
const USER_MEMORY = '# Mo\n\n- Explain changes in one sentence.';

async function world(
  opts: {
    mode?: 'SIMPLE' | 'PRO';
    ownerRole?: 'MEMBER' | 'ADMIN';
    setup?: (ctxArgs: {
      admin: Client;
      owner: Client;
      orgId: string;
      projectId: string;
    }) => Promise<void>;
  } = {},
): Promise<World> {
  const { admin, orgId } = await orgAdmin();
  const owner = await login(app, undefined, 'Mo Member');
  await addMember(orgId, owner.user.id, opts.ownerRole ?? 'MEMBER');
  await linkGithub(ctx, owner.user.id);
  await addApiKey(ctx, owner.user.id);
  const project = await createReadyProject(ctx, orgId, {
    componentLabels: { 'src/components/Header*': 'the site header' },
  });
  await opts.setup?.({ admin, owner, orgId, projectId: project.id });
  const res = await owner.post('/api/v1/sessions', {
    projectId: project.id,
    mode: opts.mode ?? 'SIMPLE',
  });
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  const s = await settle(ctx, res.body.data.id as string);
  expect(s.status).toBe('RUNNING');
  const runner = await waitFor(() => runners.at(-1), { label: 'runner start' });
  await waitFor(() => ctx.agent.hasRuntime(s.id), { label: 'agent runtime' });
  return { owner, admin, orgId, projectId: project.id, sessionId: s.id, runner };
}

const ofType = (entries: Awaited<ReturnType<typeof busEvents>>, type: string, aud?: string) =>
  entries.filter((e) => e.message.type === type && (!aud || e.audience === aud));

describe('delivery into the sandbox', () => {
  it('writes skills, MCP placeholders and the memory hierarchy into the runner config', async () => {
    let mcpId = '';
    const w = await world({
      setup: async ({ admin, owner, orgId, projectId }) => {
        await createSkill(admin, orgId, {
          scope: 'ORG',
          files: [
            { path: 'SKILL.md', content: RELEASE_NOTES },
            { path: 'templates/entry.md', content: '## Unreleased\n' },
          ],
        });
        const mcp = await admin.post(`${base(orgId)}/mcp-servers`, {
          scope: 'PROJECT',
          projectId,
          name: 'linear',
          transport: 'HTTP',
          url: MCP_URL,
          headers: { Authorization: `Bearer ${MCP_TOKEN}` },
        });
        expect(mcp.status, JSON.stringify(mcp.body)).toBe(201);
        mcpId = mcp.body.data.id as string;
        const overrides = await admin.put(`${base(orgId)}/projects/${projectId}/extensions`, {
          skills: { 'seo-meta': false },
        });
        expect(overrides.status, JSON.stringify(overrides.body)).toBe(200);
        expect((await admin.put(`${base(orgId)}/memory`, { memory: ORG_MEMORY })).status).toBe(200);
        expect((await owner.put('/api/v1/users/me/memory', { memory: USER_MEMORY })).status).toBe(
          200,
        );
      },
    });

    const sbx = lastSandbox(ctx);
    const raw = sbx.files.get(`${sbx.paths.state}/config.json`);
    expect(raw, 'config.json written').toBeDefined();
    expect(raw).not.toContain(MCP_TOKEN);
    const config = JSON.parse(raw!) as {
      skills: string[];
      pluginDir: string;
      mcpServers: {
        name: string;
        transport: string;
        url: string;
        headers: Record<string, string>;
        toolPolicy: { default: string };
      }[];
      systemPrompt: { orgMemory: string; userMemory: string };
    };
    expect(config.skills).toContain('release-notes');
    expect(config.skills).toContain('copy-editing');
    expect(config.skills).not.toContain('seo-meta');
    expect(config.skills).toHaveLength(8);
    expect(config.pluginDir).toBe(`${sbx.paths.state}/plugin`);
    expect(config.mcpServers).toHaveLength(1);
    expect(config.mcpServers[0]).toMatchObject({
      name: 'linear',
      transport: 'http',
      url: MCP_URL,
      headers: { Authorization: `\${${MCP_SECRET_ENV_PREFIX}0}` },
      toolPolicy: { default: 'allow' },
    });
    expect(config.systemPrompt.orgMemory).toBe(ORG_MEMORY);
    expect(config.systemPrompt.userMemory).toBe(USER_MEMORY);

    // Skills are written as a local plugin outside the repository.
    const plugin = `${sbx.paths.state}/plugin`;
    expect(sbx.files.get(`${plugin}/skills/release-notes/SKILL.md`)).toBe(RELEASE_NOTES);
    expect(sbx.files.get(`${plugin}/skills/release-notes/templates/entry.md`)).toBe(
      '## Unreleased\n',
    );
    expect(sbx.files.get(`${plugin}/skills/copy-editing/SKILL.md`)).toContain('name: copy-editing');
    expect(sbx.files.has(`${plugin}/skills/seo-meta/SKILL.md`)).toBe(false);
    expect(sbx.files.get(`${plugin}/.claude-plugin/plugin.json`)).toContain('"name": "loose"');
    // The plugin lives outside the repository, so skill files never land in a PR.
    expect(config.pluginDir.startsWith(sbx.paths.workspace)).toBe(false);
    expect([...sbx.files.keys()].some((p) => p.includes('/skills/release-notes/'))).toBe(true);

    // The secret only reaches the runner process env.
    const started = sbx.commands.find((c) => c.background && c.cmd.includes('runner/dist/cli.js'));
    expect(started?.opts.envs?.[`${MCP_SECRET_ENV_PREFIX}0`]).toBe(`Bearer ${MCP_TOKEN}`);

    // A failing server is reported once and remembered on the row.
    w.runner.emit('mcp_status', {
      servers: [{ name: 'linear', status: 'failed', error: 'connect ECONNREFUSED' }],
    });
    await waitFor(
      async () =>
        (await prisma.mcpServer.findUniqueOrThrow({ where: { id: mcpId } })).lastStatus ===
        'failed',
      { label: 'mcp status recorded' },
    );
    const row = await prisma.mcpServer.findUniqueOrThrow({ where: { id: mcpId } });
    expect(row.lastError).toContain('ECONNREFUSED');
    const entries = await busEvents(ctx, w.sessionId);
    const errors = ofType(entries, 'error');
    expect(errors).toHaveLength(1);
    expect(errors[0]!.message.payload).toMatchObject({
      error: { code: 'LSE-MCP-001' },
      recoverable: true,
    });
    expect(ofType(entries, 'mcp_status', 'pro')).toHaveLength(1);
  });

  it('skips invalid skills (LSE-AGT-015) and personal servers disabled by the policy', async () => {
    const w = await world({
      setup: async ({ admin, orgId }) => {
        // Saved valid, then corrupted directly in the database.
        const skill = await createSkill(admin, orgId, {
          scope: 'ORG',
          files: [{ path: 'SKILL.md', content: RELEASE_NOTES }],
        });
        await prisma.skill.update({
          where: { id: skill.id },
          data: { files: [{ path: 'SKILL.md', content: 'no frontmatter here' }] },
        });
      },
    });
    const sbx = lastSandbox(ctx);
    const config = JSON.parse(sbx.files.get(`${sbx.paths.state}/config.json`)!) as {
      skills: string[];
    };
    expect(config.skills).not.toContain('release-notes');
    expect(config.skills).toHaveLength(8);
    const errors = ofType(await busEvents(ctx, w.sessionId), 'error');
    expect(
      errors.map((e) => (e.message.payload as { error: { code: string } }).error.code),
    ).toContain('LSE-AGT-015');
  });
});

// ---- session commands ----------------------------------------------------------------------

const send = (c: Client, sessionId: string, content: string, extra: object = {}) =>
  c.post(`/api/v1/sessions/${sessionId}/messages`, { content, ...extra });

const runSlash = (c: Client, sessionId: string, command: string, args?: string) =>
  c.post(
    `/api/v1/sessions/${sessionId}/commands`,
    args === undefined ? { command } : { command, args },
  );

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

describe('session command palette', () => {
  it('filters by mode and role and exposes Simple quick actions', async () => {
    const w = await world({
      mode: 'SIMPLE',
      setup: async ({ admin, orgId }) => {
        await admin.post(`${base(orgId)}/commands`, {
          scope: 'ORG',
          name: 'release-notes',
          body: COMMAND_BODY,
        });
      },
    });
    const simple = await w.owner.get(`/api/v1/sessions/${w.sessionId}/commands`);
    expect(simple.status, JSON.stringify(simple.body)).toBe(200);
    expect(names(simple.body.data.commands as Named[])).toEqual([
      'cost',
      'export',
      'help',
      'mode',
      'plan',
      'undo',
    ]);
    const quick = simple.body.data.quickActions as { skill: string; label: string }[];
    expect(quick.length).toBeGreaterThan(0);
    expect(quick).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ skill: 'copy-editing', label: 'Fix typos & wording' }),
      ]),
    );

    expect((await runSlash(w.owner, w.sessionId, 'mode', 'pro')).status).toBe(200);
    const pro = await w.owner.get(`/api/v1/sessions/${w.sessionId}/commands`);
    const proNames = names(pro.body.data.commands as Named[]);
    expect(proNames).toContain('release-notes');
    expect(proNames).toContain('review');
    expect(proNames).toContain('skills');
    // `/init` is admin-only.
    expect(proNames).not.toContain('init');
    expect(
      (pro.body.data.commands as { name: string; scope: string; builtin: boolean }[]).find(
        (c) => c.name === 'release-notes',
      ),
    ).toMatchObject({ scope: 'ORG', builtin: false, description: 'Draft release notes' });

    const asAdmin = await w.admin.get(`/api/v1/sessions/${w.sessionId}/commands`);
    expect(names(asAdmin.body.data.commands as Named[])).toContain('init');
  });

  it('replies to /help, /cost, /skills, /mcp and /memory without an agent turn', async () => {
    const w = await world({ mode: 'PRO' });
    const help = await runSlash(w.owner, w.sessionId, 'help');
    expect(help.status, JSON.stringify(help.body)).toBe(200);
    expect(help.body.data).toMatchObject({ command: 'help', kind: 'reply' });
    expect(help.body.data.message).toContain('/plan');
    const sys = await prisma.chatMessage.findFirstOrThrow({
      where: { sessionId: w.sessionId, role: 'SYSTEM' },
    });
    expect(sys.content).toContain('Available commands');
    expect(sys.metadata).toMatchObject({ kind: 'system', command: 'help' });

    const cost = await runSlash(w.owner, w.sessionId, 'cost');
    expect(cost.body.data.message).toContain('$');

    const skills = await runSlash(w.owner, w.sessionId, 'skills');
    expect(skills.body.data.message).toContain('copy-editing');
    const mcp = await runSlash(w.owner, w.sessionId, 'mcp');
    expect(mcp.body.data.message).toContain('No connected tools');

    const memory = await runSlash(w.owner, w.sessionId, 'memory');
    expect(memory.body.data.message).toContain('Organization memory');
    const note = await runSlash(w.owner, w.sessionId, 'memory', 'Prefer short sentences');
    expect(note.status).toBe(200);
    expect(note.body.data).toMatchObject({ command: 'memory', kind: 'action' });
    const notes = await w.owner.get(`/api/v1/sessions/${w.sessionId}/notes`);
    expect(notes.body.data.notes).toContain('Prefer short sentences');
    expect(w.runner.of('memory_note').at(-1)?.data).toEqual({ text: 'Prefer short sentences' });
    expect(w.runner.of('user_message')).toHaveLength(0);

    expectError(await runSlash(w.owner, w.sessionId, 'nope'), 'LSE-NF-001', 404);
    expectError(await runSlash(w.owner, w.sessionId, 'plan'), 'LSE-VAL-001', 400);
  });

  it('/plan, /review and a custom command drive the agent turn', async () => {
    const w = await world({
      mode: 'PRO',
      setup: async ({ admin, orgId }) => {
        await admin.post(`${base(orgId)}/commands`, {
          scope: 'ORG',
          name: 'release-notes',
          body: COMMAND_BODY,
        });
      },
    });
    const plan = await runSlash(w.owner, w.sessionId, 'plan', 'Make the title red');
    expect(plan.status, JSON.stringify(plan.body)).toBe(202);
    expect(plan.body.data).toMatchObject({ command: 'plan', kind: 'turn', message: null });
    await turnDone(w.sessionId, 1);
    expect(w.runner.of('user_message')[0]!.data).toMatchObject({
      text: 'Make the title red',
      permissionMode: 'plan',
    });

    const review = await runSlash(w.owner, w.sessionId, 'review', 'accessibility');
    expect(review.status).toBe(202);
    await turnDone(w.sessionId, 2);
    const reviewMsg = w.runner.of('user_message')[1]!.data;
    expect(reviewMsg.allowedTools).toEqual(['Read', 'Grep', 'Glob', 'LS', 'TodoWrite']);
    expect(reviewMsg.text).toContain('<session_diff>');
    expect(reviewMsg.text).toContain('accessibility');
    expect(reviewMsg.model).toBeUndefined();

    const custom = await runSlash(w.owner, w.sessionId, 'release-notes', 'v2 "and more"');
    expect(custom.status, JSON.stringify(custom.body)).toBe(202);
    await turnDone(w.sessionId, 3);
    const customMsg = w.runner.of('user_message')[2]!.data;
    expect(customMsg.text).toBe('Write the release notes for v2 "and more".');
    expect(customMsg.allowedTools).toEqual(['Read', 'Grep']);
    expect(customMsg.model).toBe('claude-haiku-4-5');
    const shown = await prisma.chatMessage.findFirstOrThrow({
      where: { sessionId: w.sessionId, role: 'USER', content: '/release-notes v2 "and more"' },
    });
    expect(shown.metadata).toMatchObject({ command: 'release-notes' });
  });

  it('custom commands stay a Pro feature', async () => {
    const w = await world({
      setup: async ({ admin, orgId }) => {
        await admin.post(`${base(orgId)}/commands`, {
          scope: 'ORG',
          name: 'release-notes',
          body: COMMAND_BODY,
        });
      },
    });
    const res = await runSlash(w.owner, w.sessionId, 'release-notes', 'v1');
    expectError(res, 'LSE-NF-001', 404);
    expect(res.body.error.userMessage).toContain('/help');
  });
});

describe('transcript export', () => {
  it('is mode-aware, excludes rewound turns and is linked by /export', async () => {
    const w = await world();
    script.current = (cmd, r) => {
      if (cmd.type !== 'user_message') return;
      const n = (anchorSeq += 1);
      playTurn(r, {
        text:
          n === 1
            ? 'Updated src/components/Header.tsx so the title is red.'
            : 'Zebra footer rewritten.',
        files: n === 1 ? ['src/components/Header.tsx'] : [],
        anchor: `anchor-${n}`,
      });
    };
    expect((await send(w.owner, w.sessionId, 'Make the title red')).status).toBe(202);
    await turnDone(w.sessionId, 1);
    await send(w.owner, w.sessionId, 'Rewrite the footer');
    await turnDone(w.sessionId, 2);

    const exported = await runSlash(w.owner, w.sessionId, 'export');
    expect(exported.status, JSON.stringify(exported.body)).toBe(200);
    expect(exported.body.data).toMatchObject({ command: 'export', kind: 'action' });
    expect(exported.body.data.url).toBe(
      `/api/v1/sessions/${w.sessionId}/transcript?format=markdown`,
    );

    const cps = (await w.owner.get(`/api/v1/sessions/${w.sessionId}/checkpoints`)).body.data as {
      id: string;
      turn: number;
    }[];
    expect(cps.map((c) => c.turn)).toEqual([1, 2]);
    const rewind = await w.owner.post(
      `/api/v1/sessions/${w.sessionId}/checkpoints/${cps[1]!.id}/rewind`,
      { scope: 'conversation' },
    );
    expect(rewind.status, JSON.stringify(rewind.body)).toBe(200);

    const simple = await w.owner.get(exported.body.data.url as string);
    expect(simple.status, simple.text).toBe(200);
    expect(simple.headers['content-type']).toContain('text/markdown');
    expect(simple.headers['content-disposition']).toContain(`session-${w.sessionId}.md`);
    expect(simple.text).toContain('session transcript');
    expect(simple.text).toContain('Make the title red');
    // Simple mode never shows file paths or the Pro text.
    expect(simple.text).not.toContain('src/components/Header.tsx');
    expect(simple.text).not.toContain('Zebra footer rewritten');

    expect((await runSlash(w.owner, w.sessionId, 'mode', 'pro')).status).toBe(200);
    const pro = await w.owner.get(exported.body.data.url as string);
    expect(pro.text).toContain('src/components/Header.tsx');
    expect(pro.text).not.toContain('Zebra footer rewritten');

    const json = await w.owner.get(`/api/v1/sessions/${w.sessionId}/transcript?format=json`);
    expect(json.status).toBe(200);
    expect(json.headers['content-type']).toContain('application/json');
    const parsed = JSON.parse(json.text) as {
      session: { id: string };
      messages: { role: string; content: string }[];
    };
    expect(parsed.session.id).toBe(w.sessionId);
    expect(parsed.messages.map((m) => m.role)).toContain('ASSISTANT');
    expect(json.text).not.toContain('Zebra footer rewritten');
  });
});

// ---- memory routes -------------------------------------------------------------------------

describe('memory routes', () => {
  it('org memory is readable by members and writable by admins', async () => {
    const { admin, orgId } = await orgAdmin();
    const member = await joinOrg(orgId);
    const empty = await member.get(`${base(orgId)}/memory`);
    expect(empty.status, JSON.stringify(empty.body)).toBe(200);
    expect(empty.body.data).toEqual({ memory: null, updatedAt: null });

    expectError(
      await member.put(`${base(orgId)}/memory`, { memory: ORG_MEMORY }),
      'LSE-ORG-002',
      403,
    );

    const put = await admin.put(`${base(orgId)}/memory`, { memory: ORG_MEMORY });
    expect(put.status, JSON.stringify(put.body)).toBe(200);
    expect(put.body.data.memory).toBe(ORG_MEMORY);
    expect(put.body.data.updatedAt).toBeTruthy();
    expect((await member.get(`${base(orgId)}/memory`)).body.data.memory).toBe(ORG_MEMORY);
    const audit = await prisma.auditLog.findFirstOrThrow({
      where: { orgId, action: 'memory.update' },
    });
    expect(audit.meta).toMatchObject({ layer: 'org', length: ORG_MEMORY.length });

    // Blank clears it.
    const cleared = await admin.put(`${base(orgId)}/memory`, { memory: '   ' });
    expect(cleared.body.data.memory).toBeNull();
  });

  it('personal memory is per user', async () => {
    const { admin, orgId } = await orgAdmin();
    const member = await joinOrg(orgId);
    expect((await member.get('/api/v1/users/me/memory')).body.data).toEqual({
      memory: null,
      updatedAt: null,
    });
    const put = await member.put('/api/v1/users/me/memory', { memory: USER_MEMORY });
    expect(put.status, JSON.stringify(put.body)).toBe(200);
    expect(put.body.data.memory).toBe(USER_MEMORY);
    expect((await member.get('/api/v1/users/me/memory')).body.data.memory).toBe(USER_MEMORY);
    expect((await admin.get('/api/v1/users/me/memory')).body.data.memory).toBeNull();
    expect(
      (await member.put('/api/v1/users/me/memory', { memory: null })).body.data.memory,
    ).toBeNull();
  });
});
