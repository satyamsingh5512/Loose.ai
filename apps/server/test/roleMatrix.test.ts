/**
 * ROLE MATRIX: every org-scoped route × {OWNER, ADMIN, MEMBER, VIEWER, non-member}.
 * Allowed roles get the route's success status; lower roles get LSE-ORG-002;
 * non-members get LSE-ORG-001.
 */
import { randomBytes } from 'node:crypto';
import type { Prisma } from '@prisma/client';
import { http, HttpResponse } from 'msw';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { hasRoleAtLeast, type Role } from '@loose/shared';
import { bytes, sha256Hex } from '../src/lib/crypto';
import { saveArtifact } from '../src/services/sessionLifecycle.service';
import {
  addMember,
  createMswServer,
  createOrg,
  expectError,
  GITHUB_API,
  githubRepoHandler,
  githubTreeHandler,
  linkGithub,
  login,
  makeApp,
  onUnhandled,
  resetDb,
  testPrisma,
  type Client,
} from './helpers';

const server = createMswServer();
const prisma = testPrisma();
const { app, ctx } = makeApp();

type Actor = Role | 'NON_MEMBER';
const ACTORS: Actor[] = ['OWNER', 'ADMIN', 'MEMBER', 'VIEWER', 'NON_MEMBER'];

interface Fixture {
  orgId: string;
  projectId: string;
  inviteId: string;
  webhookId: string;
  triggerId: string;
  users: Record<Actor, Client>;
}

interface RouteCase {
  method: 'get' | 'post' | 'put' | 'delete';
  /** Human-readable route template. */
  route: string;
  min: Role;
  ok: number;
  path: (f: Fixture) => Promise<string> | string;
  body?: object | (() => object);
  /** Code expected for allowed roles whose request is rejected after authorization. */
  okCode?: string;
}

let fx: Fixture;
const base = (f: Fixture) => `/api/v1/orgs/${f.orgId}`;
/** The fixture, for `body()` callbacks that need an id. */
const f0 = () => fx;

async function freshProject(f: Fixture, extra: Partial<Prisma.ProjectUncheckedCreateInput> = {}) {
  const p = await prisma.project.create({
    data: {
      orgId: f.orgId,
      name: 'Fresh',
      githubRepoFullName: 'acme/web',
      githubRepoUrl: 'https://github.com/acme/web',
      defaultBranch: 'main',
      envVarsEnc: await ctx.crypto.encryptPacked('{}', 'project-env'),
      templateStatus: 'READY',
      e2bTemplateId: 'tpl-matrix',
      ...extra,
    },
  });
  return p.id;
}

async function freshWebhook(f: Fixture) {
  const w = await prisma.webhook.create({
    data: {
      orgId: f.orgId,
      name: 'Fresh',
      url: 'https://93.184.216.34/hook',
      secretEnc: await ctx.crypto.encryptPacked('whsec_matrix', 'generic'),
      events: ['pr.created'],
    },
  });
  return w.id;
}

async function freshTrigger(f: Fixture) {
  const t = await prisma.trigger.create({
    data: {
      orgId: f.orgId,
      projectId: f.projectId,
      kind: 'GITHUB_ISSUE_LABEL',
      name: 'Fresh',
      config: { label: 'loose' },
      runAsUserId: f.users.OWNER.user.id,
      createdById: f.users.OWNER.user.id,
    },
  });
  return t.id;
}

async function freshMember(f: Fixture) {
  const u = await prisma.user.create({
    data: { email: `fresh-${randomBytes(6).toString('hex')}@example.com` },
  });
  await addMember(f.orgId, u.id, 'MEMBER');
  return u.id;
}

async function freshInvite(f: Fixture) {
  const inv = await prisma.orgInvite.create({
    data: {
      orgId: f.orgId,
      token: sha256Hex(randomBytes(32).toString('base64url')),
      role: 'MEMBER',
      expiresAt: new Date(Date.now() + 86_400_000),
      invitedById: f.users.OWNER.user.id,
    },
  });
  return inv.id;
}

const ROUTES: RouteCase[] = [
  // org
  { method: 'get', route: '/orgs/:orgId', min: 'VIEWER', ok: 200, path: base },
  {
    method: 'put',
    route: '/orgs/:orgId',
    min: 'ADMIN',
    ok: 200,
    path: base,
    body: { name: 'Renamed' },
  },
  // No `DELETE /orgs/:orgId` (P10-SEC-005): deletion is the confirmed grace-period flow, see
  // phase10.privacy.test.ts and phase10.fix-governance.test.ts.
  // members
  {
    method: 'get',
    route: '/orgs/:orgId/members',
    min: 'ADMIN',
    ok: 200,
    path: (f) => `${base(f)}/members`,
  },
  {
    method: 'get',
    route: '/orgs/:orgId/members/:userId',
    min: 'ADMIN',
    ok: 200,
    path: (f) => `${base(f)}/members/${f.users.MEMBER.user.id}`,
  },
  {
    method: 'put',
    route: '/orgs/:orgId/members/:userId',
    min: 'ADMIN',
    ok: 200,
    path: async (f) => `${base(f)}/members/${await freshMember(f)}`,
    body: { role: 'VIEWER' },
  },
  {
    method: 'delete',
    route: '/orgs/:orgId/members/:userId',
    min: 'ADMIN',
    ok: 204,
    path: async (f) => `${base(f)}/members/${await freshMember(f)}`,
  },
  // invites
  {
    method: 'post',
    route: '/orgs/:orgId/invites',
    min: 'ADMIN',
    ok: 201,
    path: (f) => `${base(f)}/invites`,
    body: { role: 'MEMBER' },
  },
  {
    method: 'get',
    route: '/orgs/:orgId/invites',
    min: 'ADMIN',
    ok: 200,
    path: (f) => `${base(f)}/invites`,
  },
  {
    method: 'delete',
    route: '/orgs/:orgId/invites/:inviteId',
    min: 'ADMIN',
    ok: 204,
    path: async (f) => `${base(f)}/invites/${await freshInvite(f)}`,
  },
  // policy, audit, later-phase stubs
  {
    method: 'get',
    route: '/orgs/:orgId/policy',
    min: 'ADMIN',
    ok: 200,
    path: (f) => `${base(f)}/policy`,
  },
  {
    method: 'put',
    route: '/orgs/:orgId/policy',
    min: 'ADMIN',
    ok: 200,
    path: (f) => `${base(f)}/policy`,
    body: {},
  },
  {
    method: 'get',
    route: '/orgs/:orgId/audit-log',
    min: 'ADMIN',
    ok: 200,
    path: (f) => `${base(f)}/audit-log`,
  },
  {
    method: 'get',
    route: '/orgs/:orgId/usage',
    min: 'ADMIN',
    ok: 200,
    path: (f) => `${base(f)}/usage`,
  },
  {
    method: 'get',
    route: '/orgs/:orgId/webhooks',
    min: 'ADMIN',
    ok: 200,
    path: (f) => `${base(f)}/webhooks`,
  },
  {
    method: 'post',
    route: '/orgs/:orgId/webhooks',
    min: 'ADMIN',
    ok: 201,
    path: (f) => `${base(f)}/webhooks`,
    body: { name: 'Matrix', url: 'https://93.184.216.34/hook', events: ['pr.created'] },
  },
  {
    method: 'get',
    route: '/orgs/:orgId/webhooks/:id',
    min: 'ADMIN',
    ok: 200,
    path: (f) => `${base(f)}/webhooks/${f.webhookId}`,
  },
  {
    method: 'put',
    route: '/orgs/:orgId/webhooks/:id',
    min: 'ADMIN',
    ok: 200,
    path: (f) => `${base(f)}/webhooks/${f.webhookId}`,
    body: { name: 'Edited' },
  },
  {
    method: 'delete',
    route: '/orgs/:orgId/webhooks/:id',
    min: 'ADMIN',
    ok: 204,
    path: async (f) => `${base(f)}/webhooks/${await freshWebhook(f)}`,
  },
  {
    method: 'post',
    route: '/orgs/:orgId/webhooks/:id/rotate-secret',
    min: 'ADMIN',
    ok: 200,
    path: (f) => `${base(f)}/webhooks/${f.webhookId}/rotate-secret`,
  },
  {
    method: 'get',
    route: '/orgs/:orgId/webhooks/:id/deliveries',
    min: 'ADMIN',
    ok: 200,
    path: (f) => `${base(f)}/webhooks/${f.webhookId}/deliveries`,
  },
  // triggers
  {
    method: 'get',
    route: '/orgs/:orgId/triggers',
    min: 'ADMIN',
    ok: 200,
    path: (f) => `${base(f)}/triggers`,
  },
  {
    method: 'post',
    route: '/orgs/:orgId/triggers',
    min: 'ADMIN',
    ok: 201,
    path: (f) => `${base(f)}/triggers`,
    body: () => ({
      projectId: f0().projectId,
      kind: 'GITHUB_ISSUE_LABEL',
      name: 'Matrix',
      config: { label: 'loose' },
    }),
  },
  {
    method: 'get',
    route: '/orgs/:orgId/triggers/:id',
    min: 'ADMIN',
    ok: 200,
    path: (f) => `${base(f)}/triggers/${f.triggerId}`,
  },
  {
    method: 'put',
    route: '/orgs/:orgId/triggers/:id',
    min: 'ADMIN',
    ok: 200,
    path: (f) => `${base(f)}/triggers/${f.triggerId}`,
    body: { name: 'Edited' },
  },
  {
    method: 'post',
    route: '/orgs/:orgId/triggers/:id/fire',
    min: 'ADMIN',
    ok: 202,
    path: (f) => `${base(f)}/triggers/${f.triggerId}/fire`,
    body: { text: 'do it' },
  },
  {
    method: 'get',
    route: '/orgs/:orgId/triggers/:id/runs',
    min: 'ADMIN',
    ok: 200,
    path: (f) => `${base(f)}/triggers/${f.triggerId}/runs`,
  },
  {
    method: 'delete',
    route: '/orgs/:orgId/triggers/:id',
    min: 'ADMIN',
    ok: 204,
    path: async (f) => `${base(f)}/triggers/${await freshTrigger(f)}`,
  },
  // projects
  {
    method: 'post',
    route: '/orgs/:orgId/projects',
    min: 'ADMIN',
    ok: 201,
    path: (f) => `${base(f)}/projects`,
    body: { name: 'New', githubRepoFullName: 'acme/web' },
  },
  {
    method: 'get',
    route: '/orgs/:orgId/projects',
    min: 'VIEWER',
    ok: 200,
    path: (f) => `${base(f)}/projects`,
  },
  {
    method: 'get',
    route: '/orgs/:orgId/projects/:projectId',
    min: 'VIEWER',
    ok: 200,
    path: (f) => `${base(f)}/projects/${f.projectId}`,
  },
  {
    method: 'put',
    route: '/orgs/:orgId/projects/:projectId',
    min: 'ADMIN',
    ok: 200,
    path: (f) => `${base(f)}/projects/${f.projectId}`,
    body: { name: 'Edited' },
  },
  {
    method: 'delete',
    route: '/orgs/:orgId/projects/:projectId',
    min: 'ADMIN',
    ok: 204,
    path: async (f) => `${base(f)}/projects/${await freshProject(f)}`,
  },
  {
    method: 'get',
    route: '/orgs/:orgId/projects/:projectId/memory',
    min: 'ADMIN',
    ok: 200,
    path: (f) => `${base(f)}/projects/${f.projectId}/memory`,
  },
  {
    method: 'put',
    route: '/orgs/:orgId/projects/:projectId/memory',
    min: 'ADMIN',
    ok: 200,
    path: (f) => `${base(f)}/projects/${f.projectId}/memory`,
    body: { looseMd: '# Hi' },
  },
  {
    method: 'post',
    route: '/orgs/:orgId/projects/:projectId/memory/generate',
    min: 'ADMIN',
    ok: 200,
    path: (f) => `${base(f)}/projects/${f.projectId}/memory/generate`,
  },
  {
    method: 'get',
    route: '/orgs/:orgId/projects/:projectId/extensions',
    min: 'ADMIN',
    ok: 200,
    path: (f) => `${base(f)}/projects/${f.projectId}/extensions`,
  },
  {
    method: 'put',
    route: '/orgs/:orgId/projects/:projectId/extensions',
    min: 'ADMIN',
    ok: 200,
    path: (f) => `${base(f)}/projects/${f.projectId}/extensions`,
    body: { skills: { 'seo-meta': false } },
  },
  // memory & extensions (Phase 7)
  {
    method: 'get',
    route: '/orgs/:orgId/memory',
    min: 'MEMBER',
    ok: 200,
    path: (f) => `${base(f)}/memory`,
  },
  {
    method: 'put',
    route: '/orgs/:orgId/memory',
    min: 'ADMIN',
    ok: 200,
    path: (f) => `${base(f)}/memory`,
    body: { memory: 'Use British English.' },
  },
  {
    method: 'get',
    route: '/orgs/:orgId/skills',
    min: 'MEMBER',
    ok: 200,
    path: (f) => `${base(f)}/skills`,
  },
  {
    method: 'get',
    route: '/orgs/:orgId/skills/:id',
    min: 'MEMBER',
    ok: 200,
    path: (f) => `${base(f)}/skills/builtin:copy-editing`,
  },
  {
    method: 'post',
    route: '/orgs/:orgId/skills (ORG scope)',
    min: 'ADMIN',
    ok: 201,
    path: (f) => `${base(f)}/skills`,
    body: () => ({
      files: [
        {
          path: 'SKILL.md',
          content: `---\nname: matrix-${randomBytes(4).toString('hex')}\ndescription: Test skill\n---\nDo it.`,
        },
      ],
    }),
  },
  {
    method: 'post',
    route: '/orgs/:orgId/skills/dry-run',
    min: 'MEMBER',
    ok: 200,
    path: (f) => `${base(f)}/skills/dry-run`,
    body: { files: [{ path: 'SKILL.md', content: '---\nname: x\ndescription: y\n---\nz' }] },
  },
  {
    method: 'get',
    route: '/orgs/:orgId/commands',
    min: 'MEMBER',
    ok: 200,
    path: (f) => `${base(f)}/commands`,
  },
  {
    method: 'get',
    route: '/orgs/:orgId/mcp-servers',
    min: 'MEMBER',
    ok: 200,
    path: (f) => `${base(f)}/mcp-servers`,
  },
  {
    method: 'get',
    route: '/orgs/:orgId/mcp-catalog',
    min: 'MEMBER',
    ok: 200,
    path: (f) => `${base(f)}/mcp-catalog`,
  },
  // extensions (Phase 8)
  {
    method: 'get',
    route: '/orgs/:orgId/subagents',
    min: 'MEMBER',
    ok: 200,
    path: (f) => `${base(f)}/subagents`,
  },
  {
    method: 'get',
    route: '/orgs/:orgId/subagents/:id',
    min: 'MEMBER',
    ok: 200,
    path: (f) => `${base(f)}/subagents/builtin:code-reviewer`,
  },
  {
    method: 'post',
    route: '/orgs/:orgId/subagents (ORG scope)',
    min: 'ADMIN',
    ok: 201,
    path: (f) => `${base(f)}/subagents`,
    body: () => ({
      definition: `---\nname: matrix-${randomBytes(4).toString('hex')}\ndescription: Test subagent\n---\nReview things.`,
    }),
  },
  {
    method: 'get',
    route: '/orgs/:orgId/hooks',
    min: 'MEMBER',
    ok: 200,
    path: (f) => `${base(f)}/hooks`,
  },
  {
    method: 'get',
    route: '/orgs/:orgId/hooks/recipes',
    min: 'MEMBER',
    ok: 200,
    path: (f) => `${base(f)}/hooks/recipes`,
  },
  {
    method: 'post',
    route: '/orgs/:orgId/hooks',
    min: 'ADMIN',
    ok: 201,
    path: (f) => `${base(f)}/hooks`,
    body: () => ({
      name: `Matrix hook ${randomBytes(4).toString('hex')}`,
      event: 'PreToolUse',
      matcher: 'Edit|Write',
      handler: { type: 'builtin', action: 'block_paths', config: { paths: ['infra/**'] } },
    }),
  },
  {
    method: 'post',
    route: '/orgs/:orgId/hooks/:id/test',
    min: 'ADMIN',
    ok: 404,
    okCode: 'LSE-NF-001',
    path: (f) => `${base(f)}/hooks/missinghook/test`,
  },
  {
    method: 'get',
    route: '/orgs/:orgId/plugins',
    min: 'MEMBER',
    ok: 200,
    path: (f) => `${base(f)}/plugins`,
  },
  {
    method: 'post',
    route: '/orgs/:orgId/plugins',
    min: 'ADMIN',
    ok: 201,
    path: (f) => `${base(f)}/plugins`,
    body: () => ({
      manifest: {
        name: `matrix-${randomBytes(4).toString('hex')}`,
        version: '1.0.0',
        description: 'Matrix plugin',
        commands: [{ name: 'matrix-cmd', body: 'Do it.' }],
      },
    }),
  },
  {
    method: 'post',
    route: '/orgs/:orgId/plugins/validate',
    min: 'ADMIN',
    ok: 200,
    path: (f) => `${base(f)}/plugins/validate`,
    body: () => ({ manifest: { name: 'matrix-check', version: '1.0.0' } }),
  },
  {
    method: 'post',
    route: '/orgs/:orgId/plugins/:id/install',
    min: 'ADMIN',
    ok: 404,
    okCode: 'LSE-NF-001',
    path: (f) => `${base(f)}/plugins/missingplugin/install`,
    body: () => ({ projectId: f0().projectId }),
  },
  {
    method: 'post',
    route: '/orgs/:orgId/projects/:projectId/build-template',
    min: 'ADMIN',
    ok: 202,
    path: async (f) =>
      `${base(f)}/projects/${await freshProject(f, { templateStatus: 'PENDING' })}/build-template`,
  },
  {
    method: 'get',
    route: '/orgs/:orgId/projects/:projectId/template-status',
    min: 'ADMIN',
    ok: 200,
    path: (f) => `${base(f)}/projects/${f.projectId}/template-status`,
  },
  {
    method: 'get',
    route: '/orgs/:orgId/projects/:projectId/template-logs',
    min: 'ADMIN',
    ok: 200,
    path: (f) => `${base(f)}/projects/${f.projectId}/template-logs`,
  },
  {
    method: 'post',
    route: '/orgs/:orgId/projects/:projectId/smoke-test',
    min: 'ADMIN',
    ok: 200,
    path: (f) => `${base(f)}/projects/${f.projectId}/smoke-test`,
  },
  {
    method: 'get',
    route: '/orgs/:orgId/projects/:projectId/active-sessions',
    min: 'MEMBER',
    ok: 200,
    path: (f) => `${base(f)}/projects/${f.projectId}/active-sessions`,
  },
  // sessions
  {
    method: 'get',
    route: '/orgs/:orgId/sessions',
    min: 'MEMBER',
    ok: 200,
    path: (f) => `${base(f)}/sessions`,
  },
];

beforeAll(async () => {
  server.listen({ onUnhandledRequest: onUnhandled });
  await resetDb();
  const users = {} as Record<Actor, Client>;
  for (const a of ACTORS)
    users[a] = await login(app, `${a.toLowerCase()}-${randomBytes(4).toString('hex')}@example.com`);
  const org = await createOrg(users.OWNER, 'Matrix Org');
  for (const role of ['ADMIN', 'MEMBER', 'VIEWER'] as const)
    await addMember(org.id, users[role].user.id, role);
  for (const a of ACTORS) await linkGithub(ctx, users[a].user.id);
  fx = { orgId: org.id, projectId: '', inviteId: '', webhookId: '', triggerId: '', users };
  fx.projectId = await freshProject(fx);
  fx.inviteId = await freshInvite(fx);
  fx.webhookId = await freshWebhook(fx);
  fx.triggerId = await freshTrigger(fx);
});
afterEach(() => server.resetHandlers());
afterAll(async () => {
  await ctx.jobs.onIdle();
  server.close();
  await prisma.$disconnect();
});

describe('role matrix', () => {
  for (const rc of ROUTES) {
    describe(`${rc.method.toUpperCase()} ${rc.route} (min ${rc.min})`, () => {
      for (const actor of ACTORS) {
        const allowed = actor !== 'NON_MEMBER' && hasRoleAtLeast(actor, rc.min);
        const expectation =
          actor === 'NON_MEMBER' ? 'LSE-ORG-001' : allowed ? String(rc.ok) : 'LSE-ORG-002';
        it(`${actor} → ${expectation}`, async () => {
          server.use(githubRepoHandler('acme/web'), githubTreeHandler('acme/web'));
          const client = fx.users[actor];
          const url = await rc.path(fx);
          const res =
            rc.method === 'get'
              ? await client.get(url)
              : rc.method === 'delete'
                ? await client.delete(url)
                : await client[rc.method](
                    url,
                    (typeof rc.body === 'function' ? rc.body() : rc.body) ?? {},
                  );
          if (actor === 'NON_MEMBER') expectError(res, 'LSE-ORG-001', 403);
          else if (!allowed) expectError(res, 'LSE-ORG-002', 403);
          else {
            expect(res.status, `${actor} ${rc.method} ${url}: ${JSON.stringify(res.body)}`).toBe(
              rc.ok,
            );
            if (rc.ok === 503) expectError(res, 'LSE-SYS-007', 503);
            else if (rc.okCode) expectError(res, rc.okCode, rc.ok);
          }
        });
      }
    });
  }

  it('covers every org-scoped route in the API table', () => {
    expect(ROUTES.length).toBe(63);
    expect(new Set(ROUTES.map((r) => `${r.method} ${r.route}`)).size).toBe(ROUTES.length);
  });
});

// ---- session routes (/sessions/*) -------------------------------------------------------
// Not org-scoped: participants are the session owner and org ADMIN+; other org
// members get LSE-ORG-002 and non-members LSE-NF-001 (existence is not revealed).

type SessionActor = 'OWNER' | 'ADMIN' | 'SESSION_OWNER' | 'OTHER_MEMBER' | 'VIEWER' | 'NON_MEMBER';
const SESSION_ACTORS: SessionActor[] = [
  'OWNER',
  'ADMIN',
  'SESSION_OWNER',
  'OTHER_MEMBER',
  'VIEWER',
  'NON_MEMBER',
];
const PARTICIPANTS: SessionActor[] = ['OWNER', 'ADMIN', 'SESSION_OWNER'];

interface SessionRouteCase {
  method: 'get' | 'post';
  route: string;
  ok: number;
  allowed: SessionActor[];
  path: () => Promise<string> | string;
  body?: () => object;
  /** Code expected for allowed actors whose request is rejected after authorization. */
  okCode?: string;
  /** Per-actor override (e.g. Pro-only diff, policy-gated commit-to-main). */
  expectFor?: (a: SessionActor) => { status: number; code?: string } | undefined;
}

let otherMember: Client;
let sessionId = '';
let artifactId = '';

function sessionClient(a: SessionActor): Client {
  if (a === 'SESSION_OWNER') return fx.users.MEMBER;
  if (a === 'OTHER_MEMBER') return otherMember;
  return fx.users[a];
}

async function addKey(userId: string) {
  const enc = await ctx.crypto.encrypt('sk-ant-api03-matrix-dummy-key-000000', 'api-key');
  await prisma.apiKey.create({
    data: {
      userId,
      keyEnc: bytes(enc.ciphertext),
      dataKeyEnc: bytes(enc.wrappedKey),
      iv: bytes(enc.iv),
      last4: '0000',
      status: 'ACTIVE',
    },
  });
}

async function erroredSession(): Promise<string> {
  const id = `cmatrix${randomBytes(8).toString('hex')}`;
  await prisma.session.create({
    data: {
      id,
      projectId: fx.projectId,
      userId: fx.users.MEMBER.user.id,
      mode: 'SIMPLE',
      model: 'claude-sonnet-4-5',
      branchName: `loose/session-${id}`,
      status: 'ERRORED',
      errorCode: 'LSE-SBX-002',
    },
  });
  return id;
}

async function pendingApproval(): Promise<string> {
  const a = await prisma.toolApproval.create({
    data: {
      id: `capr${randomBytes(8).toString('hex')}`,
      sessionId,
      tool: 'Bash',
      input: { command: 'npm test' },
      status: 'PENDING',
      runnerRequestId: 'apr_x',
      expiresAt: new Date(Date.now() + 3_600_000),
    },
  });
  return a.id;
}

const SESSION_ROUTES: SessionRouteCase[] = [
  {
    method: 'post',
    route: '/sessions',
    ok: 201,
    allowed: ['OWNER', 'ADMIN', 'SESSION_OWNER', 'OTHER_MEMBER'],
    path: () => '/api/v1/sessions',
    body: () => ({ projectId: fx.projectId }),
  },
  {
    method: 'get',
    route: '/sessions/:id',
    ok: 200,
    allowed: PARTICIPANTS,
    path: () => `/api/v1/sessions/${sessionId}`,
  },
  {
    method: 'post',
    route: '/sessions/:id/recover',
    ok: 202,
    allowed: PARTICIPANTS,
    path: async () => `/api/v1/sessions/${await erroredSession()}/recover`,
  },
  {
    method: 'get',
    route: '/sessions/:id/artifacts',
    ok: 200,
    allowed: PARTICIPANTS,
    path: () => `/api/v1/sessions/${sessionId}/artifacts`,
  },
  {
    method: 'get',
    route: '/sessions/:id/artifacts/:artifactId/content',
    ok: 200,
    allowed: PARTICIPANTS,
    path: () => `/api/v1/sessions/${sessionId}/artifacts/${artifactId}/content`,
  },
  // Phase 5: chat & approvals (the fixture session is ERRORED → acting returns 409)
  {
    method: 'get',
    route: '/sessions/:id/messages',
    ok: 200,
    allowed: PARTICIPANTS,
    path: () => `/api/v1/sessions/${sessionId}/messages`,
  },
  {
    method: 'post',
    route: '/sessions/:id/messages',
    ok: 409,
    okCode: 'LSE-CONF-001',
    allowed: PARTICIPANTS,
    path: () => `/api/v1/sessions/${sessionId}/messages`,
    body: () => ({ content: 'hello' }),
  },
  {
    method: 'post',
    route: '/sessions/:id/interrupt',
    ok: 409,
    okCode: 'LSE-CONF-001',
    allowed: PARTICIPANTS,
    path: () => `/api/v1/sessions/${sessionId}/interrupt`,
  },
  {
    method: 'get',
    route: '/sessions/:id/approvals',
    ok: 200,
    allowed: PARTICIPANTS,
    path: () => `/api/v1/sessions/${sessionId}/approvals`,
  },
  {
    method: 'post',
    route: '/sessions/:id/approvals/:approvalId',
    ok: 200,
    allowed: PARTICIPANTS,
    path: async () => `/api/v1/sessions/${sessionId}/approvals/${await pendingApproval()}`,
    body: () => ({ decision: 'deny' }),
  },
  // Phase 6: review & delivery
  {
    method: 'get',
    route: '/sessions/:id/diff',
    ok: 200,
    allowed: PARTICIPANTS,
    path: () => `/api/v1/sessions/${sessionId}/diff`,
    // Simple session: the member owner is not allowed to see the diff.
    expectFor: (a) => (a === 'SESSION_OWNER' ? { status: 403, code: 'LSE-ORG-002' } : undefined),
  },
  {
    method: 'post',
    route: '/sessions/:id/create-pr',
    ok: 409,
    okCode: 'LSE-CONF-001',
    allowed: PARTICIPANTS,
    path: () => `/api/v1/sessions/${sessionId}/create-pr`,
  },
  {
    method: 'post',
    route: '/sessions/:id/commit-to-main',
    ok: 403,
    okCode: 'LSE-ORG-009',
    allowed: PARTICIPANTS,
    path: () => `/api/v1/sessions/${sessionId}/commit-to-main`,
    // Admins pass RBAC but the org policy is off; the member owner fails RBAC.
    expectFor: (a) => (a === 'SESSION_OWNER' ? { status: 403, code: 'LSE-ORG-002' } : undefined),
  },
  {
    method: 'post',
    route: '/sessions/:id/discard',
    ok: 200,
    allowed: PARTICIPANTS,
    path: async () => {
      server.use(
        http.delete(
          `${GITHUB_API}/repos/acme/web/git/refs/*`,
          () => new HttpResponse(null, { status: 204 }),
        ),
      );
      return `/api/v1/sessions/${await erroredSession()}/discard`;
    },
  },
  // Phase 7: checkpoints, commands, notes, transcript
  {
    method: 'get',
    route: '/sessions/:id/checkpoints',
    ok: 200,
    allowed: PARTICIPANTS,
    path: () => `/api/v1/sessions/${sessionId}/checkpoints`,
  },
  {
    method: 'post',
    route: '/sessions/:id/checkpoints/:checkpointId/rewind',
    ok: 409,
    okCode: 'LSE-CONF-001',
    allowed: PARTICIPANTS,
    path: () => `/api/v1/sessions/${sessionId}/checkpoints/cpmissing/rewind`,
    body: () => ({ scope: 'both' }),
  },
  {
    method: 'get',
    route: '/sessions/:id/commands',
    ok: 200,
    allowed: PARTICIPANTS,
    path: () => `/api/v1/sessions/${sessionId}/commands`,
  },
  {
    method: 'post',
    route: '/sessions/:id/commands',
    ok: 409,
    okCode: 'LSE-CONF-001',
    allowed: PARTICIPANTS,
    path: () => `/api/v1/sessions/${sessionId}/commands`,
    body: () => ({ command: 'help' }),
  },
  {
    method: 'get',
    route: '/sessions/:id/notes',
    ok: 200,
    allowed: PARTICIPANTS,
    path: () => `/api/v1/sessions/${sessionId}/notes`,
  },
  {
    method: 'post',
    route: '/sessions/:id/notes',
    ok: 409,
    okCode: 'LSE-CONF-001',
    allowed: PARTICIPANTS,
    path: () => `/api/v1/sessions/${sessionId}/notes`,
    body: () => ({ text: 'Use British spelling' }),
  },
  {
    method: 'get',
    route: '/sessions/:id/transcript',
    ok: 200,
    allowed: PARTICIPANTS,
    path: () => `/api/v1/sessions/${sessionId}/transcript`,
  },
  // Phase 8: attachments & element inspection
  {
    method: 'post',
    route: '/sessions/:id/attachments',
    ok: 400,
    okCode: 'LSE-AGT-009',
    allowed: PARTICIPANTS,
    path: () => `/api/v1/sessions/${sessionId}/attachments`,
  },
  {
    method: 'post',
    route: '/sessions/:id/inspect',
    ok: 409,
    okCode: 'LSE-CONF-001',
    allowed: PARTICIPANTS,
    path: () => `/api/v1/sessions/${sessionId}/inspect`,
    body: () => ({ x: 10, y: 20 }),
  },
];

describe('session route matrix', () => {
  beforeAll(async () => {
    otherMember = await login(app, `other-${randomBytes(4).toString('hex')}@example.com`);
    await addMember(fx.orgId, otherMember.user.id, 'MEMBER');
    await linkGithub(ctx, otherMember.user.id);
    for (const a of SESSION_ACTORS) await addKey(sessionClient(a).user.id);
    await prisma.organization.update({
      where: { id: fx.orgId },
      data: { policy: { maxConcurrentSessionsPerUser: 50, maxConcurrentSessionsPerOrg: 1000 } },
    });
    sessionId = await erroredSession();
    artifactId = (
      await saveArtifact(ctx, {
        sessionId,
        kind: 'screenshot',
        data: Buffer.from('89504e470d0a1a0a', 'hex'),
        contentType: 'image/png',
        meta: { viewport: 'desktop', phase: 'after' },
      })
    ).id;
  });

  for (const rc of SESSION_ROUTES) {
    describe(`${rc.method.toUpperCase()} ${rc.route}`, () => {
      for (const actor of SESSION_ACTORS) {
        const allowed = rc.allowed.includes(actor);
        const code = actor === 'NON_MEMBER' ? 'LSE-NF-001' : 'LSE-ORG-002';
        it(`${actor} → ${allowed ? rc.ok : code}`, async () => {
          const client = sessionClient(actor);
          const url = await rc.path();
          const res =
            rc.method === 'get' ? await client.get(url) : await client.post(url, rc.body?.() ?? {});
          const custom = rc.expectFor?.(actor);
          if (custom) {
            expect(res.status, `${actor} ${url}: ${JSON.stringify(res.body)}`).toBe(custom.status);
            if (custom.code) expectError(res, custom.code, custom.status);
          } else if (allowed) {
            expect(res.status, `${actor} ${url}: ${JSON.stringify(res.body)}`).toBe(rc.ok);
            if (rc.okCode) expectError(res, rc.okCode, rc.ok);
          } else {
            expectError(res, code, code === 'LSE-NF-001' ? 404 : 403);
          }
        });
      }
    });
  }

  it('covers every /sessions route implemented in Phases 4–8', () => {
    expect(SESSION_ROUTES.length).toBe(23);
    expect(new Set(SESSION_ROUTES.map((r) => `${r.method} ${r.route}`)).size).toBe(23);
  });
});
