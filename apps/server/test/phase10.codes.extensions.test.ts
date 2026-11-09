/**
 * Error-code quality gate (Phase 10 §7.4, W4): trigger-path tests for LSE-MCP-003 and
 * LSE-EXT-004. Kept in a dedicated file (no agent-runtime/fake-runner fixtures — see
 * `phase10.codes.gaps.test.ts` for why) so the `AbortSignal.timeout` used by the MCP
 * connection-test code path (`extensions.service.ts` `testHttp`) fires reliably.
 */
import { http, HttpResponse, type RequestHandler } from 'msw';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { mswFetch } from './agentHelpers';
import {
  createOrg,
  expectError,
  GITHUB_API,
  linkGithub,
  login,
  makeApp,
  resetDb,
  testPrisma,
} from './helpers';

const prisma = testPrisma();
const handlers: { current: RequestHandler[] } = { current: [] };
const { app, ctx } = makeApp({ context: { fetch: mswFetch(handlers) } });

afterAll(async () => {
  await prisma.$disconnect();
});

beforeEach(async () => {
  handlers.current = [];
  await resetDb();
});

describe('LSE-MCP-003: MCP connection test times out', () => {
  it('an http MCP server that never responds reports LSE-MCP-003 from the test endpoint', async () => {
    const admin = await login(app, undefined, 'Ada Admin');
    const org = await createOrg(admin);
    const mcpUrl = 'https://mcp.example.com/rpc';
    handlers.current = [http.post(mcpUrl, () => new Promise<Response>(() => undefined))];
    const created = await admin.post(`/api/v1/orgs/${org.id}/mcp-servers`, {
      scope: 'ORG',
      name: 'slow-mcp',
      transport: 'HTTP',
      url: mcpUrl,
    });
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    const res = await admin.post(`/api/v1/orgs/${org.id}/mcp-servers/${created.body.data.id}/test`);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.data.error?.code).toBe('LSE-MCP-003');
  }, 20_000);
});

describe('LSE-EXT-004: skill import source unreachable', () => {
  it('a GitHub 500 while walking the import tree surfaces LSE-EXT-004', async () => {
    const admin = await login(app, undefined, 'Ada Admin');
    const org = await createOrg(admin);
    await linkGithub(ctx, admin.user.id);
    const repo = `${GITHUB_API}/repos/acme/web`;
    handlers.current = [
      http.get(`${repo}/contents/*`, () => new HttpResponse(null, { status: 500 })),
    ];
    const res = await admin.post(`/api/v1/orgs/${org.id}/skills/import`, {
      scope: 'ORG',
      source: 'github',
      repo: 'acme/web',
      path: '.claude/skills/broken',
      ref: 'main',
    });
    expectError(res, 'LSE-EXT-004', 502);
  });
});
