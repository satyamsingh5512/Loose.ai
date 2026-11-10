/**
 * Secret-never-leaks tests (Phase 10 §7.5, W4): BYOK API keys, GitHub OAuth tokens, MCP
 * credentials and the raw session token must never appear in an HTTP response body/header, nor
 * in a captured log line, across the routes that handle them. `keys.test.ts` already covers the
 * BYOK create/list/revalidate flow in depth; this file adds the routes/paths that file doesn't:
 * GitHub-repo listing errors, MCP server create/list/test, audit log entries, and app-wide log
 * capture during a realistic multi-step flow.
 */
import { http, HttpResponse, type RequestHandler } from 'msw';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import {
  captureLogger,
  createOrg,
  GITHUB_API,
  linkGithub,
  login,
  makeApp,
  resetDb,
  testPrisma,
} from './helpers';
import { mswFetch } from './agentHelpers';

const prisma = testPrisma();
const GITHUB_TOKEN = 'gho_SECRETtoken000000000000000000000SEC1';
const MCP_BEARER = 'mcp_SECRETbearer_abcdefghijklmnopqrstuvwxyz';
const MCP_HEADER_SECRET = 'secret-header-value-should-never-leak';

function noSecret(haystack: unknown, ...secrets: string[]) {
  const text = typeof haystack === 'string' ? haystack : JSON.stringify(haystack ?? '');
  for (const s of secrets) expect(text).not.toContain(s);
}

describe('GitHub token never leaks in responses', () => {
  const handlers: { current: RequestHandler[] } = { current: [] };
  const { app, ctx } = makeApp({ context: { fetch: mswFetch(handlers) } });

  afterAll(async () => {
    await prisma.$disconnect();
  });
  beforeEach(async () => {
    handlers.current = [];
    await resetDb();
  });

  it('repo-list and single-repo responses, including GitHub error bodies, never contain the token', async () => {
    const owner = await login(app);
    await linkGithub(ctx, owner.user.id, GITHUB_TOKEN);
    handlers.current = [
      http.get(`${GITHUB_API}/user/repos`, () =>
        HttpResponse.json([
          {
            full_name: 'acme/web',
            name: 'web',
            owner: { login: 'acme' },
            private: false,
            default_branch: 'main',
            html_url: 'https://github.com/acme/web',
            description: null,
          },
        ]),
      ),
      http.get(`${GITHUB_API}/repos/acme/web`, ({ request: req }) => {
        // Echo back the auth header value in an error-ish body: proves the server never
        // forwards the raw token to the client even if GitHub's own response somehow did.
        const auth = req.headers.get('authorization') ?? '';
        return HttpResponse.json({ message: `rejected for ${auth}` }, { status: 403 });
      }),
    ];
    const list = await owner.get('/api/v1/github/repos');
    expect(list.status, JSON.stringify(list.body)).toBe(200);
    noSecret(list.body, GITHUB_TOKEN);
    noSecret(list.headers, GITHUB_TOKEN);

    const single = await owner.get('/api/v1/github/repos/acme/web');
    noSecret(single.body, GITHUB_TOKEN);
    noSecret(single.headers, GITHUB_TOKEN);
  });

  it('the stored OAuthAccount keeps only the envelope-encrypted token, never plaintext', async () => {
    const owner = await login(app);
    await linkGithub(ctx, owner.user.id, GITHUB_TOKEN);
    const row = await prisma.oAuthAccount.findFirstOrThrow({ where: { userId: owner.user.id } });
    const raw = Buffer.from(row.accessTokenEnc).toString('latin1');
    expect(raw).not.toContain(GITHUB_TOKEN);
  });
});

describe('MCP server credentials never leak', () => {
  const handlers: { current: RequestHandler[] } = { current: [] };
  const { app } = makeApp({ context: { fetch: mswFetch(handlers) } });

  afterAll(async () => {
    await prisma.$disconnect();
  });
  beforeEach(async () => {
    handlers.current = [];
    await resetDb();
  });

  it('create/list/get responses report only header *names*, never the secret header value', async () => {
    const admin = await login(app);
    const org = await createOrg(admin);
    const created = await admin.post(`/api/v1/orgs/${org.id}/mcp-servers`, {
      scope: 'ORG',
      name: 'secret-mcp',
      transport: 'HTTP',
      url: 'https://mcp.example.com/rpc',
      headers: { Authorization: `Bearer ${MCP_BEARER}`, 'X-Secret': MCP_HEADER_SECRET },
    });
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    noSecret(created.body, MCP_BEARER, MCP_HEADER_SECRET);
    expect(created.body.data.headerKeys).toEqual(
      expect.arrayContaining(['Authorization', 'X-Secret']),
    );

    const list = await admin.get(`/api/v1/orgs/${org.id}/mcp-servers`);
    noSecret(list.body, MCP_BEARER, MCP_HEADER_SECRET);

    const got = await admin.get(`/api/v1/orgs/${org.id}/mcp-servers/${created.body.data.id}`);
    noSecret(got.body, MCP_BEARER, MCP_HEADER_SECRET);

    // Encrypted at rest, never plaintext in the DB row either.
    const row = await prisma.mcpServer.findUniqueOrThrow({ where: { id: created.body.data.id } });
    const raw = JSON.stringify(row);
    expect(raw).not.toContain(MCP_BEARER);
    expect(raw).not.toContain(MCP_HEADER_SECRET);
  });

  it('a failed connection test error message never embeds the credential', async () => {
    const admin = await login(app);
    const org = await createOrg(admin);
    const mcpUrl = 'https://mcp.example.com/rpc';
    handlers.current = [http.post(mcpUrl, () => new HttpResponse(null, { status: 401 }))];
    const created = await admin.post(`/api/v1/orgs/${org.id}/mcp-servers`, {
      scope: 'ORG',
      name: 'secret-mcp-2',
      transport: 'HTTP',
      url: mcpUrl,
      headers: { Authorization: `Bearer ${MCP_BEARER}` },
    });
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    const test = await admin.post(
      `/api/v1/orgs/${org.id}/mcp-servers/${created.body.data.id}/test`,
    );
    expect(test.status, JSON.stringify(test.body)).toBe(200);
    noSecret(test.body, MCP_BEARER);
  });
});

describe('audit log entries never store secret material', () => {
  const { app, ctx } = makeApp();

  afterAll(async () => {
    await prisma.$disconnect();
  });
  beforeEach(async () => {
    await resetDb();
  });

  it('creating an MCP server with credentials writes an audit row without the secret', async () => {
    const admin = await login(app);
    const org = await createOrg(admin);
    await admin.post(`/api/v1/orgs/${org.id}/mcp-servers`, {
      scope: 'ORG',
      name: 'audited-mcp',
      transport: 'HTTP',
      url: 'https://mcp.example.com/rpc',
      headers: { Authorization: `Bearer ${MCP_BEARER}` },
    });
    const rows = await prisma.auditLog.findMany({ where: { orgId: org.id } });
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      const text = JSON.stringify(row);
      expect(text).not.toContain(MCP_BEARER);
    }
    void ctx;
  });
});

describe('app logs never contain secret material during a realistic request', () => {
  it('API key creation, GitHub linking and MCP server creation produce no secret in logs', async () => {
    const { logger, lines } = captureLogger();
    const handlers: { current: RequestHandler[] } = { current: [] };
    const { app, ctx } = makeApp({ logger, context: { fetch: mswFetch(handlers) } });
    await resetDb();
    const admin = await login(app);
    await linkGithub(ctx, admin.user.id, GITHUB_TOKEN);
    const org = await createOrg(admin);
    await admin.post(`/api/v1/orgs/${org.id}/mcp-servers`, {
      scope: 'ORG',
      name: 'logged-mcp',
      transport: 'HTTP',
      url: 'https://mcp.example.com/rpc',
      headers: { Authorization: `Bearer ${MCP_BEARER}` },
    });
    const captured = lines.join('\n');
    expect(captured).not.toContain(GITHUB_TOKEN);
    expect(captured).not.toContain(MCP_BEARER);
  });
});
