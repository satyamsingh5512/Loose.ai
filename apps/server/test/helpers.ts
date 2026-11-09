/** Shared test helpers: app factory, DB reset, signed-in clients, MSW. */
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Writable } from 'node:stream';
import { PrismaClient, type Role } from '@prisma/client';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import request from 'supertest';
import { expect } from 'vitest';
import { CSRF_HEADER, type UserDto } from '@loose/shared';
import { buildContext, createApp, type BuildContextInput, type CreateAppOptions } from '../src/app';
import { loadEnv, type Env } from '../src/config/env';
import type { AppContext } from '../src/context';
import { createLogger, type Logger } from '../src/lib/logger';

export const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? 'postgresql://loose:loose@127.0.0.1:5432/loose_test';

export const TEST_ARTIFACT_DIR = join(tmpdir(), `loose-test-artifacts-${process.pid}`);

export const TEST_SECRETS = {
  SESSION_SECRET: 'test-session-secret-that-is-long-enough-123456',
  LOCAL_KMS_MASTER_KEY: Buffer.alloc(32, 7).toString('base64'),
  GITHUB_WEBHOOK_SECRET: 'whsec_test_secret_value',
};

export function testEnv(overrides: Record<string, string | undefined> = {}): Env {
  return loadEnv({
    NODE_ENV: 'test',
    DATABASE_URL: TEST_DATABASE_URL,
    REDIS_URL: 'redis://127.0.0.1:6379/15',
    APP_URL: 'http://localhost:5173',
    API_URL: 'http://localhost:4000',
    KMS_PROVIDER: 'local',
    DEV_LOGIN_ENABLED: 'true',
    LOG_LEVEL: 'silent',
    // Generous limits so suites don't trip them; rate-limit tests lower these.
    RATE_LIMIT_AUTH_MAX: '10000',
    RATE_LIMIT_KEY_VALIDATION_MAX: '10000',
    RATE_LIMIT_GENERAL_MAX: '100000',
    RATE_LIMIT_SESSION_CREATE_MAX: '100000',
    // Dummy value so NODE_ENV=production configs validate; never used for network calls.
    E2B_API_KEY: 'e2b_test_dummy_not_a_real_key',
    SANDBOX_RETRY_BASE_MS: '0',
    ARTIFACT_DIR: TEST_ARTIFACT_DIR,
    ...TEST_SECRETS,
    ...overrides,
  });
}

let sharedPrisma: PrismaClient | undefined;
export function testPrisma(): PrismaClient {
  sharedPrisma ??= new PrismaClient({ datasources: { db: { url: TEST_DATABASE_URL } } });
  return sharedPrisma;
}

export async function resetDb(prisma = testPrisma()): Promise<void> {
  const tables = await prisma.$queryRaw<{ tablename: string }[]>`
    SELECT tablename FROM pg_tables WHERE schemaname = 'public'
      AND tablename NOT IN ('_prisma_migrations', 'AuditChainCutover')`;
  if (tables.length === 0) return;
  const list = tables.map((t) => `"public"."${t.tablename}"`).join(', ');
  await prisma.$executeRawUnsafe(`TRUNCATE TABLE ${list} RESTART IDENTITY CASCADE`);
}

/** Collects every log line written by the app (for "secret never logged" tests). */
export function captureLogger(level = 'trace'): { logger: Logger; lines: string[] } {
  const lines: string[] = [];
  const stream = new Writable({
    write(chunk: Buffer, _enc, cb) {
      lines.push(chunk.toString('utf8'));
      cb();
    },
  });
  return { logger: createLogger({ level, destination: stream }), lines };
}

export interface MakeAppOptions extends CreateAppOptions {
  env?: Record<string, string | undefined>;
  logger?: Logger;
  context?: Partial<BuildContextInput>;
}

export function makeApp(opts: MakeAppOptions = {}) {
  const env = testEnv(opts.env);
  const ctx: AppContext = buildContext({
    env,
    prisma: testPrisma(),
    logger: opts.logger ?? createLogger({ level: 'silent' }),
    ...opts.context,
  });
  const app = createApp(ctx, opts);
  return { app, ctx, env };
}

export type App = ReturnType<typeof makeApp>['app'];

/** A supertest agent with a session cookie and CSRF header handling. */
export class Client {
  constructor(
    readonly agent: ReturnType<typeof request.agent>,
    readonly csrf: string,
    readonly user: UserDto,
  ) {}

  get(url: string) {
    return this.agent.get(url);
  }
  post(url: string, body?: object) {
    const r = this.agent.post(url).set(CSRF_HEADER, this.csrf);
    return body === undefined ? r : r.send(body);
  }
  put(url: string, body?: object) {
    const r = this.agent.put(url).set(CSRF_HEADER, this.csrf);
    return body === undefined ? r : r.send(body);
  }
  delete(url: string) {
    return this.agent.delete(url).set(CSRF_HEADER, this.csrf);
  }
}

export async function csrfFor(agent: ReturnType<typeof request.agent>): Promise<string> {
  const res = await agent.get('/api/v1/auth/csrf');
  expect(res.status).toBe(200);
  return res.body.data.csrfToken as string;
}

let emailSeq = 0;
export function uniqueEmail(prefix = 'user'): string {
  emailSeq += 1;
  return `${prefix}-${Date.now().toString(36)}-${emailSeq}@example.com`;
}

export async function login(app: App, email = uniqueEmail(), name?: string): Promise<Client> {
  const agent = request.agent(app);
  const csrf = await csrfFor(agent);
  const res = await agent
    .post('/api/v1/auth/dev-login')
    .set(CSRF_HEADER, csrf)
    .send(name ? { email, name } : { email });
  expect(res.status, JSON.stringify(res.body)).toBe(200);
  return new Client(agent, csrf, res.body.data as UserDto);
}

export async function createOrg(
  client: Client,
  name = `Org ${Math.random().toString(36).slice(2, 8)}`,
) {
  const res = await client.post('/api/v1/orgs', { name });
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  return res.body.data as { id: string; slug: string; name: string };
}

export async function addMember(orgId: string, userId: string, role: Role, prisma = testPrisma()) {
  await prisma.orgMember.create({ data: { orgId, userId, role } });
}

/** Store an (encrypted) GitHub OAuth account for a user, as the OAuth callback would. */
export async function linkGithub(
  ctx: AppContext,
  userId: string,
  token = 'gho_testtoken000000000000000000000001',
) {
  const n = Math.floor(Math.random() * 1e9);
  await ctx.prisma.oAuthAccount.create({
    data: {
      userId,
      provider: 'github',
      providerAccountId: String(n),
      accessTokenEnc: await ctx.crypto.encryptPacked(token, 'oauth-token'),
      scopes: ['repo', 'read:user', 'user:email'],
    },
  });
}

/** Expect a §16.2 error envelope with the given code. */
export function expectError(res: request.Response, code: string, status?: number) {
  const body = res.body as { error?: Record<string, unknown> };
  expect(
    body.error,
    `expected ${code}, got ${res.status} ${JSON.stringify(res.body)}`,
  ).toBeDefined();
  expect(body.error?.code).toBe(code);
  if (status !== undefined) expect(res.status).toBe(status);
  expect(body.error?.status).toBe(res.status);
  expect(body.error?.requestId).toBe(res.headers['x-request-id']);
}

// ---- MSW ----------------------------------------------------------------------------

export function createMswServer() {
  return setupServer();
}

export function onUnhandled(req: Request, print: { error(): void }) {
  const host = new URL(req.url).hostname;
  if (host === '127.0.0.1' || host === 'localhost' || host === '::1') return;
  print.error();
}

export const ANTHROPIC_MODELS_URL = 'https://api.anthropic.com/v1/models';

export function anthropicReplies(status: number, body: object = {}) {
  return http.get(ANTHROPIC_MODELS_URL, () => HttpResponse.json(body, { status }));
}

export const GITHUB_API = 'https://api.github.com';

export function githubRepoJson(fullName: string, extra: Record<string, unknown> = {}) {
  const [owner, name] = fullName.split('/');
  return {
    id: 1,
    full_name: fullName,
    name,
    owner: { login: owner },
    private: true,
    default_branch: 'main',
    html_url: `https://github.com/${fullName}`,
    description: 'test repo',
    updated_at: '2026-09-01T00:00:00Z',
    ...extra,
  };
}

export function githubRepoHandler(fullName: string, extra: Record<string, unknown> = {}) {
  return http.get(`${GITHUB_API}/repos/${fullName}`, () =>
    HttpResponse.json(githubRepoJson(fullName, extra)),
  );
}

/** `GET /repos/:owner/:repo/git/trees/:ref` — the file listing the memory draft reads. */
export function githubTreeHandler(fullName: string, paths: string[] = []) {
  return http.get(`${GITHUB_API}/repos/${fullName}/git/trees/:ref`, () =>
    HttpResponse.json({
      sha: 'tree-sha',
      truncated: false,
      tree: paths.map((path) => ({
        path,
        type: path.endsWith('/') ? 'tree' : 'blob',
        mode: '100644',
        sha: `blob-${path}`,
      })),
    }),
  );
}
