import { http, HttpResponse } from 'msw';
import request from 'supertest';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { apiKeyDtoSchema } from '@loose/shared';
import { decryptApiKey } from '../src/services/apiKey.service';
import { AnthropicAdapter } from '../src/providers/anthropic';
import {
  ANTHROPIC_MODELS_URL,
  anthropicReplies,
  captureLogger,
  createMswServer,
  expectError,
  login,
  makeApp,
  onUnhandled,
  resetDb,
  testPrisma,
} from './helpers';

const RAW_KEY = 'sk-ant-api03-RAWKEYVALUE_' + 'a'.repeat(40) + 'WXYZ';
const server = createMswServer();
const prisma = testPrisma();

beforeAll(() => server.listen({ onUnhandledRequest: onUnhandled }));
afterEach(() => server.resetHandlers());
afterAll(async () => {
  server.close();
  await prisma.$disconnect();
});
beforeEach(() => resetDb());

/** Anthropic mock that only accepts RAW_KEY with the right headers. */
function anthropicAcceptsRawKey() {
  server.use(
    http.get(ANTHROPIC_MODELS_URL, ({ request: req }) => {
      const url = new URL(req.url);
      if (url.searchParams.get('limit') !== '1') return HttpResponse.json({}, { status: 400 });
      if (req.headers.get('anthropic-version') !== '2023-06-01')
        return HttpResponse.json({}, { status: 400 });
      if (req.headers.get('x-api-key') !== RAW_KEY) {
        return HttpResponse.json(
          { type: 'error', error: { type: 'authentication_error', message: 'invalid x-api-key' } },
          { status: 401 },
        );
      }
      return HttpResponse.json({
        data: [{ id: 'claude-sonnet-4-5', type: 'model' }],
        has_more: true,
      });
    }),
  );
}

const FORBIDDEN_FIELDS = ['keyEnc', 'dataKeyEnc', '"iv"', 'userId'];
function assertNoKeyMaterial(res: request.Response) {
  const text = JSON.stringify(res.body ?? '') + (res.text ?? '') + JSON.stringify(res.headers);
  expect(text).not.toContain(RAW_KEY);
  expect(text).not.toContain('RAWKEYVALUE');
  for (const f of FORBIDDEN_FIELDS) expect(text).not.toContain(f);
}

describe('BYOK API keys', () => {
  it('valid key → 201 ACTIVE with last4; full flow never exposes key material', async () => {
    const { app, ctx } = makeApp();
    anthropicAcceptsRawKey();
    const c = await login(app);
    const responses: request.Response[] = [];

    const created = await c.post('/api/v1/users/me/api-keys', { key: RAW_KEY, label: 'Work' });
    responses.push(created);
    expect(created.status).toBe(201);
    expect(created.body.data).toMatchObject({
      provider: 'anthropic',
      label: 'Work',
      last4: 'WXYZ',
      status: 'ACTIVE',
    });
    expect(created.body.data.lastValidatedAt).toEqual(expect.any(String));
    expect(Object.keys(created.body.data).sort()).toEqual(
      Object.keys(apiKeyDtoSchema.shape).sort(),
    );
    const id = created.body.data.id as string;

    responses.push(await c.get('/api/v1/users/me/api-keys'));
    responses.push(await c.post(`/api/v1/users/me/api-keys/${id}/revalidate`));
    responses.push(await c.get('/api/v1/auth/me'));
    responses.push(await c.get('/api/v1/users/me'));
    expect(responses[1]?.body.data).toHaveLength(1);
    expect(responses[2]?.status).toBe(200);
    for (const r of responses) assertNoKeyMaterial(r);

    // Stored encrypted; decrypts back to the original.
    const row = await prisma.apiKey.findUniqueOrThrow({ where: { id } });
    expect(Buffer.from(row.keyEnc).toString('latin1')).not.toContain('RAWKEYVALUE');
    expect(row.iv).toHaveLength(12);
    expect(await decryptApiKey(ctx, row)).toBe(RAW_KEY);

    const audit = await prisma.auditLog.findMany({ where: { target: id } });
    expect(audit.map((a) => a.action).sort()).toEqual(['api_key.create', 'api_key.revalidate']);
    expect(JSON.stringify(audit)).not.toContain('RAWKEYVALUE');

    const del = await c.delete(`/api/v1/users/me/api-keys/${id}`);
    expect(del.status).toBe(204);
    assertNoKeyMaterial(del);
    expect(await prisma.apiKey.count()).toBe(0);
    expectError(await c.delete(`/api/v1/users/me/api-keys/${id}`), 'LSE-NF-001', 404);
  });

  it('the raw key never appears in logs (even at trace level, even on failure)', async () => {
    const { logger, lines } = captureLogger('trace');
    const { app } = makeApp({ logger });
    const c = await login(app);
    anthropicAcceptsRawKey();
    expect((await c.post('/api/v1/users/me/api-keys', { key: RAW_KEY })).status).toBe(201);
    server.use(
      anthropicReplies(401, {
        error: { type: 'authentication_error', message: `bad key ${RAW_KEY}` },
      }),
    );
    expect((await c.post('/api/v1/users/me/api-keys', { key: RAW_KEY })).status).toBe(400);
    expect(lines.length).toBeGreaterThan(3);
    const all = lines.join('\n');
    expect(all).not.toContain(RAW_KEY);
    expect(all).not.toContain('RAWKEYVALUE');
    expect(all).toContain('LSE-KEY-011');
  });

  it('invalid key (provider 401) → 400 LSE-KEY-011, nothing stored', async () => {
    const { app } = makeApp();
    anthropicAcceptsRawKey();
    const c = await login(app);
    const res = await c.post('/api/v1/users/me/api-keys', {
      key: 'sk-ant-api03-not-the-right-key-000000000',
    });
    expectError(res, 'LSE-KEY-011', 400);
    expect(res.body.error.userMessage).toBe("That doesn't look like a valid key.");
    expect(res.body.error.devMessage).toContain('authentication_error');
    expect(await prisma.apiKey.count()).toBe(0);
  });

  it.each([
    [403, 'LSE-KEY-004', 403],
    [429, 'LSE-KEY-005', 429],
    [529, 'LSE-KEY-006', 503],
    [503, 'LSE-KEY-006', 503],
    [500, 'LSE-KEY-009', 500],
  ])('provider %i → %s', async (providerStatus, code, httpStatus) => {
    const { app } = makeApp();
    server.use(anthropicReplies(providerStatus, { error: { type: 'some_error' } }));
    const c = await login(app);
    const res = await c.post('/api/v1/users/me/api-keys', { key: RAW_KEY });
    expectError(res, code, httpStatus);
    assertNoKeyMaterial(res);
    expect(await prisma.apiKey.count()).toBe(0);
  });

  it('network failure → LSE-KEY-010', async () => {
    const { app } = makeApp();
    server.use(http.get(ANTHROPIC_MODELS_URL, () => HttpResponse.error()));
    const c = await login(app);
    expectError(await c.post('/api/v1/users/me/api-keys', { key: RAW_KEY }), 'LSE-KEY-010', 504);
  });

  it('timeout → LSE-KEY-010', async () => {
    const adapter = new AnthropicAdapter({
      timeoutMs: 50,
      fetch: (_url, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(init.signal?.reason));
        }),
    });
    const r = await adapter.validateKey(RAW_KEY);
    expect(r).toMatchObject({ ok: false, reason: 'timeout' });
    const { app } = makeApp({ context: { anthropic: adapter } });
    const c = await login(app);
    expectError(await c.post('/api/v1/users/me/api-keys', { key: RAW_KEY }), 'LSE-KEY-010', 504);
  });

  it('revalidate: provider 401 → key marked INVALID + LSE-KEY-003', async () => {
    const { app } = makeApp();
    anthropicAcceptsRawKey();
    const c = await login(app);
    const id = (await c.post('/api/v1/users/me/api-keys', { key: RAW_KEY })).body.data.id as string;
    server.use(anthropicReplies(401));
    const res = await c.post(`/api/v1/users/me/api-keys/${id}/revalidate`);
    expectError(res, 'LSE-KEY-003', 401);
    expect((await prisma.apiKey.findUniqueOrThrow({ where: { id } })).status).toBe('INVALID');
    const list = await c.get('/api/v1/users/me/api-keys');
    expect(list.body.data[0].status).toBe('INVALID');
  });

  it('revalidate: transient provider errors keep the status', async () => {
    const { app } = makeApp();
    anthropicAcceptsRawKey();
    const c = await login(app);
    const id = (await c.post('/api/v1/users/me/api-keys', { key: RAW_KEY })).body.data.id as string;
    server.use(anthropicReplies(529));
    expectError(await c.post(`/api/v1/users/me/api-keys/${id}/revalidate`), 'LSE-KEY-006', 503);
    expect((await prisma.apiKey.findUniqueOrThrow({ where: { id } })).status).toBe('ACTIVE');
  });

  it("users can't see or touch each other's keys", async () => {
    const { app } = makeApp();
    anthropicAcceptsRawKey();
    const a = await login(app);
    const b = await login(app);
    const id = (await a.post('/api/v1/users/me/api-keys', { key: RAW_KEY })).body.data.id as string;
    expect((await b.get('/api/v1/users/me/api-keys')).body.data).toEqual([]);
    expectError(await b.post(`/api/v1/users/me/api-keys/${id}/revalidate`), 'LSE-NF-001', 404);
    expectError(await b.delete(`/api/v1/users/me/api-keys/${id}`), 'LSE-NF-001', 404);
  });

  it('validation errors → LSE-VAL-001 (short key, unknown provider)', async () => {
    const { app } = makeApp();
    const c = await login(app);
    expectError(await c.post('/api/v1/users/me/api-keys', { key: 'short' }), 'LSE-VAL-001', 400);
    expectError(
      await c.post('/api/v1/users/me/api-keys', { key: RAW_KEY, provider: 'openai' }),
      'LSE-VAL-001',
      400,
    );
  });

  it('key validation is rate limited per user → LSE-RATE-001', async () => {
    const { app } = makeApp({ env: { RATE_LIMIT_KEY_VALIDATION_MAX: '2' } });
    server.use(anthropicReplies(401));
    const c = await login(app);
    await c.post('/api/v1/users/me/api-keys', { key: RAW_KEY });
    await c.post('/api/v1/users/me/api-keys', { key: RAW_KEY });
    const res = await c.post('/api/v1/users/me/api-keys', { key: RAW_KEY });
    expectError(res, 'LSE-RATE-001', 429);
    expect(res.headers['retry-after']).toBeDefined();
    // A different user has their own budget.
    const other = await login(app);
    expectError(
      await other.post('/api/v1/users/me/api-keys', { key: RAW_KEY }),
      'LSE-KEY-011',
      400,
    );
  });

  it('requires a session', async () => {
    const { app } = makeApp();
    expectError(await request(app).get('/api/v1/users/me/api-keys'), 'LSE-AUTH-001', 401);
  });
});

describe('Anthropic adapter', () => {
  const adapter = new AnthropicAdapter();
  it('lists models with pricing and estimates cost', () => {
    expect(adapter.listModels().map((m) => m.id)).toContain('claude-sonnet-4-5');
    expect(
      adapter.estimateCost('claude-sonnet-4-5', { tokensIn: 1_000_000, tokensOut: 1_000_000 }),
    ).toBe(18);
    expect(
      adapter.estimateCost('claude-sonnet-4-5-20250929', {
        tokensIn: 1000,
        tokensOut: 0,
        cacheRead: 1000,
      }),
    ).toBeCloseTo(0.0033, 6);
    // Unknown models are priced at the most expensive rate (never under-estimate).
    expect(adapter.estimateCost('mystery', { tokensIn: 0, tokensOut: 1_000_000 })).toBe(75);
  });
  it('toAgentEnv maps the key to ANTHROPIC_API_KEY', () => {
    expect(adapter.toAgentEnv('k')).toEqual({ ANTHROPIC_API_KEY: 'k' });
  });
});

describe('users/me', () => {
  it('GET/PUT profile and preferred mode', async () => {
    const { app } = makeApp();
    const c = await login(app);
    const res = await c.put('/api/v1/users/me', { name: 'New Name', preferredMode: 'PRO' });
    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({ name: 'New Name', preferredMode: 'PRO' });
    expect((await c.get('/api/v1/users/me')).body.data.preferredMode).toBe('PRO');
    expectError(await c.put('/api/v1/users/me', { email: 'x@y.z' }), 'LSE-VAL-001', 400);
  });
});
