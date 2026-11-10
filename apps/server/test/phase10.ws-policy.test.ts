/**
 * REAUDIT-006: an established WebSocket must not keep the SSO / 2FA assurance (or the org
 * membership) it had at upgrade time.
 *
 * - The gateway's credential re-check reloads the FULL live credential (user, cookie session /
 *   PAT rows incl. `ssoConnectionId`, `mfaVerifiedAt`) and re-runs the HTTP org access policy
 *   for the joined session.
 * - Every policy-changing path (SSO upsert / delete, security settings, member removal / role
 *   change, verified domains, SCIM membership) publishes a signed post-commit `policy_changed`
 *   event; every instance re-validates the org's sockets at once (4401 when the credential no
 *   longer satisfies the policy, 4403 when the user lost access to the session).
 *
 * The main gateway runs with a 60 s heartbeat AND a 60 s credential cache, so neither the
 * periodic sweep nor the per-command re-check can be what closes the socket in the event
 * tests: only the `policy_changed` event can. The periodic fallback has its own test.
 */
import { randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { RequestHandler } from 'msw';
import request from 'supertest';
import { afterAll, afterEach, beforeEach, describe, expect, it } from 'vitest';
import { WebSocket } from 'ws';
import {
  API_PREFIX,
  buildClientMessage,
  CSRF_HEADER,
  PAT_PREFIX,
  SESSION_COOKIE,
  type ServerMessage,
} from '@loose/shared';
import { sha256Hex } from '../src/lib/crypto';
import { parseRevocationEvent, RevocationBus } from '../src/lib/events/revocations';
import { createLogger } from '../src/lib/logger';
import { createRedis, type Redis } from '../src/lib/redis';
import { invalidateOrgSecurityCache } from '../src/services/identity/accessPolicy';
import { updateMember } from '../src/services/org.service';
import { callerStillValid, revalidateWsCaller } from '../src/ws/auth';
import { attachWsGateway, type WsGateway } from '../src/ws/gateway';
import { mswFetch } from './agentHelpers';
import {
  addMember,
  createOrg,
  csrfFor,
  login,
  makeApp,
  resetDb,
  TEST_SECRETS,
  testPrisma,
  type Client,
} from './helpers';
import {
  createFakeDns,
  createMockIdp,
  IDP_CLIENT_ID,
  IDP_CLIENT_SECRET,
  IDP_ISSUER,
  makeRsaKey,
} from './phase10.identityHelpers';
import { createReadyProject } from './sessionHelpers';

const prisma = testPrisma();
const logger = createLogger({ level: 'silent' });
const ORIGIN = 'http://localhost:5173';
const DOMAIN = 'wspolicy.test';

const handlers: { current: RequestHandler[] } = { current: [] };
const dns = createFakeDns();
const rsa = makeRsaKey('rsa-wspolicy');

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function until<T>(read: () => T | undefined | Promise<T | undefined>, label: string) {
  const deadline = Date.now() + 4_000;
  for (;;) {
    const value = await read();
    if (value !== undefined && value !== false) return value;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${label}`);
    await sleep(20);
  }
}

interface TestClient {
  ws: WebSocket;
  messages: ServerMessage[];
  closed: Promise<{ code: number; reason: string }>;
  isOpen(): boolean;
  send(type: Parameters<typeof buildClientMessage>[0], sessionId: string, payload: object): void;
  next(pred: (m: ServerMessage) => boolean, label?: string): Promise<ServerMessage>;
}

const sockets: WebSocket[] = [];

function connect(url: string, headers: Record<string, string>): Promise<TestClient> {
  const ws = new WebSocket(url, { headers });
  sockets.push(ws);
  const messages: ServerMessage[] = [];
  ws.on('message', (d) => messages.push(JSON.parse(String(d)) as ServerMessage));
  let open = true;
  const closed = new Promise<{ code: number; reason: string }>((resolve) =>
    ws.on('close', (code, reason) => {
      open = false;
      resolve({ code, reason: String(reason) });
    }),
  );
  const client: TestClient = {
    ws,
    messages,
    closed,
    isOpen: () => open,
    send(type, sessionId, payload) {
      ws.send(JSON.stringify(buildClientMessage(type, sessionId, payload as never)));
    },
    next: (pred, label = 'message') =>
      until(() => messages.find(pred), label) as Promise<ServerMessage>,
  };
  return new Promise((resolve, reject) => {
    ws.once('open', () => resolve(client));
    ws.once('error', reject);
  });
}

/** Resolves with the close event, or 'open' if the socket is still open after `ms`. */
async function closedWithin(c: TestClient, ms = 1_500) {
  return Promise.race([c.closed, sleep(ms).then(() => 'open' as const)]);
}

const listen = (server: Server) =>
  new Promise<string>((resolve) =>
    server.listen(0, '127.0.0.1', () =>
      resolve(`ws://127.0.0.1:${(server.address() as AddressInfo).port}/ws`),
    ),
  );

const identityUrl = (orgId: string, path = '') => `${API_PREFIX}/orgs/${orgId}/identity${path}`;

describe('REAUDIT-006 live WebSockets follow the current org access policy', () => {
  const { app, ctx } = makeApp({ context: { fetch: mswFetch(handlers), dns } });
  let server: Server;
  let gateway: WsGateway;
  let base = '';

  beforeEach(async () => {
    await ctx.agent.shutdownAll();
    await resetDb();
    invalidateOrgSecurityCache(ctx);
    dns.txt.clear();
    handlers.current = createMockIdp([rsa]).handlers();
    if (!server) {
      server = createServer(app);
      // Neither the sweep nor the per-command check may fire during a test (see header).
      gateway = attachWsGateway(server, ctx, {
        heartbeatMs: 60_000,
        idleTimeoutMs: 120_000,
        credentialCacheMs: 60_000,
      });
      base = await listen(server);
    }
  });

  afterAll(async () => {
    for (const s of sockets.splice(0)) s.terminate();
    await gateway?.close();
    if (server) await new Promise<void>((r) => server.close(() => r()));
    await ctx.agent.shutdownAll();
    await ctx.jobs.onIdle();
  });

  async function cookieLogin(email: string) {
    const agent = request.agent(app);
    const csrf = await csrfFor(agent);
    const res = await agent
      .post('/api/v1/auth/dev-login')
      .set(CSRF_HEADER, csrf)
      .send({ email, name: 'Member' });
    const raw = ([] as string[])
      .concat(res.headers['set-cookie'] ?? [])
      .find((c) => c.startsWith(`${SESSION_COOKIE}=`))!;
    const user = res.body.data as { id: string; email: string };
    const authSession = await prisma.authSession.findFirstOrThrow({ where: { userId: user.id } });
    return { cookie: raw.split(';')[0]!, user, authSession };
  }

  async function configureSso(owner: Client, orgId: string, overrides: object = {}) {
    const res = await owner.put(identityUrl(orgId, '/sso'), {
      protocol: 'OIDC',
      issuer: IDP_ISSUER,
      clientId: IDP_CLIENT_ID,
      clientSecret: IDP_CLIENT_SECRET,
      enabled: true,
      ...overrides,
    });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    return prisma.ssoConnection.findUniqueOrThrow({ where: { orgId } });
  }

  async function verifyDomain(owner: Client, orgId: string) {
    const created = await owner.post(identityUrl(orgId, '/domains'), { domain: DOMAIN });
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    const dto = created.body.data as {
      id: string;
      verificationRecord: { name: string; value: string };
    };
    dns.txt.set(dto.verificationRecord.name, [[dto.verificationRecord.value]]);
    const verified = await owner.post(identityUrl(orgId, `/domains/${dto.id}/verify`));
    expect(verified.status, JSON.stringify(verified.body)).toBe(200);
  }

  /** Org (owner outside the SSO domain), a MEMBER at the verified domain, and their session. */
  async function fixture(opts: { sso?: 'enforced' | 'off' } = {}) {
    const owner = await login(app, `owner-${randomBytes(3).toString('hex')}@owner.test`);
    const org = await createOrg(owner);
    await verifyDomain(owner, org.id);
    const member = await cookieLogin(`m-${randomBytes(3).toString('hex')}@${DOMAIN}`);
    await addMember(org.id, member.user.id, 'MEMBER');
    const connection =
      opts.sso === 'off' ? null : await configureSso(owner, org.id, { enforce: true });
    if (connection) {
      // Model a sign-in through the org's IdP: the cookie session carries current assurance.
      await prisma.authSession.update({
        where: { id: member.authSession.id },
        data: { ssoOrgId: org.id, ssoConnectionId: connection.id },
      });
    }
    const project = await createReadyProject(ctx, org.id);
    const sessionId = `cwspol${randomBytes(8).toString('hex')}`;
    await prisma.session.create({
      data: {
        id: sessionId,
        projectId: project.id,
        userId: member.user.id,
        mode: 'SIMPLE',
        model: 'claude-sonnet-4-5',
        branchName: `loose/session-${sessionId}`,
        status: 'PAUSED',
      },
    });
    invalidateOrgSecurityCache(ctx);
    return { owner, org, member, connection, sessionId };
  }

  async function mintPat(f: Awaited<ReturnType<typeof fixture>>) {
    const raw = `${PAT_PREFIX}${randomBytes(24).toString('base64url')}`;
    await prisma.apiToken.create({
      data: {
        orgId: f.org.id,
        userId: f.member.user.id,
        name: 'ci',
        hash: sha256Hex(raw),
        scopes: ['sessions:read', 'sessions:write'],
        ssoConnectionId: f.connection?.id ?? null,
      },
    });
    return raw;
  }

  async function joined(f: { sessionId: string }, headers: Record<string, string>, url = base) {
    const c = await connect(url, headers);
    c.send('join_session', f.sessionId, {});
    await c.next((m) => m.type === 'replay_complete', 'replay_complete');
    return c;
  }

  const cookieHeaders = (f: Awaited<ReturnType<typeof fixture>>) => ({
    cookie: f.member.cookie,
    origin: ORIGIN,
  });

  const sessionMode = async (id: string) =>
    (await prisma.session.findUniqueOrThrow({ where: { id } })).mode;

  it('SSO connection replaced (new client id): live cookie and PAT sockets close 4401, no side effect', async () => {
    const f = await fixture();
    const cookie = await joined(f, cookieHeaders(f));
    const pat = await joined(f, { authorization: `Bearer ${await mintPat(f)}` });

    await configureSso(f.owner, f.org.id, { enforce: true, clientId: 'migrated-client' });
    // A command racing the event is refused too (the check is serialized before it).
    cookie.send('set_mode', f.sessionId, { mode: 'PRO' });
    pat.send('set_mode', f.sessionId, { mode: 'PRO' });

    expect(await closedWithin(cookie)).toEqual({ code: 4401, reason: 'LSE-WS-001' });
    expect(await closedWithin(pat)).toEqual({ code: 4401, reason: 'LSE-WS-001' });
    expect(await sessionMode(f.sessionId)).toBe('SIMPLE');
  });

  it('SSO connection deleted and re-created: sockets with the old assurance close 4401', async () => {
    const f = await fixture();
    const cookie = await joined(f, cookieHeaders(f));
    const pat = await joined(f, { authorization: `Bearer ${await mintPat(f)}` });

    expect((await f.owner.delete(identityUrl(f.org.id, '/sso'))).status).toBe(204);
    // No connection → SSO is not required any more, so the sockets legitimately stay up...
    expect(await closedWithin(cookie, 300)).toBe('open');
    // ...until a new connection is enforced: the old assurance does not carry over.
    await configureSso(f.owner, f.org.id, { enforce: true });

    expect(await closedWithin(cookie)).toEqual({ code: 4401, reason: 'LSE-WS-001' });
    expect(await closedWithin(pat)).toEqual({ code: 4401, reason: 'LSE-WS-001' });
  });

  it('enforce-SSO switched on: non-SSO cookie and PAT sockets close 4401', async () => {
    const f = await fixture({ sso: 'off' });
    await configureSso(f.owner, f.org.id, { enforce: false });
    const cookie = await joined(f, cookieHeaders(f));
    const pat = await joined(f, { authorization: `Bearer ${await mintPat(f)}` });

    await configureSso(f.owner, f.org.id, { enforce: true });

    expect(await closedWithin(cookie)).toEqual({ code: 4401, reason: 'LSE-WS-001' });
    expect(await closedWithin(pat)).toEqual({ code: 4401, reason: 'LSE-WS-001' });
    const err = cookie.messages.find((m) => m.type === 'error');
    expect((err?.payload as { error?: { code?: string } }).error?.code).toBe('LSE-WS-001');
  });

  it('member removed: cookie socket closes 4403, PAT socket 4401; the set_mode is not applied', async () => {
    const f = await fixture({ sso: 'off' });
    const cookie = await joined(f, cookieHeaders(f));
    const pat = await joined(f, { authorization: `Bearer ${await mintPat(f)}` });

    const res = await f.owner.delete(`${API_PREFIX}/orgs/${f.org.id}/members/${f.member.user.id}`);
    expect(res.status, JSON.stringify(res.body)).toBe(204);
    cookie.send('set_mode', f.sessionId, { mode: 'PRO' });

    expect(await closedWithin(cookie)).toEqual({ code: 4403, reason: 'LSE-WS-002' });
    expect(await closedWithin(pat)).toEqual({ code: 4401, reason: 'LSE-WS-001' });
    expect(await sessionMode(f.sessionId)).toBe('SIMPLE');
  });

  it('role change into an admin role under requireAdmin2fa (no 2FA): socket closes 4401', async () => {
    const f = await fixture({ sso: 'off' });
    await prisma.organization.update({ where: { id: f.org.id }, data: { requireAdmin2fa: true } });
    const cookie = await joined(f, cookieHeaders(f));
    expect(await closedWithin(cookie, 300)).toBe('open'); // MEMBERs are not subject to it

    // Service call (the route itself would demand 2FA from the owner, too).
    await updateMember(
      ctx,
      f.org.id,
      f.member.user.id,
      { userId: f.owner.user.id, role: 'OWNER' },
      { role: 'ADMIN' },
    );

    expect(await closedWithin(cookie)).toEqual({ code: 4401, reason: 'LSE-WS-001' });
  });

  it('IP allowlist switched on that excludes the socket: closes 4403', async () => {
    const f = await fixture({ sso: 'off' });
    const cookie = await joined(f, cookieHeaders(f));

    const res = await f.owner.put(identityUrl(f.org.id, '/security'), {
      ipAllowlistEnabled: true,
      ipAllowlist: ['10.20.0.0/16'],
      confirmLockout: true,
    });
    expect(res.status, JSON.stringify(res.body)).toBe(200);

    expect(await closedWithin(cookie)).toEqual({ code: 4403, reason: 'LSE-WS-002' });
  });

  it('a policy change that still admits the socket keeps it open (no mass disconnect)', async () => {
    const f = await fixture();
    const cookie = await joined(f, cookieHeaders(f));

    // Unrelated change (JIT off) on the same connection: assurance still current.
    await configureSso(f.owner, f.org.id, { enforce: true, jitProvisioning: false });

    expect(await closedWithin(cookie, 500)).toBe('open');
    cookie.send('set_mode', f.sessionId, { mode: 'PRO' });
    await until(async () => (await sessionMode(f.sessionId)) === 'PRO', 'mode applied');
  });

  it('primitives: a cached caller whose assurance was cleared is not "still valid"; revalidation refuses it', async () => {
    const f = await fixture();
    const user = await prisma.user.findUniqueOrThrow({ where: { id: f.member.user.id } });
    const authSession = await prisma.authSession.findUniqueOrThrow({
      where: { id: f.member.authSession.id },
    });
    const cached = { user, authSession, ip: '127.0.0.1' };
    expect(await callerStillValid(ctx, cached)).toBe(true);
    expect(await revalidateWsCaller(ctx, cached, f.sessionId)).toMatchObject({ state: 'ok' });
    // Exactly what SSO replacement / deletion does to the row (session.service dropSsoAssurance).
    await prisma.authSession.update({
      where: { id: authSession.id },
      data: { ssoOrgId: null, ssoConnectionId: null },
    });
    invalidateOrgSecurityCache(ctx);
    expect(await callerStillValid(ctx, cached)).toBe(false);
    expect(await revalidateWsCaller(ctx, cached, f.sessionId)).toEqual({
      state: 'revoked',
      code: 'LSE-AUTH-006',
    });
  });

  it('periodic fallback: without any event, the sweep closes a socket whose assurance was cleared', async () => {
    const sweepServer = createServer(app);
    const sweepGateway = attachWsGateway(sweepServer, ctx, {
      heartbeatMs: 80,
      idleTimeoutMs: 20_000,
      credentialCacheMs: 60_000,
    });
    const url = await listen(sweepServer);
    try {
      const f = await fixture();
      const cookie = await joined(f, cookieHeaders(f), url);
      // Out of band (e.g. a publisher crashed after commit): only the sweep can notice.
      await prisma.authSession.update({
        where: { id: f.member.authSession.id },
        data: { ssoOrgId: null, ssoConnectionId: null },
      });
      expect(await closedWithin(cookie)).toEqual({ code: 4401, reason: 'LSE-WS-001' });
    } finally {
      await sweepGateway.close();
      await new Promise<void>((r) => sweepServer.close(() => r()));
    }
  });
});

describe('REAUDIT-006 policy_changed across instances', () => {
  let redisA: Redis;
  let redisB: Redis;

  beforeEach(async () => {
    await resetDb();
    redisA = createRedis('redis://127.0.0.1:6379/15', logger);
    redisB = createRedis('redis://127.0.0.1:6379/15', logger);
  });

  afterEach(async () => {
    await redisA?.quit().catch(() => undefined);
    await redisB?.quit().catch(() => undefined);
  });

  it('parses only org-scoped policy_changed events', () => {
    expect(parseRevocationEvent({ reason: 'policy_changed', orgId: 'org_1' })).toEqual({
      reason: 'policy_changed',
      orgId: 'org_1',
    });
    expect(parseRevocationEvent({ reason: 'logout', orgId: 'org_1' })).toBeNull();
    expect(parseRevocationEvent({ reason: 'policy_changed' })).toBeNull();
  });

  it('a signed event from another instance makes this instance re-validate (and drop its cached policy)', async () => {
    const b = makeApp({ context: { redis: redisB, instanceId: 'wspol-b' } });
    const server = createServer(b.app);
    const gateway = attachWsGateway(server, b.ctx, {
      heartbeatMs: 60_000,
      idleTimeoutMs: 120_000,
      credentialCacheMs: 60_000,
    });
    const url = await listen(server);
    // Instance A's bus is not registered in this process' registry: delivery to B can only
    // happen over Redis.
    const busA = new RevocationBus({
      redis: redisA,
      instanceId: 'wspol-a',
      logger,
      secret: TEST_SECRETS.SESSION_SECRET,
    });
    try {
      const owner = await login(b.app, `owner-${randomBytes(3).toString('hex')}@owner.test`);
      const org = await createOrg(owner);
      const memberEmail = `m-${randomBytes(3).toString('hex')}@${DOMAIN}`;
      const member = await login(b.app, memberEmail);
      await addMember(org.id, member.user.id, 'MEMBER');
      await prisma.orgDomain.create({
        data: {
          orgId: org.id,
          domain: DOMAIN,
          verificationToken: 't',
          verifiedAt: new Date(),
          verifiedDomain: DOMAIN,
        },
      });
      const connection = await prisma.ssoConnection.create({
        data: { orgId: org.id, enabled: true, enforce: false, issuer: IDP_ISSUER, clientId: 'x' },
      });
      const raw = `${PAT_PREFIX}${randomBytes(24).toString('base64url')}`;
      await prisma.apiToken.create({
        data: {
          orgId: org.id,
          userId: member.user.id,
          name: 'ci',
          hash: sha256Hex(raw),
          scopes: ['sessions:read', 'sessions:write'],
        },
      });
      const project = await createReadyProject(b.ctx, org.id);
      const sessionId = `cwspolx${randomBytes(8).toString('hex')}`;
      await prisma.session.create({
        data: {
          id: sessionId,
          projectId: project.id,
          userId: member.user.id,
          mode: 'SIMPLE',
          model: 'claude-sonnet-4-5',
          branchName: `loose/session-${sessionId}`,
          status: 'PAUSED',
        },
      });
      const c = await connect(url, { authorization: `Bearer ${raw}` });
      c.send('join_session', sessionId, {});
      await c.next((m) => m.type === 'replay_complete', 'replay_complete');

      // "Instance A" enforces SSO and publishes after commit. B's 5 s policy cache still says
      // "not enforced"; the event must invalidate it.
      await prisma.ssoConnection.update({ where: { id: connection.id }, data: { enforce: true } });
      // A forged (unsigned) event is ignored.
      await redisA.publish('revoke', JSON.stringify({ reason: 'policy_changed', orgId: org.id }));
      expect(await closedWithin(c, 400)).toBe('open');

      await busA.publish({ reason: 'policy_changed', orgId: org.id });
      expect(await closedWithin(c)).toEqual({ code: 4401, reason: 'LSE-WS-001' });
    } finally {
      await busA.close();
      await gateway.close();
      await new Promise<void>((r) => server.close(() => r()));
      await b.ctx.agent.shutdownAll();
      await b.ctx.jobs.onIdle();
    }
  });
});
