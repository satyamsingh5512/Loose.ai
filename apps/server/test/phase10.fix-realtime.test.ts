/**
 * Phase 10 security fixes — fix-realtime stage.
 *
 * P10-SEC-003: logout / session deletion / PAT revocation / expiry terminate an established
 *              WebSocket (revocation event over the cluster bus, close 4401 + LSE-WS-001),
 *              and every state-changing command re-validates the credential.
 * P10-SEC-004: Redis pub/sub is authenticated — unsigned, forged, cross-channel, stale,
 *              replayed and credential-less control messages are rejected.
 * P10-SEC-007: Linear/Jira webhooks are bound to one trigger (unguessable path token) and
 *              verified with that trigger's own secret; no global trigger scan.
 */
import { createHmac, randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import request from 'supertest';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { WebSocket } from 'ws';
import {
  buildClientMessage,
  buildServerMessage,
  CSRF_HEADER,
  PAT_PREFIX,
  SESSION_COOKIE,
  type ServerMessage,
} from '@loose/shared';
import { sha256Hex } from '../src/lib/crypto';
import { ClusterCommandForwarder, SessionOwnerLease } from '../src/lib/events/cluster';
import {
  deriveClusterKey,
  NonceCache,
  signClusterMessage,
  verifyClusterMessage,
} from '../src/lib/events/envelope';
import { ClusterPresence } from '../src/lib/events/presence';
import {
  parseRevocationEvent,
  revocationMatches,
  RevocationBus,
  REVOCATION_CHANNEL,
  type RevocationEvent,
} from '../src/lib/events/revocations';
import { RedisSessionEventBus } from '../src/lib/events/sessionEventBus';
import { createLogger } from '../src/lib/logger';
import { createRedis, type Redis } from '../src/lib/redis';
import { deleteToken } from '../src/services/token.service';
import {
  parseTriggerWebhookToken,
  triggerWebhookSecret,
  triggerWebhookToken,
} from '../src/services/triggers/webhookAuth';
import type * as WsAuth from '../src/ws/auth';
import { attachWsGateway, type WsGateway } from '../src/ws/gateway';
import {
  addMember,
  createOrg,
  csrfFor,
  expectError,
  login,
  makeApp,
  resetDb,
  TEST_SECRETS,
  testPrisma,
  type Client,
} from './helpers';
import { createReadyProject } from './sessionHelpers';

/** P10-SEC-003: lets a test make the WS credential re-check throw (a DB blip). */
const credentialCheck = vi.hoisted(() => ({ fail: false }));
vi.mock('../src/ws/auth', async (importOriginal) => {
  const real = await importOriginal<typeof WsAuth>();
  return {
    ...real,
    revalidateWsCaller: async (...args: Parameters<typeof real.revalidateWsCaller>) => {
      if (credentialCheck.fail) throw new Error('database unavailable');
      return real.revalidateWsCaller(...args);
    },
  };
});

const prisma = testPrisma();
const logger = createLogger({ level: 'silent' });
const SECRET = TEST_SECRETS.SESSION_SECRET;
const KEY = deriveClusterKey(SECRET);
const ORIGIN = 'http://localhost:5173';

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

// ---- P10-SEC-004: the envelope primitive ----------------------------------------------------

describe('P10-SEC-004 authenticated cluster envelopes', () => {
  const channel = 'cmd:instance-a';

  it('round-trips a signed message with the publisher instance id', () => {
    const raw = signClusterMessage(KEY, {
      instanceId: 'instance-b',
      channel,
      payload: { hello: 'world' },
    });
    const v = verifyClusterMessage<{ hello: string }>(KEY, raw, { channel });
    expect(v).toMatchObject({ instanceId: 'instance-b', payload: { hello: 'world' } });
    expect(typeof v!.nonce).toBe('string');
  });

  it('rejects unsigned, tampered, foreign-key, cross-channel and stale messages', () => {
    const raw = signClusterMessage(KEY, { instanceId: 'b', channel, payload: { n: 1 } });
    // unsigned legacy JSON
    expect(verifyClusterMessage(KEY, JSON.stringify({ n: 1 }), { channel })).toBeNull();
    // tampered body (same MAC)
    const [v, body, mac] = raw.split('.');
    const forgedBody = Buffer.from(
      JSON.stringify({ v: 1, iid: 'b', ts: Date.now(), n: 'x', ch: channel, p: { n: 2 } }),
      'utf8',
    ).toString('base64url');
    expect(verifyClusterMessage(KEY, `${v}.${forgedBody}.${mac}`, { channel })).toBeNull();
    expect(body).not.toBe(forgedBody);
    // signed with another key
    expect(
      verifyClusterMessage(
        KEY,
        signClusterMessage(deriveClusterKey('another-secret-that-is-long-enough-xx'), {
          instanceId: 'b',
          channel,
          payload: { n: 1 },
        }),
        { channel },
      ),
    ).toBeNull();
    // replayed onto a different channel
    expect(verifyClusterMessage(KEY, raw, { channel: 'cmd:instance-z' })).toBeNull();
    // stale / future timestamps
    const old = signClusterMessage(KEY, {
      instanceId: 'b',
      channel,
      payload: { n: 1 },
      now: Date.now() - 120_000,
    });
    expect(verifyClusterMessage(KEY, old, { channel })).toBeNull();
    expect(verifyClusterMessage(KEY, raw, { channel, now: Date.now() + 120_000 })).toBeNull();
    // no key configured → nothing is trusted
    expect(verifyClusterMessage(null, raw, { channel })).toBeNull();
  });

  it('NonceCache accepts a nonce once', () => {
    const cache = new NonceCache();
    expect(cache.accept('n1')).toBe(true);
    expect(cache.accept('n1')).toBe(false);
    expect(cache.accept('n2')).toBe(true);
  });

  // REAUDIT-005 / P10-SEC-004-R: a full cache used to clear itself, forgetting live nonces.
  it('NonceCache never re-accepts a live nonce after saturation (small capacity)', () => {
    const t0 = 1_000_000;
    const cache = new NonceCache(60_000, 2);
    expect(cache.accept('a', t0, t0)).toBe(true);
    expect(cache.accept('b', t0 + 1, t0 + 1)).toBe(true);
    // full: 'c' evicts 'a' and raises the floor to a's ts
    expect(cache.accept('c', t0 + 2, t0 + 2)).toBe(true);
    expect(cache.size).toBe(2);
    expect(cache.accept('a', t0 + 3, t0)).toBe(false); // the exact replay from the reaudit proof
    expect(cache.accept('b', t0 + 3, t0 + 1)).toBe(false);
    expect(cache.accept('c', t0 + 3, t0 + 2)).toBe(false);
    // a fresh message newer than the floor still gets through; an older one is refused
    expect(cache.accept('d', t0 + 4, t0 + 4)).toBe(true);
    expect(cache.accept('late', t0 + 5, t0 - 1)).toBe(false);
    expect(cache.size).toBeLessThanOrEqual(2);
  });

  it('NonceCache stays bounded and replay-proof under heavy saturation', () => {
    const t0 = 5_000_000;
    const cache = new NonceCache(60_000, 100);
    const seen: Array<[string, number]> = [];
    for (let i = 0; i < 1000; i += 1) {
      const ts = t0 + i;
      expect(cache.accept(`n${i}`, ts, ts)).toBe(true);
      seen.push([`n${i}`, ts]);
      expect(cache.size).toBeLessThanOrEqual(100);
    }
    // every nonce, evicted or not, is still refused inside the window
    const now = t0 + 1000;
    for (const [n, ts] of seen) expect(cache.accept(n, now, ts)).toBe(false);
    // interleaved concurrent deliveries of one nonce: exactly one wins
    const results = Array.from({ length: 50 }, () => cache.accept('burst', now, now));
    expect(results.filter(Boolean)).toHaveLength(1);
  });

  it('NonceCache drops out-of-window entries without raising the floor', () => {
    const t0 = 9_000_000;
    const cache = new NonceCache(1_000, 2);
    expect(cache.accept('a', t0, t0)).toBe(true);
    expect(cache.accept('b', t0, t0)).toBe(true);
    // both expired: pruned, not evicted, so a message just after them is accepted
    expect(cache.accept('c', t0 + 1_001, t0 + 1)).toBe(true);
    expect(cache.size).toBe(1);
  });
});

// ---- P10-SEC-004: the cluster control plane over a real Redis --------------------------------

describe('P10-SEC-004 cluster control plane', () => {
  let redisA: Redis;
  let redisB: Redis;

  beforeEach(async () => {
    await resetDb();
    redisA = createRedis('redis://127.0.0.1:6379/15', logger);
    redisB = createRedis('redis://127.0.0.1:6379/15', logger);
  });

  afterAll(async () => {
    await redisA?.quit().catch(() => undefined);
    await redisB?.quit().catch(() => undefined);
  });

  async function fixture() {
    const a = makeApp({ context: { redis: redisA, instanceId: 'fixrt-owner' } });
    const client = await login(a.app, undefined, 'Cluster Owner');
    const org = await createOrg(client, 'Cluster Org');
    const project = await createReadyProject(a.ctx, org.id);
    const sessionId = `cfixrt${randomBytes(8).toString('hex')}`;
    await prisma.session.create({
      data: {
        id: sessionId,
        projectId: project.id,
        userId: client.user.id,
        mode: 'SIMPLE',
        model: 'claude-sonnet-4-5',
        branchName: `loose/session-${sessionId}`,
        status: 'PAUSED',
      },
    });
    const authSession = await prisma.authSession.findFirstOrThrow({
      where: { userId: client.user.id },
    });
    return { ...a, client, sessionId, authSession };
  }

  it('executes only signed, credential-backed commands on the owning instance', async () => {
    const f = await fixture();
    const executed: string[] = [];
    const owner = new ClusterCommandForwarder(f.ctx, async (caller, message) => {
      executed.push(`${caller.user.id}:${message.type}`);
      return message.type === 'set_mode' ? message.payload.mode : undefined;
    });
    const channel = `cmd:${f.ctx.instanceId}`;
    const command = buildClientMessage('set_mode', f.sessionId, { mode: 'PRO' });
    try {
      await owner.start();

      // 1. legacy/unsigned JSON (what an attacker with Redis write access would publish)
      await redisB.publish(
        channel,
        JSON.stringify({
          id: 'atk1',
          sourceInstanceId: 'evil',
          caller: { userId: f.client.user.id },
          message: command,
        }),
      );
      // 2. signed with the wrong key
      await redisB.publish(
        channel,
        signClusterMessage(deriveClusterKey('evil-secret-that-is-long-enough-abcd'), {
          instanceId: 'evil',
          channel,
          payload: {
            id: 'atk2',
            caller: { userId: f.client.user.id, authSessionId: f.authSession.id },
            message: command,
          },
        }),
      );
      // 3. correctly signed but credential-less (the old "internal caller" shortcut)
      await redisB.publish(
        channel,
        signClusterMessage(KEY, {
          instanceId: 'fixrt-peer',
          channel,
          payload: { id: 'atk3', caller: { userId: f.client.user.id }, message: command },
        }),
      );
      // 4. correctly signed, but for a credential that no longer exists
      await redisB.publish(
        channel,
        signClusterMessage(KEY, {
          instanceId: 'fixrt-peer',
          channel,
          payload: {
            id: 'atk4',
            caller: { userId: f.client.user.id, authSessionId: `${f.authSession.id}-gone` },
            message: command,
          },
        }),
      );
      await sleep(300);
      expect(executed).toEqual([]);
      expect(await prisma.session.findUniqueOrThrow({ where: { id: f.sessionId } })).toMatchObject({
        mode: 'SIMPLE',
      });

      // 5. a correctly signed command from a peer with a live cookie session runs
      const replies: unknown[] = [];
      const sub = redisB.duplicate();
      sub.on('message', (_c: string, raw: string) => {
        const v = verifyClusterMessage<unknown>(KEY, raw, { channel: 'cmd:reply:fixrt-peer' });
        if (v) replies.push(v.payload);
      });
      await sub.subscribe('cmd:reply:fixrt-peer');
      const good = signClusterMessage(KEY, {
        instanceId: 'fixrt-peer',
        channel,
        payload: {
          id: 'ok1',
          caller: { userId: f.client.user.id, authSessionId: f.authSession.id },
          message: command,
        },
      });
      await redisB.publish(channel, good);
      await until(() => (executed.length ? executed : undefined), 'forwarded command');
      expect(executed).toEqual([`${f.client.user.id}:set_mode`]);
      expect(await until(() => replies[0], 'signed reply')).toMatchObject({
        id: 'ok1',
        ok: true,
        value: 'PRO',
      });

      // 6. an exact replay of the same signed envelope is ignored
      await redisB.publish(channel, good);
      await sleep(250);
      expect(executed).toHaveLength(1);
      // 7. a burst of concurrent replays of the same envelope still executes nothing more
      await Promise.all(Array.from({ length: 20 }, () => redisB.publish(channel, good)));
      await sleep(300);
      expect(executed).toHaveLength(1);
      await sub.quit().catch(() => undefined);
    } finally {
      await owner.close();
      await f.ctx.agent.shutdownAll();
    }
  });

  it('refuses to relay a caller without a cookie session or API token', async () => {
    const f = await fixture();
    const peer = new ClusterCommandForwarder(f.ctx, async () => undefined);
    const lease = new SessionOwnerLease(redisA, 'some-other-instance', logger);
    try {
      await lease.claim(f.sessionId);
      const user = await prisma.user.findUniqueOrThrow({ where: { id: f.client.user.id } });
      await expect(
        peer.forwardIfRemote(
          { user },
          buildClientMessage('set_mode', f.sessionId, { mode: 'PRO' }),
        ),
      ).rejects.toMatchObject({ code: 'LSE-AUTH-001' });
    } finally {
      await lease.close();
      await peer.close();
      await f.ctx.agent.shutdownAll();
    }
  });

  it('drops unsigned and cross-session session events instead of delivering them', async () => {
    const sessionId = `cevt${randomBytes(6).toString('hex')}`;
    const publisher = new RedisSessionEventBus(redisA, logger, {
      secret: SECRET,
      instanceId: 'fixrt-a',
    });
    const consumer = new RedisSessionEventBus(redisB, logger, {
      secret: SECRET,
      instanceId: 'fixrt-b',
    });
    const seen: ServerMessage[] = [];
    const off = consumer.subscribe(sessionId, (m) => seen.push(m));
    await consumer.ready?.(sessionId);
    try {
      // forged, unsigned `preview_updated` with a script-capable URL (the SPA would iframe it)
      await redisB.publish(
        `sess:${sessionId}`,
        JSON.stringify({
          a: 'all',
          m: buildServerMessage('preview_updated', sessionId, 99, {
            url: 'javascript:alert(document.cookie)',
            reason: 'forged',
          }),
        }),
      );
      // signed for another session's channel, then replayed onto this one
      await redisB.publish(
        `sess:${sessionId}`,
        signClusterMessage(KEY, {
          instanceId: 'evil',
          channel: `sess:${sessionId}-other`,
          payload: {
            a: 'all',
            m: buildServerMessage('chat_message', `${sessionId}-other`, 98, {
              message: {
                id: 'm1',
                sessionId: `${sessionId}-other`,
                role: 'ASSISTANT',
                content: 'forged',
                createdAt: new Date().toISOString(),
              },
            }),
          },
        }),
      );
      // signed for this channel but naming a different session
      await redisB.publish(
        `sess:${sessionId}`,
        signClusterMessage(KEY, {
          instanceId: 'evil',
          channel: `sess:${sessionId}`,
          payload: {
            a: 'all',
            m: buildServerMessage('chat_message', `${sessionId}-other`, 97, {
              message: {
                id: 'm2',
                sessionId: `${sessionId}-other`,
                role: 'ASSISTANT',
                content: 'forged',
                createdAt: new Date().toISOString(),
              },
            }),
          },
        }),
      );
      await sleep(250);
      expect(seen).toEqual([]);

      // the real bus still works, and its entries replay
      await publisher.publish(sessionId, 'session_status', { status: 'PAUSED', message: 'real' });
      await until(() => (seen.length ? seen : undefined), 'signed session event');
      expect(seen.map((m) => m.type)).toEqual(['session_status']);
      const replay = await consumer.replay(sessionId, 0);
      expect(replay.events.map((e) => e.seq)).toEqual([1]);
    } finally {
      off();
      await publisher.close();
      await consumer.close();
    }
  });

  it('ignores unsigned presence notifications and forged presence entries', async () => {
    const sessionId = `cpres${randomBytes(6).toString('hex')}`;
    const a = new ClusterPresence(redisA, 'fixrt-a', logger, SECRET);
    const b = new ClusterPresence(redisB, 'fixrt-b', logger, SECRET);
    let notifications = 0;
    const off = b.subscribe(sessionId, () => (notifications += 1));
    await b.ready();
    try {
      await redisB.publish(`presence:${sessionId}`, 'changed');
      await redisB.publish(
        `presence:${sessionId}`,
        signClusterMessage(deriveClusterKey('evil-secret-that-is-long-enough-abcd'), {
          instanceId: 'evil',
          channel: `presence:${sessionId}`,
          payload: 'changed',
        }),
      );
      await sleep(250);
      expect(notifications).toBe(0);

      await a.join(sessionId, 'socket-a', {
        id: 'user-a',
        name: 'A',
        avatarUrl: null,
        mode: 'PRO',
        controller: false,
      });
      await until(() => (notifications > 0 ? notifications : undefined), 'presence notification');
      // an unsigned hash entry injected straight into Redis is not listed
      await redisB.hset(
        `presence:${sessionId}`,
        'evil:1',
        JSON.stringify({
          id: 'ghost',
          name: 'Ghost',
          avatarUrl: null,
          mode: 'PRO',
          controller: true,
        }),
      );
      expect((await b.list(sessionId)).map((e) => e.id)).toEqual(['user-a']);
    } finally {
      off();
      await a.leave(sessionId, 'socket-a');
      await a.close();
      await b.close();
    }
  });
  it('relays revocations to other instances and rejects forged ones', async () => {
    const a = new RevocationBus({
      redis: redisA,
      instanceId: 'fixrt-a',
      logger,
      secret: SECRET,
    });
    const b = new RevocationBus({
      redis: redisB,
      instanceId: 'fixrt-b',
      logger,
      secret: SECRET,
    });
    const seen: RevocationEvent[] = [];
    const off = b.subscribe((e) => seen.push(e));
    await b.ready();
    try {
      // unsigned, and signed with a foreign key / another channel → dropped
      await redisA.publish(
        REVOCATION_CHANNEL,
        JSON.stringify({ reason: 'logout', userId: 'victim', allForUser: true }),
      );
      await redisA.publish(
        REVOCATION_CHANNEL,
        signClusterMessage(deriveClusterKey('evil-secret-that-is-long-enough-abcd'), {
          instanceId: 'evil',
          channel: REVOCATION_CHANNEL,
          payload: { reason: 'logout', userId: 'victim', allForUser: true },
        }),
      );
      await redisA.publish(
        REVOCATION_CHANNEL,
        signClusterMessage(KEY, {
          instanceId: 'evil',
          channel: 'some:other:channel',
          payload: { reason: 'logout', userId: 'victim', allForUser: true },
        }),
      );
      await sleep(250);
      expect(seen).toEqual([]);

      await a.publish({ reason: 'token_revoked', userId: 'u1', apiTokenIds: ['tok1'] });
      await until(() => (seen.length ? seen : undefined), 'relayed revocation');
      expect(seen[0]).toMatchObject({ reason: 'token_revoked', apiTokenIds: ['tok1'] });
      expect(revocationMatches(seen[0]!, { userId: 'u1', apiTokenId: 'tok1' })).toBe(true);
      expect(revocationMatches(seen[0]!, { userId: 'u1', apiTokenId: 'other' })).toBe(false);
      // a payload with nothing identifiable is not an event
      expect(parseRevocationEvent({ reason: 'logout' })).toBeNull();
      expect(parseRevocationEvent({ reason: 'nope', apiTokenIds: ['x'] })).toBeNull();
    } finally {
      off();
      await a.close();
      await b.close();
    }
  });
});

// ---- P10-SEC-003: revoking a credential closes its WebSockets --------------------------------

describe('P10-SEC-003 WebSocket credential revocation', () => {
  const { app, ctx } = makeApp();
  let server: Server;
  let gateway: WsGateway;
  let base = '';
  const sockets: WebSocket[] = [];

  beforeEach(async () => {
    await ctx.agent.shutdownAll();
    await resetDb();
    if (!server) {
      server = createServer(app);
      // credentialCacheMs: 0 → every state-changing command re-checks the credential.
      gateway = attachWsGateway(server, ctx, {
        heartbeatMs: 80,
        idleTimeoutMs: 20_000,
        credentialCacheMs: 0,
      });
      await new Promise<void>((resolve) =>
        server.listen(0, '127.0.0.1', () => {
          base = `ws://127.0.0.1:${(server.address() as AddressInfo).port}/ws`;
          resolve();
        }),
      );
    }
  });

  afterEach(() => {
    credentialCheck.fail = false;
  });

  afterAll(async () => {
    for (const s of sockets.splice(0)) s.terminate();
    await gateway?.close();
    if (server) await new Promise<void>((r) => server.close(() => r()));
    await ctx.agent.shutdownAll();
    await ctx.jobs.onIdle();
  });

  interface TestClient {
    ws: WebSocket;
    messages: ServerMessage[];
    closed: Promise<{ code: number; reason: string }>;
    send(type: Parameters<typeof buildClientMessage>[0], sessionId: string, payload: object): void;
    next(pred: (m: ServerMessage) => boolean, label?: string): Promise<ServerMessage>;
  }

  function connect(headers: Record<string, string>, url = base): Promise<TestClient> {
    const ws = new WebSocket(url, { headers });
    sockets.push(ws);
    const messages: ServerMessage[] = [];
    ws.on('message', (d) => messages.push(JSON.parse(String(d)) as ServerMessage));
    const closed = new Promise<{ code: number; reason: string }>((resolve) =>
      ws.on('close', (code, reason) => resolve({ code, reason: String(reason) })),
    );
    const client: TestClient = {
      ws,
      messages,
      closed,
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

  async function cookieLogin(name = 'Wes') {
    const agent = request.agent(app);
    const csrf = await csrfFor(agent);
    const email = `fixrt-${randomBytes(4).toString('hex')}@example.com`;
    const res = await agent
      .post('/api/v1/auth/dev-login')
      .set(CSRF_HEADER, csrf)
      .send({ email, name });
    const raw = ([] as string[])
      .concat(res.headers['set-cookie'] ?? [])
      .find((c) => c.startsWith(`${SESSION_COOKIE}=`))!;
    return { cookie: raw.split(';')[0]!, user: res.body.data as { id: string; email: string } };
  }

  async function fixture() {
    const owner = await cookieLogin('Owner');
    const admin = await login(app);
    const org = await createOrg(admin);
    await addMember(org.id, owner.user.id, 'MEMBER');
    const project = await createReadyProject(ctx, org.id);
    const sessionId = `cwsrt${randomBytes(8).toString('hex')}`;
    await prisma.session.create({
      data: {
        id: sessionId,
        projectId: project.id,
        userId: owner.user.id,
        mode: 'SIMPLE',
        model: 'claude-sonnet-4-5',
        branchName: `loose/session-${sessionId}`,
        status: 'PAUSED',
      },
    });
    return { owner, admin, orgId: org.id, sessionId };
  }

  const codeOf = (m: ServerMessage) => (m.payload as { error?: { code?: string } }).error?.code;

  it('"sign out everywhere" closes the live socket with 4401 LSE-WS-001', async () => {
    const f = await fixture();
    const c = await connect({ cookie: f.owner.cookie, origin: ORIGIN });
    c.send('join_session', f.sessionId, {});
    await c.next((m) => m.type === 'replay_complete');

    await ctx.sessions.invalidateAllForUser(f.owner.user.id);

    expect(await c.closed).toEqual({ code: 4401, reason: 'LSE-WS-001' });
    expect(codeOf(c.messages.find((m) => m.type === 'error')!)).toBe('LSE-WS-001');
  });

  it('deleting the PAT closes the socket it authenticated', async () => {
    const f = await fixture();
    const raw = `${PAT_PREFIX}${randomBytes(24).toString('base64url')}`;
    const token = await prisma.apiToken.create({
      data: {
        orgId: f.orgId,
        userId: f.owner.user.id,
        name: 'ci',
        hash: sha256Hex(raw),
        scopes: ['sessions:read', 'sessions:write'],
      },
    });
    const c = await connect({ authorization: `Bearer ${raw}` });
    c.send('join_session', f.sessionId, {});
    await c.next((m) => m.type === 'replay_complete');

    await deleteToken(ctx, f.owner.user.id, token.id);

    expect(await c.closed).toEqual({ code: 4401, reason: 'LSE-WS-001' });
  });

  it('a state-changing command on a socket whose session row is gone is refused (no side effect)', async () => {
    const f = await fixture();
    const c = await connect({ cookie: f.owner.cookie, origin: ORIGIN });
    c.send('join_session', f.sessionId, {});
    await c.next((m) => m.type === 'replay_complete');

    // Delete the row directly: no revocation event is published, so only the per-command
    // re-validation can catch this (e.g. another instance / a crashed publisher).
    await prisma.authSession.deleteMany({ where: { userId: f.owner.user.id } });
    c.send('set_mode', f.sessionId, { mode: 'PRO' });

    expect(await c.closed).toEqual({ code: 4401, reason: 'LSE-WS-001' });
    expect(await prisma.session.findUniqueOrThrow({ where: { id: f.sessionId } })).toMatchObject({
      mode: 'SIMPLE',
    });
  });

  it('closes a socket whose cookie session expired, without any client traffic', async () => {
    const f = await fixture();
    const c = await connect({ cookie: f.owner.cookie, origin: ORIGIN });
    c.send('join_session', f.sessionId, {});
    await c.next((m) => m.type === 'replay_complete');

    await prisma.authSession.updateMany({
      where: { userId: f.owner.user.id },
      data: { expiresAt: new Date(Date.now() - 1_000) },
    });

    expect(await c.closed).toEqual({ code: 4401, reason: 'LSE-WS-001' });
  });

  it('closes a socket whose API token expired', async () => {
    const f = await fixture();
    const raw = `${PAT_PREFIX}${randomBytes(24).toString('base64url')}`;
    const token = await prisma.apiToken.create({
      data: {
        orgId: f.orgId,
        userId: f.owner.user.id,
        name: 'ci',
        hash: sha256Hex(raw),
        scopes: ['sessions:read', 'sessions:write'],
        expiresAt: new Date(Date.now() + 60_000),
      },
    });
    const c = await connect({ authorization: `Bearer ${raw}` });
    c.send('join_session', f.sessionId, {});
    await c.next((m) => m.type === 'replay_complete');

    await prisma.apiToken.update({
      where: { id: token.id },
      data: { expiresAt: new Date(Date.now() - 1_000) },
    });

    expect(await c.closed).toEqual({ code: 4401, reason: 'LSE-WS-001' });
  });

  it('fails closed when the periodic re-check errors: close 1013, and the reconnect re-authenticates', async () => {
    const f = await fixture();
    const c = await connect({ cookie: f.owner.cookie, origin: ORIGIN });
    c.send('join_session', f.sessionId, {});
    await c.next((m) => m.type === 'replay_complete');

    // The session is revoked out of band (no revocation event) while the DB check is failing:
    // the socket must not survive on the strength of the failed check.
    await prisma.authSession.deleteMany({ where: { userId: f.owner.user.id } });
    credentialCheck.fail = true;
    expect(await c.closed).toEqual({ code: 1013, reason: 'credential check unavailable' });

    // The client's retry goes through upgrade auth again, which refuses the revoked session.
    credentialCheck.fail = false;
    const again = await connect({ cookie: f.owner.cookie, origin: ORIGIN });
    expect(await again.closed).toEqual({ code: 4401, reason: 'LSE-WS-001' });
  });

  it('fails closed when the pre-command re-check errors: command rejected, close 1013', async () => {
    // A gateway whose periodic sweep will not run during the test, so only the pre-command
    // check sees the failure.
    const quiet = createServer(app);
    const quietGateway = attachWsGateway(quiet, ctx, {
      heartbeatMs: 60_000,
      idleTimeoutMs: 120_000,
      credentialCacheMs: 0,
    });
    const url = await new Promise<string>((resolve) =>
      quiet.listen(0, '127.0.0.1', () =>
        resolve(`ws://127.0.0.1:${(quiet.address() as AddressInfo).port}/ws`),
      ),
    );
    try {
      const f = await fixture();
      const c = await connect({ cookie: f.owner.cookie, origin: ORIGIN }, url);
      c.send('join_session', f.sessionId, {});
      await c.next((m) => m.type === 'replay_complete');

      credentialCheck.fail = true;
      c.send('set_mode', f.sessionId, { mode: 'PRO' });
      expect(await c.closed).toEqual({ code: 1013, reason: 'credential check unavailable' });
      expect(await prisma.session.findUniqueOrThrow({ where: { id: f.sessionId } })).toMatchObject({
        mode: 'SIMPLE',
      });
    } finally {
      await quietGateway.close();
      await new Promise<void>((r) => quiet.close(() => r()));
    }
  });
});

// ---- P10-SEC-007: per-trigger inbound webhook credentials ------------------------------------

describe('P10-SEC-007 Linear/Jira trigger isolation', () => {
  const { app, ctx } = makeApp();

  beforeEach(async () => {
    await resetDb();
  });

  afterAll(async () => {
    await ctx.agent.shutdownAll();
    await ctx.jobs.onIdle();
  });

  async function orgWithTrigger(
    kind: 'LINEAR' | 'JIRA',
    config: Record<string, unknown>,
    label: string,
  ) {
    const admin: Client = await login(app, undefined, `Admin ${label}`);
    const org = await createOrg(admin, `Org ${label}`);
    const project = await createReadyProject(ctx, org.id);
    const res = await admin.post(`/api/v1/orgs/${org.id}/triggers`, {
      projectId: project.id,
      kind,
      name: `${kind} ${label}`,
      config,
      runAsUserId: admin.user.id,
    });
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    const dto = res.body.data as { id: string; webhookUrl: string; webhookSecret: string };
    return { admin, orgId: org.id, trigger: dto, path: new URL(dto.webhookUrl).pathname };
  }

  const linearBody = (teamId: string, issueId: string) =>
    JSON.stringify({
      action: 'create',
      type: 'Issue',
      data: {
        id: issueId,
        identifier: 'ENG-1',
        title: 'Fix the thing',
        team: { id: teamId },
        labels: { nodes: [{ name: 'loose' }] },
      },
    });

  it('per-trigger URL and secret are derived, distinct per trigger and kind-bound', async () => {
    const a = await orgWithTrigger('LINEAR', { label: 'loose', teamId: 'team-a' }, 'A');
    const b = await orgWithTrigger('LINEAR', { label: 'loose', teamId: 'team-b' }, 'B');
    expect(a.trigger.webhookUrl).toContain(`/integrations/linear/webhook/${a.trigger.id}.`);
    expect(a.trigger.webhookSecret).not.toBe(b.trigger.webhookSecret);
    const token = a.trigger.webhookUrl.split('/').pop()!;
    expect(parseTriggerWebhookToken(SECRET, 'LINEAR', token)).toBe(a.trigger.id);
    // the same trigger id signed for the other provider does not validate
    expect(parseTriggerWebhookToken(SECRET, 'JIRA', token)).toBeNull();
    expect(triggerWebhookToken(SECRET, 'JIRA', a.trigger.id)).not.toBe(token);
    expect(triggerWebhookSecret(SECRET, 'LINEAR', a.trigger.id)).toBe(a.trigger.webhookSecret);
    expect(parseTriggerWebhookToken(SECRET, 'LINEAR', `${a.trigger.id}.deadbeef`)).toBeNull();
  });

  it("org A's secret cannot fire org B's Linear trigger, and A cannot reach B's trigger at all", async () => {
    const a = await orgWithTrigger('LINEAR', { label: 'loose', teamId: 'team-a' }, 'A');
    const b = await orgWithTrigger('LINEAR', { label: 'loose', teamId: 'team-b' }, 'B');
    const body = linearBody('team-b', 'issue-b1');

    // 1. org B's URL, signed with org A's secret → 401, nothing fires
    const crossTenant = await request(app)
      .post(b.path)
      .set(
        'linear-signature',
        createHmac('sha256', a.trigger.webhookSecret).update(body).digest('hex'),
      )
      .set('Content-Type', 'application/json')
      .send(body);
    expectError(crossTenant, 'LSE-AUTH-009', 401);

    // 2. org A's own URL + secret, but a payload naming org B's team: no global scan any more
    const scan = await request(app)
      .post(a.path)
      .set(
        'linear-signature',
        createHmac('sha256', a.trigger.webhookSecret).update(body).digest('hex'),
      )
      .set('Content-Type', 'application/json')
      .send(body);
    expect(scan.status, JSON.stringify(scan.body)).toBe(202);
    expect(scan.body.data.handled).toBe(false);

    await sleep(100);
    expect(await prisma.triggerFire.count()).toBe(0);
    expect(await prisma.run.count()).toBe(0);
    const audits = await prisma.auditLog.findMany({ where: { action: { startsWith: 'run.' } } });
    expect(audits).toEqual([]);
  });

  it('unknown, forged and wrong-provider trigger tokens are rejected (401 LSE-AUTH-009)', async () => {
    const a = await orgWithTrigger('LINEAR', { label: 'loose', teamId: 'team-a' }, 'A');
    const body = linearBody('team-a', 'issue-a1');
    const sign = (secret: string) => createHmac('sha256', secret).update(body).digest('hex');

    for (const token of [
      `${a.trigger.id}.not-a-real-mac`,
      `trigger-does-not-exist.${a.trigger.webhookUrl.split('.').pop()}`,
      triggerWebhookToken(SECRET, 'JIRA', a.trigger.id), // right trigger, wrong provider path
    ]) {
      const res = await request(app)
        .post(`/api/v1/integrations/linear/webhook/${token}`)
        .set('linear-signature', sign(a.trigger.webhookSecret))
        .set('Content-Type', 'application/json')
        .send(body);
      expectError(res, 'LSE-AUTH-009', 401);
    }
  });

  it("Jira: org A's secret cannot fire org B's trigger", async () => {
    const a = await orgWithTrigger('JIRA', { label: 'loose', projectKey: 'AAA' }, 'A');
    const b = await orgWithTrigger('JIRA', { label: 'loose', projectKey: 'BBB' }, 'B');
    const body = JSON.stringify({
      webhookEvent: 'jira:issue_created',
      issue: {
        key: 'BBB-1',
        fields: { summary: 'x', project: { key: 'BBB' }, labels: ['loose'] },
      },
    });
    const jiraSig = (secret: string) =>
      `sha256=${createHmac('sha256', secret).update(body).digest('hex')}`;

    const crossTenant = await request(app)
      .post(b.path)
      .set('x-hub-signature', jiraSig(a.trigger.webhookSecret))
      .set('Content-Type', 'application/json')
      .send(body);
    expectError(crossTenant, 'LSE-AUTH-009', 401);

    const scan = await request(app)
      .post(a.path)
      .set('x-hub-signature', jiraSig(a.trigger.webhookSecret))
      .set('Content-Type', 'application/json')
      .send(body);
    expect(scan.status, JSON.stringify(scan.body)).toBe(202);
    expect(scan.body.data.handled).toBe(false);
    await sleep(100);
    expect(await prisma.triggerFire.count()).toBe(0);
  });

  it('a disabled trigger does not fire even with its own valid credentials', async () => {
    const a = await orgWithTrigger('LINEAR', { label: 'loose', teamId: 'team-a' }, 'A');
    await prisma.trigger.update({ where: { id: a.trigger.id }, data: { enabled: false } });
    const body = linearBody('team-a', 'issue-a2');
    const res = await request(app)
      .post(a.path)
      .set(
        'linear-signature',
        createHmac('sha256', a.trigger.webhookSecret).update(body).digest('hex'),
      )
      .set('Content-Type', 'application/json')
      .send(body);
    expect(res.status).toBe(202);
    expect(res.body.data.handled).toBe(false);
    expect(await prisma.triggerFire.count()).toBe(0);
  });
});
