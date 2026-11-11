/**
 * WS gateway protocol (spec §11): upgrade auth (cookie + Origin, PAT), join participant
 * check, replay from lastEventId, replay gap, Pro/Simple filtering, invalid messages,
 * rate limit, size limit, heartbeat idle timeout, chat over WS, graceful drain.
 */
import { randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import request from 'supertest';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { WebSocket } from 'ws';
import {
  buildClientMessage,
  CSRF_HEADER,
  PAT_PREFIX,
  SESSION_COOKIE,
  type ServerMessage,
} from '@loose/shared';
import { sha256Hex } from '../src/lib/crypto';
import { InMemorySessionEventBus } from '../src/lib/events/sessionEventBus';
import { attachWsGateway, type WsGateway } from '../src/ws/gateway';
import { installFakeRunner, playTurn, waitFor, type RunnerScript } from './agentHelpers';
import {
  addMember,
  captureLogger,
  createOrg,
  csrfFor,
  linkGithub,
  login,
  makeApp,
  resetDb,
  testPrisma,
} from './helpers';
import { addApiKey, createReadyProject, fakeSandbox, settle } from './sessionHelpers';

const prisma = testPrisma();
const bus = new InMemorySessionEventBus(5);
const logs = captureLogger('warn');
const { app, ctx } = makeApp({ logger: logs.logger, context: { sessionEvents: bus } });
const ORIGIN = 'http://localhost:5173';

let server: Server;
let gateway: WsGateway;
let base = '';
const sockets: WebSocket[] = [];

function startServer(opts: Parameters<typeof attachWsGateway>[2] = {}) {
  server = createServer(app);
  gateway = attachWsGateway(server, ctx, { heartbeatMs: 50, idleTimeoutMs: 400, ...opts });
  return new Promise<void>((resolve) =>
    server.listen(0, '127.0.0.1', () => {
      base = `ws://127.0.0.1:${(server.address() as AddressInfo).port}/ws`;
      resolve();
    }),
  );
}

async function stopServer() {
  for (const s of sockets.splice(0)) s.terminate();
  await gateway.close();
  await new Promise<void>((r) => server.close(() => r()));
}

beforeAll(() => startServer());
afterAll(async () => {
  await stopServer();
  await ctx.agent.shutdownAll();
  await ctx.jobs.onIdle();
  await prisma.$disconnect();
});
beforeEach(async () => {
  await ctx.agent.shutdownAll();
  await resetDb();
});
afterEach(() => {
  for (const s of sockets.splice(0)) s.terminate();
});

/** dev-login and return the raw session cookie. */
async function cookieLogin(name = 'Wes') {
  const agent = request.agent(app);
  const csrf = await csrfFor(agent);
  const email = `ws-${randomBytes(4).toString('hex')}@example.com`;
  const res = await agent
    .post('/api/v1/auth/dev-login')
    .set(CSRF_HEADER, csrf)
    .send({ email, name });
  const raw = ([] as string[])
    .concat(res.headers['set-cookie'] ?? [])
    .find((c) => c.startsWith(`${SESSION_COOKIE}=`))!;
  return {
    cookie: raw.split(';')[0]!,
    user: res.body.data as { id: string; email: string },
    agent,
    csrf,
  };
}

interface Client {
  ws: WebSocket;
  messages: ServerMessage[];
  closed: Promise<{ code: number; reason: string }>;
  send(type: Parameters<typeof buildClientMessage>[0], sessionId: string, payload: object): void;
  next(pred: (m: ServerMessage) => boolean, label?: string): Promise<ServerMessage>;
}

function connect(
  headers: Record<string, string>,
  opts: { autoPong?: boolean } = {},
): Promise<Client> {
  const ws = new WebSocket(base, { headers, autoPong: opts.autoPong ?? true });
  sockets.push(ws);
  const messages: ServerMessage[] = [];
  ws.on('message', (d) => messages.push(JSON.parse(String(d)) as ServerMessage));
  const closed = new Promise<{ code: number; reason: string }>((resolve) =>
    ws.on('close', (code, reason) => resolve({ code, reason: String(reason) })),
  );
  const client: Client = {
    ws,
    messages,
    closed,
    send(type, sessionId, payload) {
      ws.send(JSON.stringify(buildClientMessage(type, sessionId, payload as never)));
    },
    next: (pred, label = 'message') =>
      waitFor(() => messages.find(pred), { label, timeoutMs: 4000 }),
  };
  return new Promise((resolve, reject) => {
    ws.once('open', () => resolve(client));
    ws.once('error', reject);
  });
}

async function sessionFixture(mode: 'SIMPLE' | 'PRO' = 'SIMPLE') {
  const owner = await cookieLogin('Owner');
  const admin = await login(app);
  const org = await createOrg(admin);
  await addMember(org.id, owner.user.id, 'MEMBER');
  const project = await createReadyProject(ctx, org.id);
  const id = `cws${randomBytes(8).toString('hex')}`;
  await prisma.session.create({
    data: {
      id,
      projectId: project.id,
      userId: owner.user.id,
      mode,
      model: 'claude-sonnet-4-5',
      branchName: `loose/session-${id}`,
      status: 'PAUSED',
    },
  });
  return { owner, orgId: org.id, sessionId: id, project };
}

const codeOf = (m: ServerMessage) => (m.payload as { error?: { code?: string } }).error?.code;

describe('upgrade auth', () => {
  it('no credentials → error LSE-WS-001 + close 4401', async () => {
    const c = await connect({});
    expect(await c.closed).toEqual({ code: 4401, reason: 'LSE-WS-001' });
    expect(codeOf(c.messages[0]!)).toBe('LSE-WS-001');
  });

  it('cookie from a foreign Origin → 4401', async () => {
    const { cookie } = await cookieLogin();
    logs.lines.length = 0;
    const c = await connect({ cookie, origin: 'https://evil.example' });
    expect((await c.closed).code).toBe(4401);
    // The rejection is diagnosable from the server log (reason + Origin), without the cookie.
    const line = logs.lines.find((l) => l.includes('ws upgrade rejected'));
    expect(line).toBeDefined();
    expect(JSON.parse(line!)).toMatchObject({
      reason: 'bad_origin',
      origin: 'https://evil.example',
    });
    expect(logs.lines.join('\n')).not.toContain(cookie.split('=')[1]!);
  });

  it('PAT bearer is accepted; unknown token → 4401', async () => {
    const f = await sessionFixture();
    const raw = `${PAT_PREFIX}${randomBytes(24).toString('base64url')}`;
    await prisma.apiToken.create({
      data: {
        orgId: f.orgId,
        userId: f.owner.user.id,
        name: 't',
        hash: sha256Hex(raw),
        scopes: ['sessions:read'],
      },
    });
    const c = await connect({ authorization: `Bearer ${raw}` });
    c.send('join_session', f.sessionId, {});
    await c.next((m) => m.type === 'replay_complete');
    const bad = await connect({ authorization: `Bearer ${PAT_PREFIX}nope` });
    expect((await bad.closed).code).toBe(4401);
  });
});

describe('join & replay', () => {
  it('non-participant → LSE-WS-002 + close 4403', async () => {
    const f = await sessionFixture();
    const other = await cookieLogin('Other');
    await addMember(f.orgId, other.user.id, 'MEMBER');
    const c = await connect({ cookie: other.cookie, origin: ORIGIN });
    c.send('join_session', f.sessionId, {});
    expect(await c.closed).toEqual({ code: 4403, reason: 'LSE-WS-002' });
  });

  it('replays events after lastEventId, then replay_complete, then live', async () => {
    const f = await sessionFixture();
    for (let i = 1; i <= 4; i += 1) {
      await bus.publish(f.sessionId, 'session_status', { status: 'RUNNING', message: `m${i}` });
    }
    const c = await connect({ cookie: f.owner.cookie, origin: ORIGIN });
    c.send('join_session', f.sessionId, { lastEventId: 2 });
    const done = await c.next((m) => m.type === 'replay_complete');
    expect(done.payload).toEqual({ lastSeq: 4 });
    expect(c.messages.filter((m) => m.type === 'session_status').map((m) => m.seq)).toEqual([3, 4]);
    await bus.publish(f.sessionId, 'session_status', { status: 'RUNNING', message: 'live' });
    const live = await c.next((m) => m.type === 'session_status' && m.seq === 5);
    expect(live.payload).toMatchObject({ message: 'live' });
    expect(c.messages.find((m) => m.type === 'presence')?.payload).toMatchObject({
      users: [expect.objectContaining({ id: f.owner.user.id })],
    });
    // ping/pong
    c.send('ping', f.sessionId, {});
    await c.next((m) => m.type === 'pong');
  });

  it('gap beyond the retained log → LSE-WS-004 + close 4409', async () => {
    const f = await sessionFixture();
    for (let i = 1; i <= 9; i += 1) {
      await bus.publish(f.sessionId, 'session_status', { status: 'RUNNING', message: `m${i}` });
    }
    const c = await connect({ cookie: f.owner.cookie, origin: ORIGIN });
    c.send('join_session', f.sessionId, { lastEventId: 1 });
    expect(await c.closed).toEqual({ code: 4409, reason: 'LSE-WS-004' });
    expect(codeOf(c.messages.find((m) => m.type === 'error')!)).toBe('LSE-WS-004');
  });

  it('Simple viewers never get Pro-only events or file lists; Pro viewers do', async () => {
    const f = await sessionFixture('SIMPLE');
    const sid = f.sessionId;
    await bus.publish(
      sid,
      'tool_event',
      { id: 't', name: 'Read', phase: 'start', input: { file_path: 'src/a.ts' } },
      { audience: 'pro' },
    );
    await bus.publish(
      sid,
      'agent_status',
      { state: 'reading', label: 'Looking through the project…' },
      { audience: 'simple' },
    );
    await bus.publish(
      sid,
      'agent_status',
      { state: 'reading', label: 'Read src/a.ts' },
      { audience: 'pro' },
    );
    await bus.publish(sid, 'change_summary', {
      messageId: 'm1',
      summary: 'I updated the header.',
      areas: ['the header'],
      risk: 'LOW',
      files: [{ path: 'src/a.ts', status: 'modified' }],
      screenshots: [],
    });
    const simple = await connect({ cookie: f.owner.cookie, origin: ORIGIN });
    simple.send('join_session', sid, {});
    await simple.next((m) => m.type === 'replay_complete');
    const types = simple.messages.map((m) => m.type);
    expect(types).not.toContain('tool_event');
    expect(simple.messages.filter((m) => m.type === 'agent_status').map((m) => m.payload)).toEqual([
      { state: 'reading', label: 'Looking through the project…' },
    ]);
    const cs = simple.messages.find((m) => m.type === 'change_summary')!;
    expect(cs.payload).not.toHaveProperty('files');
    expect(JSON.stringify(simple.messages)).not.toContain('src/a.ts');

    await prisma.session.update({ where: { id: sid }, data: { mode: 'PRO' } });
    const pro = await connect({ cookie: f.owner.cookie, origin: ORIGIN });
    pro.send('join_session', sid, {});
    await pro.next((m) => m.type === 'replay_complete');
    expect(pro.messages.map((m) => m.type)).toContain('tool_event');
    expect(
      pro.messages
        .filter((m) => m.type === 'agent_status')
        .map((m) => (m.payload as { label: string }).label),
    ).toEqual(['Read src/a.ts']);
    expect(pro.messages.find((m) => m.type === 'change_summary')!.payload).toHaveProperty('files');
  });

  it('a mode lock keeps the viewer in Simple even for a Pro session', async () => {
    const f = await sessionFixture('PRO');
    await prisma.orgMember.updateMany({
      where: { userId: f.owner.user.id },
      data: { lockedMode: 'SIMPLE' },
    });
    await bus.publish(
      f.sessionId,
      'tool_event',
      { id: 't', name: 'Read', phase: 'start' },
      { audience: 'pro' },
    );
    const c = await connect({ cookie: f.owner.cookie, origin: ORIGIN });
    c.send('join_session', f.sessionId, {});
    await c.next((m) => m.type === 'replay_complete');
    expect(c.messages.map((m) => m.type)).not.toContain('tool_event');
  });
});

describe('message ordering', () => {
  it('a message sent right after join_session is handled after the join completes', async () => {
    // The web client flushes its offline outbox immediately after sending join_session.
    const { owner, sessionId } = await sessionFixture();
    const c = await connect({ cookie: owner.cookie, origin: ORIGIN });
    c.send('join_session', sessionId, {});
    c.send('chat_message', sessionId, { clientMessageId: 'early-1', content: 'hi' });
    const err = await c.next((m) => m.type === 'error', 'error');
    // Joined (not LSE-WS-002 "join first"); the PAUSED session then refuses the message.
    expect(codeOf(err)).toBe('LSE-CONF-001');
    const types = c.messages.map((m) => m.type);
    expect(types.indexOf('replay_complete')).toBeGreaterThanOrEqual(0);
    expect(types.indexOf('replay_complete')).toBeLessThan(types.indexOf('error'));
  });
});

describe('limits & validation', () => {
  it('invalid messages → LSE-WS-006, connection kept', async () => {
    const { cookie } = await cookieLogin();
    const c = await connect({ cookie, origin: ORIGIN });
    c.ws.send('not json');
    await c.next((m) => codeOf(m) === 'LSE-WS-006');
    c.ws.send(
      JSON.stringify({
        id: 'x',
        type: 'chat_message',
        sessionId: 's',
        ts: new Date().toISOString(),
        payload: {},
      }),
    );
    await waitFor(() => c.messages.filter((m) => codeOf(m) === 'LSE-WS-006').length === 2);
    c.send('chat_message', 'cnotjoined', { clientMessageId: 'a', content: 'hi' });
    await c.next((m) => codeOf(m) === 'LSE-WS-002');
    c.send('ping', '-', {});
    await c.next((m) => m.type === 'pong');
    expect(c.ws.readyState).toBe(WebSocket.OPEN);
  });

  it('rate limit → LSE-WS-005 + close 4429', async () => {
    const { cookie } = await cookieLogin();
    const c = await connect({ cookie, origin: ORIGIN });
    for (let i = 0; i < 31; i += 1) c.send('ping', '-', {});
    expect(await c.closed).toEqual({ code: 4429, reason: 'LSE-WS-005' });
  });

  it('frames over 256 KB → LSE-WS-007 + close 4413', async () => {
    const { cookie } = await cookieLogin();
    const c = await connect({ cookie, origin: ORIGIN });
    c.ws.send('x'.repeat(256 * 1024 + 1));
    expect(await c.closed).toEqual({ code: 4413, reason: 'LSE-WS-007' });
  });

  it('a client that stops answering pings is closed with 4408', async () => {
    const { cookie } = await cookieLogin();
    const c = await connect({ cookie, origin: ORIGIN }, { autoPong: false });
    const closed = await c.closed;
    expect(closed.code).toBe(4408);
  });

  it('a client that answers pings stays connected', async () => {
    const { cookie } = await cookieLogin();
    const c = await connect({ cookie, origin: ORIGIN });
    await new Promise((r) => setTimeout(r, 600));
    expect(c.ws.readyState).toBe(WebSocket.OPEN);
  });
});

describe('chat over WS', () => {
  it('chat_message runs a turn and streams the results to the joined client', async () => {
    const fake = fakeSandbox(ctx);
    fake.reset();
    const script: { current: RunnerScript } = {
      current: (cmd, r) => {
        if (cmd.type === 'user_message') playTurn(r, { text: 'All set, the page says Howdy now.' });
      },
    };
    installFakeRunner(fake, script);
    const owner = await cookieLogin('Owner');
    const admin = await login(app);
    const org = await createOrg(admin);
    await addMember(org.id, owner.user.id, 'MEMBER');
    await linkGithub(ctx, owner.user.id);
    await addApiKey(ctx, owner.user.id);
    const project = await createReadyProject(ctx, org.id);
    const start = await owner.agent
      .post('/api/v1/sessions')
      .set(CSRF_HEADER, owner.csrf)
      .send({ projectId: project.id });
    expect(start.status, JSON.stringify(start.body)).toBe(201);
    const s = await settle(ctx, start.body.data.id as string);
    expect(s.status).toBe('RUNNING');
    await waitFor(() => ctx.agent.hasRuntime(s.id));

    const c = await connect({ cookie: owner.cookie, origin: ORIGIN });
    c.send('join_session', s.id, {});
    await c.next((m) => m.type === 'replay_complete');
    c.send('chat_message', s.id, { clientMessageId: 'ws-1', content: 'Say howdy' });
    await c.next(
      (m) =>
        m.type === 'chat_message' &&
        (m.payload as { message: { role: string } }).message.role === 'USER',
    );
    await c.next((m) => m.type === 'agent_streaming');
    const final = await c.next(
      (m) =>
        m.type === 'chat_message' &&
        (m.payload as { message: { role: string } }).message.role === 'ASSISTANT',
    );
    expect((final.payload as { message: { content: string } }).message.content).toBe(
      'All set, the page says Howdy now.',
    );
    await c.next((m) => m.type === 'cost_update');
    await c.next(
      (m) => m.type === 'agent_status' && (m.payload as { state: string }).state === 'idle',
    );
    expect(c.messages.map((m) => m.type)).not.toContain('tool_event');
    await ctx.agent.idle();
  });
});

describe('graceful drain', () => {
  it('close() sends 1001 to every client and refuses new upgrades', async () => {
    const { cookie } = await cookieLogin();
    const c = await connect({ cookie, origin: ORIGIN });
    await gateway.close();
    expect((await c.closed).code).toBe(1001);
    const late = new WebSocket(base, { headers: { cookie, origin: ORIGIN } });
    sockets.push(late);
    await new Promise((resolve) => late.once('error', resolve).once('close', resolve));
    await stopServer();
    await startServer();
  });
});
