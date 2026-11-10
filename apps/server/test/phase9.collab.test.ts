/**
 * Phase 9 — shared sessions (spec §8.18): share / list / revoke, the role matrix, viewers
 * that may watch but not act, co-editors that may, developer take-over (LSE-AGT-017 while
 * someone else is in control), and presence over the WebSocket.
 */
import { randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { WebSocket } from 'ws';
import {
  buildClientMessage,
  CSRF_HEADER,
  MAX_SESSION_COLLABORATORS,
  SESSION_COOKIE,
  type ServerMessage,
} from '@loose/shared';
import { attachWsGateway, type WsGateway } from '../src/ws/gateway';
import { installFakeRunner, playTurn, waitFor, type RunnerScript } from './agentHelpers';
import {
  addMember,
  createOrg,
  csrfFor,
  expectError,
  linkGithub,
  login,
  makeApp,
  resetDb,
  testPrisma,
  uniqueEmail,
  type Client,
} from './helpers';
import { addApiKey, createReadyProject, fakeSandbox, settle } from './sessionHelpers';

const prisma = testPrisma();
const { app, ctx } = makeApp();
const fake = fakeSandbox(ctx);
const script: { current: RunnerScript } = { current: () => undefined };
const ORIGIN = 'http://localhost:5173';

let server: Server;
let gateway: WsGateway;
let wsBase = '';
const sockets: WebSocket[] = [];

beforeAll(async () => {
  server = createServer(app);
  gateway = attachWsGateway(server, ctx, { heartbeatMs: 500, idleTimeoutMs: 20_000 });
  await new Promise<void>((resolve) =>
    server.listen(0, '127.0.0.1', () => {
      wsBase = `ws://127.0.0.1:${(server.address() as AddressInfo).port}/ws`;
      resolve();
    }),
  );
});

afterAll(async () => {
  for (const s of sockets.splice(0)) s.terminate();
  await gateway.close();
  await new Promise<void>((r) => server.close(() => r()));
  await ctx.agent.shutdownAll();
  await ctx.jobs.onIdle();
  await prisma.$disconnect();
});

beforeEach(async () => {
  for (const s of sockets.splice(0)) s.terminate();
  await ctx.agent.shutdownAll();
  await ctx.jobs.onIdle();
  fake.reset();
  installFakeRunner(fake, script);
  script.current = (cmd, r) => {
    if (cmd.type === 'user_message') playTurn(r, { text: 'Done.' });
  };
  await resetDb();
  ctx.platformEvents.clearHistory();
});

// ---- fixtures --------------------------------------------------------------------------------

interface Actor extends Client {
  cookie: string;
}

/**
 * A signed-in client that also exposes its raw session cookie, so the same user can drive
 * both REST (supertest agent) and a WebSocket upgrade.
 */
async function actor(name: string): Promise<Actor> {
  const email = uniqueEmail('collab');
  const client = await login(app, email, name);
  const agent = request.agent(app);
  const csrf = await csrfFor(agent);
  const res = await agent
    .post('/api/v1/auth/dev-login')
    .set(CSRF_HEADER, csrf)
    .send({ email, name });
  expect(res.status, JSON.stringify(res.body)).toBe(200);
  const raw = ([] as string[])
    .concat(res.headers['set-cookie'] ?? [])
    .find((c) => c.startsWith(`${SESSION_COOKIE}=`))!;
  return Object.assign(client, { cookie: raw.split(';')[0]! });
}

interface World {
  admin: Client;
  owner: Actor;
  dev: Actor;
  watcher: Actor;
  stranger: Client;
  orgId: string;
  projectId: string;
}

async function world(): Promise<World> {
  const admin = await login(app, undefined, 'Ada Admin');
  const org = await createOrg(admin);
  await linkGithub(ctx, admin.user.id);
  await addApiKey(ctx, admin.user.id);
  const owner = await actor('Olive Owner');
  await addMember(org.id, owner.user.id, 'MEMBER');
  await linkGithub(ctx, owner.user.id);
  await addApiKey(ctx, owner.user.id);
  const dev = await actor('Dev Dana');
  await addMember(org.id, dev.user.id, 'MEMBER');
  const watcher = await actor('Vic Viewer');
  await addMember(org.id, watcher.user.id, 'MEMBER');
  const stranger = await login(app, undefined, 'Sam Stranger');
  await addMember(org.id, stranger.user.id, 'MEMBER');
  const project = await createReadyProject(ctx, org.id);
  await prisma.organization.update({
    where: { id: org.id },
    data: { policy: { maxConcurrentSessionsPerUser: 10, maxConcurrentSessionsPerOrg: 50 } },
  });
  return { admin, owner, dev, watcher, stranger, orgId: org.id, projectId: project.id };
}

async function startRunning(w: World): Promise<string> {
  const res = await w.owner.post('/api/v1/sessions', { projectId: w.projectId });
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  const s = await settle(ctx, res.body.data.id as string);
  expect(s.status).toBe('RUNNING');
  await waitFor(() => ctx.agent.hasRuntime(s.id));
  return s.id;
}

async function share(w: World, sessionId: string, who: Client, role: 'VIEWER' | 'CO_EDITOR') {
  const res = await w.owner.post(`/api/v1/sessions/${sessionId}/share`, {
    userId: who.user.id,
    role,
  });
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  return res.body.data as Record<string, unknown>;
}

// ---- WS client -------------------------------------------------------------------------------

interface WsClient {
  ws: WebSocket;
  messages: ServerMessage[];
  closed: Promise<{ code: number; reason: string }>;
  send(type: Parameters<typeof buildClientMessage>[0], sessionId: string, payload: object): void;
  next(pred: (m: ServerMessage) => boolean, label?: string): Promise<ServerMessage>;
}

function connect(cookie: string): Promise<WsClient> {
  const ws = new WebSocket(wsBase, { headers: { cookie, origin: ORIGIN } });
  sockets.push(ws);
  const messages: ServerMessage[] = [];
  ws.on('message', (d) => messages.push(JSON.parse(String(d)) as ServerMessage));
  const closed = new Promise<{ code: number; reason: string }>((resolve) =>
    ws.on('close', (code, reason) => resolve({ code, reason: String(reason) })),
  );
  const client: WsClient = {
    ws,
    messages,
    closed,
    send(type, sessionId, payload) {
      ws.send(JSON.stringify(buildClientMessage(type, sessionId, payload as never)));
    },
    next: (pred, label = 'message') =>
      waitFor(() => messages.find(pred), { label, timeoutMs: 5000 }),
  };
  return new Promise((resolve, reject) => {
    ws.once('open', () => resolve(client));
    ws.once('error', reject);
  });
}

async function join(cookie: string, sessionId: string): Promise<WsClient> {
  const c = await connect(cookie);
  c.send('join_session', sessionId, {});
  await Promise.race([
    c.next((m) => m.type === 'replay_complete', 'replay_complete'),
    c.closed.then((r) => {
      throw new Error(
        `join closed ${r.code} ${r.reason}: ${JSON.stringify(c.messages.slice(0, 3))}`,
      );
    }),
  ]);
  return c;
}

interface PresenceUser {
  id: string;
  role?: string;
  mode?: string;
  controller?: boolean;
}

const presenceOf = (c: WsClient): PresenceUser[] =>
  (
    [...c.messages].reverse().find((m) => m.type === 'presence')?.payload as
      { users: PresenceUser[] } | undefined
  )?.users ?? [];

// ---- sharing ---------------------------------------------------------------------------------

describe('POST /sessions/:id/share', () => {
  it('shares with an org member by id or email, upserts the role, lists and revokes', async () => {
    const w = await world();
    const id = await startRunning(w);

    const dto = await share(w, id, w.dev, 'CO_EDITOR');
    expect(dto).toMatchObject({
      sessionId: id,
      userId: w.dev.user.id,
      role: 'CO_EDITOR',
      invitedById: w.owner.user.id,
      name: 'Dev Dana',
    });

    const byEmail = await w.owner.post(`/api/v1/sessions/${id}/share`, {
      email: w.watcher.user.email.toUpperCase(),
      role: 'VIEWER',
    });
    expect(byEmail.status, JSON.stringify(byEmail.body)).toBe(201);
    expect(byEmail.body.data.userId).toBe(w.watcher.user.id);

    // Re-sharing changes the role instead of failing.
    const demoted = await w.owner.post(`/api/v1/sessions/${id}/share`, {
      userId: w.dev.user.id,
      role: 'VIEWER',
    });
    expect(demoted.status).toBe(201);
    expect(demoted.body.data.role).toBe('VIEWER');
    await share(w, id, w.dev, 'CO_EDITOR');

    const list = await w.dev.get(`/api/v1/sessions/${id}/collaborators`);
    expect(list.status, JSON.stringify(list.body)).toBe(200);
    expect(
      (list.body.data as { userId: string; role: string }[]).map((c) => [c.userId, c.role]),
    ).toEqual([
      [w.dev.user.id, 'CO_EDITOR'],
      [w.watcher.user.id, 'VIEWER'],
    ]);

    const del = await w.owner.delete(`/api/v1/sessions/${id}/share/${w.watcher.user.id}`);
    expect(del.status, JSON.stringify(del.body)).toBe(204);
    expect(await prisma.sessionCollaborator.count({ where: { sessionId: id } })).toBe(1);
    expectError(
      await w.owner.delete(`/api/v1/sessions/${id}/share/${w.watcher.user.id}`),
      'LSE-NF-001',
      404,
    );

    const audits = await prisma.auditLog.findMany({
      where: { target: id, action: { in: ['session.share', 'session.unshare'] } },
      orderBy: { createdAt: 'asc' },
    });
    expect(audits.map((a) => a.action)).toEqual([
      'session.share',
      'session.share',
      'session.share',
      'session.share',
      'session.unshare',
    ]);
  });

  it('share role matrix: only the owner and org admins may share', async () => {
    const w = await world();
    const id = await startRunning(w);
    await share(w, id, w.dev, 'CO_EDITOR');
    await share(w, id, w.watcher, 'VIEWER');
    const body = { userId: w.stranger.user.id, role: 'VIEWER' as const };

    // Org admin may share (the owner is covered above).
    const byAdmin = await w.admin.post(`/api/v1/sessions/${id}/share`, body);
    expect(byAdmin.status, JSON.stringify(byAdmin.body)).toBe(201);
    await w.owner.delete(`/api/v1/sessions/${id}/share/${w.stranger.user.id}`);

    // Neither a co-editor nor a viewer may re-share.
    expectError(await w.dev.post(`/api/v1/sessions/${id}/share`, body), 'LSE-ORG-002', 403);
    expectError(await w.watcher.post(`/api/v1/sessions/${id}/share`, body), 'LSE-ORG-002', 403);
    // A plain org member who is not a participant does not take part at all.
    expectError(await w.stranger.post(`/api/v1/sessions/${id}/share`, body), 'LSE-ORG-002', 403);
    // Someone outside the org gets "not found" (existence is not revealed).
    const outsider = await login(app);
    expectError(await outsider.post(`/api/v1/sessions/${id}/share`, body), 'LSE-NF-001', 404);

    // A collaborator may remove themselves, but not someone else.
    expectError(
      await w.watcher.delete(`/api/v1/sessions/${id}/share/${w.dev.user.id}`),
      'LSE-ORG-002',
      403,
    );
    expect(
      (await w.watcher.delete(`/api/v1/sessions/${id}/share/${w.watcher.user.id}`)).status,
    ).toBe(204);
  });

  it('rejects non-members, the owner, org viewers as co-editors, and over-sharing', async () => {
    const w = await world();
    const id = await startRunning(w);

    const outsider = await login(app);
    expectError(
      await w.owner.post(`/api/v1/sessions/${id}/share`, {
        userId: outsider.user.id,
        role: 'VIEWER',
      }),
      'LSE-ORG-001',
      403,
    );
    expectError(
      await w.owner.post(`/api/v1/sessions/${id}/share`, {
        email: 'nobody@example.com',
        role: 'VIEWER',
      }),
      'LSE-NF-001',
      404,
    );
    expectError(
      await w.owner.post(`/api/v1/sessions/${id}/share`, {
        userId: w.owner.user.id,
        role: 'CO_EDITOR',
      }),
      'LSE-CONF-001',
      409,
    );

    // Org VIEWERs can only watch.
    await prisma.orgMember.update({
      where: { userId_orgId: { userId: w.watcher.user.id, orgId: w.orgId } },
      data: { role: 'VIEWER' },
    });
    expectError(
      await w.owner.post(`/api/v1/sessions/${id}/share`, {
        userId: w.watcher.user.id,
        role: 'CO_EDITOR',
      }),
      'LSE-ORG-002',
      403,
    );
    await share(w, id, w.watcher, 'VIEWER');

    // The per-session cap.
    for (let i = 0; i < MAX_SESSION_COLLABORATORS; i += 1) {
      const u = await prisma.user.create({
        data: { email: `cap-${i}-${randomBytes(3).toString('hex')}@example.com` },
      });
      await addMember(w.orgId, u.id, 'MEMBER');
      const res = await w.owner.post(`/api/v1/sessions/${id}/share`, {
        userId: u.id,
        role: 'VIEWER',
      });
      if (res.status === 201) continue;
      expectError(res, 'LSE-VAL-001', 400);
      expect(await prisma.sessionCollaborator.count({ where: { sessionId: id } })).toBe(
        MAX_SESSION_COLLABORATORS,
      );
      return;
    }
    throw new Error('the collaborator cap was never reached');
  });
});

// ---- what each role may do -------------------------------------------------------------------

describe('collaborator permissions', () => {
  it('a VIEWER may read but every write is LSE-ORG-002', async () => {
    const w = await world();
    const id = await startRunning(w);
    await share(w, id, w.watcher, 'VIEWER');

    const get = await w.watcher.get(`/api/v1/sessions/${id}`);
    expect(get.status, JSON.stringify(get.body)).toBe(200);
    expect(get.body.data.access).toEqual({ role: 'viewer', canAct: false });
    expect((await w.watcher.get(`/api/v1/sessions/${id}/messages`)).status).toBe(200);
    expect((await w.watcher.get(`/api/v1/sessions/${id}/checkpoints`)).status).toBe(200);
    expect((await w.watcher.get(`/api/v1/sessions/${id}/notes`)).status).toBe(200);
    expect((await w.watcher.get(`/api/v1/sessions/${id}/collaborators`)).status).toBe(200);

    expectError(
      await w.watcher.post(`/api/v1/sessions/${id}/messages`, { content: 'Change it' }),
      'LSE-ORG-002',
      403,
    );
    expectError(await w.watcher.post(`/api/v1/sessions/${id}/interrupt`), 'LSE-ORG-002', 403);
    expectError(
      await w.watcher.put(`/api/v1/sessions/${id}/notes`, { notes: 'mine now' }),
      'LSE-ORG-002',
      403,
    );
    // `/help` is read-only, so a viewer may run it; `/undo` changes the session.
    expect(
      (await w.watcher.post(`/api/v1/sessions/${id}/commands`, { command: 'help' })).status,
    ).toBe(200);
    expectError(
      await w.watcher.post(`/api/v1/sessions/${id}/commands`, { command: 'undo' }),
      'LSE-ORG-002',
      403,
    );
    expectError(await w.watcher.post(`/api/v1/sessions/${id}/create-pr`, {}), 'LSE-ORG-002', 403);
    expectError(await w.watcher.post(`/api/v1/sessions/${id}/discard`), 'LSE-ORG-002', 403);
    expectError(await w.watcher.post(`/api/v1/sessions/${id}/take-over`), 'LSE-ORG-002', 403);
    expectError(await w.watcher.post(`/api/v1/sessions/${id}/attachments`), 'LSE-ORG-002', 403);
  });

  it('a CO_EDITOR may send messages and act', async () => {
    const w = await world();
    const id = await startRunning(w);
    await share(w, id, w.dev, 'CO_EDITOR');
    const get = await w.dev.get(`/api/v1/sessions/${id}`);
    expect(get.body.data.access).toEqual({ role: 'co_editor', canAct: true });
    const sent = await w.dev.post(`/api/v1/sessions/${id}/messages`, { content: 'Change it' });
    expect(sent.status, JSON.stringify(sent.body)).toBe(202);
    await ctx.agent.idle(id);
    expect((await w.dev.put(`/api/v1/sessions/${id}/notes`, { notes: 'use tabs' })).status).toBe(
      200,
    );
  });

  it('the owner and org admin see their own role in the DTO', async () => {
    const w = await world();
    const id = await startRunning(w);
    expect((await w.owner.get(`/api/v1/sessions/${id}`)).body.data.access).toEqual({
      role: 'owner',
      canAct: true,
    });
    expect((await w.admin.get(`/api/v1/sessions/${id}`)).body.data.access).toEqual({
      role: 'admin',
      canAct: true,
    });
  });
});

// ---- take-over -------------------------------------------------------------------------------

describe('take-over and release', () => {
  it('a co-editor takes control, switches to Pro and locks everyone else out', async () => {
    const w = await world();
    const id = await startRunning(w);
    await share(w, id, w.dev, 'CO_EDITOR');
    expect((await prisma.session.findUniqueOrThrow({ where: { id } })).mode).toBe('SIMPLE');

    const res = await w.dev.post(`/api/v1/sessions/${id}/take-over`);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.data).toMatchObject({
      sessionId: id,
      controllerId: w.dev.user.id,
      controllerName: 'Dev Dana',
      mode: 'PRO',
    });
    expect(res.body.data.controlTakenAt).toBeTruthy();
    const row = await prisma.session.findUniqueOrThrow({ where: { id } });
    expect([row.mode, row.controllerId]).toEqual(['PRO', w.dev.user.id]);

    expect(
      await prisma.auditLog.findFirst({ where: { action: 'session.take_over', target: id } }),
    ).toMatchObject({
      actorId: w.dev.user.id,
      meta: {
        previousMode: 'SIMPLE',
        mode: 'PRO',
        participantRole: 'co_editor',
        ownerId: w.owner.user.id,
      },
    });

    // The session owner can now only watch: LSE-AGT-017 (409).
    const blocked = await w.owner.post(`/api/v1/sessions/${id}/messages`, { content: 'mine' });
    expectError(blocked, 'LSE-AGT-017', 409);
    expect(blocked.body.error.title).toBe('Someone else is in control');
    expectError(await w.owner.post(`/api/v1/sessions/${id}/interrupt`), 'LSE-AGT-017', 409);
    expectError(await w.owner.post(`/api/v1/sessions/${id}/create-pr`, {}), 'LSE-AGT-017', 409);
    expect((await w.owner.get(`/api/v1/sessions/${id}`)).body.data.access).toEqual({
      role: 'owner',
      canAct: false,
    });

    // The controller still may.
    const sent = await w.dev.post(`/api/v1/sessions/${id}/messages`, { content: 'Change it' });
    expect(sent.status, JSON.stringify(sent.body)).toBe(202);
    await ctx.agent.idle(id);

    // A second taker is refused while control is held; the holder is idempotent.
    await share(w, id, w.stranger, 'CO_EDITOR');
    expectError(await w.stranger.post(`/api/v1/sessions/${id}/take-over`), 'LSE-AGT-017', 409);
    expect((await w.dev.post(`/api/v1/sessions/${id}/take-over`)).status).toBe(200);

    const released = await w.dev.post(`/api/v1/sessions/${id}/release`);
    expect(released.status, JSON.stringify(released.body)).toBe(200);
    expect(released.body.data).toMatchObject({ controllerId: null, controllerName: null });
    expect((await prisma.session.findUniqueOrThrow({ where: { id } })).controlTakenAt).toBeNull();
    expect(
      await prisma.auditLog.findFirst({
        where: { action: 'session.release_control', target: id },
      }),
    ).toMatchObject({ actorId: w.dev.user.id, meta: { previousControllerId: w.dev.user.id } });
    expect(
      (await w.owner.post(`/api/v1/sessions/${id}/messages`, { content: 'mine again' })).status,
    ).toBe(202);
    await ctx.agent.idle(id);
  });

  it('the owner can force a release; a stopped session cannot be taken over', async () => {
    const w = await world();
    const id = await startRunning(w);
    await share(w, id, w.dev, 'CO_EDITOR');
    expect((await w.dev.post(`/api/v1/sessions/${id}/take-over`)).status).toBe(200);
    const forced = await w.owner.post(`/api/v1/sessions/${id}/release`);
    expect(forced.status, JSON.stringify(forced.body)).toBe(200);
    expect(
      await prisma.auditLog.findFirst({
        where: { action: 'session.release_control', target: id },
      }),
    ).toMatchObject({ meta: { forced: true } });
    // Releasing again is a no-op.
    expect((await w.owner.post(`/api/v1/sessions/${id}/release`)).status).toBe(200);

    await prisma.session.update({ where: { id }, data: { status: 'PAUSED' } });
    expectError(await w.dev.post(`/api/v1/sessions/${id}/take-over`), 'LSE-CONF-001', 409);
  });

  it('a member locked to Simple cannot take over (LSE-ORG-009)', async () => {
    const w = await world();
    const id = await startRunning(w);
    await share(w, id, w.dev, 'CO_EDITOR');
    await prisma.orgMember.update({
      where: { userId_orgId: { userId: w.dev.user.id, orgId: w.orgId } },
      data: { lockedMode: 'SIMPLE' },
    });
    expectError(await w.dev.post(`/api/v1/sessions/${id}/take-over`), 'LSE-ORG-009', 403);
  });

  it('restarting the session gives control back to its owner', async () => {
    const w = await world();
    const id = await startRunning(w);
    await share(w, id, w.dev, 'CO_EDITOR');
    expect((await w.dev.post(`/api/v1/sessions/${id}/take-over`)).status).toBe(200);
    await prisma.session.update({
      where: { id },
      data: { status: 'PAUSED', wipRef: `refs/loose/wip/${id}` },
    });
    const res = await w.owner.post(`/api/v1/sessions/${id}/resume`);
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect((await prisma.session.findUniqueOrThrow({ where: { id } })).controllerId).toBeNull();
  });

  it('demoting the active controller to viewer releases control', async () => {
    const w = await world();
    const id = await startRunning(w);
    await share(w, id, w.dev, 'CO_EDITOR');
    expect((await w.dev.post(`/api/v1/sessions/${id}/take-over`)).status).toBe(200);

    const demoted = await w.owner.post(`/api/v1/sessions/${id}/share`, {
      userId: w.dev.user.id,
      role: 'VIEWER',
    });
    expect(demoted.status, JSON.stringify(demoted.body)).toBe(201);
    expect((await prisma.session.findUniqueOrThrow({ where: { id } })).controllerId).toBeNull();
    expectError(
      await w.dev.post(`/api/v1/sessions/${id}/messages`, { content: 'still mine' }),
      'LSE-ORG-002',
      403,
    );
    expect(
      (await w.owner.post(`/api/v1/sessions/${id}/messages`, { content: 'mine again' })).status,
    ).toBe(202);
    await ctx.agent.idle(id);
  });

  it('losing the share also loses control', async () => {
    const w = await world();
    const id = await startRunning(w);
    await share(w, id, w.dev, 'CO_EDITOR');
    expect((await w.dev.post(`/api/v1/sessions/${id}/take-over`)).status).toBe(200);
    expect((await w.owner.delete(`/api/v1/sessions/${id}/share/${w.dev.user.id}`)).status).toBe(
      204,
    );
    expect((await prisma.session.findUniqueOrThrow({ where: { id } })).controllerId).toBeNull();
    expect(
      (await w.owner.post(`/api/v1/sessions/${id}/messages`, { content: 'mine again' })).status,
    ).toBe(202);
    await ctx.agent.idle(id);
  });
});

// ---- presence over the WebSocket -------------------------------------------------------------

describe('presence & live updates over /ws', () => {
  it('collaborators may join; presence carries roles, modes and the controller', async () => {
    const w = await world();
    const id = await startRunning(w);
    await share(w, id, w.dev, 'CO_EDITOR');
    await share(w, id, w.watcher, 'VIEWER');

    const ownerWs = await join(w.owner.cookie, id);
    expect(presenceOf(ownerWs)).toEqual([
      expect.objectContaining({ id: w.owner.user.id, role: 'owner', mode: 'SIMPLE' }),
    ]);

    const devWs = await join(w.dev.cookie, id);
    const watcherWs = await join(w.watcher.cookie, id);
    await ownerWs.next(
      (m) => m.type === 'presence' && (m.payload as { users: unknown[] }).users.length === 3,
      'three participants',
    );
    const roles = new Map(presenceOf(ownerWs).map((u) => [u.id, u.role] as const));
    expect(roles.get(w.owner.user.id)).toBe('owner');
    expect(roles.get(w.dev.user.id)).toBe('co_editor');
    expect(roles.get(w.watcher.user.id)).toBe('viewer');
    expect(presenceOf(ownerWs).every((u) => u.controller === false)).toBe(true);

    // Take-over is announced to everyone and marks the controller in presence.
    expect((await w.dev.post(`/api/v1/sessions/${id}/take-over`)).status).toBe(200);
    for (const c of [ownerWs, devWs, watcherWs]) {
      const msg = await c.next((m) => m.type === 'control_changed', 'control_changed');
      expect(msg.payload).toEqual({
        controllerId: w.dev.user.id,
        controllerName: 'Dev Dana',
        mode: 'PRO',
      });
    }
    await ownerWs.next(
      (m) =>
        m.type === 'presence' &&
        (m.payload as { users: PresenceUser[] }).users.some(
          (u) => u.id === w.dev.user.id && u.controller === true,
        ),
      'controller in presence',
    );

    // Leaving removes the user from everyone else's presence.
    watcherWs.send('leave_session', id, {});
    await ownerWs.next(
      (m) =>
        m.type === 'presence' &&
        !(m.payload as { users: PresenceUser[] }).users.some((u) => u.id === w.watcher.user.id),
      'watcher left',
    );
  });

  it('Simple/Pro filtering follows each viewer, not the session', async () => {
    const w = await world();
    const id = await startRunning(w);
    await share(w, id, w.dev, 'CO_EDITOR');
    await prisma.session.update({ where: { id }, data: { mode: 'PRO' } });
    // The co-editor is locked to Simple, the owner is not.
    await prisma.orgMember.update({
      where: { userId_orgId: { userId: w.dev.user.id, orgId: w.orgId } },
      data: { lockedMode: 'SIMPLE' },
    });
    await ctx.sessionEvents.publish(
      id,
      'tool_event',
      { id: 't1', name: 'Read', phase: 'start', input: { file_path: 'src/secret.ts' } },
      { audience: 'pro' },
    );
    const proWs = await join(w.owner.cookie, id);
    const simpleWs = await join(w.dev.cookie, id);
    await proWs.next((m) => m.type === 'tool_event', 'tool_event for Pro');
    expect(simpleWs.messages.map((m) => m.type)).not.toContain('tool_event');
    expect(JSON.stringify(simpleWs.messages)).not.toContain('src/secret.ts');
    await proWs.next(
      (m) =>
        m.type === 'presence' &&
        (m.payload as { users: PresenceUser[] }).users.some(
          (u) => u.id === w.dev.user.id && u.mode === 'SIMPLE',
        ),
      'co-editor shown in Simple',
    );
  });

  it('share_updated reaches participants and disconnects a revoked collaborator', async () => {
    const w = await world();
    const id = await startRunning(w);
    await share(w, id, w.watcher, 'VIEWER');
    const ownerWs = await join(w.owner.cookie, id);
    const watcherWs = await join(w.watcher.cookie, id);

    await share(w, id, w.dev, 'CO_EDITOR');
    // The join replays the earlier share too, so wait for the one that lists both.
    const update = await ownerWs.next(
      (m) =>
        m.type === 'share_updated' &&
        (m.payload as { collaborators: unknown[] }).collaborators.length === 2,
      'share_updated with two collaborators',
    );
    expect(
      (update.payload as { collaborators: { userId: string; role: string }[] }).collaborators.map(
        (c) => [c.userId, c.role],
      ),
    ).toEqual([
      [w.watcher.user.id, 'VIEWER'],
      [w.dev.user.id, 'CO_EDITOR'],
    ]);

    expect((await w.owner.delete(`/api/v1/sessions/${id}/share/${w.watcher.user.id}`)).status).toBe(
      204,
    );
    expect(await watcherWs.closed).toEqual({ code: 4403, reason: 'LSE-WS-002' });
    // The removed viewer never saw the list they were cut from.
    expect(
      watcherWs.messages
        .filter((m) => m.type === 'share_updated')
        .every((m) => (m.payload as { collaborators: unknown[] }).collaborators.length < 3),
    ).toBe(true);
    expect(ownerWs.ws.readyState).toBe(WebSocket.OPEN);
    expectError(await w.watcher.get(`/api/v1/sessions/${id}`), 'LSE-ORG-002', 403);
  });

  it('a non-participant org member still cannot join (LSE-WS-002 / 4403)', async () => {
    const w = await world();
    const id = await startRunning(w);
    const c = await connect(w.dev.cookie);
    c.send('join_session', id, {});
    expect(await c.closed).toEqual({ code: 4403, reason: 'LSE-WS-002' });
  });

  it('a VIEWER collaborator cannot send chat over the WebSocket', async () => {
    const w = await world();
    const id = await startRunning(w);
    await share(w, id, w.watcher, 'VIEWER');
    const c = await join(w.watcher.cookie, id);
    c.send('chat_message', id, { clientMessageId: 'v-1', content: 'let me in' });
    const err = await c.next((m) => m.type === 'error', 'error');
    expect((err.payload as { error: { code: string } }).error.code).toBe('LSE-ORG-002');
    expect(c.ws.readyState).toBe(WebSocket.OPEN);
  });

  it('while someone is in control, other participants get LSE-AGT-017 over the WebSocket', async () => {
    const w = await world();
    const id = await startRunning(w);
    await share(w, id, w.dev, 'CO_EDITOR');
    const ownerWs = await join(w.owner.cookie, id);
    expect((await w.dev.post(`/api/v1/sessions/${id}/take-over`)).status).toBe(200);
    await ownerWs.next((m) => m.type === 'control_changed', 'control_changed');
    ownerWs.send('chat_message', id, { clientMessageId: 'o-1', content: 'mine' });
    const err = await ownerWs.next((m) => m.type === 'error', 'error');
    expect((err.payload as { error: { code: string } }).error.code).toBe('LSE-AGT-017');
  });
});
