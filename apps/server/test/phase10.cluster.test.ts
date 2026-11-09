import { randomBytes } from 'node:crypto';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { buildClientMessage } from '@loose/shared';
import { ClusterCommandForwarder, SessionOwnerLease } from '../src/lib/events/cluster';
import { ClusterPresence } from '../src/lib/events/presence';
import { RedisSessionEventBus } from '../src/lib/events/sessionEventBus';
import { createLogger } from '../src/lib/logger';
import { createRedis, type Redis } from '../src/lib/redis';
import { createOrg, login, makeApp, resetDb, TEST_SECRETS, testPrisma } from './helpers';
import { createReadyProject } from './sessionHelpers';

const prisma = testPrisma();
const logger = createLogger({ level: 'silent' });
/** Must match the SESSION_SECRET of the test app context (cluster envelopes, P10-SEC-004). */
const CLUSTER_SECRET = TEST_SECRETS.SESSION_SECRET;
let redisA: Redis;
let redisB: Redis;

function eventually<T>(read: () => T | undefined, label: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const until = Date.now() + 3_000;
    const tick = () => {
      const value = read();
      if (value !== undefined) return resolve(value);
      if (Date.now() >= until) return reject(new Error(`timed out waiting for ${label}`));
      setTimeout(tick, 20);
    };
    tick();
  });
}

beforeEach(async () => {
  await resetDb();
  redisA = createRedis('redis://127.0.0.1:6379/15', logger);
  redisB = createRedis('redis://127.0.0.1:6379/15', logger);
});

afterAll(async () => {
  await redisA?.quit();
  await redisB?.quit();
  await prisma.$disconnect();
});

describe('Phase 10 cross-instance session routing', () => {
  it('fans out events and presence and forwards a control to the runner-owning instance', async () => {
    const eventsA = new RedisSessionEventBus(redisA, logger, {
      secret: CLUSTER_SECRET,
      instanceId: 'phase10-instance-a',
    });
    const eventsB = new RedisSessionEventBus(redisB, logger, {
      secret: CLUSTER_SECRET,
      instanceId: 'phase10-instance-b',
    });
    const a = makeApp({
      context: { redis: redisA, sessionEvents: eventsA, instanceId: 'phase10-instance-a' },
    });
    const b = makeApp({
      context: { redis: redisB, sessionEvents: eventsB, instanceId: 'phase10-instance-b' },
    });
    const client = await login(a.app, 'cluster-owner@example.com', 'Cluster Owner');
    const org = await createOrg(client, 'Cluster Org');
    const project = await createReadyProject(a.ctx, org.id);
    const sessionId = `ccluster${randomBytes(8).toString('hex')}`;
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

    const seenEvents: string[] = [];
    const offEvent = eventsB.subscribe(sessionId, (message) => seenEvents.push(message.type));
    await eventsB.ready?.(sessionId);
    await eventsA.publish(sessionId, 'session_status', {
      status: 'PAUSED',
      message: 'from instance A',
    });
    expect(
      await eventually(
        () => (seenEvents.includes('session_status') ? seenEvents : undefined),
        'event fan-out',
      ),
    ).toContain('session_status');

    const presenceA = new ClusterPresence(redisA, 'phase10-instance-a', logger, CLUSTER_SECRET);
    const presenceB = new ClusterPresence(redisB, 'phase10-instance-b', logger, CLUSTER_SECRET);
    let remotePresence: string[] | undefined;
    const offPresence = presenceB.subscribe(sessionId, () => {
      void presenceB.list(sessionId).then((users) => (remotePresence = users.map((u) => u.id)));
    });
    await presenceB.ready();
    await presenceA.join(sessionId, 'socket-a', {
      id: client.user.id,
      name: 'Cluster Owner',
      avatarUrl: null,
      role: 'owner',
      mode: 'SIMPLE',
      controller: false,
    });
    expect(await eventually(() => remotePresence, 'presence fan-out')).toEqual([client.user.id]);

    const authSession = await prisma.authSession.findFirstOrThrow({
      where: { userId: client.user.id },
    });
    const user = await prisma.user.findUniqueOrThrow({ where: { id: client.user.id } });
    const controls: string[] = [];
    const owner = new ClusterCommandForwarder(a.ctx, async (caller, message) => {
      controls.push(`${caller.user.id}:${message.type}`);
      return message.type === 'set_mode' ? message.payload.mode : undefined;
    });
    const peer = new ClusterCommandForwarder(b.ctx, async () => undefined);
    const lease = new SessionOwnerLease(redisA, a.ctx.instanceId, logger);
    try {
      await owner.start();
      await peer.start();
      await lease.claim(sessionId);
      const command = buildClientMessage('set_mode', sessionId, { mode: 'PRO' });
      const forwarded = await peer.forwardIfRemote({ user, authSession }, command);
      expect(forwarded).toEqual({ forwarded: true, value: 'PRO' });
      expect(controls).toEqual([`${client.user.id}:set_mode`]);
    } finally {
      offEvent();
      offPresence();
      await presenceA.leave(sessionId, 'socket-a');
      await presenceA.close();
      await presenceB.close();
      await owner.close();
      await peer.close();
      await lease.close();
      await eventsA.close();
      await eventsB.close();
      await a.ctx.agent.shutdownAll();
      await b.ctx.agent.shutdownAll();
    }
  });
});
