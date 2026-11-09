/** Redis template log store + Redis session event bus against a real Redis (db 15), plus the in-memory bus. */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { TEMPLATE_LOG_MAX_LINES, type TemplateStatusDto } from '@loose/shared';
import {
  deliverableFor,
  InMemorySessionEventBus,
  RedisSessionEventBus,
  type EventAudience,
} from '../src/lib/events/sessionEventBus';
import { RedisTemplateLogStore, type TemplateLogEvent } from '../src/lib/events/templateLogs';
import { createLogger } from '../src/lib/logger';
import { createRedis, type Redis } from '../src/lib/redis';

const logger = createLogger({ level: 'silent' });
let redis: Redis;
let store: RedisTemplateLogStore;
const pid = `ptest${Date.now().toString(36)}`;

beforeAll(async () => {
  redis = createRedis('redis://127.0.0.1:6379/15', logger);
  store = new RedisTemplateLogStore(redis, logger);
});
afterAll(async () => {
  await redis.del(`tpl:${pid}:logs`, `tpl:${pid}:seq`, `sess:${pid}:events`, `sess:${pid}:seq`);
  await store.close();
  await redis.quit();
});

const line = (l: string) => ({ ts: new Date().toISOString(), stream: 'stdout' as const, line: l });

describe('RedisTemplateLogStore', () => {
  it('buffers with monotonic seq, caps the list, sets a TTL and fans out live events', async () => {
    const seen: TemplateLogEvent[] = [];
    const unsubscribe = await store.subscribe(pid, (e) => seen.push(e));
    const a = await store.append(pid, line('first'));
    const b = await store.append(pid, line('second'));
    expect(b.seq).toBe(a.seq + 1);
    const status = { status: 'READY', version: 1, templateId: 't' } as TemplateStatusDto;
    await store.publishStatus(pid, status);
    for (let i = 0; i < 50 && seen.length < 3; i += 1) await new Promise((r) => setTimeout(r, 20));
    expect(seen.map((e) => e.type)).toEqual(['log', 'log', 'status']);
    unsubscribe();

    expect((await store.read(pid)).map((l) => l.line)).toEqual(['first', 'second']);
    expect(await redis.ttl(`tpl:${pid}:logs`)).toBeGreaterThan(0);
    await store.reset(pid);
    expect(await store.read(pid)).toEqual([]);
    const c = await store.append(pid, line('after reset'));
    expect(c.seq).toBeGreaterThan(b.seq); // Last-Event-ID stays meaningful
    expect(TEMPLATE_LOG_MAX_LINES).toBe(2000);
  });
});

describe('InMemorySessionEventBus', () => {
  it('assigns per-session seq, validates payloads, replays and reports gaps', async () => {
    const bus = new InMemorySessionEventBus(3);
    const got: number[] = [];
    const off = bus.subscribe('s1', (m) => got.push(m.seq));
    for (let i = 0; i < 5; i += 1) {
      await bus.publish('s1', 'session_status', { status: 'STARTING', message: `step ${i}` });
    }
    await bus.publish('s2', 'pong', {});
    off();
    expect(got).toEqual([1, 2, 3, 4, 5]);
    expect(await bus.lastSeq('s1')).toBe(5);
    expect(await bus.lastSeq('s2')).toBe(1);
    const r = await bus.replay('s1', 3);
    expect(r).toMatchObject({ complete: true, lastSeq: 5 });
    expect(r.events.map((e) => e.seq)).toEqual([4, 5]);
    expect((await bus.replay('s1', 1)).complete).toBe(false); // seq 2 was evicted (cap 3)
    await expect(
      bus.publish('s1', 'session_status', { status: 'NOPE' as 'RUNNING', message: 'x' }),
    ).rejects.toThrow();
  });
});

describe('RedisSessionEventBus', () => {
  it('INCR seq, capped list with TTL, pub/sub fan-out across instances, audiences, gaps', async () => {
    // P10-SEC-004: both instances share the deployment's signing secret.
    const opts = { maxEvents: 3, secret: 'test-session-secret-at-least-32-chars!!' };
    const a = new RedisSessionEventBus(redis, logger, { ...opts, instanceId: 'bus-a' });
    const b = new RedisSessionEventBus(redis, logger, { ...opts, instanceId: 'bus-b' }); // 2nd API instance
    const seen: [number, EventAudience][] = [];
    const off = b.subscribe(pid, (m, aud) => seen.push([m.seq, aud]));
    await b.ready(pid);
    await a.publish(pid, 'session_status', { status: 'RUNNING', message: 'one' });
    await a.publish(
      pid,
      'tool_event',
      { id: 't', name: 'Read', phase: 'start' },
      { audience: 'pro' },
    );
    await a.publish(
      pid,
      'agent_status',
      { state: 'reading', label: 'Looking…' },
      { audience: 'simple' },
    );
    await a.publish(pid, 'pong', {});
    for (let i = 0; i < 50 && seen.length < 4; i += 1) await new Promise((r) => setTimeout(r, 20));
    off();
    expect(seen).toEqual([
      [1, 'all'],
      [2, 'pro'],
      [3, 'simple'],
      [4, 'all'],
    ]);
    expect(await a.lastSeq(pid)).toBe(4);
    expect(await redis.ttl(`sess:${pid}:events`)).toBeGreaterThan(0);
    const r = await b.replay(pid, 1);
    expect(r).toMatchObject({ complete: true, lastSeq: 4 });
    expect(r.entries.map((e) => [e.message.seq, e.audience])).toEqual([
      [2, 'pro'],
      [3, 'simple'],
      [4, 'all'],
    ]);
    expect((await b.replay(pid, 0)).complete).toBe(false); // seq 1 evicted (cap 3)
    const [pro, simple] = [r.entries[0]!, r.entries[1]!];
    expect(deliverableFor(pro, 'SIMPLE')).toBeNull();
    expect(deliverableFor(pro, 'PRO')?.type).toBe('tool_event');
    expect(deliverableFor(simple, 'PRO')).toBeNull();
    await a.clear(pid);
    expect((await a.replay(pid, 4)).events).toEqual([]);
    await Promise.all([a.close(), b.close()]);
  });
});
