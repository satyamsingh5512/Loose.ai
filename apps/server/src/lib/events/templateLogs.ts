/**
 * Template build log buffer + live fan-out for the `template-logs` SSE stream.
 * Redis: capped list `tpl:<projectId>:logs` (TEMPLATE_LOG_MAX_LINES, 7 d TTL),
 * monotonic `tpl:<projectId>:seq`, pub/sub channel `tpl:<projectId>` so any API
 * instance can stream a build running in a worker. In-memory fallback for tests.
 * Lines are already secret-scrubbed by the caller.
 */
import {
  TEMPLATE_LOG_MAX_LINES,
  TEMPLATE_LOG_TTL_SEC,
  type TemplateLogLine,
  type TemplateStatusDto,
} from '@loose/shared';
import type { Logger } from '../logger';
import type { Redis } from '../redis';

export interface TemplateLogEntry extends TemplateLogLine {
  seq: number;
}

export type TemplateLogEvent =
  { type: 'log'; entry: TemplateLogEntry } | { type: 'status'; status: TemplateStatusDto };

export type TemplateLogListener = (e: TemplateLogEvent) => void;

export interface TemplateLogStore {
  append(projectId: string, line: TemplateLogLine): Promise<TemplateLogEntry>;
  read(projectId: string): Promise<TemplateLogEntry[]>;
  /** Clear buffered lines (start of a new build). Seq keeps increasing. */
  reset(projectId: string): Promise<void>;
  publishStatus(projectId: string, status: TemplateStatusDto): Promise<void>;
  subscribe(projectId: string, listener: TemplateLogListener): Promise<() => void>;
}

export class MemoryTemplateLogStore implements TemplateLogStore {
  readonly #lines = new Map<string, TemplateLogEntry[]>();
  readonly #seq = new Map<string, number>();
  readonly #listeners = new Map<string, Set<TemplateLogListener>>();

  #emit(projectId: string, e: TemplateLogEvent) {
    for (const l of this.#listeners.get(projectId) ?? []) l(e);
  }

  async append(projectId: string, line: TemplateLogLine) {
    const seq = (this.#seq.get(projectId) ?? 0) + 1;
    this.#seq.set(projectId, seq);
    const entry = { ...line, seq };
    const list = this.#lines.get(projectId) ?? [];
    list.push(entry);
    if (list.length > TEMPLATE_LOG_MAX_LINES) list.splice(0, list.length - TEMPLATE_LOG_MAX_LINES);
    this.#lines.set(projectId, list);
    this.#emit(projectId, { type: 'log', entry });
    return entry;
  }

  async read(projectId: string) {
    return [...(this.#lines.get(projectId) ?? [])];
  }

  async reset(projectId: string) {
    this.#lines.delete(projectId);
  }

  async publishStatus(projectId: string, status: TemplateStatusDto) {
    this.#emit(projectId, { type: 'status', status });
  }

  async subscribe(projectId: string, listener: TemplateLogListener) {
    let set = this.#listeners.get(projectId);
    if (!set) {
      set = new Set();
      this.#listeners.set(projectId, set);
    }
    set.add(listener);
    return () => {
      set.delete(listener);
    };
  }
}

export class RedisTemplateLogStore implements TemplateLogStore {
  #sub: Redis | null = null;
  readonly #listeners = new Map<string, Set<TemplateLogListener>>();

  constructor(
    private readonly redis: Redis,
    private readonly logger: Logger,
  ) {}

  #key = (p: string, k: 'logs' | 'seq') => `tpl:${p}:${k}`;
  #channel = (p: string) => `tpl:${p}`;

  async append(projectId: string, line: TemplateLogLine) {
    const seq = await this.redis.incr(this.#key(projectId, 'seq'));
    const entry = { ...line, seq };
    const json = JSON.stringify(entry);
    await this.redis
      .multi()
      .rpush(this.#key(projectId, 'logs'), json)
      .ltrim(this.#key(projectId, 'logs'), -TEMPLATE_LOG_MAX_LINES, -1)
      .expire(this.#key(projectId, 'logs'), TEMPLATE_LOG_TTL_SEC)
      .expire(this.#key(projectId, 'seq'), TEMPLATE_LOG_TTL_SEC)
      .publish(this.#channel(projectId), JSON.stringify({ type: 'log', entry }))
      .exec();
    return entry;
  }

  async read(projectId: string) {
    const rows = await this.redis.lrange(this.#key(projectId, 'logs'), 0, -1);
    return rows.flatMap((r) => {
      try {
        return [JSON.parse(r) as TemplateLogEntry];
      } catch {
        return [];
      }
    });
  }

  async reset(projectId: string) {
    await this.redis.del(this.#key(projectId, 'logs'));
  }

  async publishStatus(projectId: string, status: TemplateStatusDto) {
    await this.redis.publish(this.#channel(projectId), JSON.stringify({ type: 'status', status }));
  }

  async #subscriber(): Promise<Redis> {
    if (this.#sub) return this.#sub;
    const sub = this.redis.duplicate();
    sub.on('error', (err) =>
      this.logger.warn({ err: { message: err.message } }, 'template log subscriber error'),
    );
    sub.on('message', (channel: string, raw: string) => {
      const projectId = channel.slice('tpl:'.length);
      let evt: TemplateLogEvent;
      try {
        evt = JSON.parse(raw) as TemplateLogEvent;
      } catch {
        return;
      }
      for (const l of this.#listeners.get(projectId) ?? []) l(evt);
    });
    this.#sub = sub;
    return sub;
  }

  async subscribe(projectId: string, listener: TemplateLogListener) {
    const sub = await this.#subscriber();
    let set = this.#listeners.get(projectId);
    if (!set) {
      set = new Set();
      this.#listeners.set(projectId, set);
      await sub.subscribe(this.#channel(projectId));
    }
    set.add(listener);
    return () => {
      set.delete(listener);
      if (set.size === 0) {
        this.#listeners.delete(projectId);
        void sub.unsubscribe(this.#channel(projectId)).catch(() => undefined);
      }
    };
  }

  async close() {
    await this.#sub?.quit().catch(() => undefined);
  }
}
