/**
 * Background jobs (spec §16.4 "Job queue"). Two runners behind one interface:
 * - InlineJobRunner (JOBS_INLINE=true; dev/test): runs handlers in-process,
 *   schedules repeatables with timers. Tests await `onIdle()`.
 * - BullJobRunner (production): BullMQ queues on Redis. The API process only
 *   enqueues; `src/worker.ts` runs the workers and repeatable schedulers.
 * Every handler is also a plain async function callable directly (tests, CLI).
 */
import { Queue, Worker, type ConnectionOptions } from 'bullmq';
import { Redis } from 'ioredis';
import type { Logger } from './logger';

export const QUEUE_NAMES = [
  'template-builds',
  'session-provision',
  'cleanup-sandboxes',
  'orphan-reconciliation',
  'session-idle-check',
  'key-health-check',
  'usage-rollup',
  'approval-expiry',
  // ---- Phase 9 (platform) ----
  /** One webhook delivery attempt `{deliveryId}` (W1). */
  'webhook-delivery',
  /** Repeatable: re-enqueue overdue deliveries, prune old ones (W1). */
  'webhook-sweep',
  /** Repeatable: re-attach / time out headless run drivers (W1). */
  'runs-reconcile',
  /** Process one inbound trigger event `{triggerId, …}` (W4). */
  'trigger-fire',
  /** Repeatable: fire due schedule triggers (W4). */
  'trigger-schedule-tick',
  // ---- Phase 10 (hardening & GA; phase10-design.md §5.3) ----
  /** Build one GDPR/DPDP export `{exportId}` (W2). */
  'data-export',
  /** Repeatable (daily): purge data past each org's retention (W2). */
  'retention-purge',
  /** Repeatable (hourly): execute due account/org deletions, expire exports (W2). */
  'deletion-sweep',
] as const;
export type QueueName = (typeof QUEUE_NAMES)[number];

export type JobData = Record<string, unknown>;
export type JobHandler = (data: JobData) => Promise<void>;

export interface EnqueueOptions {
  /** Dedupe: a job with the same id that is queued/running is not added again. */
  jobId?: string;
  delayMs?: number;
  attempts?: number;
}

export interface RepeatableJob {
  queue: QueueName;
  everyMs: number;
}

/** Repeatable Phase 9 jobs (merged into MAINTENANCE_SCHEDULES). */
export const PLATFORM_SCHEDULES: readonly RepeatableJob[] = Object.freeze([
  { queue: 'webhook-sweep', everyMs: 60_000 },
  { queue: 'runs-reconcile', everyMs: 60_000 },
  { queue: 'trigger-schedule-tick', everyMs: 60_000 },
]);

const HOUR_MS = 60 * 60_000;

/** Repeatable Phase 10 jobs (merged into MAINTENANCE_SCHEDULES). */
export const HARDENING_SCHEDULES: readonly RepeatableJob[] = Object.freeze([
  { queue: 'retention-purge', everyMs: 24 * HOUR_MS },
  { queue: 'deletion-sweep', everyMs: HOUR_MS },
]);

export interface JobRunner {
  readonly inline: boolean;
  register(queue: QueueName, handler: JobHandler): void;
  enqueue(queue: QueueName, data: JobData, opts?: EnqueueOptions): Promise<void>;
  /** Start repeatable schedules (and, for BullMQ, the workers). Worker processes only. */
  start(schedules: readonly RepeatableJob[]): Promise<void>;
  /** Resolves when no inline job is running (BullMQ: immediately). */
  onIdle(): Promise<void>;
  close(): Promise<void>;
}

export class InlineJobRunner implements JobRunner {
  readonly inline = true;
  readonly #handlers = new Map<QueueName, JobHandler>();
  readonly #running = new Set<Promise<void>>();
  readonly #ids = new Set<string>();
  readonly #timers = new Set<NodeJS.Timeout>();
  #closed = false;

  constructor(private readonly logger: Logger) {}

  register(queue: QueueName, handler: JobHandler) {
    this.#handlers.set(queue, handler);
  }

  #run(queue: QueueName, data: JobData, jobId?: string) {
    const handler = this.#handlers.get(queue);
    if (!handler || this.#closed) return;
    if (jobId) this.#ids.add(jobId);
    const p = (async () => {
      await Promise.resolve(); // never run synchronously inside the caller
      try {
        await handler(data);
      } catch (err) {
        this.logger.error({ err, queue }, 'inline job failed');
      }
    })().finally(() => {
      this.#running.delete(p);
      if (jobId) this.#ids.delete(jobId);
    });
    this.#running.add(p);
  }

  async enqueue(queue: QueueName, data: JobData, opts: EnqueueOptions = {}) {
    if (opts.jobId && this.#ids.has(opts.jobId)) return;
    if (opts.delayMs && opts.delayMs > 0) {
      const t = setTimeout(() => {
        this.#timers.delete(t);
        this.#run(queue, data, opts.jobId);
      }, opts.delayMs);
      t.unref();
      this.#timers.add(t);
      return;
    }
    this.#run(queue, data, opts.jobId);
  }

  async start(schedules: readonly RepeatableJob[]) {
    for (const s of schedules) {
      const t = setInterval(() => {
        if (!this.#ids.has(`repeat:${s.queue}`)) this.#run(s.queue, {}, `repeat:${s.queue}`);
      }, s.everyMs);
      t.unref();
      this.#timers.add(t);
    }
  }

  async onIdle() {
    while (this.#running.size > 0) await Promise.allSettled([...this.#running]);
  }

  async close() {
    this.#closed = true;
    for (const t of this.#timers) {
      clearTimeout(t);
      clearInterval(t);
    }
    this.#timers.clear();
    await this.onIdle();
  }
}

export class BullJobRunner implements JobRunner {
  readonly inline = false;
  readonly #handlers = new Map<QueueName, JobHandler>();
  readonly #queues = new Map<QueueName, Queue>();
  readonly #workers: Worker[] = [];
  readonly #connection: Redis;

  constructor(
    redisUrl: string,
    private readonly logger: Logger,
  ) {
    // BullMQ requires maxRetriesPerRequest: null on its connection.
    this.#connection = new Redis(redisUrl, { maxRetriesPerRequest: null });
    this.#connection.on('error', (err) =>
      logger.warn({ err: { message: err.message } }, 'bullmq redis error'),
    );
  }

  get #conn(): ConnectionOptions {
    return this.#connection;
  }

  #queue(name: QueueName) {
    let q = this.#queues.get(name);
    if (!q) {
      q = new Queue(name, { connection: this.#conn });
      this.#queues.set(name, q);
    }
    return q;
  }

  register(queue: QueueName, handler: JobHandler) {
    this.#handlers.set(queue, handler);
  }

  async enqueue(queue: QueueName, data: JobData, opts: EnqueueOptions = {}) {
    await this.#queue(queue).add(queue, data, {
      ...(opts.jobId ? { jobId: opts.jobId } : {}),
      ...(opts.delayMs ? { delay: opts.delayMs } : {}),
      attempts: opts.attempts ?? 1,
      backoff: { type: 'exponential', delay: 1000 },
      removeOnComplete: 1000,
      // Failed jobs are kept (dead-letter set) for inspection/alerting.
      removeOnFail: 5000,
    });
  }

  async start(schedules: readonly RepeatableJob[]) {
    for (const [name, handler] of this.#handlers) {
      const w = new Worker(name, async (job) => handler((job.data ?? {}) as JobData), {
        connection: this.#conn,
        concurrency: name === 'template-builds' ? 2 : 5,
      });
      w.on('failed', (job, err) =>
        this.logger.error({ err, queue: name, jobId: job?.id }, 'job failed'),
      );
      this.#workers.push(w);
    }
    for (const s of schedules) {
      await this.#queue(s.queue).upsertJobScheduler(
        s.queue,
        { every: s.everyMs },
        { name: s.queue, data: {} },
      );
    }
  }

  async onIdle() {}

  async close() {
    await Promise.allSettled(this.#workers.map((w) => w.close()));
    await Promise.allSettled([...this.#queues.values()].map((q) => q.close()));
    await this.#connection.quit().catch(() => undefined);
  }
}
