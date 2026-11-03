/**
 * Platform event bus (Phase 9): typed, in-process fan-out of business events — the source of
 * outbound webhooks (spec §8.15), headless-run progress and trigger post-backs.
 *
 * - Each event is emitted exactly once, in the process where it happened (API or worker).
 *   Every process registers the same subscribers (`registerPlatform`), and subscribers that
 *   need durability (webhook deliveries) persist + enqueue work, so no cross-process relay
 *   is required.
 * - `emit()` never throws and never rejects: listener failures are logged. It resolves after
 *   every listener finished, so tests are deterministic and callers may simply `await` it.
 * - Emitters must not depend on listeners (emission is fire-and-forget business-wise).
 *
 * Event ids (`evt_…`) are unique and stable: webhook deliveries use them as idempotency keys.
 */
import { randomBytes } from 'node:crypto';
import type {
  BudgetExceededData,
  PrCreatedData,
  RunStatus,
  SessionCompletedData,
  SessionErroredData,
  SessionStartedData,
  WebhookEventType,
  WebhookSession,
} from '@loose/shared';
import type { AppContext } from '../../context';
import type { Logger } from '../logger';

/** Internal (non-webhook) events. */
export interface TurnCompletedData {
  sessionId: string;
  projectId: string;
  userId: string;
  /** ASSISTANT chat message of the turn. */
  messageId: string;
  filesChanged: string[];
  errorCode: string | null;
  interrupted: boolean;
  /** Plan-mode turn: a plan awaits approval (nothing was changed yet). */
  planPending: boolean;
}

export interface RunCompletedData {
  runId: string;
  sessionId: string | null;
  projectId: string;
  triggerId: string | null;
  status: RunStatus;
  prUrl: string | null;
  prNumber: number | null;
  errorCode: string | null;
  summary: string | null;
  externalRef: Record<string, unknown> | null;
}

export type InternalEventType = 'session.turn_completed' | 'run.completed';
export type PlatformEventType = WebhookEventType | InternalEventType;

export interface PlatformEventMap {
  'session.started': SessionStartedData;
  'session.completed': SessionCompletedData;
  'session.errored': SessionErroredData;
  'pr.created': PrCreatedData;
  'budget.exceeded': BudgetExceededData;
  'session.turn_completed': TurnCompletedData;
  'run.completed': RunCompletedData;
}

export interface PlatformEvent<T extends PlatformEventType = PlatformEventType> {
  /** `evt_<random>` — unique; the webhook event id / idempotency key. */
  id: string;
  type: T;
  orgId: string;
  /** ISO-8601. */
  occurredAt: string;
  data: PlatformEventMap[T];
}

export type AnyPlatformEvent = { [K in PlatformEventType]: PlatformEvent<K> }[PlatformEventType];
export type PlatformListener<T extends PlatformEventType> = (
  event: PlatformEvent<T>,
) => void | Promise<void>;
export type AnyPlatformListener = (event: AnyPlatformEvent) => void | Promise<void>;

export function newEventId(): string {
  return `evt_${randomBytes(12).toString('hex')}`;
}

export class PlatformEventBus {
  readonly #listeners = new Map<PlatformEventType, Set<PlatformListener<PlatformEventType>>>();
  readonly #any = new Set<AnyPlatformListener>();
  readonly #history: AnyPlatformEvent[] = [];
  readonly #historySize: number;

  constructor(
    private readonly logger: Logger,
    opts: { historySize?: number } = {},
  ) {
    this.#historySize = opts.historySize ?? 200;
  }

  on<T extends PlatformEventType>(type: T, listener: PlatformListener<T>): () => void {
    let set = this.#listeners.get(type);
    if (!set) {
      set = new Set();
      this.#listeners.set(type, set);
    }
    const l = listener as unknown as PlatformListener<PlatformEventType>;
    set.add(l);
    return () => {
      set.delete(l);
    };
  }

  /** Listen to every event (webhook fan-out, debugging). */
  onAny(listener: AnyPlatformListener): () => void {
    this.#any.add(listener);
    return () => {
      this.#any.delete(listener);
    };
  }

  listenerCount(type?: PlatformEventType): number {
    if (!type) {
      let n = this.#any.size;
      for (const s of this.#listeners.values()) n += s.size;
      return n;
    }
    return (this.#listeners.get(type)?.size ?? 0) + this.#any.size;
  }

  async emit<T extends PlatformEventType>(
    type: T,
    orgId: string,
    data: PlatformEventMap[T],
  ): Promise<PlatformEvent<T>> {
    const event: PlatformEvent<T> = {
      id: newEventId(),
      type,
      orgId,
      occurredAt: new Date().toISOString(),
      data,
    };
    this.#history.push(event as unknown as AnyPlatformEvent);
    if (this.#history.length > this.#historySize) {
      this.#history.splice(0, this.#history.length - this.#historySize);
    }
    const listeners: ((e: AnyPlatformEvent) => void | Promise<void>)[] = [
      ...((this.#listeners.get(type) ?? []) as Iterable<AnyPlatformListener>),
      ...this.#any,
    ];
    const results = await Promise.allSettled(
      listeners.map(async (l) => l(event as unknown as AnyPlatformEvent)),
    );
    for (const r of results) {
      if (r.status === 'rejected') {
        this.logger.warn(
          { err: r.reason as unknown, event: type, eventId: event.id },
          'platform event listener failed',
        );
      }
    }
    return event;
  }

  /** Most recent events, oldest first (tests / debugging). */
  history(): AnyPlatformEvent[];
  history<T extends PlatformEventType>(type: T): PlatformEvent<T>[];
  history(type?: PlatformEventType): AnyPlatformEvent[] {
    return type ? this.#history.filter((e) => e.type === type) : [...this.#history];
  }

  clearHistory(): void {
    this.#history.length = 0;
  }
}

// ---- emit helpers (used at the emission points) ------------------------------------------

/** Web URL of a session. */
export function sessionWebUrl(ctx: Pick<AppContext, 'env'>, sessionId: string): string {
  return `${ctx.env.APP_URL.replace(/\/+$/, '')}/session/${sessionId}`;
}

/** Webhook-safe snapshot of a session (no secrets, no transcript). */
export async function sessionSnapshot(
  ctx: AppContext,
  sessionId: string,
): Promise<WebhookSession | null> {
  const s = await ctx.prisma.session.findUnique({
    where: { id: sessionId },
    include: {
      project: { select: { name: true, orgId: true } },
      run: { select: { id: true } },
    },
  });
  if (!s) return null;
  return {
    id: s.id,
    orgId: s.project.orgId,
    projectId: s.projectId,
    projectName: s.project.name,
    userId: s.userId,
    mode: s.mode,
    model: s.model,
    branchName: s.branchName,
    baseBranch: s.baseBranch,
    status: s.status,
    outcome: s.outcome,
    previewUrl: s.previewUrl,
    prUrl: s.prUrl,
    errorCode: s.errorCode,
    totalCostUsd: Number(s.totalCostUsd),
    parentSessionId: s.parentSessionId,
    runId: s.run?.id ?? null,
    url: sessionWebUrl(ctx, s.id),
    startedAt: s.startedAt?.toISOString() ?? null,
    endedAt: s.endedAt?.toISOString() ?? null,
  };
}

/** Wrap an emission so a failure (e.g. the snapshot query) never affects the caller. */
async function safely(ctx: AppContext, what: string, fn: () => Promise<unknown>): Promise<void> {
  try {
    await fn();
  } catch (err) {
    ctx.logger.warn({ err, event: what }, 'platform event emission failed');
  }
}

export async function emitSessionEvent(
  ctx: AppContext,
  type: 'session.started' | 'session.completed' | 'session.errored',
  sessionId: string,
  extra: { resumed?: boolean } = {},
): Promise<void> {
  await safely(ctx, type, async () => {
    const session = await sessionSnapshot(ctx, sessionId);
    if (!session) return;
    if (type === 'session.started') {
      await ctx.platformEvents.emit(type, session.orgId, {
        session,
        resumed: extra.resumed ?? false,
      });
    } else {
      await ctx.platformEvents.emit(type, session.orgId, { session });
    }
  });
}

export async function emitPrCreated(
  ctx: AppContext,
  sessionId: string,
  pr: { url: string; number: number; repo: string; head: string; base: string },
): Promise<void> {
  await safely(ctx, 'pr.created', async () => {
    const session = await sessionSnapshot(ctx, sessionId);
    if (!session) return;
    await ctx.platformEvents.emit('pr.created', session.orgId, { session, pr });
  });
}

export async function emitBudgetExceeded(
  ctx: AppContext,
  orgId: string,
  data: BudgetExceededData,
): Promise<void> {
  await safely(ctx, 'budget.exceeded', () =>
    ctx.platformEvents.emit('budget.exceeded', orgId, data),
  );
}

export async function emitTurnCompleted(
  ctx: AppContext,
  orgId: string,
  data: TurnCompletedData,
): Promise<void> {
  await safely(ctx, 'session.turn_completed', () =>
    ctx.platformEvents.emit('session.turn_completed', orgId, data),
  );
}
