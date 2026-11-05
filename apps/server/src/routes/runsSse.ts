/**
 * `GET /runs/:id/events` — Server-Sent Events for one run (spec §10.6; pattern of
 * `templateLogsSse.ts`).
 *
 *   event: status   RunDto on every change (no id)
 *   event: event    a session ServerMessage for the run's mode, `id:` = the session seq
 *   event: end      final RunDto, then the stream closes
 *   : ping          comment heartbeat every 15 s
 *
 * Resume: send `Last-Event-ID: <seq>` and the retained session events after that seq are replayed
 * (then a fresh `status`, then live). Status is pushed by the process that drives the run and also
 * polled from the DB, so a stream served by another API instance stays correct.
 */
import type { Request, Response } from 'express';
import { isTerminalRunStatus, RUN_SSE_HEARTBEAT_MS, type Mode, type RunDto } from '@loose/shared';
import type { AppContext } from '../context';
import { deliverableFor, type BusEntry } from '../lib/events/sessionEventBus';
import { getRun, subscribeRun } from '../services/runs.service';
import type { Caller } from '../services/sessionLifecycle.service';

/** How often the stream re-reads the run from the DB (cross-instance status changes). */
export const RUN_SSE_POLL_MS = 2_000;

export async function streamRunEvents(
  ctx: AppContext,
  caller: Caller,
  runId: string,
  req: Request,
  res: Response,
): Promise<void> {
  // Authorization (scope, org, owner/admin) happens before any byte is streamed.
  let current = await getRun(ctx, caller, runId);
  const sessionId = current.sessionId;
  const sessionRow = sessionId
    ? await ctx.prisma.session.findUnique({ where: { id: sessionId }, select: { mode: true } })
    : null;
  const mode: Mode = sessionRow?.mode ?? 'PRO';

  res.status(200);
  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const lastEventId = Number(req.get('last-event-id') ?? 0);
  let lastSeq = Number.isFinite(lastEventId) && lastEventId > 0 ? Math.floor(lastEventId) : 0;
  let closed = false;
  let replaying = true;
  const queued: BusEntry[] = [];
  const offs: (() => void)[] = [];
  let poll: NodeJS.Timeout | undefined;
  let lastStatusJson = '';

  const heartbeat = setInterval(() => {
    if (!closed) res.write(': ping\n\n');
  }, RUN_SSE_HEARTBEAT_MS);
  heartbeat.unref();

  const cleanup = () => {
    if (closed) return;
    closed = true;
    if (poll) clearInterval(poll);
    clearInterval(heartbeat);
    for (const off of offs.splice(0)) off();
  };
  const send = (event: string, data: unknown, id?: number) => {
    if (closed) return;
    res.write(
      `${id !== undefined ? `id: ${id}\n` : ''}event: ${event}\ndata: ${JSON.stringify(data)}\n\n`,
    );
  };
  const sendEntry = (entry: BusEntry) => {
    const seq = entry.message.seq;
    if (seq <= lastSeq) return;
    lastSeq = seq;
    const m = deliverableFor(entry, mode);
    if (m) send('event', m, seq);
  };
  const sendStatus = (run: RunDto) => {
    const json = JSON.stringify(run);
    if (json === lastStatusJson) return;
    lastStatusJson = json;
    current = run;
    send('status', run);
  };
  /** Flush session events up to now, so `end` never overtakes the last events. */
  const drain = async () => {
    if (!sessionId) return;
    const { entries } = await ctx.sessionEvents.replay(sessionId, lastSeq);
    for (const e of entries) sendEntry(e);
  };
  let finishing = false;
  const finish = async (run: RunDto) => {
    if (closed || finishing) return;
    finishing = true;
    try {
      await drain();
    } catch (err) {
      ctx.logger.warn({ err, runId }, 'run stream drain failed');
    }
    sendStatus(run);
    send('end', run);
    cleanup();
    res.end();
  };
  const refresh = async () => {
    if (closed || finishing) return;
    try {
      const run = await getRun(ctx, caller, runId);
      sendStatus(run);
      if (isTerminalRunStatus(run.status)) await finish(run);
    } catch (err) {
      ctx.logger.warn({ err, runId }, 'run stream refresh failed');
    }
  };

  req.on('close', cleanup);

  try {
    // Subscribe before replaying so nothing falls in the gap (dedupe by seq).
    if (sessionId) {
      offs.push(
        ctx.sessionEvents.subscribe(sessionId, (message, audience) => {
          const entry = { message, audience };
          if (replaying) queued.push(entry);
          else sendEntry(entry);
        }),
      );
      await ctx.sessionEvents.ready?.(sessionId);
    }
    offs.push(
      subscribeRun(
        ctx,
        runId,
        (e) => {
          if (e.kind === 'status') {
            sendStatus(e.run);
            if (isTerminalRunStatus(e.run.status)) void finish(e.run);
          }
        },
        { events: false },
      ),
    );
    await drain();
    replaying = false;
    for (const e of queued.splice(0)) sendEntry(e);
    // The first status always goes out (a resumed client wants the current state).
    sendStatus(await getRun(ctx, caller, runId));
    if (isTerminalRunStatus(current.status)) {
      await finish(current);
      return;
    }
    poll = setInterval(() => void refresh(), RUN_SSE_POLL_MS);
    poll.unref();
  } catch (err) {
    ctx.logger.warn({ err, runId }, 'run event stream failed');
    cleanup();
    if (!res.writableEnded) res.end();
  }
}
