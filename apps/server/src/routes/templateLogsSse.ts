/**
 * `GET …/projects/:projectId/template-logs` — Server-Sent Events (spec §7.2 step 8).
 * Replays the buffered lines (honouring `Last-Event-ID`), sends the current
 * `status`, then streams live lines until the build leaves BUILDING (`end`).
 * Events: `log` {ts, stream, line} (id = line seq), `status` TemplateStatusDto, `end` {}.
 */
import type { Request, Response } from 'express';
import type { AppContext } from '../context';
import type { TemplateLogEvent } from '../lib/events/templateLogs';
import { toTemplateStatusDto } from '../services/template.service';

export const SSE_HEARTBEAT_MS = 15_000;

export async function streamTemplateLogs(
  ctx: AppContext,
  projectId: string,
  req: Request,
  res: Response,
): Promise<void> {
  res.status(200);
  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const lastEventId = Number(req.get('last-event-id') ?? 0);
  let lastSent = Number.isFinite(lastEventId) && lastEventId > 0 ? lastEventId : 0;
  let closed = false;
  let replaying = true;
  const queued: TemplateLogEvent[] = [];
  let unsubscribe: (() => void) | undefined;

  const cleanup = () => {
    if (closed) return;
    closed = true;
    clearInterval(heartbeat);
    unsubscribe?.();
  };
  const send = (event: string, data: unknown, id?: number) => {
    if (closed) return;
    res.write(
      `${id !== undefined ? `id: ${id}\n` : ''}event: ${event}\ndata: ${JSON.stringify(data)}\n\n`,
    );
  };
  const finish = () => {
    if (closed) return;
    send('end', {});
    cleanup();
    res.end();
  };
  const handle = (e: TemplateLogEvent) => {
    if (e.type === 'log') {
      if (e.entry.seq <= lastSent) return;
      lastSent = e.entry.seq;
      send('log', { ts: e.entry.ts, stream: e.entry.stream, line: e.entry.line }, e.entry.seq);
      return;
    }
    send('status', e.status);
    if (e.status.status !== 'BUILDING') finish();
  };

  const heartbeat = setInterval(() => {
    if (!closed) res.write(': ping\n\n');
  }, SSE_HEARTBEAT_MS);
  heartbeat.unref();
  req.on('close', cleanup);

  try {
    // Subscribe before reading the buffer so no line falls in between (dedupe by seq).
    unsubscribe = await ctx.templateLogs.subscribe(projectId, (e) => {
      if (replaying) queued.push(e);
      else handle(e);
    });
    for (const entry of await ctx.templateLogs.read(projectId)) handle({ type: 'log', entry });
    const project = await ctx.prisma.project.findUnique({ where: { id: projectId } });
    if (!project) return finish();
    const status = toTemplateStatusDto(project);
    send('status', status);
    replaying = false;
    for (const e of queued.splice(0)) handle(e);
    if (status.status !== 'BUILDING') finish();
  } catch (err) {
    ctx.logger.warn({ err, projectId }, 'template log stream failed');
    send('error', { code: 'LSE-SYS-003' });
    cleanup();
    res.end();
  }
}
