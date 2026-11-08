/**
 * Scheduled/cron trigger ticks (spec §8.15). Runs every minute (`PLATFORM_SCHEDULES`); claims
 * every enabled SCHEDULE trigger whose `nextRunAt` is due with a single `updateMany` (so two
 * processes racing on the same minute fire it at most once), fires it, then computes the next
 * run deterministically from the shared cron parser (no jitter: `nextCronRun` is pure).
 */
import { nextCronRun, type RunSource } from '@loose/shared';
import type { AppContext } from '../../context';
import { fireTrigger } from './fire';

interface ScheduleConfig {
  cron: string;
  timezone: string;
}

/** Claim due SCHEDULE triggers and fire each exactly once for this minute's slot. */
export async function scheduleTick(
  ctx: AppContext,
  now: Date = new Date(),
): Promise<{ fired: string[] }> {
  const due = await ctx.prisma.trigger.findMany({
    where: { kind: 'SCHEDULE', enabled: true, nextRunAt: { lte: now } },
    take: 200,
  });
  const fired: string[] = [];
  for (const trigger of due) {
    // Claim this slot: only a process that successfully moves nextRunAt forward fires it.
    const cfg = trigger.config as unknown as ScheduleConfig;
    const next = nextCronRun(cfg.cron, now, cfg.timezone);
    const claimed = await ctx.prisma.trigger.updateMany({
      where: { id: trigger.id, nextRunAt: trigger.nextRunAt },
      data: { nextRunAt: next },
    });
    if (claimed.count === 0) continue; // another process already claimed this slot

    const slotIso = (trigger.nextRunAt ?? now).toISOString();
    const r = await fireTrigger(ctx, trigger.id, {
      dedupeKey: `schedule:${slotIso}`,
      vars: { text: trigger.promptTemplate },
      source: 'SCHEDULE' satisfies RunSource,
      externalRef: { slot: slotIso },
    });
    if (r.runId || r.duplicate) fired.push(trigger.id);
  }
  return { fired };
}
