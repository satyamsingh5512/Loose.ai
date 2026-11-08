/**
 * The common "fire a trigger" path, split out of `triggers.service.ts` so the per-kind
 * inbound handlers (`triggers/github.ts` etc.) can call it without an import cycle
 * (`triggers.service.ts` imports the handlers for dispatch; the handlers call `fireTrigger`).
 */
import { DEFAULT_TRIGGER_PROMPTS, renderTriggerPrompt, type RunSource } from '@loose/shared';
import type { AppContext } from '../../context';
import { AppError } from '../../lib/errors';
import { createRun, type CreateRunInput } from '../runs.service';

export interface FireTriggerInput {
  dedupeKey: string;
  vars: Record<string, string>;
  externalRef?: Record<string, unknown>;
  source: RunSource;
  /** Override the derived options (PR-comment flow: fix on the PR's branch). */
  overrideOptions?: Partial<CreateRunInput['options']>;
}

/**
 * Dedupe by `(triggerId, dedupeKey)`, render the prompt, start the run as the trigger's
 * `runAsUser` (a token-less `Caller`, so `runs:write` is skipped) and record the outcome.
 * Never throws — preflight failures are recorded on `lastError` and surfaced as `runId: null`.
 */
export async function fireTrigger(
  ctx: AppContext,
  triggerId: string,
  input: FireTriggerInput,
): Promise<{ runId: string | null; duplicate: boolean }> {
  const trigger = await ctx.prisma.trigger.findUnique({ where: { id: triggerId } });
  if (!trigger || !trigger.enabled) return { runId: null, duplicate: false };

  let fire;
  try {
    fire = await ctx.prisma.triggerFire.create({
      data: { triggerId, dedupeKey: input.dedupeKey },
    });
  } catch (err) {
    if ((err as { code?: string }).code === 'P2002') return { runId: null, duplicate: true };
    throw err;
  }

  const template = trigger.promptTemplate || DEFAULT_TRIGGER_PROMPTS[trigger.kind];
  const prompt = renderTriggerPrompt(template, input.vars);
  const runAsUser = await ctx.prisma.user.findUnique({ where: { id: trigger.runAsUserId } });
  if (!runAsUser) {
    await ctx.prisma.triggerFire.update({ where: { id: fire.id }, data: {} });
    await ctx.prisma.trigger.update({
      where: { id: trigger.id },
      data: { lastError: 'LSE-NF-001: runAsUser no longer exists' },
    });
    return { runId: null, duplicate: false };
  }

  let runId: string | null = null;
  let lastError: string | null = null;
  try {
    const dto = await createRun(
      ctx,
      { user: runAsUser },
      {
        projectId: trigger.projectId,
        prompt,
        options: {
          createPr: trigger.createPr,
          draft: false,
          ...(trigger.model ? { model: trigger.model } : {}),
          mode: trigger.mode,
          ...input.overrideOptions,
        },
        source: input.source,
        triggerId: trigger.id,
        ...(input.externalRef ? { externalRef: input.externalRef } : {}),
      },
    );
    runId = dto.id;
  } catch (err) {
    lastError = err instanceof AppError ? err.code : 'LSE-SYS-001';
  }

  await ctx.prisma.triggerFire.update({ where: { id: fire.id }, data: { runId } });
  await ctx.prisma.trigger.update({
    where: { id: trigger.id },
    data: { lastFiredAt: new Date(), lastRunId: runId, lastError },
  });
  await ctx.audit.record({
    orgId: trigger.orgId,
    actorId: null,
    action: 'trigger.fire',
    target: trigger.id,
    meta: { source: input.source, runId, duplicate: false, ...(lastError ? { lastError } : {}) },
  });
  return { runId, duplicate: false };
}
