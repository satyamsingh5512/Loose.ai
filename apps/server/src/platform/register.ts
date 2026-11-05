/**
 * Phase 9 platform wiring (FOUNDATION — frozen; owned modules plug in here).
 * Called once from `buildContext` in every process. Each `register*` function belongs to
 * one workstream (see phase9-design.md §11) and must be idempotent per context.
 *
 *  - webhooks.service (W1): platform events → WebhookDelivery rows → `webhook-delivery` jobs
 *  - runs.service     (W1): headless run driver (`session.*` events → prompt → PR)
 *  - collab.service   (W2): shared-session housekeeping
 *  - triggers.service (W4): `trigger-fire`, schedule ticks, `run.completed` post-backs
 * Phase 10 (phase10-design.md §10):
 *  - identity      (W1): SSO / SCIM / 2FA background wiring
 *  - governance    (W2): `data-export`, `retention-purge`, `deletion-sweep`
 *  - observability (W3): metric collectors, cross-instance presence / command forwarding
 */
import type { AppContext } from '../context';
import { registerCollabHandlers } from '../services/collab.service';
import { registerGovernance } from '../services/governance/register';
import { registerIdentity } from '../services/identity/register';
import { registerObservability } from '../services/observability/register';
import { registerRunsService } from '../services/runs.service';
import { registerTriggerHandlers } from '../services/triggers.service';
import { registerWebhookDelivery } from '../services/webhooks.service';

/** `api` serves HTTP/WS and hosts runners; `worker` runs background jobs only. */
export type PlatformRole = 'api' | 'worker';

/** Repeatable platform jobs live in lib/jobs.ts (`PLATFORM_SCHEDULES`, no import cycles). */
export { PLATFORM_SCHEDULES } from '../lib/jobs';

export function registerPlatform(ctx: AppContext): void {
  registerWebhookDelivery(ctx, ctx.platformRole);
  registerRunsService(ctx, ctx.platformRole);
  registerCollabHandlers(ctx, ctx.platformRole);
  registerTriggerHandlers(ctx, ctx.platformRole);
  registerIdentity(ctx, ctx.platformRole);
  registerGovernance(ctx, ctx.platformRole);
  registerObservability(ctx, ctx.platformRole);
}
