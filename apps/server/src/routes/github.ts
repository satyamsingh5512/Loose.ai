/** GitHub routes (spec §10.3). */
import { createHmac, timingSafeEqual } from 'node:crypto';
import { Router, type RequestHandler } from 'express';
import {
  githubRepoParamsSchema,
  githubReposQuerySchema,
  type GithubReposQuery,
} from '@loose/shared';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';
import { requireAuth } from '../middleware/requireAuth';
import { authUser } from '../middleware/requireOrg';
import { queryOf, validate } from '../middleware/validate';
import { handlePullRequestEvent } from '../services/delivery.service';
import { getRepo, listRepos } from '../services/github.service';
import { handleGithubTriggerEvent } from '../services/triggers.service';

export function githubRouter(ctx: AppContext): Router {
  const r = Router();

  r.get(
    '/repos',
    requireAuth(ctx),
    validate({ query: githubReposQuerySchema }),
    async (req, res) => {
      const q = queryOf<GithubReposQuery>(req);
      const page = q.cursor ? Number(q.cursor) : 1;
      res.json(await listRepos(ctx, authUser(req).id, { page, perPage: q.limit, q: q.q }));
    },
  );

  r.get(
    '/repos/:owner/:repo',
    requireAuth(ctx),
    validate({ params: githubRepoParamsSchema }),
    async (req, res) => {
      const { owner, repo } = req.params as { owner: string; repo: string };
      res.json({ data: await getRepo(ctx, authUser(req).id, owner, repo) });
    },
  );

  return r;
}

/** Constant-time check of `x-hub-signature-256: sha256=<hex>` over the raw body. */
export function verifyGithubSignature(
  secret: string,
  rawBody: Buffer,
  header: string | undefined,
): boolean {
  if (!header?.startsWith('sha256=')) return false;
  const given = Buffer.from(header.slice('sha256='.length), 'hex');
  const expected = createHmac('sha256', secret).update(rawBody).digest();
  return given.length === expected.length && timingSafeEqual(given, expected);
}

/** A GitHub delivery id is retried verbatim; dedupe it for a day regardless of the event type. */
const deliveryKey = (deliveryId: string): string => `gh-delivery:${deliveryId}`;

async function isDuplicateDelivery(
  ctx: AppContext,
  deliveryId: string | undefined,
): Promise<boolean> {
  if (!deliveryId) return false;
  try {
    const acquired = await ctx.kv.setIfAbsent(deliveryKey(deliveryId), '1', 86_400);
    return !acquired;
  } catch {
    return false; // KV unavailable: fail open (per-trigger dedupeKey still protects runs)
  }
}

async function releaseDelivery(ctx: AppContext, deliveryId: string | undefined): Promise<void> {
  if (!deliveryId) return;
  await ctx.kv.del(deliveryKey(deliveryId)).catch(() => undefined);
}

/**
 * Inbound webhook. Mounted with express.raw() BEFORE the JSON parser and CSRF
 * check so the signature is computed over the exact bytes GitHub sent.
 * Valid → 202. `pull_request` closed/merged events update the matching session;
 * `issues` / `issue_comment` events are dispatched to the automation triggers (spec §8.15).
 */
export function githubWebhookHandler(ctx: AppContext): RequestHandler {
  return async (req, res) => {
    const secret = ctx.env.GITHUB_WEBHOOK_SECRET;
    const raw = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
    if (!secret) {
      throw new AppError('LSE-GH-014', { devMessage: 'GITHUB_WEBHOOK_SECRET is not configured' });
    }
    if (!verifyGithubSignature(secret, raw, req.get('x-hub-signature-256'))) {
      throw new AppError('LSE-GH-014', { devMessage: 'x-hub-signature-256 mismatch' });
    }
    const event = req.get('x-github-event');
    const deliveryId = req.get('x-github-delivery');
    ctx.logger.info(
      { requestId: req.requestId, event, delivery: deliveryId },
      'github webhook accepted',
    );

    if (await isDuplicateDelivery(ctx, deliveryId)) {
      res.status(202).json({ data: { received: true, handled: false, duplicate: true } });
      return;
    }

    let handled = false;
    if (event === 'pull_request') {
      try {
        handled = await handlePullRequestEvent(ctx, JSON.parse(raw.toString('utf8')) as object);
      } catch (err) {
        await releaseDelivery(ctx, deliveryId);
        ctx.logger.warn(
          { err: { message: (err as Error).message } },
          'pull_request webhook failed',
        );
      }
    } else if (event === 'issues' || event === 'issue_comment') {
      try {
        handled = await handleGithubTriggerEvent(
          ctx,
          event,
          deliveryId,
          JSON.parse(raw.toString('utf8')) as unknown,
        );
      } catch (err) {
        await releaseDelivery(ctx, deliveryId);
        ctx.logger.warn({ err: { message: (err as Error).message } }, `${event} webhook failed`);
      }
    }
    res.status(202).json({ data: { received: true, handled } });
  };
}
