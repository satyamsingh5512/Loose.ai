/** `/users/me` profile, BYOK keys and personal API tokens (spec §10.1). */
import { Router } from 'express';
import {
  createApiKeyBodySchema,
  createApiTokenBodySchema,
  resourceIdParamsSchema,
  updateMeBodySchema,
  updateUserMemoryBodySchema,
  type CreateApiKeyBody,
  type CreateApiTokenBody,
  type UpdateMeBody,
} from '@loose/shared';
import type { AppContext } from '../context';
import { idempotency } from '../middleware/idempotency';
import type { RateLimiters } from '../middleware/rateLimit';
import { requireAuth } from '../middleware/requireAuth';
import { authUser } from '../middleware/requireOrg';
import { validate } from '../middleware/validate';
import {
  createApiKey,
  deleteApiKey,
  listApiKeys,
  revalidateApiKey,
} from '../services/apiKey.service';
import { listMyMcpServers } from '../services/extensions.service';
import { getUserMemory, updateUserMemory } from '../services/memory.service';
import { createToken, deleteToken, listTokens } from '../services/token.service';
import { getUserDto, updateMe } from '../services/user.service';

export function usersRouter(ctx: AppContext, limiters: RateLimiters): Router {
  const r = Router();
  const idParams = validate({ params: resourceIdParamsSchema });
  // Key & token management is session-only: a leaked PAT must not mint more credentials.
  const sessionOnly = requireAuth(ctx, { allowToken: false });

  r.get('/me', requireAuth(ctx), async (req, res) => {
    // Phase 10: `session` fills `mfaRequired` (this session still needs the 2FA challenge).
    res.json({ data: await getUserDto(ctx, authUser(req).id, { session: req.auth?.session }) });
  });

  r.put('/me', sessionOnly, validate({ body: updateMeBodySchema }), async (req, res) => {
    res.json({ data: await updateMe(ctx, authUser(req).id, req.body as UpdateMeBody) });
  });

  // ---- BYOK keys ------------------------------------------------------------------
  // Personal memory (spec §8.10) and personal MCP connections (§10.4.1).
  r.get('/me/memory', sessionOnly, async (req, res) => {
    res.json({ data: await getUserMemory(ctx, authUser(req).id) });
  });
  r.put(
    '/me/memory',
    sessionOnly,
    validate({ body: updateUserMemoryBodySchema }),
    async (req, res) => {
      const memory = (req.body as { memory: string | null }).memory;
      res.json({ data: await updateUserMemory(ctx, authUser(req).id, memory) });
    },
  );
  r.get('/me/mcp-servers', sessionOnly, async (req, res) => {
    res.json({ data: await listMyMcpServers(ctx, authUser(req).id), nextCursor: null });
  });

  r.get('/me/api-keys', sessionOnly, async (req, res) => {
    res.json({ data: await listApiKeys(ctx, authUser(req).id), nextCursor: null });
  });

  r.post(
    '/me/api-keys',
    sessionOnly,
    limiters.keyValidation,
    idempotency(ctx),
    validate({ body: createApiKeyBodySchema }),
    async (req, res) => {
      const dto = await createApiKey(ctx, authUser(req).id, req.body as CreateApiKeyBody, req.ip);
      res.status(201).json({ data: dto });
    },
  );

  r.post(
    '/me/api-keys/:id/revalidate',
    sessionOnly,
    limiters.keyValidation,
    idParams,
    async (req, res) => {
      res.json({
        data: await revalidateApiKey(ctx, authUser(req).id, req.params.id as string, req.ip),
      });
    },
  );

  r.delete('/me/api-keys/:id', sessionOnly, idParams, async (req, res) => {
    await deleteApiKey(ctx, authUser(req).id, req.params.id as string, req.ip);
    res.status(204).end();
  });

  // ---- personal API tokens ----------------------------------------------------------
  r.get('/me/tokens', sessionOnly, async (req, res) => {
    res.json({ data: await listTokens(ctx, authUser(req).id), nextCursor: null });
  });

  r.post(
    '/me/tokens',
    sessionOnly,
    idempotency(ctx),
    validate({ body: createApiTokenBodySchema }),
    async (req, res) => {
      const dto = await createToken(
        ctx,
        authUser(req).id,
        req.body as CreateApiTokenBody,
        req.ip,
        req.auth?.session,
      );
      res.status(201).json({ data: dto });
    },
  );

  r.delete('/me/tokens/:id', sessionOnly, idParams, async (req, res) => {
    await deleteToken(ctx, authUser(req).id, req.params.id as string, req.ip);
    res.status(204).end();
  });

  return r;
}
