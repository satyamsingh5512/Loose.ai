/**
 * Agent sessions (spec §10.5; Phases 4–6). Access: the session owner or an org
 * ADMIN+ ("participants"); other org members get LSE-ORG-002, everyone else
 * LSE-NF-001. API tokens need `sessions:read` (GET) / `sessions:write` (POST).
 * Viewers can read but never act (messages, approvals, delivery → LSE-ORG-002).
 */
import express, { Router, type Request, type RequestHandler } from 'express';
import {
  approvalDecisionBodySchema,
  approvalParamsSchema,
  addSessionNoteBodySchema,
  artifactParamsSchema,
  ATTACHMENT_FILE_NAME_HEADER,
  ATTACHMENT_MIME_TYPES,
  attachmentFileNameSchema,
  checkpointParamsSchema,
  collaboratorParamsSchema,
  commitToMainBodySchema,
  createPrBodySchema,
  forkSessionBodySchema,
  inspectBodySchema,
  MAX_ATTACHMENT_BYTES,
  paginationQuerySchema,
  rewindBodySchema,
  runCommandBodySchema,
  sendMessageBodySchema,
  sessionIdParamsSchema,
  shareSessionBodySchema,
  startSessionBodySchema,
  transcriptQuerySchema,
  updateSessionNotesBodySchema,
  type ApprovalDecisionBody,
  type CommitToMainBody,
  type CreatePrBody,
  type ForkSessionBody,
  type InspectBody,
  type PaginationQuery,
  type RewindBody,
  type RunCommandBody,
  type SendMessageBody,
  type ShareSessionBody,
  type StartSessionBody,
  type TranscriptQuery,
} from '@loose/shared';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';
import { idempotency } from '../middleware/idempotency';
import type { RateLimiters } from '../middleware/rateLimit';
import { requireAuth } from '../middleware/requireAuth';
import { authUser } from '../middleware/requireOrg';
import { queryOf, validate } from '../middleware/validate';
import { decideApproval, listApprovals, listMessages } from '../services/agentChat.service';
import { normalizeMimeType, uploadAttachment } from '../services/attachments.service';
import { listCheckpoints } from '../services/checkpoint.service';
import {
  listCollaborators,
  releaseControl,
  shareSession,
  takeOver,
  unshareSession,
} from '../services/collab.service';
import { forkSession, resumeSession } from '../services/fork.service';
import { exportTranscript, runCommand, sessionExtensions } from '../services/commands.service';
import { addSessionNote, getSessionNotes, setSessionNotes } from '../services/memory.service';
import { commitToMain, createPr, discardSession, getDiff } from '../services/delivery.service';
import {
  assertTokenScope,
  getSession,
  listArtifacts,
  loadSessionForParticipant,
  openArtifact,
  recoverSession,
  startSession,
  type Caller,
} from '../services/sessionLifecycle.service';

export function callerOf(req: Request): Caller {
  return {
    user: authUser(req),
    apiToken: req.auth?.apiToken,
    ip: req.ip,
    authSession: req.auth?.session,
  };
}

/**
 * Raw body parser for attachment uploads: content type and size are the only gate, and
 * an over-sized body becomes LSE-AGT-009 (not the generic LSE-VAL-002).
 */
const attachmentBody: RequestHandler = (req, res, next) => {
  express.raw({ type: [...ATTACHMENT_MIME_TYPES], limit: MAX_ATTACHMENT_BYTES })(
    req,
    res,
    (err: unknown) => {
      if (!err) return next();
      const type = (err as { type?: string }).type;
      next(
        type === 'entity.too.large'
          ? new AppError('LSE-AGT-009', {
              devMessage: 'Attachment exceeds the size limit',
              fields: {
                file: [`Attachments may be at most ${MAX_ATTACHMENT_BYTES / (1024 * 1024)} MB`],
              },
            })
          : err,
      );
    },
  );
};

/**
 * `x-file-name` carries a percent-encoded file name (header values are ASCII-only, so the
 * browser client sends `encodeURIComponent(file.name)`). Malformed escapes fall back to the
 * raw value instead of failing the upload.
 */
function decodeFileName(raw: string | undefined): string {
  if (!raw) return 'attachment';
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

/** Bodiless POSTs are validated as `{}`. */
const emptyBody: RequestHandler = (req, _res, next) => {
  req.body ??= {};
  next();
};

export function sessionsRouter(ctx: AppContext, limiters: RateLimiters): Router {
  const r = Router();
  r.use(requireAuth(ctx));
  const id = (req: Request) => req.params.id as string;
  const params = validate({ params: sessionIdParamsSchema });

  r.post(
    '/',
    limiters.sessionCreate,
    idempotency(ctx),
    validate({ body: startSessionBodySchema }),
    async (req, res) => {
      const dto = await startSession(ctx, callerOf(req), req.body as StartSessionBody);
      res.status(201).json({ data: dto });
    },
  );

  r.get('/:id', params, async (req, res) => {
    res.json({ data: await getSession(ctx, callerOf(req), id(req)) });
  });

  r.post('/:id/recover', params, idempotency(ctx), async (req, res) => {
    res.status(202).json({ data: await recoverSession(ctx, callerOf(req), id(req)) });
  });

  // ---- fork / resume (Phase 9, spec §8.14) ---------------------------------------------

  r.post(
    '/:id/fork',
    params,
    limiters.sessionCreate,
    idempotency(ctx),
    emptyBody,
    validate({ body: forkSessionBodySchema }),
    async (req, res) => {
      const dto = await forkSession(ctx, callerOf(req), id(req), req.body as ForkSessionBody);
      res.status(201).json({ data: dto });
    },
  );

  r.post('/:id/resume', params, idempotency(ctx), async (req, res) => {
    res.status(202).json({ data: await resumeSession(ctx, callerOf(req), id(req)) });
  });

  // ---- shared sessions (Phase 9, spec §8.18) -------------------------------------------

  r.post(
    '/:id/share',
    params,
    idempotency(ctx),
    validate({ body: shareSessionBodySchema }),
    async (req, res) => {
      const dto = await shareSession(ctx, callerOf(req), id(req), req.body as ShareSessionBody);
      res.status(201).json({ data: dto });
    },
  );

  r.get('/:id/collaborators', params, async (req, res) => {
    res.json({ data: await listCollaborators(ctx, callerOf(req), id(req)), nextCursor: null });
  });

  r.delete(
    '/:id/share/:userId',
    validate({ params: collaboratorParamsSchema }),
    async (req, res) => {
      await unshareSession(ctx, callerOf(req), id(req), req.params.userId as string);
      res.status(204).end();
    },
  );

  r.post('/:id/take-over', params, async (req, res) => {
    res.json({ data: await takeOver(ctx, callerOf(req), id(req)) });
  });

  r.post('/:id/release', params, async (req, res) => {
    res.json({ data: await releaseControl(ctx, callerOf(req), id(req)) });
  });

  r.get('/:id/artifacts', params, async (req, res) => {
    res.json({ data: await listArtifacts(ctx, callerOf(req), id(req)), nextCursor: null });
  });

  r.get(
    '/:id/artifacts/:artifactId/content',
    validate({ params: artifactParamsSchema }),
    async (req, res) => {
      const { row, obj } = await openArtifact(
        ctx,
        callerOf(req),
        id(req),
        req.params.artifactId as string,
      );
      res.setHeader('Content-Type', row.contentType);
      res.setHeader('Content-Length', String(obj.bytes));
      res.setHeader('Content-Disposition', `inline; filename="${row.id}"`);
      res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox");
      res.setHeader('Cache-Control', 'private, no-store');
      obj.stream.on('error', () => res.destroy());
      obj.stream.pipe(res);
    },
  );

  // ---- chat (Phase 5) ------------------------------------------------------------------

  r.get(
    '/:id/messages',
    validate({ params: sessionIdParamsSchema, query: paginationQuerySchema }),
    async (req, res) => {
      res.json(await listMessages(ctx, callerOf(req), id(req), queryOf<PaginationQuery>(req)));
    },
  );

  r.post(
    '/:id/messages',
    params,
    idempotency(ctx),
    validate({ body: sendMessageBodySchema }),
    async (req, res) => {
      const result = await ctx.agent.sendMessage(
        callerOf(req),
        id(req),
        req.body as SendMessageBody,
      );
      res.status(202).json({ data: result });
    },
  );

  r.post('/:id/interrupt', params, async (req, res) => {
    res.status(202).json({ data: await ctx.agent.interrupt(callerOf(req), id(req)) });
  });

  r.get('/:id/approvals', params, async (req, res) => {
    res.json({ data: await listApprovals(ctx, callerOf(req), id(req)), nextCursor: null });
  });

  r.post(
    '/:id/approvals/:approvalId',
    validate({ params: approvalParamsSchema, body: approvalDecisionBodySchema }),
    async (req, res) => {
      const dto = await decideApproval(
        ctx,
        callerOf(req),
        id(req),
        req.params.approvalId as string,
        req.body as ApprovalDecisionBody,
      );
      res.json({ data: dto });
    },
  );

  // ---- checkpoints, commands, notes, transcript (Phase 7) ----------------------------

  r.get('/:id/checkpoints', params, async (req, res) => {
    const caller = callerOf(req);
    assertTokenScope(caller, 'read');
    await loadSessionForParticipant(ctx, caller, id(req));
    res.json({ data: await listCheckpoints(ctx, id(req)), nextCursor: null });
  });

  r.post(
    '/:id/checkpoints/:checkpointId/rewind',
    validate({ params: checkpointParamsSchema }),
    emptyBody,
    validate({ body: rewindBodySchema }),
    async (req, res) => {
      const dto = await ctx.agent.rewind(
        callerOf(req),
        id(req),
        req.params.checkpointId as string,
        (req.body as RewindBody).scope,
      );
      res.json({ data: dto });
    },
  );

  r.get('/:id/commands', params, async (req, res) => {
    res.json({ data: await sessionExtensions(ctx, callerOf(req), id(req)) });
  });

  r.post(
    '/:id/commands',
    params,
    idempotency(ctx),
    validate({ body: runCommandBodySchema }),
    async (req, res) => {
      const dto = await runCommand(ctx, callerOf(req), id(req), req.body as RunCommandBody);
      res.status(dto.kind === 'turn' ? 202 : 200).json({ data: dto });
    },
  );

  r.get('/:id/notes', params, async (req, res) => {
    res.json({ data: await getSessionNotes(ctx, callerOf(req), id(req)) });
  });

  r.put(
    '/:id/notes',
    params,
    validate({ body: updateSessionNotesBodySchema }),
    async (req, res) => {
      const { notes } = req.body as { notes: string };
      res.json({ data: await setSessionNotes(ctx, callerOf(req), id(req), notes) });
    },
  );

  r.post('/:id/notes', params, validate({ body: addSessionNoteBodySchema }), async (req, res) => {
    const { text } = req.body as { text: string };
    res.status(201).json({ data: await addSessionNote(ctx, callerOf(req), id(req), text) });
  });

  r.get(
    '/:id/transcript',
    validate({ params: sessionIdParamsSchema, query: transcriptQuerySchema }),
    async (req, res) => {
      const { format } = queryOf<TranscriptQuery>(req);
      const out = await exportTranscript(ctx, callerOf(req), id(req), format);
      res.setHeader('Content-Type', out.contentType);
      res.setHeader('Content-Disposition', `attachment; filename="${out.filename}"`);
      res.setHeader('Cache-Control', 'private, no-store');
      res.send(out.body);
    },
  );

  // ---- attachments & element inspection (Phase 8, spec §8.12) -------------------------

  /**
   * Raw-body upload (the only non-JSON route under /api/v1): an image or PDF, at most
   * `MAX_ATTACHMENT_BYTES`. Anything else → LSE-AGT-009.
   */
  r.post('/:id/attachments', params, attachmentBody, async (req, res) => {
    const contentType = normalizeMimeType(req.headers['content-type']);
    const body = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
    const name = attachmentFileNameSchema
      .catch('attachment')
      .parse(decodeFileName(req.get(ATTACHMENT_FILE_NAME_HEADER)));
    const dto = await uploadAttachment(ctx, callerOf(req), id(req), {
      name,
      contentType,
      data: body,
    });
    res.status(201).json({ data: dto });
  });

  r.post('/:id/inspect', params, validate({ body: inspectBodySchema }), async (req, res) => {
    const dto = await ctx.agent.inspect(callerOf(req), id(req), req.body as InspectBody);
    res.json({ data: dto });
  });

  // ---- review & delivery (Phase 6) -----------------------------------------------------

  r.get('/:id/diff', params, async (req, res) => {
    res.json({ data: await getDiff(ctx, callerOf(req), id(req)) });
  });

  r.post(
    '/:id/create-pr',
    params,
    idempotency(ctx),
    emptyBody,
    validate({ body: createPrBodySchema }),
    async (req, res) => {
      res.json({ data: await createPr(ctx, callerOf(req), id(req), req.body as CreatePrBody) });
    },
  );

  r.post(
    '/:id/commit-to-main',
    params,
    idempotency(ctx),
    emptyBody,
    validate({ body: commitToMainBodySchema }),
    async (req, res) => {
      res.json({
        data: await commitToMain(ctx, callerOf(req), id(req), req.body as CommitToMainBody),
      });
    },
  );

  r.post('/:id/discard', params, idempotency(ctx), async (req, res) => {
    res.json({ data: await discardSession(ctx, callerOf(req), id(req)) });
  });

  return r;
}
