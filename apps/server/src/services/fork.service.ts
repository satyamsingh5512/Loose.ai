/**
 * Session fork & resume (spec §8.14, §10.5; Phase 9).
 *
 * Fork = "branch off from here": a NEW session (own branch, own sandbox, the forker's key,
 * budget and concurrency slot) that starts from a snapshot of the parent. Because sandboxes
 * are not shared, the snapshot travels through the remote: whatever the fork starts from is
 * pushed to a `refs/loose/wip/fork-<id>` ref and restored by the normal provisioning path
 * (`Session.wipRef`). The visible transcript up to the fork point is copied so the user sees
 * the conversation they forked from; the agent conversation itself starts fresh (the SDK
 * session files live in the parent's sandbox).
 *
 * Snapshot sources, in order (else LSE-SBX-015 "can't copy from there"):
 *   1. an explicit checkpoint — parent RUNNING, sandbox reachable, snapshot exists;
 *   2. the parent's live working tree (parent RUNNING) — pushed as a fresh WIP snapshot;
 *   3. the parent's saved WIP ref (paused / timed out / errored session);
 *   4. the parent's pushed branch (it committed or opened a PR).
 *
 * Resume = continue the SAME session: PAUSED/ERRORED/TIMED_OUT go through the recover path,
 * a COMPLETED session with an open PR is re-provisioned from its branch tip.
 */
import type { Checkpoint, Prisma } from '@prisma/client';
import {
  isRecoverableSessionStatus,
  wipRefName,
  type ForkSessionBody,
  type SessionDto,
} from '@loose/shared';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';
import { resolveGitAccess, type GitAccess } from './gitAccess.service';
import { decryptProjectEnv } from './project.service';
import {
  assertNotViewer,
  assertTokenScope,
  getOrConnectSandbox,
  loadSessionForParticipant,
  newId,
  REMOTE_BRANCH_REF_PREFIX,
  requeueSession,
  startSession,
  type Caller,
  type SessionRow,
} from './sessionLifecycle.service';
import { pushRef, pushWip, secretValuesOf, type WorkspaceContext } from './workspace.service';

const MAX_COPIED_MESSAGES = 1000;

function forkSourceGone(devMessage: string): AppError {
  return new AppError('LSE-SBX-015', { devMessage });
}

/** A workspace handle on the parent's live sandbox, or null when it is gone. */
async function parentWorkspace(
  ctx: AppContext,
  session: SessionRow,
): Promise<{ w: WorkspaceContext; access: GitAccess } | null> {
  const sandbox = await getOrConnectSandbox(ctx, session);
  if (!sandbox) return null;
  const alive = await sandbox.isRunning().catch(() => false);
  if (!alive) return null;
  const project = await ctx.prisma.project.findUnique({
    where: { id: session.projectId },
    include: { org: true },
  });
  if (!project) return null;
  try {
    const access = await resolveGitAccess(ctx, {
      org: project.org,
      userId: session.userId,
      repoFullName: project.githubRepoFullName,
    });
    const env = await decryptProjectEnv(ctx, project);
    return {
      access,
      w: {
        ctx,
        sandbox,
        project,
        secrets: secretValuesOf(env),
        reporter: { log: () => undefined },
      },
    };
  } catch (err) {
    ctx.logger.warn({ err, sessionId: session.id }, 'fork: parent workspace unavailable');
    return null;
  }
}

/** The remote ref the fork's first provision restores. */
async function resolveForkSource(
  ctx: AppContext,
  parent: SessionRow,
  checkpoint: Checkpoint | null,
): Promise<string> {
  const target = wipRefName(`fork-${newId()}`);
  if (checkpoint) {
    if (!checkpoint.hasCode) {
      throw forkSourceGone(`Checkpoint ${checkpoint.id} has no code snapshot`);
    }
    if (parent.status !== 'RUNNING') {
      throw forkSourceGone(
        `Checkpoint snapshots only live in the session sandbox (parent is ${parent.status})`,
      );
    }
    const live = await parentWorkspace(ctx, parent);
    if (!live) throw forkSourceGone('The source sandbox is no longer reachable');
    if (!(await pushRef(live.w, live.access, checkpoint.gitRef, target))) {
      throw forkSourceGone(`Could not copy the snapshot of checkpoint ${checkpoint.id}`);
    }
    return target;
  }
  if (parent.status === 'RUNNING') {
    const live = await parentWorkspace(ctx, parent);
    if (live && (await pushWip(live.w, live.access, target))) return target;
  }
  if (parent.wipRef) return parent.wipRef;
  if (parent.commitSha || parent.prUrl) return `${REMOTE_BRANCH_REF_PREFIX}${parent.branchName}`;
  throw forkSourceGone('This session has nothing saved that could be copied');
}

function jsonObject(v: Prisma.JsonValue | null): Record<string, unknown> {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

/**
 * Copy the parent's visible messages up to (excluding) the checkpoint's USER message.
 * `clientMessageId` and `checkpointId` are deliberately not copied (they belong to the
 * parent); `metadata.forkedFrom` records where the copy came from.
 */
async function copyTranscript(
  ctx: AppContext,
  parentId: string,
  childId: string,
  checkpoint: Checkpoint | null,
): Promise<number> {
  const cutoff = checkpoint
    ? await ctx.prisma.chatMessage.findUnique({ where: { id: checkpoint.messageId } })
    : null;
  const rows = await ctx.prisma.chatMessage.findMany({
    where: {
      sessionId: parentId,
      rewoundAt: null,
      ...(cutoff ? { createdAt: { lt: cutoff.createdAt } } : {}),
    },
    orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
    take: MAX_COPIED_MESSAGES,
  });
  if (!rows.length) return 0;
  const forkedFrom = { sessionId: parentId, checkpointId: checkpoint?.id ?? null };
  const { count } = await ctx.prisma.chatMessage.createMany({
    data: rows.map((m) => ({
      sessionId: childId,
      role: m.role,
      content: m.content,
      ...(m.attachments === null ? {} : { attachments: m.attachments as Prisma.InputJsonValue }),
      metadata: { ...jsonObject(m.metadata), forkedFrom } as Prisma.InputJsonValue,
      createdAt: m.createdAt,
    })),
  });
  return count;
}

/**
 * `POST /sessions/:id/fork` and `POST /sessions {forkFrom}` (spec §10.5). The fork belongs to
 * the caller: their API key, their budget and their concurrency slot, enforced by
 * `startSession`'s preflight.
 */
export async function forkSession(
  ctx: AppContext,
  caller: Caller,
  parentId: string,
  body: ForkSessionBody = {},
): Promise<SessionDto> {
  assertTokenScope(caller, 'write');
  const access = await loadSessionForParticipant(ctx, caller, parentId);
  assertNotViewer(access, 'fork sessions');
  const parent = access.session;

  const checkpoint = body.checkpointId
    ? await ctx.prisma.checkpoint.findFirst({
        where: { id: body.checkpointId, sessionId: parent.id, rewoundAt: null },
      })
    : null;
  if (body.checkpointId && !checkpoint) {
    throw forkSourceGone(`Checkpoint ${body.checkpointId} is not part of this session anymore`);
  }
  const wipRef = await resolveForkSource(ctx, parent, checkpoint);

  const dto = await startSession(
    ctx,
    caller,
    {
      projectId: parent.projectId,
      ...(body.mode ? { mode: body.mode } : {}),
      ...(body.model ? { model: body.model } : {}),
    },
    {
      wipRef,
      parentSessionId: parent.id,
      ...(checkpoint ? { forkedFromCheckpointId: checkpoint.id } : {}),
      ...(parent.baseBranch ? { baseBranch: parent.baseBranch } : {}),
      notes: parent.notes,
    },
  );
  const copied = await copyTranscript(ctx, parent.id, dto.id, checkpoint);
  await ctx.audit.record({
    orgId: parent.project.orgId,
    actorId: caller.user.id,
    action: 'session.fork',
    target: dto.id,
    meta: {
      parentSessionId: parent.id,
      checkpointId: checkpoint?.id ?? null,
      wipRef,
      messagesCopied: copied,
    },
    ip: caller.ip,
  });
  return dto;
}

/**
 * `POST /sessions/:id/resume` (spec §8.14): continue a stopped session in a fresh sandbox
 * rehydrated from the project template, restoring its saved work (or its pushed branch).
 */
export async function resumeSession(
  ctx: AppContext,
  caller: Caller,
  sessionId: string,
): Promise<SessionDto> {
  assertTokenScope(caller, 'write');
  const access = await loadSessionForParticipant(ctx, caller, sessionId);
  assertNotViewer(access, 'resume sessions');
  const session = access.session;
  const from = session.status;
  let dto: SessionDto;
  if (isRecoverableSessionStatus(from)) {
    dto = await requeueSession(ctx, session);
  } else if (
    from === 'COMPLETED' &&
    session.outcome === 'PR_CREATED' &&
    session.prState === 'open'
  ) {
    dto = await requeueSession(ctx, session, {
      wipRef: `${REMOTE_BRANCH_REF_PREFIX}${session.branchName}`,
      message: 'Reopening your workspace…',
    });
  } else {
    throw new AppError('LSE-CONF-001', { devMessage: `Cannot resume a ${from} session` });
  }
  await ctx.audit.record({
    orgId: session.project.orgId,
    actorId: caller.user.id,
    action: 'session.resume',
    target: session.id,
    meta: { from, branchName: session.branchName },
    ip: caller.ip,
  });
  return dto;
}
