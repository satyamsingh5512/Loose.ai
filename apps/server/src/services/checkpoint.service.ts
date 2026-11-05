/**
 * Checkpoints & rewind (spec §8.5; Phase 7). Before every user turn the working tree
 * (tracked + untracked, not ignored) is snapshotted to a sandbox-local ref
 * `refs/loose/checkpoints/<id>` with a temporary index — the branch, index and working
 * tree stay untouched — and the agent conversation anchor is recorded. Rewinding code
 * restores the tree (changes stay uncommitted); rewinding the conversation hides later
 * messages and resumes the agent at the anchor.
 */
import type { Checkpoint, Prisma } from '@prisma/client';
import { checkpointDtoSchema, checkpointRefName, type CheckpointDto } from '@loose/shared';
import type { AppContext } from '../context';
import type { SandboxHandle } from '../lib/sandbox';
import { shq } from './gitAccess.service';

const GIT = 'git -c core.quotePath=false';
export const CHECKPOINT_LABEL_MAX = 120;

export function checkpointLabel(text: string): string {
  const t = text.replace(/\s+/g, ' ').trim();
  return t.length > CHECKPOINT_LABEL_MAX ? `${t.slice(0, CHECKPOINT_LABEL_MAX - 1)}…` : t;
}

/** Snapshot the working tree to `ref` without touching HEAD, the index or files. */
export async function snapshotWorkspace(sandbox: SandboxHandle, ref: string): Promise<boolean> {
  const script = [
    'set -e',
    'export GIT_INDEX_FILE="$(git rev-parse --git-dir)/loose-checkpoint-index"',
    'rm -f "$GIT_INDEX_FILE"',
    'git read-tree HEAD',
    `${GIT} add -A`,
    'tree=$(git write-tree)',
    'commit=$(git commit-tree "$tree" -p HEAD -m "loose.ai checkpoint")',
    'rm -f "$GIT_INDEX_FILE"',
    `git update-ref ${shq(ref)} "$commit"`,
  ].join('\n');
  const r = await sandbox.run(script, { cwd: sandbox.paths.workspace, timeoutMs: 120_000 });
  return r.exitCode === 0;
}

/**
 * Make the working tree equal to the snapshot in `ref` (files created later are removed,
 * ignored files such as `.env` and `node_modules` are kept); the index is reset to HEAD
 * so the restored state shows as uncommitted changes.
 */
export async function restoreWorkspace(sandbox: SandboxHandle, ref: string): Promise<boolean> {
  const script = [
    'set -e',
    `git rev-parse --verify -q ${shq(`${ref}^{commit}`)} >/dev/null`,
    `git read-tree -u --reset ${shq(ref)}`,
    `${GIT} clean -fdq`,
    'git reset -q',
  ].join('\n');
  const r = await sandbox.run(script, { cwd: sandbox.paths.workspace, timeoutMs: 120_000 });
  return r.exitCode === 0;
}

/** Remove the refs of checkpoints that no longer apply (best effort). */
export async function deleteCheckpointRefs(sandbox: SandboxHandle, ids: readonly string[]) {
  if (!ids.length) return;
  const cmds = ids.map(
    (id) => `git update-ref -d ${shq(checkpointRefName(id))} 2>/dev/null || true`,
  );
  await sandbox
    .run(cmds.join('\n'), { cwd: sandbox.paths.workspace, timeoutMs: 60_000 })
    .catch(() => undefined);
}

export function toCheckpointDto(row: Checkpoint): CheckpointDto {
  return checkpointDtoSchema.parse({ ...row, label: row.label ?? '' });
}

export interface NewCheckpoint {
  sessionId: string;
  messageId: string;
  label: string;
  conversationAnchor: string | null;
  agentSessionId: string | null;
}

/** Create a checkpoint (snapshot + row) and link it to the USER message. */
export async function createCheckpoint(
  ctx: AppContext,
  sandbox: SandboxHandle,
  input: NewCheckpoint,
  id: string,
): Promise<Checkpoint> {
  const ref = checkpointRefName(id);
  let hasCode = false;
  try {
    hasCode = await snapshotWorkspace(sandbox, ref);
  } catch (err) {
    ctx.logger.warn({ err, sessionId: input.sessionId }, 'checkpoint snapshot failed');
  }
  if (!hasCode) ctx.logger.warn({ sessionId: input.sessionId }, 'checkpoint has no code snapshot');
  const turn =
    (await ctx.prisma.checkpoint.count({
      where: { sessionId: input.sessionId, rewoundAt: null },
    })) + 1;
  const row = await ctx.prisma.checkpoint.create({
    data: {
      id,
      sessionId: input.sessionId,
      messageId: input.messageId,
      gitRef: ref,
      label: checkpointLabel(input.label),
      turn,
      conversationAnchor: input.conversationAnchor,
      agentSessionId: input.agentSessionId,
      hasCode,
    },
  });
  await ctx.prisma.chatMessage.update({
    where: { id: input.messageId },
    data: { checkpointId: row.id },
  });
  return row;
}

export async function listCheckpoints(
  ctx: AppContext,
  sessionId: string,
): Promise<CheckpointDto[]> {
  const rows = await ctx.prisma.checkpoint.findMany({
    where: { sessionId, rewoundAt: null },
    orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
    take: 500,
  });
  return rows.map(toCheckpointDto);
}

/** Hide everything from the checkpoint's turn on (conversation rewind). */
export async function hideFrom(
  ctx: AppContext,
  cp: Checkpoint,
  now = new Date(),
): Promise<{ messageIds: string[]; checkpointIds: string[] }> {
  const userMsg = await ctx.prisma.chatMessage.findUnique({ where: { id: cp.messageId } });
  const since = userMsg?.createdAt ?? cp.createdAt;
  const where: Prisma.ChatMessageWhereInput = {
    sessionId: cp.sessionId,
    rewoundAt: null,
    OR: [{ createdAt: { gte: since } }, { id: cp.messageId }],
  };
  const msgs = await ctx.prisma.chatMessage.findMany({ where, select: { id: true } });
  const cps = await ctx.prisma.checkpoint.findMany({
    where: { sessionId: cp.sessionId, rewoundAt: null, turn: { gte: cp.turn } },
    select: { id: true },
  });
  await ctx.prisma.$transaction([
    ctx.prisma.chatMessage.updateMany({
      where: { id: { in: msgs.map((m) => m.id) } },
      data: { rewoundAt: now },
    }),
    ctx.prisma.checkpoint.updateMany({
      where: { id: { in: cps.map((c) => c.id) } },
      data: { rewoundAt: now },
    }),
  ]);
  return { messageIds: msgs.map((m) => m.id), checkpointIds: cps.map((c) => c.id) };
}
