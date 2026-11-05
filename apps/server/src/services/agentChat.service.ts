/**
 * Chat history, approvals and per-viewer mode (spec §8.3, §10.5, §11; Phase 5).
 * The Simple/Pro mode a viewer sees: their locked mode (member lock or org policy for
 * their role) else the session's mode.
 */
import { Prisma, type Organization, type OrgMember, type Session } from '@prisma/client';
import {
  buildErrorEnvelope,
  chatMessageDtoSchema,
  isAdminRole,
  parseOrgPolicy,
  toSimpleChatMessage,
  type ApprovalDecisionBody,
  type ChatMessageDto,
  type Mode,
  type PaginationQuery,
  type ToolApprovalDto,
} from '@loose/shared';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';
import { pageArgs, toPage, type Page } from '../lib/pagination';
import { approvalDto, withAttachments } from './orchestrator.service';
import {
  assertCanAct,
  assertTokenScope,
  loadSessionForParticipant,
  type Caller,
} from './sessionLifecycle.service';

export function viewerMode(
  session: Pick<Session, 'mode'>,
  membership: Pick<OrgMember, 'role' | 'lockedMode'>,
  org: Pick<Organization, 'policy'>,
): Mode {
  const policy = parseOrgPolicy(org.policy);
  const locked =
    membership.lockedMode ??
    (membership.role === 'MEMBER' || membership.role === 'VIEWER'
      ? policy.lockedModes[membership.role]
      : undefined);
  return locked ?? session.mode;
}

async function accessWithMode(ctx: AppContext, caller: Caller, sessionId: string) {
  assertTokenScope(caller, 'read');
  const access = await loadSessionForParticipant(ctx, caller, sessionId);
  const org = await ctx.prisma.organization.findUniqueOrThrow({
    where: { id: access.session.project.orgId },
  });
  return { ...access, org, mode: viewerMode(access.session, access.membership, org) };
}

export async function resolveViewerMode(
  ctx: AppContext,
  caller: Caller,
  sessionId: string,
): Promise<Mode> {
  return (await accessWithMode(ctx, caller, sessionId)).mode;
}

function rawObj(v: Prisma.JsonValue): Record<string, unknown> | null {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

/** `GET /sessions/:id/messages` — oldest first, cursor = message id. */
export async function listMessages(
  ctx: AppContext,
  caller: Caller,
  sessionId: string,
  q: PaginationQuery,
): Promise<Page<ChatMessageDto>> {
  const { mode } = await accessWithMode(ctx, caller, sessionId);
  const rows = await ctx.prisma.chatMessage.findMany({
    where: {
      sessionId,
      // Rewound messages are kept for audit only.
      rewoundAt: null,
      // Turns still in progress are streamed over WS, not listed.
      OR: [
        { rawContent: { equals: Prisma.AnyNull } },
        { rawContent: { path: ['pending'], equals: false } },
      ],
    },
    orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
    ...pageArgs(q),
  });
  return toPage(rows, q.limit, (r) => {
    const raw = rawObj(r.rawContent);
    const proText = typeof raw?.proText === 'string' ? raw.proText : undefined;
    const dto = chatMessageDtoSchema.parse({
      ...r,
      content: mode === 'PRO' && r.role === 'ASSISTANT' && proText ? proText : r.content,
      metadata: withAttachments(r.metadata, r.attachments),
    });
    return mode === 'PRO' ? dto : toSimpleChatMessage(dto);
  });
}

// ---- approvals --------------------------------------------------------------------------

export async function listApprovals(
  ctx: AppContext,
  caller: Caller,
  sessionId: string,
): Promise<ToolApprovalDto[]> {
  const { mode } = await accessWithMode(ctx, caller, sessionId);
  const rows = await ctx.prisma.toolApproval.findMany({
    where: { sessionId },
    orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
    take: 100,
  });
  return rows.map((r) => approvalDto(r, mode, ctx.agent.translator));
}

/**
 * Decide a PENDING approval (owner, or ADMIN+; `requiresAdmin` approvals — dependency /
 * migration gates and high-risk actions in sessions owned by MEMBERs — need ADMIN+).
 */
export async function decideApproval(
  ctx: AppContext,
  caller: Caller,
  sessionId: string,
  approvalId: string,
  body: ApprovalDecisionBody,
): Promise<ToolApprovalDto> {
  assertTokenScope(caller, 'write');
  const access = await accessWithMode(ctx, caller, sessionId);
  const { session, membership, mode } = access;
  assertCanAct(access, 'decide approvals');
  const row = await ctx.prisma.toolApproval.findFirst({ where: { id: approvalId, sessionId } });
  if (!row) throw new AppError('LSE-NF-001', { devMessage: 'Approval not found' });
  if (row.status !== 'PENDING') {
    throw new AppError('LSE-CONF-001', { devMessage: `Approval is already ${row.status}` });
  }
  if (row.expiresAt && row.expiresAt.getTime() <= Date.now()) {
    await expireApproval(ctx, row.id);
    throw new AppError('LSE-AGT-006', { devMessage: 'Approval expired' });
  }
  const isPlan = row.kind === 'plan';
  if (!isPlan && body.plan !== undefined) {
    throw new AppError('LSE-VAL-001', { fields: { plan: ['Only plan approvals take a plan'] } });
  }
  if (isPlan && body.decision === 'approve' && session.status !== 'RUNNING') {
    throw new AppError('LSE-CONF-001', { devMessage: `Session is ${session.status}, not RUNNING` });
  }
  if (row.requiresAdmin && !isAdminRole(membership.role)) {
    throw new AppError('LSE-ORG-002', {
      devMessage: 'This approval needs an org admin',
      userMessage: 'An admin needs to approve this step.',
    });
  }
  const approve = body.decision === 'approve';
  const status = approve ? 'APPROVED' : 'DENIED';
  const updated = await ctx.prisma.toolApproval.updateMany({
    where: { id: row.id, status: 'PENDING' },
    data: {
      status,
      decidedById: caller.user.id,
      decidedAt: new Date(),
      ...(body.reason
        ? { reason: `${row.reason ?? ''}\nDecision note: ${body.reason}`.trim() }
        : {}),
    },
  });
  if (updated.count === 0)
    throw new AppError('LSE-CONF-001', { devMessage: 'Approval changed concurrently' });
  if (isPlan) {
    const input = rawObj(row.input);
    const edited = body.plan !== undefined && body.plan !== input?.plan;
    if (edited) {
      await ctx.prisma.toolApproval.update({
        where: { id: row.id },
        data: {
          input: { ...(input ?? {}), plan: body.plan, edited: true } as Prisma.InputJsonValue,
        },
      });
    }
    await ctx.sessionEvents
      .publish(sessionId, 'approval_resolved', {
        approvalId: row.id,
        status,
        decidedByName: caller.user.name ?? caller.user.email,
      })
      .catch(() => undefined);
    await ctx.audit.record({
      orgId: session.project.orgId,
      actorId: caller.user.id,
      action: 'plan.decide',
      target: row.id,
      meta: { sessionId, decision: status, edited },
      ip: caller.ip,
    });
    await ctx.agent.onPlanDecision(sessionId, row, {
      approve,
      edited,
      ...(body.plan !== undefined ? { plan: body.plan } : {}),
    });
    const fresh = await ctx.prisma.toolApproval.findUniqueOrThrow({ where: { id: row.id } });
    return approvalDto(fresh, mode, ctx.agent.translator);
  }
  if (session.status === 'RUNNING' && row.runnerRequestId) {
    const sent = await ctx.agent.sendApprovalResponse(
      sessionId,
      row.runnerRequestId,
      approve,
      body.reason,
    );
    if (!sent)
      ctx.logger.warn({ sessionId, approvalId }, 'approval decided but the runner is not attached');
  }
  await ctx.sessionEvents
    .publish(sessionId, 'approval_resolved', {
      approvalId: row.id,
      status,
      decidedByName: caller.user.name ?? caller.user.email,
    })
    .catch(() => undefined);
  await ctx.audit.record({
    orgId: session.project.orgId,
    actorId: caller.user.id,
    action: 'approval.decide',
    target: row.id,
    meta: { sessionId, decision: status, tool: row.tool, gate: row.gate },
    ip: caller.ip,
  });
  const fresh = await ctx.prisma.toolApproval.findUniqueOrThrow({ where: { id: row.id } });
  return approvalDto(fresh, mode, ctx.agent.translator);
}

async function expireApproval(ctx: AppContext, approvalId: string): Promise<boolean> {
  const row = await ctx.prisma.toolApproval.findUnique({
    where: { id: approvalId },
    include: { session: { include: { project: { select: { orgId: true } } } } },
  });
  if (!row || row.status !== 'PENDING') return false;
  const r = await ctx.prisma.toolApproval.updateMany({
    where: { id: row.id, status: 'PENDING' },
    data: { status: 'EXPIRED', decidedAt: new Date() },
  });
  if (r.count === 0) return false;
  if (row.runnerRequestId) {
    await ctx.agent.sendApprovalResponse(
      row.sessionId,
      row.runnerRequestId,
      false,
      'No decision was made in time',
    );
  }
  await ctx.sessionEvents
    .publish(row.sessionId, 'approval_resolved', { approvalId: row.id, status: 'EXPIRED' })
    .catch(() => undefined);
  const { error } = buildErrorEnvelope('LSE-AGT-006', {
    requestId: `sess_${row.sessionId}`,
  });
  await ctx.sessionEvents
    .publish(row.sessionId, 'error', { error, recoverable: true })
    .catch(() => undefined);
  await ctx.audit.record({
    orgId: row.session.project.orgId,
    actorId: null,
    action: 'approval.expire',
    target: row.id,
    meta: { sessionId: row.sessionId, tool: row.tool, gate: row.gate },
  });
  return true;
}

/**
 * `approval-expiry` job: `{approvalId}` expires one approval (delayed job), `{}` sweeps
 * every PENDING approval past its `expiresAt` (repeatable safety net).
 */
export async function expireApprovals(
  ctx: AppContext,
  data: { approvalId?: string } = {},
  now = new Date(),
): Promise<string[]> {
  const ids = data.approvalId
    ? [data.approvalId]
    : (
        await ctx.prisma.toolApproval.findMany({
          where: { status: 'PENDING', expiresAt: { lte: now } },
          select: { id: true },
          take: 500,
        })
      ).map((r) => r.id);
  const expired: string[] = [];
  for (const id of ids) {
    const row = await ctx.prisma.toolApproval.findUnique({ where: { id } });
    if (!row || row.status !== 'PENDING') continue;
    if (row.expiresAt && row.expiresAt.getTime() > now.getTime()) continue;
    if (await expireApproval(ctx, id)) expired.push(id);
  }
  return expired;
}
