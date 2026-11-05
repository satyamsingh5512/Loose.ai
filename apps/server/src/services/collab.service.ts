/**
 * Shared sessions: collaborators, control take-over, presence roles (spec §8.18; Phase 9).
 *
 * A session owner (or an org ADMIN+) can invite other org members to watch (`VIEWER`) or to
 * take part (`CO_EDITOR`). Authorization lives in `loadSessionForParticipant` /
 * `assertCanAct` (sessionLifecycle.service): a VIEWER collaborator is handed a membership
 * copy with `role: 'VIEWER'`, so every existing write check refuses them, and while someone
 * holds control every other participant's write actions fail with LSE-AGT-017.
 *
 * "Take over" is the hand-off from a non-technical owner to a developer: the developer gets
 * control, the session switches to PRO, and everyone watching is told over the WebSocket
 * (`control_changed`). Each step is audited.
 */
import type { Organization, OrgMember, SessionCollaborator, User } from '@prisma/client';
import {
  hasRoleAtLeast,
  MAX_SESSION_COLLABORATORS,
  parseOrgPolicy,
  sessionCollaboratorDtoSchema,
  sessionControlDtoSchema,
  type Mode,
  type SessionCollaboratorDto,
  type SessionControlDto,
  type ShareSessionBody,
} from '@loose/shared';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';
import type { PlatformRole } from '../platform/register';
import {
  assertTokenScope,
  loadSessionForParticipant,
  type Caller,
  type SessionAccess,
} from './sessionLifecycle.service';

export { assertCanAct, assertNotViewer } from './sessionLifecycle.service';

type CollaboratorRow = SessionCollaborator & {
  user: Pick<User, 'name' | 'email' | 'avatarUrl'>;
};

const collaboratorInclude = {
  user: { select: { name: true, email: true, avatarUrl: true } },
} as const;

function toCollaboratorDto(row: CollaboratorRow): SessionCollaboratorDto {
  return sessionCollaboratorDtoSchema.parse({
    sessionId: row.sessionId,
    userId: row.userId,
    name: row.user.name,
    email: row.user.email,
    avatarUrl: row.user.avatarUrl,
    role: row.role,
    invitedById: row.invitedById,
    createdAt: row.createdAt,
  });
}

function toControlDto(s: {
  id: string;
  controllerId: string | null;
  controlTakenAt: Date | null;
  mode: Mode;
  controller?: Pick<User, 'name' | 'email'> | null;
}): SessionControlDto {
  return sessionControlDtoSchema.parse({
    sessionId: s.id,
    controllerId: s.controllerId,
    controllerName: s.controller ? (s.controller.name ?? s.controller.email) : null,
    mode: s.mode,
    controlTakenAt: s.controlTakenAt,
  });
}

/** Only the session owner and org ADMIN+ manage who a session is shared with. */
function assertCanShare(access: SessionAccess): void {
  if (!access.isOwner && !access.isAdmin) {
    throw new AppError('LSE-ORG-002', {
      devMessage: 'Only the session owner or an org admin can change sharing',
    });
  }
}

export async function collaboratorsOf(
  ctx: AppContext,
  sessionId: string,
): Promise<SessionCollaboratorDto[]> {
  const rows = await ctx.prisma.sessionCollaborator.findMany({
    where: { sessionId },
    include: collaboratorInclude,
    orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
    take: MAX_SESSION_COLLABORATORS + 1,
  });
  return rows.map(toCollaboratorDto);
}

/** Tell everyone watching that the collaborator list changed (gateway drops removed users). */
async function publishShares(ctx: AppContext, sessionId: string): Promise<void> {
  const collaborators = await collaboratorsOf(ctx, sessionId);
  await ctx.sessionEvents
    .publish(sessionId, 'share_updated', { collaborators })
    .catch((err: unknown) =>
      ctx.logger.warn({ err, sessionId }, 'failed to publish share_updated'),
    );
}

async function publishControl(ctx: AppContext, control: SessionControlDto): Promise<void> {
  await ctx.sessionEvents
    .publish(control.sessionId, 'control_changed', {
      controllerId: control.controllerId,
      controllerName: control.controllerName,
      mode: control.mode,
    })
    .catch((err: unknown) =>
      ctx.logger.warn({ err, sessionId: control.sessionId }, 'failed to publish control_changed'),
    );
}

/** The mode a member is locked to by their member lock or the org policy, if any. */
function lockedModeFor(
  membership: Pick<OrgMember, 'role' | 'lockedMode'>,
  org: Pick<Organization, 'policy'>,
): 'SIMPLE' | 'PRO' | undefined {
  const policy = parseOrgPolicy(org.policy);
  return (
    membership.lockedMode ??
    (membership.role === 'MEMBER' || membership.role === 'VIEWER'
      ? policy.lockedModes[membership.role]
      : undefined)
  );
}

// ---- sharing -------------------------------------------------------------------------------

/** `POST /sessions/:id/share` — invite an org member as VIEWER or CO_EDITOR (upsert). */
export async function shareSession(
  ctx: AppContext,
  caller: Caller,
  sessionId: string,
  body: ShareSessionBody,
): Promise<SessionCollaboratorDto> {
  assertTokenScope(caller, 'write');
  const access = await loadSessionForParticipant(ctx, caller, sessionId);
  assertCanShare(access);
  const orgId = access.session.project.orgId;

  const target = body.userId
    ? await ctx.prisma.user.findUnique({ where: { id: body.userId } })
    : await ctx.prisma.user.findFirst({
        where: { email: { equals: body.email, mode: 'insensitive' } },
      });
  if (!target) throw new AppError('LSE-NF-001', { devMessage: 'User not found' });
  if (target.id === access.session.userId) {
    throw new AppError('LSE-CONF-001', {
      devMessage: 'The session owner already has full access',
    });
  }
  const membership = await ctx.prisma.orgMember.findUnique({
    where: { userId_orgId: { userId: target.id, orgId } },
  });
  if (!membership) {
    throw new AppError('LSE-ORG-001', {
      devMessage: 'Sessions can only be shared with members of the same organization',
    });
  }
  // Org VIEWERs may watch but never act, whatever the share says.
  if (body.role === 'CO_EDITOR' && !hasRoleAtLeast(membership.role, 'MEMBER')) {
    throw new AppError('LSE-ORG-002', {
      devMessage: 'Organization viewers can only be invited as session viewers',
    });
  }
  const existing = await ctx.prisma.sessionCollaborator.findUnique({
    where: { sessionId_userId: { sessionId, userId: target.id } },
  });
  if (!existing) {
    const count = await ctx.prisma.sessionCollaborator.count({ where: { sessionId } });
    if (count >= MAX_SESSION_COLLABORATORS) {
      throw new AppError('LSE-VAL-001', {
        devMessage: `A session can be shared with at most ${MAX_SESSION_COLLABORATORS} people`,
        fields: { userId: [`At most ${MAX_SESSION_COLLABORATORS} people per session`] },
      });
    }
  }
  const row = await ctx.prisma.sessionCollaborator.upsert({
    where: { sessionId_userId: { sessionId, userId: target.id } },
    create: {
      sessionId,
      userId: target.id,
      role: body.role,
      invitedById: caller.user.id,
    },
    update: { role: body.role },
    include: collaboratorInclude,
  });
  await ctx.audit.record({
    orgId,
    actorId: caller.user.id,
    action: 'session.share',
    target: sessionId,
    meta: { userId: target.id, role: body.role, updated: existing !== null },
    ip: caller.ip,
  });
  // A viewer cannot remain the controller and keep every writer locked out.
  if (body.role === 'VIEWER' && access.session.controllerId === target.id) {
    await clearControl(ctx, sessionId);
  }
  await publishShares(ctx, sessionId);
  return toCollaboratorDto(row);
}

/** `GET /sessions/:id/collaborators` — every participant may see who else is in. */
export async function listCollaborators(
  ctx: AppContext,
  caller: Caller,
  sessionId: string,
): Promise<SessionCollaboratorDto[]> {
  assertTokenScope(caller, 'read');
  await loadSessionForParticipant(ctx, caller, sessionId);
  return collaboratorsOf(ctx, sessionId);
}

/** `DELETE /sessions/:id/share/:userId` — owner/admin, or a collaborator removing themselves. */
export async function unshareSession(
  ctx: AppContext,
  caller: Caller,
  sessionId: string,
  userId: string,
): Promise<void> {
  assertTokenScope(caller, 'write');
  const access = await loadSessionForParticipant(ctx, caller, sessionId);
  if (userId !== caller.user.id) assertCanShare(access);
  const removed = await ctx.prisma.sessionCollaborator.deleteMany({
    where: { sessionId, userId },
  });
  if (removed.count === 0) {
    throw new AppError('LSE-NF-001', { devMessage: 'This session is not shared with that user' });
  }
  await ctx.audit.record({
    orgId: access.session.project.orgId,
    actorId: caller.user.id,
    action: 'session.unshare',
    target: sessionId,
    meta: { userId, self: userId === caller.user.id },
    ip: caller.ip,
  });
  // Losing the share also loses control of the session.
  if (access.session.controllerId === userId) await clearControl(ctx, sessionId);
  await publishShares(ctx, sessionId);
}

// ---- control -------------------------------------------------------------------------------

async function clearControl(ctx: AppContext, sessionId: string): Promise<SessionControlDto> {
  const updated = await ctx.prisma.session.update({
    where: { id: sessionId },
    data: { controllerId: null, controlTakenAt: null },
    include: { controller: { select: { name: true, email: true } } },
  });
  const control = toControlDto(updated);
  await publishControl(ctx, control);
  return control;
}

/**
 * `POST /sessions/:id/take-over` (spec §8.18): a co-editor (or org admin) takes the wheel of
 * a running session and switches it to Pro. Only one participant can hold control, so a
 * second taker gets LSE-AGT-017.
 */
export async function takeOver(
  ctx: AppContext,
  caller: Caller,
  sessionId: string,
): Promise<SessionControlDto> {
  assertTokenScope(caller, 'write');
  const access = await loadSessionForParticipant(ctx, caller, sessionId);
  const session = access.session;
  if (access.membership.role === 'VIEWER') {
    throw new AppError('LSE-ORG-002', {
      devMessage: 'Viewers cannot take control of a session',
    });
  }
  if (!access.isOwner && !access.isAdmin && access.collaboratorRole !== 'CO_EDITOR') {
    throw new AppError('LSE-ORG-002', {
      devMessage: 'Only the owner, an org admin or a co-editor can take control',
    });
  }
  if (session.status !== 'RUNNING') {
    throw new AppError('LSE-CONF-001', {
      devMessage: `Only a running session can be taken over (it is ${session.status})`,
    });
  }
  if (session.controllerId && session.controllerId !== caller.user.id) {
    throw new AppError('LSE-AGT-017', {
      devMessage: 'Another participant already has control of this session',
    });
  }
  // Taking over means driving in Pro: the taker must be allowed to use it.
  const org = await ctx.prisma.organization.findUniqueOrThrow({
    where: { id: session.project.orgId },
  });
  const locked = lockedModeFor(access.membership, org);
  if (locked === 'SIMPLE') {
    throw new AppError('LSE-ORG-009', { devMessage: 'Your mode is locked to Simple' });
  }
  const claimed = await ctx.prisma.session.updateMany({
    where: {
      id: sessionId,
      status: 'RUNNING',
      OR: [{ controllerId: null }, { controllerId: caller.user.id }],
    },
    data: { controllerId: caller.user.id, controlTakenAt: new Date(), mode: 'PRO' },
  });
  if (claimed.count === 0) {
    throw new AppError('LSE-AGT-017', {
      devMessage: 'Control was taken by someone else while taking over',
    });
  }
  const fresh = await ctx.prisma.session.findUniqueOrThrow({
    where: { id: sessionId },
    include: { controller: { select: { name: true, email: true } } },
  });
  const control = toControlDto(fresh);
  await ctx.audit.record({
    orgId: session.project.orgId,
    actorId: caller.user.id,
    action: 'session.take_over',
    target: sessionId,
    meta: {
      previousMode: session.mode,
      mode: 'PRO',
      participantRole: access.participantRole,
      ownerId: session.userId,
    },
    ip: caller.ip,
  });
  await publishControl(ctx, control);
  await ctx.sessionEvents
    .publish(sessionId, 'session_status', {
      status: 'RUNNING',
      message: `${control.controllerName ?? 'A developer'} is driving this session now`,
    })
    .catch(() => undefined);
  return control;
}

/** `POST /sessions/:id/release` — the controller hands the session back (owner/admin may force). */
export async function releaseControl(
  ctx: AppContext,
  caller: Caller,
  sessionId: string,
): Promise<SessionControlDto> {
  assertTokenScope(caller, 'write');
  const access = await loadSessionForParticipant(ctx, caller, sessionId);
  const session = access.session;
  const isController = session.controllerId === caller.user.id;
  if (!isController && !access.isOwner && !access.isAdmin) {
    throw new AppError('LSE-ORG-002', {
      devMessage: 'Only the controller, the session owner or an org admin can release control',
    });
  }
  if (!session.controllerId) {
    return toControlDto({ ...session, controller: session.controller ?? null });
  }
  const control = await clearControl(ctx, sessionId);
  await ctx.audit.record({
    orgId: session.project.orgId,
    actorId: caller.user.id,
    action: 'session.release_control',
    target: sessionId,
    meta: { previousControllerId: session.controllerId, forced: !isController },
    ip: caller.ip,
  });
  return control;
}

/**
 * Platform wiring: an ended session has nobody at the wheel, so control is dropped when the
 * session completes or errors (listeners must stay quick — see phase9-design.md §3).
 */
export function registerCollabHandlers(ctx: AppContext, role: PlatformRole): void {
  if (role !== 'api') return;
  const release = async (sessionId: string) => {
    await ctx.prisma.session
      .updateMany({
        where: { id: sessionId, controllerId: { not: null } },
        data: { controllerId: null, controlTakenAt: null },
      })
      .catch((err: unknown) =>
        ctx.logger.warn({ err, sessionId }, 'failed to release session control'),
      );
  };
  ctx.platformEvents.on('session.completed', (e) => release(e.data.session.id));
  ctx.platformEvents.on('session.errored', (e) => release(e.data.session.id));
}
