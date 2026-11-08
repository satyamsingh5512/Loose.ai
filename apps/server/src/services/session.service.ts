/**
 * Lucia-style sessions implemented directly (lucia v3 is deprecated).
 * The cookie holds a random token; the DB stores only sha256(token) as the
 * session id, so a database leak doesn't yield usable sessions.
 * 30-day expiry with sliding renewal once less than 15 days remain.
 */
import type { AuthSession, Prisma, PrismaClient, User } from '@prisma/client';
import { SESSION_RENEW_THRESHOLD_MS, SESSION_TOKEN_BYTES, SESSION_TTL_MS } from '@loose/shared';
import { randomToken, sha256Hex } from '../lib/crypto';
import { publishSessionRevoked, publishUserRevoked } from '../lib/events/revocations';

export interface SessionMeta {
  ip?: string | undefined;
  userAgent?: string | undefined;
  /** Phase 10: the session was established through this org's SSO connection. */
  ssoOrgId?: string | undefined;
  ssoConnectionId?: string | undefined;
  /** Phase 10: mark the session as having passed the 2FA challenge right away. */
  mfaVerified?: boolean | undefined;
}

export interface ValidatedSession {
  session: AuthSession;
  user: User;
  /** True when expiry was extended — the cookie must be re-issued. */
  fresh: boolean;
}

const TOKEN_REGEX = /^[A-Za-z0-9_-]{20,128}$/;

export class SessionService {
  constructor(
    private readonly prisma: PrismaClient,
    private readonly now: () => Date = () => new Date(),
  ) {}

  static hashToken(token: string): string {
    return sha256Hex(token);
  }

  async create(
    userId: string,
    meta: SessionMeta = {},
  ): Promise<{ token: string; session: AuthSession }> {
    const token = randomToken(SESSION_TOKEN_BYTES);
    const session = await this.prisma.authSession.create({
      data: {
        id: SessionService.hashToken(token),
        userId,
        expiresAt: new Date(this.now().getTime() + SESSION_TTL_MS),
        ip: meta.ip?.slice(0, 64) ?? null,
        userAgent: meta.userAgent?.slice(0, 512) ?? null,
        ssoOrgId: meta.ssoOrgId ?? null,
        ssoConnectionId: meta.ssoConnectionId ?? null,
        mfaVerifiedAt: meta.mfaVerified ? this.now() : null,
      },
    });
    return { token, session };
  }

  async validate(token: string | undefined): Promise<ValidatedSession | null> {
    if (!token || !TOKEN_REGEX.test(token)) return null;
    const id = SessionService.hashToken(token);
    const row = await this.prisma.authSession.findUnique({
      where: { id },
      include: { user: true },
    });
    if (!row) return null;
    const now = this.now().getTime();
    if (row.expiresAt.getTime() <= now) {
      await this.prisma.authSession.deleteMany({ where: { id } });
      return null;
    }
    const { user, ...session } = row;
    if (row.expiresAt.getTime() - now < SESSION_RENEW_THRESHOLD_MS) {
      const renewed = await this.prisma.authSession.update({
        where: { id },
        data: { expiresAt: new Date(now + SESSION_TTL_MS) },
      });
      return { session: renewed, user, fresh: true };
    }
    return { session, user, fresh: false };
  }

  async invalidate(sessionId: string): Promise<void> {
    await this.prisma.authSession.deleteMany({ where: { id: sessionId } });
    // P10-SEC-003: close WebSockets established with this cookie session (every instance).
    await publishSessionRevoked([sessionId], { reason: 'logout' });
  }

  // ---- Phase 10 (spec §8.20): 2FA challenge state + token rotation ----------------------

  /** Mark a session as having passed the two-step challenge. */
  async markMfaVerified(sessionId: string): Promise<void> {
    await this.prisma.authSession.updateMany({
      where: { id: sessionId },
      data: { mfaVerifiedAt: this.now() },
    });
  }

  /** Drop the challenge state of every session of a user (2FA disabled / secret changed). */
  async clearMfaForUser(userId: string): Promise<void> {
    await this.prisma.authSession.updateMany({
      where: { userId },
      data: { mfaVerifiedAt: null },
    });
  }

  /**
   * Replace a session's token (session fixation protection after a privilege change such as
   * passing the 2FA challenge): a new random token is issued, the old row is deleted and the
   * remaining attributes (user, expiry, ip, user agent, SSO origin) are carried over.
   */
  async rotate(
    sessionId: string,
    opts: { mfaVerified?: boolean } = {},
  ): Promise<{ token: string; session: AuthSession }> {
    const current = await this.prisma.authSession.findUnique({ where: { id: sessionId } });
    if (!current) throw new Error('cannot rotate an unknown session');
    const token = randomToken(SESSION_TOKEN_BYTES);
    const [, session] = await this.prisma.$transaction([
      this.prisma.authSession.delete({ where: { id: current.id } }),
      this.prisma.authSession.create({
        data: {
          id: SessionService.hashToken(token),
          userId: current.userId,
          expiresAt: current.expiresAt,
          ip: current.ip,
          userAgent: current.userAgent,
          ssoOrgId: current.ssoOrgId,
          ssoConnectionId: current.ssoConnectionId,
          mfaVerifiedAt: opts.mfaVerified ? this.now() : current.mfaVerifiedAt,
        },
      }),
    ]);
    // P10-SEC-003: the old token is gone — its sockets must not keep running.
    await publishSessionRevoked([current.id], {
      userId: current.userId,
      reason: 'session_revoked',
    });
    return { token, session };
  }

  async invalidateAllForUser(userId: string): Promise<number> {
    const r = await this.prisma.authSession.deleteMany({ where: { userId } });
    await publishUserRevoked(userId, 'logout');
    return r.count;
  }

  /** Delete every session of a user except `keepSessionId` (credential change, P10-SEC-009). */
  async invalidateOthersForUser(userId: string, keepSessionId?: string): Promise<number> {
    const where = keepSessionId ? { userId, id: { not: keepSessionId } } : { userId };
    const doomed = await this.prisma.authSession.findMany({ where, select: { id: true } });
    const r = await this.prisma.authSession.deleteMany({ where });
    // P10-SEC-003: close the WebSockets of the sessions that were just invalidated.
    await publishSessionRevoked(
      doomed.map((s) => s.id),
      { userId, reason: 'session_revoked' },
    );
    return r.count;
  }

  /**
   * P10-SEC-002: an org's IdP changed (issuer / client id) or its connection was removed. Sessions
   * established through the old connection keep working as ordinary sessions but no longer count
   * as SSO sessions, so enforce-SSO refuses them until the user signs in through the new IdP.
   */
  async dropSsoAssurance(
    ssoConnectionId: string,
    db: PrismaClient | Prisma.TransactionClient = this.prisma,
  ): Promise<number> {
    const r = await db.authSession.updateMany({
      where: { ssoConnectionId },
      data: { ssoConnectionId: null, ssoOrgId: null },
    });
    return r.count;
  }

  async listForUser(userId: string): Promise<AuthSession[]> {
    return this.prisma.authSession.findMany({
      where: { userId, expiresAt: { gt: this.now() } },
      orderBy: { createdAt: 'desc' },
    });
  }
}
