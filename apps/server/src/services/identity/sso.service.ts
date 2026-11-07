/**
 * Org SSO (OIDC) — spec §8.20. One connection per org; sign-in runs the authorization-code flow
 * with PKCE (S256), `state` and `nonce`, and the ID token is verified against the IdP's JWKS
 * (see `jwt.ts`). SAML is accepted by the DTO but gated behind the `sso_saml` feature flag
 * (off by default, see phase10-design.md §1) — we never hand-roll XML-DSig.
 *
 * Security notes
 * - The client secret is envelope-encrypted and never returned by any endpoint.
 * - `state` is bound to a short-lived HttpOnly cookie *and* consumed once through `ctx.kv`, so a
 *   replayed callback fails even when the cookie is still present.
 * - The org in the callback must match the org the flow started for (`SSO_ORG_COOKIE`).
 * - JIT provisioning only matches/creates accounts whose email domain is a *verified* org domain,
 *   and requires `email_verified: true`. An IdP subject is never silently merged into an
 *   existing account by email (P10-SEC-001): see `linkDecision`; otherwise LSE-AUTH-005.
 */
import {
  API_PREFIX,
  ssoConnectionDtoSchema,
  ssoDiscoverDtoSchema,
  ssoTestResultDtoSchema,
  type Role,
  type SsoConnectionDto,
  type SsoDiscoverDto,
  type SsoTestResultDto,
  type UpsertSsoConnectionBody,
} from '@loose/shared';
import { Prisma } from '@prisma/client';
import type { AuthSession, Organization, SsoConnection, User } from '@prisma/client';
import type { AppContext } from '../../context';
import { bytes, randomToken, safeEqual, sha256Hex } from '../../lib/crypto';
import { AppError } from '../../lib/errors';
import { publishPolicyChanged } from '../../lib/events/revocations';
import type { Actor } from '../org.service';
import { emailDomain, verifiedDomainNames } from './domains.service';
import { verifyIdToken, type IdTokenClaims } from './jwt';
import {
  authorizationUrl,
  exchangeCode,
  fetchDiscovery,
  fetchJwks,
  getSsoMetadata,
  pkcePair,
  refreshJwks,
} from './oidc';

const ENC_PURPOSE = 'oauth-token' as const;
/** `state` is single use for this long (matches the cookie TTL). */
const STATE_TTL_SEC = 600;

export function ssoRedirectUri(ctx: AppContext, orgSlug: string): string {
  const base = ctx.env.API_URL.replace(/\/$/, '');
  return `${base}${API_PREFIX}/auth/sso/${encodeURIComponent(orgSlug)}/callback`;
}

export function ssoAcsUrl(ctx: AppContext, orgSlug: string): string {
  const base = ctx.env.API_URL.replace(/\/$/, '');
  return `${base}${API_PREFIX}/auth/sso/${encodeURIComponent(orgSlug)}/saml/acs`;
}

export function toSsoConnectionDto(
  ctx: AppContext,
  org: Pick<Organization, 'slug'>,
  row: SsoConnection,
): SsoConnectionDto {
  return ssoConnectionDtoSchema.parse({
    ...row,
    hasClientSecret: row.clientSecretEnc !== null,
    hasSamlCertificate: row.samlCertificate !== null,
    redirectUri: ssoRedirectUri(ctx, org.slug),
    acsUrl: ssoAcsUrl(ctx, org.slug),
  });
}

export async function getSsoConnection(
  ctx: AppContext,
  orgId: string,
): Promise<SsoConnection | null> {
  return ctx.prisma.ssoConnection.findUnique({ where: { orgId } });
}

export async function getSsoConnectionDto(
  ctx: AppContext,
  org: Organization,
): Promise<SsoConnectionDto | null> {
  const row = await getSsoConnection(ctx, org.id);
  return row ? toSsoConnectionDto(ctx, org, row) : null;
}

function assertProtocolAvailable(ctx: AppContext, protocol: 'OIDC' | 'SAML'): void {
  ctx.featureFlags.assertEnabled(protocol === 'SAML' ? 'sso_saml' : 'sso_oidc');
}

function assertIssuerAllowed(ctx: AppContext, issuer: string): void {
  let url: URL;
  try {
    url = new URL(issuer);
  } catch {
    throw new AppError('LSE-VAL-001', { fields: { issuer: ['Enter a valid https URL'] } });
  }
  if (url.protocol === 'https:') return;
  const host = url.hostname.toLowerCase();
  const localhost = host === 'localhost' || host === '127.0.0.1' || host === '::1';
  if (ctx.env.NODE_ENV === 'production' || !localhost) {
    throw new AppError('LSE-VAL-001', {
      devMessage: 'OIDC issuers must use https (http is only allowed for localhost in dev)',
      fields: { issuer: ['Use an https URL'] },
    });
  }
}

/**
 * P10-SEC-002: the org moved to another IdP (issuer / client id changed) or removed its
 * connection. Sessions and PATs that drew their SSO assurance from the old connection stop
 * counting as SSO-authenticated, so enforce-SSO refuses them until the user signs in again.
 */
async function dropSsoAssurance(
  ctx: AppContext,
  tx: Prisma.TransactionClient,
  connectionId: string,
): Promise<void> {
  await ctx.sessions.dropSsoAssurance(connectionId, tx);
  await tx.apiToken.updateMany({
    where: { ssoConnectionId: connectionId },
    data: { ssoConnectionId: null },
  });
}

export async function upsertSsoConnection(
  ctx: AppContext,
  org: Organization,
  actor: Actor,
  body: UpsertSsoConnectionBody,
): Promise<SsoConnectionDto> {
  assertProtocolAvailable(ctx, body.protocol);
  const existing = await getSsoConnection(ctx, org.id);
  const common = {
    protocol: body.protocol,
    enabled: body.enabled,
    defaultRole: body.defaultRole as Role,
    jitProvisioning: body.jitProvisioning,
    enforce: body.enforce,
    allowOwnerBypass: body.allowOwnerBypass,
  };

  if (body.protocol === 'SAML') {
    // Unreachable while `sso_saml` is off; kept so enabling the flag is a one-line change.
    const row = await inTx(ctx, async (tx) => {
      if (existing && existing.issuer !== body.entityId)
        await dropSsoAssurance(ctx, tx, existing.id);
      const saved = await tx.ssoConnection.upsert({
        where: { orgId: org.id },
        create: {
          orgId: org.id,
          ...common,
          issuer: body.entityId,
          samlEntityId: body.entityId,
          samlSsoUrl: body.ssoUrl,
          samlCertificate: body.certificate,
        },
        update: {
          ...common,
          issuer: body.entityId,
          samlEntityId: body.entityId,
          samlSsoUrl: body.ssoUrl,
          samlCertificate: body.certificate,
          metadata: Prisma.DbNull,
        },
      });
      await auditConnection(ctx, tx, org.id, actor, saved);
      return saved;
    });
    // REAUDIT-006: after commit, every instance re-validates this org's live sockets.
    await publishPolicyChanged(org.id);
    return toSsoConnectionDto(ctx, org, row);
  }

  assertIssuerAllowed(ctx, body.issuer);
  if (!body.clientSecret && !existing?.clientSecretEnc) {
    throw new AppError('LSE-VAL-001', {
      devMessage: 'a client secret is required',
      fields: { clientSecret: ['Enter the client secret from your identity provider'] },
    });
  }
  const secretEnc = body.clientSecret
    ? bytes(await ctx.crypto.encryptPacked(body.clientSecret, ENC_PURPOSE))
    : undefined;
  // Enabling a connection validates it live, so a typo can't lock an org out of its own SSO.
  if (body.enabled) await fetchDiscovery(ctx, body.issuer);
  const issuerChanged = existing?.issuer !== body.issuer;
  const row = await inTx(ctx, async (tx) => {
    if (existing && (issuerChanged || existing.clientId !== body.clientId)) {
      await dropSsoAssurance(ctx, tx, existing.id);
    }
    const saved = await tx.ssoConnection.upsert({
      where: { orgId: org.id },
      create: {
        orgId: org.id,
        ...common,
        issuer: body.issuer,
        clientId: body.clientId,
        ...(secretEnc ? { clientSecretEnc: secretEnc } : {}),
      },
      update: {
        ...common,
        issuer: body.issuer,
        clientId: body.clientId,
        ...(secretEnc ? { clientSecretEnc: secretEnc } : {}),
        ...(issuerChanged ? { metadata: Prisma.DbNull } : {}),
        samlEntityId: null,
        samlSsoUrl: null,
        samlCertificate: null,
      },
    });
    await auditConnection(ctx, tx, org.id, actor, saved);
    return saved;
  });
  // REAUDIT-006: after commit, every instance re-validates this org's live sockets (sessions /
  // PATs whose assurance came from a replaced connection, or newly enforced SSO).
  await publishPolicyChanged(org.id);
  return toSsoConnectionDto(ctx, org, row);
}

/**
 * P10-SEC-011: SSO configuration changes and their audit row commit (or roll back) together, so
 * a failed audit append can never leave an unaudited IdP change behind.
 */
function inTx<T>(ctx: AppContext, fn: (tx: Prisma.TransactionClient) => Promise<T>): Promise<T> {
  return ctx.prisma.$transaction(fn, { maxWait: 10_000, timeout: 15_000 });
}

async function auditConnection(
  ctx: AppContext,
  tx: Prisma.TransactionClient,
  orgId: string,
  actor: Actor,
  row: SsoConnection,
): Promise<void> {
  await ctx.audit.record(
    {
      orgId,
      actorId: actor.userId,
      action: 'sso.update',
      target: row.id,
      // No secret, no issuer credentials — only the switches an auditor needs.
      meta: {
        protocol: row.protocol,
        enabled: row.enabled,
        enforce: row.enforce,
        jitProvisioning: row.jitProvisioning,
        defaultRole: row.defaultRole,
        allowOwnerBypass: row.allowOwnerBypass,
        issuerHost: safeHost(row.issuer),
      },
      ip: actor.ip,
    },
    tx,
  );
}

function safeHost(value: string): string | null {
  try {
    return new URL(value).host;
  } catch {
    return null;
  }
}

export async function deleteSsoConnection(
  ctx: AppContext,
  org: Organization,
  actor: Actor,
): Promise<void> {
  const row = await getSsoConnection(ctx, org.id);
  if (!row) throw new AppError('LSE-NF-001', { devMessage: 'no SSO connection' });
  await inTx(ctx, async (tx) => {
    await dropSsoAssurance(ctx, tx, row.id);
    await tx.ssoConnection.delete({ where: { id: row.id } });
    await ctx.audit.record(
      {
        orgId: org.id,
        actorId: actor.userId,
        action: 'sso.delete',
        target: row.id,
        ip: actor.ip,
      },
      tx,
    );
  });
  // REAUDIT-006: sockets whose SSO assurance came from the deleted connection.
  await publishPolicyChanged(org.id);
}

export async function testSsoConnection(
  ctx: AppContext,
  org: Organization,
): Promise<SsoTestResultDto> {
  const row = await getSsoConnection(ctx, org.id);
  if (!row) throw new AppError('LSE-NF-001', { devMessage: 'no SSO connection' });
  assertProtocolAvailable(ctx, row.protocol);
  const checks: SsoTestResultDto['checks'] = [];
  try {
    const discovery = await fetchDiscovery(ctx, row.issuer);
    checks.push({ name: 'discovery', ok: true, message: 'Discovery document loaded' });
    checks.push({
      name: 'token_endpoint',
      ok: true,
      message: `Token endpoint: ${safeHost(discovery.token_endpoint) ?? 'unknown'}`,
    });
    try {
      const jwks = await fetchJwks(ctx, discovery.jwks_uri);
      checks.push({ name: 'jwks', ok: true, message: `${jwks.keys.length} signing key(s)` });
    } catch (err) {
      checks.push({ name: 'jwks', ok: false, message: messageOf(err) });
    }
  } catch (err) {
    checks.push({ name: 'discovery', ok: false, message: messageOf(err) });
  }
  return ssoTestResultDtoSchema.parse({ ok: checks.every((c) => c.ok), checks });
}

function messageOf(err: unknown): string {
  if (err instanceof AppError) return err.devMessage ?? err.title;
  return err instanceof Error ? err.message : 'Unknown error';
}

// ---- discovery by email ----------------------------------------------------------------------

export async function discoverSso(ctx: AppContext, email: string): Promise<SsoDiscoverDto> {
  const none = {
    sso: false,
    orgSlug: null,
    orgName: null,
    protocol: null,
    enforced: false,
    startUrl: null,
  };
  if (!ctx.featureFlags.isEnabled('sso_oidc')) return ssoDiscoverDtoSchema.parse(none);
  const domain = emailDomain(email);
  if (!domain) return ssoDiscoverDtoSchema.parse(none);
  const row = await ctx.prisma.orgDomain.findFirst({
    where: { domain, verifiedAt: { not: null } },
    include: { org: { include: { ssoConnection: true } } },
  });
  const connection = row?.org.ssoConnection;
  if (!row || !connection || !connection.enabled) return ssoDiscoverDtoSchema.parse(none);
  return ssoDiscoverDtoSchema.parse({
    sso: true,
    orgSlug: row.org.slug,
    orgName: row.org.name,
    protocol: connection.protocol,
    enforced: connection.enforce,
    startUrl: `${API_PREFIX}/auth/sso/${row.org.slug}/start`,
  });
}

// ---- sign-in ---------------------------------------------------------------------------------

export interface SsoStartResult {
  url: string;
  orgId: string;
  state: string;
  nonce: string;
  verifier: string;
}

async function enabledConnectionForSlug(
  ctx: AppContext,
  orgSlug: string,
): Promise<{ org: Organization; connection: SsoConnection }> {
  const org = await ctx.prisma.organization.findUnique({
    where: { slug: orgSlug },
    include: { ssoConnection: true },
  });
  if (!org) throw new AppError('LSE-ORG-003', { devMessage: 'unknown organization' });
  const { ssoConnection, ...plain } = org;
  if (!ssoConnection || !ssoConnection.enabled) {
    throw new AppError('LSE-AUTH-004', { devMessage: 'SSO is not enabled for this organization' });
  }
  assertProtocolAvailable(ctx, ssoConnection.protocol);
  return { org: plain as Organization, connection: ssoConnection };
}

export async function beginSso(ctx: AppContext, orgSlug: string): Promise<SsoStartResult> {
  const { org, connection } = await enabledConnectionForSlug(ctx, orgSlug);
  const meta = await getSsoMetadata(ctx, connection);
  const { verifier, challenge } = pkcePair();
  const state = randomToken(32);
  const nonce = randomToken(32);
  return {
    url: authorizationUrl({
      discovery: meta.discovery,
      clientId: connection.clientId,
      redirectUri: ssoRedirectUri(ctx, org.slug),
      state,
      nonce,
      codeChallenge: challenge,
    }),
    orgId: org.id,
    state,
    nonce,
    verifier,
  };
}

export interface SsoCallbackInput {
  orgSlug: string;
  code: string | undefined;
  state: string | undefined;
  cookies: {
    state?: string | undefined;
    nonce?: string | undefined;
    verifier?: string | undefined;
    orgId?: string | undefined;
  };
  ip?: string | undefined;
  userAgent?: string | undefined;
  /** The caller's existing `loose_session` cookie, if any (explicit account linking). */
  sessionToken?: string | undefined;
}

/** The live session behind the callback's existing session cookie (null when absent/expired). */
async function signedInSession(
  ctx: AppContext,
  token: string | undefined,
): Promise<AuthSession | null> {
  if (!token) return null;
  const validated = await ctx.sessions.validate(token);
  return validated?.session ?? null;
}

export interface SsoCallbackResult {
  user: User;
  session: AuthSession;
  token: string;
  orgId: string;
}

/** Single-use `state`: false when this state was already consumed. */
async function consumeState(ctx: AppContext, state: string): Promise<boolean> {
  try {
    return await ctx.kv.setIfAbsent(`sso:state:${sha256Hex(state)}`, '1', STATE_TTL_SEC);
  } catch {
    // Store unavailable: the cookie binding below is still enforced.
    return true;
  }
}

export async function completeSso(
  ctx: AppContext,
  input: SsoCallbackInput,
): Promise<SsoCallbackResult> {
  const { org, connection } = await enabledConnectionForSlug(ctx, input.orgSlug);
  const { cookies } = input;
  if (!input.state || !safeEqual(input.state, cookies.state)) {
    throw new AppError('LSE-AUTH-011', { devMessage: 'SSO state mismatch' });
  }
  if (!cookies.orgId || !safeEqual(cookies.orgId, org.id)) {
    throw new AppError('LSE-AUTH-011', { devMessage: 'SSO state belongs to another organization' });
  }
  if (!cookies.nonce || !cookies.verifier) {
    throw new AppError('LSE-AUTH-011', { devMessage: 'SSO nonce/verifier cookie missing' });
  }
  if (!input.code) throw new AppError('LSE-AUTH-002', { devMessage: 'missing code' });
  if (!(await consumeState(ctx, input.state))) {
    throw new AppError('LSE-AUTH-011', { devMessage: 'SSO state was already used' });
  }

  const meta = await getSsoMetadata(ctx, connection);
  const clientSecret = connection.clientSecretEnc
    ? await ctx.crypto.decryptPackedString(connection.clientSecretEnc, ENC_PURPOSE)
    : undefined;
  const tokens = await exchangeCode(ctx, {
    discovery: meta.discovery,
    clientId: connection.clientId,
    clientSecret,
    code: input.code,
    redirectUri: ssoRedirectUri(ctx, org.slug),
    codeVerifier: cookies.verifier,
  });
  const claims = await verifyIdToken({
    token: tokens.id_token,
    jwks: meta.jwks,
    issuer: connection.issuer,
    audience: connection.clientId,
    nonce: cookies.nonce,
    refreshJwks: () => refreshJwks(ctx, connection, meta),
  });

  const user = await resolveSsoUser(
    ctx,
    org,
    connection,
    claims,
    await signedInSession(ctx, input.sessionToken),
    input.ip,
  );
  const { token, session } = await ctx.sessions.create(user.id, {
    ip: input.ip,
    userAgent: input.userAgent,
    ssoOrgId: org.id,
    ssoConnectionId: connection.id,
  });
  await ctx.prisma.ssoConnection.update({
    where: { id: connection.id },
    data: { lastLoginAt: new Date() },
  });
  await ctx.audit.record({
    orgId: org.id,
    actorId: user.id,
    action: 'auth.sso_sign_in',
    target: user.id,
    meta: { connectionId: connection.id, protocol: connection.protocol },
    ip: input.ip,
  });
  ctx.metrics
    .counter('loose_auth_events_total', 'Authentication events', ['event'])
    .inc({ event: 'sign_in' });
  return { user, session, token, orgId: org.id };
}

/**
 * P10-SEC-001: may this (not yet linked) IdP subject be attached to the existing account
 * `existing` whose email it asserts? The caller already checked that the email domain is a
 * *verified* domain of `org`. Domain control alone never authorizes taking over a global
 * account; one of these must also hold:
 *
 * - `signed_in`: the callback request carries a live session of that very account (and, when
 *   the account uses 2FA, that session passed the challenge) — explicit, consented linking.
 * - `member`: the account already belongs to this org by its own action (invite / creation),
 *   i.e. the membership was not created by this org's SCIM provisioning (which an org admin
 *   controls and which would otherwise let them manufacture the precondition).
 *
 * Returns null when linking must be refused.
 */
async function linkDecision(
  ctx: AppContext,
  org: Organization,
  existing: User,
  signedIn: AuthSession | null,
): Promise<'signed_in' | 'member' | null> {
  if (
    signedIn &&
    signedIn.userId === existing.id &&
    (!existing.totpEnabledAt || signedIn.mfaVerifiedAt !== null)
  ) {
    return 'signed_in';
  }
  const membership = await ctx.prisma.orgMember.findUnique({
    where: { userId_orgId: { userId: existing.id, orgId: org.id } },
  });
  if (!membership) return null;
  const scim = await ctx.prisma.scimIdentity.findUnique({
    where: { orgId_userId: { orgId: org.id, userId: existing.id } },
    select: { createdAt: true },
  });
  // Membership created by (or after) SCIM provisioning of this account is not consent.
  if (scim && scim.createdAt.getTime() <= membership.createdAt.getTime()) return null;
  return 'member';
}

/** Highest org role mapped by the user's SCIM groups, if any. */
async function scimGroupRole(ctx: AppContext, orgId: string, userId: string): Promise<Role | null> {
  const rows = await ctx.prisma.scimGroupMember.findMany({
    where: { userId, group: { orgId, role: { not: null } } },
    include: { group: { select: { role: true } } },
  });
  const roles = rows.map((r) => r.group.role).filter((r): r is Role => r !== null);
  if (roles.length === 0) return null;
  const rank: Record<Role, number> = { VIEWER: 0, MEMBER: 1, ADMIN: 2, OWNER: 3 };
  return roles.reduce((best, r) => (rank[r] > rank[best] ? r : best), roles[0] as Role);
}

async function resolveSsoUser(
  ctx: AppContext,
  org: Organization,
  connection: SsoConnection,
  claims: IdTokenClaims,
  signedIn: AuthSession | null,
  ip: string | undefined,
): Promise<User> {
  const email = typeof claims.email === 'string' ? claims.email.trim().toLowerCase() : '';
  if (claims.email_verified === false) {
    throw new AppError('LSE-AUTH-011', { devMessage: 'IdP reports the email as unverified' });
  }
  const identity = await ctx.prisma.ssoIdentity.findUnique({
    where: { connectionId_subject: { connectionId: connection.id, subject: claims.sub } },
    include: { user: true },
  });
  let user = identity?.user ?? null;
  let jitUser: { email: string; name: string | null } | null = null;
  let linkedVia: 'signed_in' | 'member' | null = null;

  if (!user) {
    if (email.length === 0) {
      throw new AppError('LSE-AUTH-011', { devMessage: 'id_token has no email claim' });
    }
    // P10-SEC-001: the email becomes (or selects) a global account here, so the IdP must
    // positively assert it — a missing `email_verified` claim is not enough.
    if (claims.email_verified !== true) {
      throw new AppError('LSE-AUTH-011', {
        devMessage: 'IdP did not assert email_verified=true for a first-time sign-in',
      });
    }
    const domain = emailDomain(email);
    const verified = await verifiedDomainNames(ctx, org.id);
    if (!domain || !verified.includes(domain)) {
      throw new AppError('LSE-AUTH-006', {
        devMessage: 'email domain is not a verified domain of this organization',
      });
    }
    const existing = await ctx.prisma.user.findUnique({ where: { email } });
    if (existing) {
      // P10-SEC-001: never silently merge an IdP subject into an existing global account.
      const via = await linkDecision(ctx, org, existing, signedIn);
      if (!via) {
        await ctx.audit.record({
          orgId: org.id,
          action: 'auth.sso_link_refused',
          target: existing.id,
          meta: { connectionId: connection.id, reason: 'existing_account' },
          ip,
        });
        throw new AppError('LSE-AUTH-005', {
          devMessage:
            'an account with this email already exists; sign in with its usual method first, then sign in with SSO to link it',
        });
      }
      // P10-SEC-011: the link audit is written inside the identity transaction below.
      linkedVia = via;
      user = existing;
    } else {
      if (!connection.jitProvisioning) {
        throw new AppError('LSE-ORG-001', {
          devMessage: 'no account for this email and JIT provisioning is off',
        });
      }
      jitUser = { email, name: typeof claims.name === 'string' ? claims.name.slice(0, 100) : null };
    }
  }

  // P10-SEC-011: the JIT account, the identity link (and its `auth.sso_linked` audit), the JIT
  // membership and its audit row commit (or roll back) together, so a failed audit append leaves
  // nothing provisioned or linked.
  const known = user;
  return inTx(ctx, async (tx) => {
    const u = known ?? (await tx.user.create({ data: jitUser! }));
    await tx.ssoIdentity.upsert({
      where: { connectionId_subject: { connectionId: connection.id, subject: claims.sub } },
      create: {
        connectionId: connection.id,
        userId: u.id,
        subject: claims.sub,
        email: email || u.email,
        lastLoginAt: new Date(),
      },
      update: { lastLoginAt: new Date(), email: email || u.email },
    });
    if (linkedVia) {
      await ctx.audit.record(
        {
          orgId: org.id,
          actorId: u.id,
          action: 'auth.sso_linked',
          target: u.id,
          meta: { connectionId: connection.id, via: linkedVia },
          ip,
        },
        tx,
      );
    }

    const membership = known
      ? await tx.orgMember.findUnique({ where: { userId_orgId: { userId: u.id, orgId: org.id } } })
      : null;
    if (!membership) {
      if (!connection.jitProvisioning) {
        throw new AppError('LSE-ORG-001', {
          devMessage: 'user is not a member and JIT provisioning is off',
        });
      }
      // A brand-new account has no SCIM group memberships yet.
      const role =
        (known ? await scimGroupRole(ctx, org.id, u.id) : null) ?? connection.defaultRole;
      await tx.orgMember.create({ data: { userId: u.id, orgId: org.id, role } });
      await ctx.audit.record(
        {
          orgId: org.id,
          actorId: u.id,
          action: 'member.role_change',
          target: u.id,
          meta: { role, via: 'sso_jit' },
          ip,
        },
        tx,
      );
    }
    return u;
  });
}

/**
 * Enforce-SSO decision for `enforceOrgAccess`: `true` when this session must have been
 * established through the org's SSO connection.
 */
export function ssoRequiredFor(
  connection: Pick<SsoConnection, 'enabled' | 'enforce' | 'allowOwnerBypass'> | null,
  role: Role,
  userEmail: string,
  verifiedDomains: readonly string[],
): boolean {
  if (!connection || !connection.enabled || !connection.enforce) return false;
  if (role === 'OWNER' && connection.allowOwnerBypass) return false;
  const domain = emailDomain(userEmail);
  return domain !== null && verifiedDomains.includes(domain);
}
