/**
 * SCIM 2.0 provisioning (RFC 7642/7643/7644) — spec §8.20.
 *
 * Supported: `/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas`, `/Users` (list with
 * `userName eq` / `externalId eq` filters, create, get, replace, patch, delete) and `/Groups`
 * (list, create, get, replace, patch, delete). Bulk, sorting and ETags are advertised as
 * unsupported in `/ServiceProviderConfig`.
 *
 * Security
 * - Bearer tokens are `loose_scim_<random>`; only `sha256(token)` is stored, and the lookup is a
 *   hash lookup (no token value ever reaches a log, response or audit entry).
 * - A token is bound to exactly one org; every query is scoped by `orgId`.
 * - Group names can map to an org role (`SCIM_ROLE_GROUPS`) but **never to OWNER**, so an IdP
 *   admin cannot escalate to org ownership, and the last OWNER can never be deprovisioned.
 */
import {
  MAX_SCIM_TOKENS_PER_ORG,
  SCIM_BASE_PATH,
  SCIM_MAX_PAGE_SIZE,
  SCIM_SCHEMAS,
  SCIM_TOKEN_BYTES,
  SCIM_TOKEN_DEFAULT_TTL_DAYS,
  SCIM_TOKEN_PREFIX,
  API_PREFIX,
  createScimTokenResponseSchema,
  scimTokenDtoSchema,
  type CreateScimTokenResponse,
  type Role,
  type ScimTokenDto,
} from '@loose/shared';
import type { Organization, Prisma, ScimGroup, ScimIdentity, ScimToken } from '@prisma/client';
import type { AppContext } from '../../context';
import { randomToken, sha256Hex } from '../../lib/crypto';
import { AppError } from '../../lib/errors';
import { publishPolicyChanged } from '../../lib/events/revocations';
import type { Actor } from '../org.service';

const DAY_MS = 24 * 60 * 60 * 1000;

// ---- errors ----------------------------------------------------------------------------------

export type ScimErrorType =
  | 'invalidFilter'
  | 'tooMany'
  | 'uniqueness'
  | 'mutability'
  | 'invalidSyntax'
  | 'invalidPath'
  | 'invalidValue'
  | 'noTarget';

/** RFC 7644 §3.12 error. `looseCode` is surfaced in the `x-loose-error-code` header. */
export class ScimError extends Error {
  constructor(
    readonly status: number,
    readonly detail: string,
    readonly scimType?: ScimErrorType,
    readonly looseCode?: string,
  ) {
    super(detail);
    this.name = 'ScimError';
  }

  toBody(): Record<string, unknown> {
    return {
      schemas: [SCIM_SCHEMAS.error],
      status: String(this.status),
      ...(this.scimType ? { scimType: this.scimType } : {}),
      detail: this.detail,
    };
  }
}

// ---- tokens ----------------------------------------------------------------------------------

export function scimBaseUrl(ctx: AppContext): string {
  return `${ctx.env.API_URL.replace(/\/$/, '')}${API_PREFIX}${SCIM_BASE_PATH}`;
}

export function toScimTokenDto(row: ScimToken): ScimTokenDto {
  return scimTokenDtoSchema.parse(row);
}

export async function listScimTokens(ctx: AppContext, orgId: string): Promise<ScimTokenDto[]> {
  const rows = await ctx.prisma.scimToken.findMany({
    where: { orgId, revokedAt: null },
    orderBy: { createdAt: 'asc' },
  });
  return rows.map(toScimTokenDto);
}

export async function createScimToken(
  ctx: AppContext,
  orgId: string,
  actor: Actor,
  name: string,
  expiresInDays: number = SCIM_TOKEN_DEFAULT_TTL_DAYS,
): Promise<CreateScimTokenResponse> {
  const active = await ctx.prisma.scimToken.count({ where: { orgId, revokedAt: null } });
  if (active >= MAX_SCIM_TOKENS_PER_ORG) {
    throw new AppError('LSE-VAL-001', {
      devMessage: `at most ${MAX_SCIM_TOKENS_PER_ORG} active SCIM tokens per organization`,
      fields: { name: [`Revoke an existing token first (limit ${MAX_SCIM_TOKENS_PER_ORG}).`] },
    });
  }
  const token = `${SCIM_TOKEN_PREFIX}${randomToken(SCIM_TOKEN_BYTES)}`;
  // P10-SEC-014: a SCIM token is a privileged service credential, so it always expires.
  const expiresAt = new Date(Date.now() + expiresInDays * DAY_MS);
  // P10-SEC-011: a SCIM credential never exists without its audit row.
  const row = await ctx.prisma.$transaction(
    async (tx) => {
      const created = await tx.scimToken.create({
        data: { orgId, name, hash: sha256Hex(token), createdById: actor.userId, expiresAt },
      });
      await ctx.audit.record(
        {
          orgId,
          actorId: actor.userId,
          action: 'scim_token.create',
          target: created.id,
          meta: { name, expiresAt: expiresAt.toISOString() },
          ip: actor.ip,
        },
        tx,
      );
      return created;
    },
    { maxWait: 10_000, timeout: 15_000 },
  );
  return createScimTokenResponseSchema.parse({
    ...toScimTokenDto(row),
    token,
    scimBaseUrl: scimBaseUrl(ctx),
  });
}

export async function revokeScimToken(
  ctx: AppContext,
  orgId: string,
  actor: Actor,
  id: string,
): Promise<void> {
  const row = await ctx.prisma.scimToken.findFirst({ where: { id, orgId, revokedAt: null } });
  if (!row) throw new AppError('LSE-NF-001', { devMessage: 'SCIM token not found' });
  await ctx.prisma.$transaction(
    async (tx) => {
      await tx.scimToken.update({ where: { id: row.id }, data: { revokedAt: new Date() } });
      await ctx.audit.record(
        {
          orgId,
          actorId: actor.userId,
          action: 'scim_token.revoke',
          target: row.id,
          meta: { name: row.name },
          ip: actor.ip,
        },
        tx,
      );
    },
    { maxWait: 10_000, timeout: 15_000 },
  );
}

export interface ScimAuth {
  token: ScimToken;
  org: Organization;
}

/** Authenticate a SCIM request. Throws ScimError(401) for anything unusable. */
export async function authenticateScim(
  ctx: AppContext,
  authorization: string | undefined,
): Promise<ScimAuth> {
  const unauthorized = new ScimError(
    401,
    'A valid SCIM bearer token is required.',
    undefined,
    'LSE-AUTH-007',
  );
  const match = /^Bearer\s+(\S+)\s*$/i.exec(authorization ?? '');
  const presented = match?.[1];
  if (!presented || !presented.startsWith(SCIM_TOKEN_PREFIX)) throw unauthorized;
  const row = await ctx.prisma.scimToken.findUnique({
    where: { hash: sha256Hex(presented) },
    include: { org: true },
  });
  if (!row || row.revokedAt !== null) throw unauthorized;
  // P10-SEC-014: expired tokens are dead (null = legacy row inserted outside the service).
  if (row.expiresAt !== null && row.expiresAt.getTime() <= Date.now()) throw unauthorized;
  void ctx.prisma.scimToken
    .update({ where: { id: row.id }, data: { lastUsedAt: new Date() } })
    .catch((err: unknown) => ctx.logger.warn({ err }, 'failed to update SCIM token lastUsedAt'));
  const { org, ...token } = row;
  if (!ctx.featureFlags.isEnabled('scim', org)) {
    throw new ScimError(503, 'SCIM is not enabled.', undefined, 'LSE-SYS-007');
  }
  return { token, org };
}

const SCIM_SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * P10-SEC-014: SCIM follows the org lifecycle. While a deletion is pending (`deletionScheduledAt`)
 * provisioning writes are frozen exactly like interactive admin writes (LSE-ORG-012, SCIM 409);
 * reads and discovery stay available so the IdP can still reconcile.
 */
export function assertScimWritable(org: Organization, method: string): void {
  if (SCIM_SAFE_METHODS.has(method.toUpperCase())) return;
  if (!org.deletionScheduledAt) return;
  throw new ScimError(
    409,
    'This organization is scheduled for deletion; provisioning changes are paused.',
    'mutability',
    'LSE-ORG-012',
  );
}

// ---- representation --------------------------------------------------------------------------

interface ScimName {
  givenName?: string;
  familyName?: string;
  formatted?: string;
}

interface ScimAttributes {
  name?: ScimName;
  emails?: { value: string; primary?: boolean; type?: string }[];
}

function attributesOf(row: ScimIdentity): ScimAttributes {
  const raw = row.attributes;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  return raw as ScimAttributes;
}

export function scimUserResource(
  ctx: AppContext,
  row: ScimIdentity & { user: { email: string; name: string | null } },
): Record<string, unknown> {
  const attrs = attributesOf(row);
  return {
    schemas: [SCIM_SCHEMAS.user],
    id: row.id,
    ...(row.externalId ? { externalId: row.externalId } : {}),
    userName: row.userName,
    active: row.active,
    ...(row.displayName ? { displayName: row.displayName } : {}),
    ...(attrs.name ? { name: attrs.name } : {}),
    emails: attrs.emails ?? [{ value: row.user.email, primary: true, type: 'work' }],
    meta: {
      resourceType: 'User',
      created: row.createdAt.toISOString(),
      lastModified: row.updatedAt.toISOString(),
      location: `${scimBaseUrl(ctx)}/Users/${row.id}`,
    },
  };
}

export function scimGroupResource(
  ctx: AppContext,
  row: ScimGroup & { members: { userId: string }[] },
  memberIds: Map<string, string>,
): Record<string, unknown> {
  return {
    schemas: [SCIM_SCHEMAS.group],
    id: row.id,
    ...(row.externalId ? { externalId: row.externalId } : {}),
    displayName: row.displayName,
    members: row.members
      .map((m) => memberIds.get(m.userId))
      .filter((v): v is string => v !== undefined)
      .map((value) => ({ value, type: 'User' })),
    meta: {
      resourceType: 'Group',
      created: row.createdAt.toISOString(),
      lastModified: row.updatedAt.toISOString(),
      location: `${scimBaseUrl(ctx)}/Groups/${row.id}`,
    },
  };
}

export function scimListResponse(
  resources: Record<string, unknown>[],
  totalResults: number,
  startIndex: number,
): Record<string, unknown> {
  return {
    schemas: [SCIM_SCHEMAS.listResponse],
    totalResults,
    itemsPerPage: resources.length,
    startIndex,
    Resources: resources,
  };
}

// ---- filters & paging ------------------------------------------------------------------------

export interface ScimPaging {
  startIndex: number;
  count: number;
}

export function parsePaging(query: Record<string, unknown>): ScimPaging {
  const asInt = (value: unknown, fallback: number) => {
    if (value === undefined) return fallback;
    const n = Number(Array.isArray(value) ? value[0] : value);
    return Number.isInteger(n) ? n : NaN;
  };
  const startIndex = asInt(query.startIndex, 1);
  const count = asInt(query.count, SCIM_MAX_PAGE_SIZE);
  if (Number.isNaN(startIndex) || Number.isNaN(count) || startIndex < 1 || count < 0) {
    throw new ScimError(400, 'startIndex and count must be positive integers.', 'invalidValue');
  }
  return { startIndex, count: Math.min(count, SCIM_MAX_PAGE_SIZE) };
}

export interface ScimFilter {
  attribute: string;
  value: string;
}

const FILTER_REGEX = /^\s*([A-Za-z][A-Za-z0-9_.]{0,63})\s+eq\s+"([^"]{0,320})"\s*$/;

/** Only `<attr> eq "<value>"` is supported (what Okta/Entra/Google send for lookups). */
export function parseFilter(raw: unknown, allowed: readonly string[]): ScimFilter | undefined {
  if (raw === undefined) return undefined;
  const text = Array.isArray(raw) ? String(raw[0]) : String(raw);
  const m = FILTER_REGEX.exec(text);
  if (!m) {
    throw new ScimError(
      400,
      `Only filters of the form \`attr eq "value"\` are supported.`,
      'invalidFilter',
    );
  }
  const attribute = (m[1] as string).toLowerCase();
  const match = allowed.find((a) => a.toLowerCase() === attribute);
  if (!match) {
    throw new ScimError(400, `Filtering on "${m[1] as string}" is not supported.`, 'invalidFilter');
  }
  return { attribute: match, value: m[2] as string };
}

// ---- role mapping ----------------------------------------------------------------------------

/**
 * Group names that map to an org role (lower-case). OWNER is deliberately absent: ownership is
 * never granted by an external directory.
 */
export const SCIM_ROLE_GROUPS: Readonly<Record<string, Role>> = Object.freeze({
  'loose-admins': 'ADMIN',
  'loose-members': 'MEMBER',
  'loose-viewers': 'VIEWER',
});

export function roleForGroupName(displayName: string): Role | null {
  return SCIM_ROLE_GROUPS[displayName.trim().toLowerCase()] ?? null;
}

const ROLE_RANK: Record<Role, number> = { VIEWER: 0, MEMBER: 1, ADMIN: 2, OWNER: 3 };

async function defaultRoleFor(ctx: AppContext, orgId: string): Promise<Role> {
  const connection = await ctx.prisma.ssoConnection.findUnique({
    where: { orgId },
    select: { defaultRole: true },
  });
  return connection?.defaultRole ?? 'MEMBER';
}

/** Effective role of a SCIM-managed member: highest mapped group role, else the default. */
export async function effectiveRole(ctx: AppContext, orgId: string, userId: string): Promise<Role> {
  const rows = await ctx.prisma.scimGroupMember.findMany({
    where: { userId, group: { orgId, role: { not: null } } },
    include: { group: { select: { role: true } } },
  });
  const roles = rows.map((r) => r.group.role).filter((r): r is Role => r !== null);
  if (roles.length === 0) return defaultRoleFor(ctx, orgId);
  return roles.reduce((best, r) => (ROLE_RANK[r] > ROLE_RANK[best] ? r : best), roles[0] as Role);
}

async function ownerCount(ctx: AppContext, orgId: string): Promise<number> {
  return ctx.prisma.orgMember.count({ where: { orgId, role: 'OWNER' } });
}

/** Create or update the org membership of a SCIM-managed user (never demotes an OWNER). */
export async function syncMembership(
  ctx: AppContext,
  orgId: string,
  userId: string,
): Promise<Role> {
  const role = await effectiveRole(ctx, orgId, userId);
  const existing = await ctx.prisma.orgMember.findUnique({
    where: { userId_orgId: { userId, orgId } },
  });
  if (!existing) {
    await ctx.prisma.orgMember.create({ data: { orgId, userId, role } });
    return role;
  }
  if (existing.role === 'OWNER' || existing.role === role) return existing.role;
  await ctx.prisma.orgMember.update({ where: { id: existing.id }, data: { role } });
  await publishPolicyChanged(orgId, { userId }); // REAUDIT-006
  return role;
}

async function removeMembership(ctx: AppContext, orgId: string, userId: string): Promise<void> {
  const existing = await ctx.prisma.orgMember.findUnique({
    where: { userId_orgId: { userId, orgId } },
  });
  if (!existing) return;
  if (existing.role === 'OWNER' && (await ownerCount(ctx, orgId)) <= 1) {
    throw new ScimError(
      409,
      'An organization needs at least one owner.',
      'mutability',
      'LSE-ORG-007',
    );
  }
  await ctx.prisma.orgMember.delete({ where: { id: existing.id } });
  await publishPolicyChanged(orgId, { userId }); // REAUDIT-006
}

// ---- Users -----------------------------------------------------------------------------------

const userInclude = { user: { select: { email: true, name: true } } } as const;

export type ScimUserRow = ScimIdentity & { user: { email: string; name: string | null } };

function normalizeEmail(value: string): string {
  return value.trim().toLowerCase();
}

function emailFromPayload(body: Record<string, unknown>): string {
  const userName = typeof body.userName === 'string' ? normalizeEmail(body.userName) : '';
  const emails = Array.isArray(body.emails) ? (body.emails as Record<string, unknown>[]) : [];
  const primary = emails.find((e) => e.primary === true) ?? emails[0];
  const fromEmails =
    primary && typeof primary.value === 'string' ? normalizeEmail(primary.value) : '';
  const candidate = /.+@.+\..+/.test(userName) ? userName : fromEmails;
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(candidate) || candidate.length > 254) {
    throw new ScimError(
      400,
      'userName must be the user\u2019s email address.',
      'invalidValue',
      'LSE-VAL-001',
    );
  }
  return candidate;
}

function nameFromPayload(body: Record<string, unknown>): ScimAttributes {
  const out: ScimAttributes = {};
  const name = body.name;
  if (name && typeof name === 'object' && !Array.isArray(name)) {
    const n = name as Record<string, unknown>;
    const picked: ScimName = {};
    if (typeof n.givenName === 'string') picked.givenName = n.givenName.slice(0, 100);
    if (typeof n.familyName === 'string') picked.familyName = n.familyName.slice(0, 100);
    if (typeof n.formatted === 'string') picked.formatted = n.formatted.slice(0, 200);
    if (Object.keys(picked).length > 0) out.name = picked;
  }
  if (Array.isArray(body.emails)) {
    out.emails = (body.emails as Record<string, unknown>[])
      .filter((e) => typeof e.value === 'string')
      .slice(0, 5)
      .map((e) => ({
        value: normalizeEmail(e.value as string),
        ...(e.primary === true ? { primary: true } : {}),
        ...(typeof e.type === 'string' ? { type: e.type.slice(0, 32) } : {}),
      }));
  }
  return out;
}

function displayNameOf(body: Record<string, unknown>, attrs: ScimAttributes): string | null {
  if (typeof body.displayName === 'string' && body.displayName.trim().length > 0) {
    return body.displayName.trim().slice(0, 200);
  }
  const n = attrs.name;
  const joined = [n?.givenName, n?.familyName].filter(Boolean).join(' ').trim();
  return joined.length > 0 ? joined : (n?.formatted ?? null);
}

export async function scimFindUser(
  ctx: AppContext,
  orgId: string,
  id: string,
): Promise<ScimUserRow> {
  const row = await ctx.prisma.scimIdentity.findFirst({
    where: { id, orgId },
    include: userInclude,
  });
  if (!row) throw new ScimError(404, `User ${id} not found.`, undefined, 'LSE-NF-001');
  return row;
}

export async function scimListUsers(
  ctx: AppContext,
  orgId: string,
  query: Record<string, unknown>,
): Promise<{ rows: ScimUserRow[]; total: number; startIndex: number }> {
  const paging = parsePaging(query);
  const filter = parseFilter(query.filter, ['userName', 'externalId', 'active']);
  const where: Prisma.ScimIdentityWhereInput = { orgId };
  if (filter?.attribute === 'userName') where.userName = normalizeEmail(filter.value);
  if (filter?.attribute === 'externalId') where.externalId = filter.value;
  if (filter?.attribute === 'active') where.active = filter.value === 'true';
  const total = await ctx.prisma.scimIdentity.count({ where });
  const rows = await ctx.prisma.scimIdentity.findMany({
    where,
    include: userInclude,
    orderBy: { createdAt: 'asc' },
    skip: paging.startIndex - 1,
    take: paging.count,
  });
  return { rows, total, startIndex: paging.startIndex };
}

export async function scimCreateUser(
  ctx: AppContext,
  org: Organization,
  body: Record<string, unknown>,
): Promise<ScimUserRow> {
  const email = emailFromPayload(body);
  const attrs = nameFromPayload(body);
  const existing = await ctx.prisma.scimIdentity.findUnique({
    where: { orgId_userName: { orgId: org.id, userName: email } },
    include: userInclude,
  });
  if (existing) {
    throw new ScimError(409, 'A user with this userName already exists.', 'uniqueness');
  }
  const displayName = displayNameOf(body, attrs);
  const user =
    (await ctx.prisma.user.findUnique({ where: { email } })) ??
    (await ctx.prisma.user.create({ data: { email, name: displayName } }));
  const alreadyLinked = await ctx.prisma.scimIdentity.findUnique({
    where: { orgId_userId: { orgId: org.id, userId: user.id } },
  });
  if (alreadyLinked) {
    throw new ScimError(409, 'This account is already provisioned.', 'uniqueness');
  }
  const active = body.active === undefined ? true : body.active === true;
  const row = await ctx.prisma.scimIdentity.create({
    data: {
      orgId: org.id,
      userId: user.id,
      userName: email,
      externalId: typeof body.externalId === 'string' ? body.externalId.slice(0, 255) : null,
      displayName,
      active,
      attributes: attrs as unknown as Prisma.InputJsonValue,
    },
    include: userInclude,
  });
  if (active) await syncMembership(ctx, org.id, user.id);
  await ctx.audit.record({
    orgId: org.id,
    action: 'scim.user_provision',
    target: user.id,
    meta: { userName: email, active, via: 'scim' },
  });
  return row;
}

interface UserUpdate {
  active?: boolean;
  userName?: string;
  displayName?: string | null;
  externalId?: string | null;
  attributes?: ScimAttributes;
}

async function applyUserUpdate(
  ctx: AppContext,
  org: Organization,
  row: ScimUserRow,
  update: UserUpdate,
): Promise<ScimUserRow> {
  const data: Prisma.ScimIdentityUpdateInput = {};
  if (update.userName !== undefined && update.userName !== row.userName) {
    const clash = await ctx.prisma.scimIdentity.findUnique({
      where: { orgId_userName: { orgId: org.id, userName: update.userName } },
    });
    if (clash && clash.id !== row.id) {
      throw new ScimError(409, 'A user with this userName already exists.', 'uniqueness');
    }
    data.userName = update.userName;
  }
  if (update.displayName !== undefined) data.displayName = update.displayName;
  if (update.externalId !== undefined) data.externalId = update.externalId;
  if (update.attributes !== undefined) {
    data.attributes = {
      ...attributesOf(row),
      ...update.attributes,
    } as unknown as Prisma.InputJsonValue;
  }
  if (update.active !== undefined) data.active = update.active;

  if (update.active === false && row.active) await removeMembership(ctx, org.id, row.userId);
  const updated = await ctx.prisma.scimIdentity.update({
    where: { id: row.id },
    data,
    include: userInclude,
  });
  if (update.active === true && !row.active) await syncMembership(ctx, org.id, row.userId);

  await ctx.audit.record({
    orgId: org.id,
    action: update.active === false ? 'scim.user_deprovision' : 'scim.user_update',
    target: row.userId,
    meta: { userName: updated.userName, active: updated.active, via: 'scim' },
  });
  return updated;
}

export async function scimReplaceUser(
  ctx: AppContext,
  org: Organization,
  id: string,
  body: Record<string, unknown>,
): Promise<ScimUserRow> {
  const row = await scimFindUser(ctx, org.id, id);
  const attrs = nameFromPayload(body);
  return applyUserUpdate(ctx, org, row, {
    userName: emailFromPayload(body),
    displayName: displayNameOf(body, attrs),
    externalId: typeof body.externalId === 'string' ? body.externalId.slice(0, 255) : null,
    attributes: attrs,
    active: body.active === undefined ? row.active : body.active === true,
  });
}

interface PatchOperation {
  op: string;
  path?: string;
  value?: unknown;
}

function parsePatchOps(body: Record<string, unknown>): PatchOperation[] {
  const schemas = Array.isArray(body.schemas) ? (body.schemas as unknown[]) : [];
  if (!schemas.includes(SCIM_SCHEMAS.patchOp)) {
    throw new ScimError(400, 'PATCH requests must use the PatchOp schema.', 'invalidSyntax');
  }
  const ops = Array.isArray(body.Operations) ? (body.Operations as Record<string, unknown>[]) : [];
  if (ops.length === 0 || ops.length > 50) {
    throw new ScimError(400, 'PATCH requires 1-50 operations.', 'invalidSyntax');
  }
  return ops.map((o) => {
    const op = typeof o.op === 'string' ? o.op.toLowerCase() : '';
    if (!['add', 'replace', 'remove'].includes(op)) {
      throw new ScimError(400, `Unsupported PATCH op "${String(o.op)}".`, 'invalidSyntax');
    }
    return {
      op,
      ...(typeof o.path === 'string' ? { path: o.path.trim() } : {}),
      ...(o.value !== undefined ? { value: o.value } : {}),
    };
  });
}

function asBool(value: unknown): boolean {
  return value === true || value === 'true' || value === 'True';
}

export async function scimPatchUser(
  ctx: AppContext,
  org: Organization,
  id: string,
  body: Record<string, unknown>,
): Promise<ScimUserRow> {
  const row = await scimFindUser(ctx, org.id, id);
  const update: UserUpdate = {};
  const attrs: ScimAttributes = {};
  for (const op of parsePatchOps(body)) {
    const path = (op.path ?? '').replace(/^urn:[^:]+:[^:]+:[^:]+:[^:]+:/i, '').toLowerCase();
    if (path === '' && (op.op === 'replace' || op.op === 'add')) {
      // Whole-resource replace: `{op: "replace", value: {active: false, ...}}`
      const value = op.value;
      if (!value || typeof value !== 'object' || Array.isArray(value)) {
        throw new ScimError(400, 'A path-less PATCH needs an object value.', 'invalidValue');
      }
      const v = value as Record<string, unknown>;
      if (v.active !== undefined) update.active = asBool(v.active);
      if (typeof v.userName === 'string') update.userName = normalizeEmail(v.userName);
      if (typeof v.displayName === 'string') update.displayName = v.displayName.slice(0, 200);
      if (typeof v.externalId === 'string') update.externalId = v.externalId.slice(0, 255);
      Object.assign(attrs, nameFromPayload(v));
      continue;
    }
    switch (path) {
      case 'active':
        if (op.op === 'remove') update.active = false;
        else update.active = asBool(op.value);
        break;
      case 'username':
        if (typeof op.value !== 'string') {
          throw new ScimError(400, 'userName must be a string.', 'invalidValue');
        }
        update.userName = normalizeEmail(op.value);
        break;
      case 'displayname':
        update.displayName =
          op.op === 'remove' || typeof op.value !== 'string' ? null : op.value.slice(0, 200);
        break;
      case 'externalid':
        update.externalId =
          op.op === 'remove' || typeof op.value !== 'string' ? null : op.value.slice(0, 255);
        break;
      case 'name':
      case 'name.givenname':
      case 'name.familyname':
      case 'name.formatted': {
        const current = { ...(attrs.name ?? attributesOf(row).name ?? {}) };
        if (path === 'name') Object.assign(current, nameFromPayload({ name: op.value }).name ?? {});
        else {
          const key = path.split('.')[1] as 'givenname' | 'familyname' | 'formatted';
          const field = (
            { givenname: 'givenName', familyname: 'familyName', formatted: 'formatted' } as const
          )[key];
          if (op.op === 'remove') delete current[field];
          else if (typeof op.value === 'string') current[field] = op.value.slice(0, 200);
        }
        attrs.name = current;
        break;
      }
      case 'emails':
        if (op.op === 'remove') attrs.emails = [];
        else Object.assign(attrs, nameFromPayload({ emails: op.value }));
        break;
      default:
        throw new ScimError(400, `PATCH path "${op.path ?? ''}" is not supported.`, 'invalidPath');
    }
  }
  if (Object.keys(attrs).length > 0) update.attributes = attrs;
  if (update.displayName === undefined && attrs.name) {
    update.displayName = displayNameOf({}, attrs);
  }
  return applyUserUpdate(ctx, org, row, update);
}

/** DELETE /Users/:id — deprovision: membership removed, the SCIM record kept inactive. */
export async function scimDeleteUser(
  ctx: AppContext,
  org: Organization,
  id: string,
): Promise<void> {
  const row = await scimFindUser(ctx, org.id, id);
  await removeMembership(ctx, org.id, row.userId);
  await ctx.prisma.scimGroupMember.deleteMany({
    where: { userId: row.userId, group: { orgId: org.id } },
  });
  await ctx.prisma.scimIdentity.update({ where: { id: row.id }, data: { active: false } });
  await ctx.audit.record({
    orgId: org.id,
    action: 'scim.user_deprovision',
    target: row.userId,
    meta: { userName: row.userName, via: 'scim' },
  });
}

// ---- Groups ----------------------------------------------------------------------------------

const groupInclude = { members: { select: { userId: true } } } as const;
export type ScimGroupRow = ScimGroup & { members: { userId: string }[] };

/** Map `userId → ScimIdentity.id` for rendering group members. */
export async function scimMemberIds(
  ctx: AppContext,
  orgId: string,
  userIds: string[],
): Promise<Map<string, string>> {
  if (userIds.length === 0) return new Map();
  const rows = await ctx.prisma.scimIdentity.findMany({
    where: { orgId, userId: { in: [...new Set(userIds)] } },
    select: { id: true, userId: true },
  });
  return new Map(rows.map((r) => [r.userId, r.id]));
}

export async function scimFindGroup(
  ctx: AppContext,
  orgId: string,
  id: string,
): Promise<ScimGroupRow> {
  const row = await ctx.prisma.scimGroup.findFirst({
    where: { id, orgId },
    include: groupInclude,
  });
  if (!row) throw new ScimError(404, `Group ${id} not found.`, undefined, 'LSE-NF-001');
  return row;
}

export async function scimListGroups(
  ctx: AppContext,
  orgId: string,
  query: Record<string, unknown>,
): Promise<{ rows: ScimGroupRow[]; total: number; startIndex: number }> {
  const paging = parsePaging(query);
  const filter = parseFilter(query.filter, ['displayName', 'externalId']);
  const where: Prisma.ScimGroupWhereInput = { orgId };
  if (filter?.attribute === 'displayName') where.displayName = filter.value;
  if (filter?.attribute === 'externalId') where.externalId = filter.value;
  const total = await ctx.prisma.scimGroup.count({ where });
  const rows = await ctx.prisma.scimGroup.findMany({
    where,
    include: groupInclude,
    orderBy: { createdAt: 'asc' },
    skip: paging.startIndex - 1,
    take: paging.count,
  });
  return { rows, total, startIndex: paging.startIndex };
}

function memberValues(value: unknown): string[] {
  const list = Array.isArray(value) ? value : value === undefined ? [] : [value];
  return list
    .map((m) =>
      typeof m === 'string'
        ? m
        : m && typeof m === 'object' && typeof (m as { value?: unknown }).value === 'string'
          ? (m as { value: string }).value
          : null,
    )
    .filter((v): v is string => v !== null)
    .slice(0, 500);
}

/** Resolve SCIM user ids to internal user ids (unknown ids → 400 invalidValue). */
async function resolveMembers(
  ctx: AppContext,
  orgId: string,
  scimUserIds: string[],
): Promise<string[]> {
  if (scimUserIds.length === 0) return [];
  const rows = await ctx.prisma.scimIdentity.findMany({
    where: { orgId, id: { in: [...new Set(scimUserIds)] } },
    select: { id: true, userId: true },
  });
  if (rows.length !== new Set(scimUserIds).size) {
    throw new ScimError(400, 'A group member references an unknown user.', 'invalidValue');
  }
  return rows.map((r) => r.userId);
}

async function auditGroup(
  ctx: AppContext,
  orgId: string,
  row: ScimGroup,
  action: string,
): Promise<void> {
  await ctx.audit.record({
    orgId,
    action: 'scim.group_update',
    target: row.id,
    meta: { displayName: row.displayName, role: row.role, action, via: 'scim' },
  });
}

export async function scimCreateGroup(
  ctx: AppContext,
  org: Organization,
  body: Record<string, unknown>,
): Promise<ScimGroupRow> {
  const displayName =
    typeof body.displayName === 'string' ? body.displayName.trim().slice(0, 200) : '';
  if (displayName.length === 0) {
    throw new ScimError(400, 'displayName is required.', 'invalidValue', 'LSE-VAL-001');
  }
  const existing = await ctx.prisma.scimGroup.findUnique({
    where: { orgId_displayName: { orgId: org.id, displayName } },
  });
  if (existing) throw new ScimError(409, 'A group with this name already exists.', 'uniqueness');
  const userIds = await resolveMembers(ctx, org.id, memberValues(body.members));
  const row = await ctx.prisma.scimGroup.create({
    data: {
      orgId: org.id,
      displayName,
      role: roleForGroupName(displayName),
      externalId: typeof body.externalId === 'string' ? body.externalId.slice(0, 255) : null,
      members: { create: userIds.map((userId) => ({ userId })) },
    },
    include: groupInclude,
  });
  for (const userId of userIds) await syncMembership(ctx, org.id, userId);
  await auditGroup(ctx, org.id, row, 'create');
  return row;
}

async function setGroupMembers(
  ctx: AppContext,
  orgId: string,
  groupId: string,
  userIds: string[],
): Promise<void> {
  const before = await ctx.prisma.scimGroupMember.findMany({
    where: { groupId },
    select: { userId: true },
  });
  await ctx.prisma.scimGroupMember.deleteMany({ where: { groupId } });
  if (userIds.length > 0) {
    await ctx.prisma.scimGroupMember.createMany({
      data: userIds.map((userId) => ({ groupId, userId })),
      skipDuplicates: true,
    });
  }
  const touched = new Set([...before.map((b) => b.userId), ...userIds]);
  for (const userId of touched) await syncMembership(ctx, orgId, userId);
}

export async function scimReplaceGroup(
  ctx: AppContext,
  org: Organization,
  id: string,
  body: Record<string, unknown>,
): Promise<ScimGroupRow> {
  const row = await scimFindGroup(ctx, org.id, id);
  const displayName =
    typeof body.displayName === 'string' && body.displayName.trim().length > 0
      ? body.displayName.trim().slice(0, 200)
      : row.displayName;
  const userIds = await resolveMembers(ctx, org.id, memberValues(body.members));
  await setGroupMembers(ctx, org.id, row.id, userIds);
  const updated = await ctx.prisma.scimGroup.update({
    where: { id: row.id },
    data: {
      displayName,
      role: roleForGroupName(displayName),
      ...(typeof body.externalId === 'string' ? { externalId: body.externalId.slice(0, 255) } : {}),
    },
    include: groupInclude,
  });
  await auditGroup(ctx, org.id, updated, 'replace');
  return updated;
}

export async function scimPatchGroup(
  ctx: AppContext,
  org: Organization,
  id: string,
  body: Record<string, unknown>,
): Promise<ScimGroupRow> {
  const row = await scimFindGroup(ctx, org.id, id);
  let displayName = row.displayName;
  let members = row.members.map((m) => m.userId);
  let membersChanged = false;
  for (const op of parsePatchOps(body)) {
    const path = (op.path ?? '').toLowerCase();
    if (path === 'displayname') {
      if (typeof op.value !== 'string' || op.value.trim().length === 0) {
        throw new ScimError(400, 'displayName must be a non-empty string.', 'invalidValue');
      }
      displayName = op.value.trim().slice(0, 200);
      continue;
    }
    // Okta/Entra send `members` or `members[value eq "id"]`.
    if (path === 'members' || path.startsWith('members[')) {
      const inlineId = /value\s+eq\s+"([^"]+)"/i.exec(op.path ?? '')?.[1];
      const ids = inlineId ? [inlineId] : memberValues(op.value);
      membersChanged = true;
      if (op.op === 'remove') {
        if (ids.length === 0) {
          members = [];
        } else {
          const remove = new Set(await resolveMembers(ctx, org.id, ids));
          members = members.filter((m) => !remove.has(m));
        }
      } else {
        const resolved = await resolveMembers(ctx, org.id, ids);
        members = op.op === 'replace' ? resolved : [...new Set([...members, ...resolved])];
      }
      continue;
    }
    if (path === '' && (op.op === 'replace' || op.op === 'add')) {
      const v =
        op.value && typeof op.value === 'object' && !Array.isArray(op.value)
          ? (op.value as Record<string, unknown>)
          : {};
      if (typeof v.displayName === 'string' && v.displayName.trim().length > 0) {
        displayName = v.displayName.trim().slice(0, 200);
      }
      if (v.members !== undefined) {
        members = await resolveMembers(ctx, org.id, memberValues(v.members));
        membersChanged = true;
      }
      continue;
    }
    throw new ScimError(400, `PATCH path "${op.path ?? ''}" is not supported.`, 'invalidPath');
  }
  if (membersChanged) await setGroupMembers(ctx, org.id, row.id, members);
  const updated = await ctx.prisma.scimGroup.update({
    where: { id: row.id },
    data: { displayName, role: roleForGroupName(displayName) },
    include: groupInclude,
  });
  if (displayName !== row.displayName && membersChanged === false) {
    // A role-mapping change must be applied to the current members.
    for (const userId of members) await syncMembership(ctx, org.id, userId);
  }
  await auditGroup(ctx, org.id, updated, 'patch');
  return updated;
}

export async function scimDeleteGroup(
  ctx: AppContext,
  org: Organization,
  id: string,
): Promise<void> {
  const row = await scimFindGroup(ctx, org.id, id);
  const members = row.members.map((m) => m.userId);
  await ctx.prisma.scimGroup.delete({ where: { id: row.id } });
  for (const userId of members) await syncMembership(ctx, org.id, userId);
  await auditGroup(ctx, org.id, row, 'delete');
}

// ---- discovery documents ---------------------------------------------------------------------

export function serviceProviderConfig(ctx: AppContext): Record<string, unknown> {
  return {
    schemas: [SCIM_SCHEMAS.serviceProviderConfig],
    documentationUri: 'https://docs.loose.ai/scim',
    patch: { supported: true },
    bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
    filter: { supported: true, maxResults: SCIM_MAX_PAGE_SIZE },
    changePassword: { supported: false },
    sort: { supported: false },
    etag: { supported: false },
    authenticationSchemes: [
      {
        type: 'oauthbearertoken',
        name: 'OAuth Bearer Token',
        description: 'A SCIM token created in Organization settings → Security.',
        specUri: 'https://www.rfc-editor.org/rfc/rfc6750',
        primary: true,
      },
    ],
    meta: {
      resourceType: 'ServiceProviderConfig',
      location: `${scimBaseUrl(ctx)}/ServiceProviderConfig`,
    },
  };
}

export function resourceTypes(ctx: AppContext): Record<string, unknown> {
  const base = scimBaseUrl(ctx);
  const types = [
    {
      schemas: [SCIM_SCHEMAS.resourceType],
      id: 'User',
      name: 'User',
      endpoint: '/Users',
      description: 'User Account',
      schema: SCIM_SCHEMAS.user,
      meta: { resourceType: 'ResourceType', location: `${base}/ResourceTypes/User` },
    },
    {
      schemas: [SCIM_SCHEMAS.resourceType],
      id: 'Group',
      name: 'Group',
      endpoint: '/Groups',
      description: 'Group',
      schema: SCIM_SCHEMAS.group,
      meta: { resourceType: 'ResourceType', location: `${base}/ResourceTypes/Group` },
    },
  ];
  return scimListResponse(types, types.length, 1);
}

export function schemas(): Record<string, unknown> {
  const attr = (name: string, type: 'string' | 'boolean' | 'complex', multiValued = false) => ({
    name,
    type,
    multiValued,
    required: false,
    caseExact: false,
    mutability: 'readWrite',
    returned: 'default',
    uniqueness: 'none',
  });
  const list = [
    {
      schemas: [SCIM_SCHEMAS.schema],
      id: SCIM_SCHEMAS.user,
      name: 'User',
      description: 'SCIM core User',
      attributes: [
        { ...attr('userName', 'string'), required: true, uniqueness: 'server' },
        attr('name', 'complex'),
        attr('displayName', 'string'),
        attr('emails', 'complex', true),
        attr('active', 'boolean'),
        attr('externalId', 'string'),
      ],
      meta: { resourceType: 'Schema' },
    },
    {
      schemas: [SCIM_SCHEMAS.schema],
      id: SCIM_SCHEMAS.group,
      name: 'Group',
      description: 'SCIM core Group',
      attributes: [
        { ...attr('displayName', 'string'), required: true },
        attr('members', 'complex', true),
      ],
      meta: { resourceType: 'Schema' },
    },
  ];
  return scimListResponse(list, list.length, 1);
}
