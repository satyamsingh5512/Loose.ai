/**
 * OIDC relying-party plumbing: discovery, JWKS caching (with rotation), PKCE and the
 * authorization-code exchange. Every outbound call goes through `safeFetch` (SSRF guard: no
 * redirects, pinned/validated address, timeout + size cap) and never logs response bodies.
 *
 * The discovery document and JWKS are cached in `SsoConnection.metadata` for
 * `SSO_METADATA_TTL_SEC`; an unknown `kid` triggers a JWKS refetch at most once per
 * `JWKS_MIN_REFRESH_SEC` so a hostile IdP cannot be used to hammer us.
 */
import { createHash, randomBytes } from 'node:crypto';
import { z } from 'zod';
import { SSO_METADATA_TTL_SEC } from '@loose/shared';
import type { Prisma, SsoConnection } from '@prisma/client';
import type { AppContext } from '../../context';
import { AppError } from '../../lib/errors';
import { safeFetch } from '../../lib/net/safeFetch';
import type { JwkSet } from './jwt';

export const JWKS_MIN_REFRESH_SEC = 60;
const MAX_METADATA_BYTES = 256 * 1024;

const urlString = z.url({ protocol: /^https?$/ }).max(2048);

export const oidcDiscoverySchema = z
  .object({
    issuer: z.string().min(1).max(2048),
    authorization_endpoint: urlString,
    token_endpoint: urlString,
    jwks_uri: urlString,
    userinfo_endpoint: urlString.optional(),
    end_session_endpoint: urlString.optional(),
    scopes_supported: z.array(z.string().max(100)).max(200).optional(),
    response_types_supported: z.array(z.string().max(100)).max(100).optional(),
    id_token_signing_alg_values_supported: z.array(z.string().max(32)).max(100).optional(),
    token_endpoint_auth_methods_supported: z.array(z.string().max(64)).max(50).optional(),
    code_challenge_methods_supported: z.array(z.string().max(32)).max(20).optional(),
  })
  .loose();
export type OidcDiscovery = z.infer<typeof oidcDiscoverySchema>;

const jwkSchema = z
  .object({
    kty: z.string().min(1).max(16),
    kid: z.string().max(256).optional(),
    alg: z.string().max(16).optional(),
    use: z.string().max(16).optional(),
    n: z.string().max(4096).optional(),
    e: z.string().max(64).optional(),
    crv: z.string().max(32).optional(),
    x: z.string().max(512).optional(),
    y: z.string().max(512).optional(),
  })
  .loose();

export const jwkSetSchema = z.object({ keys: z.array(jwkSchema).max(50) });

export interface SsoMetadata {
  discovery: OidcDiscovery;
  jwks: JwkSet;
  /** Epoch ms of the discovery fetch. */
  fetchedAt: number;
  /** Epoch ms of the last JWKS fetch. */
  jwksFetchedAt: number;
}

function discoveryUrl(issuer: string): string {
  return `${issuer.replace(/\/+$/, '')}/.well-known/openid-configuration`;
}

function assertSameIssuer(expected: string, actual: string): void {
  if (expected.replace(/\/+$/, '') !== actual.replace(/\/+$/, '')) {
    throw new AppError('LSE-AUTH-011', {
      devMessage: 'discovery document issuer does not match the configured issuer',
    });
  }
}

async function getJson(ctx: AppContext, url: string, what: string): Promise<unknown> {
  const res = await safeFetch(ctx, url, {
    errorCode: 'LSE-AUTH-004',
    timeoutMs: ctx.env.SSO_HTTP_TIMEOUT_MS,
    maxResponseBytes: MAX_METADATA_BYTES,
    headers: { accept: 'application/json' },
  });
  if (!res.ok) {
    throw new AppError('LSE-AUTH-004', {
      devMessage: `${what} request failed with status ${res.status}`,
    });
  }
  try {
    return (await res.json()) as unknown;
  } catch (cause) {
    throw new AppError('LSE-AUTH-004', { devMessage: `${what} response was not JSON`, cause });
  }
}

export async function fetchDiscovery(ctx: AppContext, issuer: string): Promise<OidcDiscovery> {
  const parsed = oidcDiscoverySchema.safeParse(
    await getJson(ctx, discoveryUrl(issuer), 'OIDC discovery'),
  );
  if (!parsed.success) {
    throw new AppError('LSE-AUTH-004', {
      devMessage: 'OIDC discovery document is missing required endpoints',
    });
  }
  assertSameIssuer(issuer, parsed.data.issuer);
  return parsed.data;
}

export async function fetchJwks(ctx: AppContext, jwksUri: string): Promise<JwkSet> {
  const parsed = jwkSetSchema.safeParse(await getJson(ctx, jwksUri, 'JWKS'));
  if (!parsed.success || parsed.data.keys.length === 0) {
    throw new AppError('LSE-AUTH-004', { devMessage: 'JWKS document has no usable keys' });
  }
  return parsed.data as JwkSet;
}

function readMetadata(connection: Pick<SsoConnection, 'metadata'>): SsoMetadata | null {
  const raw = connection.metadata;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const obj = raw as Record<string, unknown>;
  const discovery = oidcDiscoverySchema.safeParse(obj.discovery);
  const jwks = jwkSetSchema.safeParse(obj.jwks);
  if (!discovery.success || !jwks.success) return null;
  return {
    discovery: discovery.data,
    jwks: jwks.data as JwkSet,
    fetchedAt: typeof obj.fetchedAt === 'number' ? obj.fetchedAt : 0,
    jwksFetchedAt: typeof obj.jwksFetchedAt === 'number' ? obj.jwksFetchedAt : 0,
  };
}

async function storeMetadata(
  ctx: AppContext,
  connectionId: string,
  meta: SsoMetadata,
): Promise<void> {
  await ctx.prisma.ssoConnection
    .update({
      where: { id: connectionId },
      data: { metadata: meta as unknown as Prisma.InputJsonValue },
    })
    .catch((err: unknown) => {
      ctx.logger.warn({ err, connectionId }, 'failed to cache SSO metadata');
    });
}

/** Discovery + JWKS for a connection, fetching and caching when stale. */
export async function getSsoMetadata(
  ctx: AppContext,
  connection: SsoConnection,
  opts: { force?: boolean } = {},
): Promise<SsoMetadata> {
  const cached = readMetadata(connection);
  const fresh =
    cached !== null && Date.now() - cached.fetchedAt < SSO_METADATA_TTL_SEC * 1000 && !opts.force;
  if (fresh && cached) return cached;
  const discovery = await fetchDiscovery(ctx, connection.issuer);
  const jwks = await fetchJwks(ctx, discovery.jwks_uri);
  const meta: SsoMetadata = {
    discovery,
    jwks,
    fetchedAt: Date.now(),
    jwksFetchedAt: Date.now(),
  };
  await storeMetadata(ctx, connection.id, meta);
  return meta;
}

/**
 * Refetch only the JWKS (key rotation). Returns null when the previous fetch is too recent,
 * so an attacker cannot turn unknown `kid`s into an outbound request amplifier.
 */
export async function refreshJwks(
  ctx: AppContext,
  connection: SsoConnection,
  meta: SsoMetadata,
): Promise<JwkSet | null> {
  if (Date.now() - meta.jwksFetchedAt < JWKS_MIN_REFRESH_SEC * 1000) return null;
  const jwks = await fetchJwks(ctx, meta.discovery.jwks_uri);
  await storeMetadata(ctx, connection.id, { ...meta, jwks, jwksFetchedAt: Date.now() });
  return jwks;
}

// ---- PKCE ------------------------------------------------------------------------------------

export interface PkcePair {
  verifier: string;
  challenge: string;
}

export function pkcePair(): PkcePair {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: pkceChallenge(verifier) };
}

export function pkceChallenge(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
}

// ---- authorization request / token exchange ---------------------------------------------------

export interface AuthorizationUrlInput {
  discovery: OidcDiscovery;
  clientId: string;
  redirectUri: string;
  state: string;
  nonce: string;
  codeChallenge: string;
  loginHint?: string | undefined;
}

export function authorizationUrl(input: AuthorizationUrlInput): string {
  const url = new URL(input.discovery.authorization_endpoint);
  const params = url.searchParams;
  params.set('response_type', 'code');
  params.set('client_id', input.clientId);
  params.set('redirect_uri', input.redirectUri);
  params.set('scope', 'openid email profile');
  params.set('state', input.state);
  params.set('nonce', input.nonce);
  params.set('code_challenge', input.codeChallenge);
  params.set('code_challenge_method', 'S256');
  if (input.loginHint) params.set('login_hint', input.loginHint);
  return url.toString();
}

export interface TokenExchangeInput {
  discovery: OidcDiscovery;
  clientId: string;
  clientSecret?: string | undefined;
  code: string;
  redirectUri: string;
  codeVerifier: string;
}

export interface TokenResponse {
  id_token: string;
  access_token?: string;
  token_type?: string;
}

const tokenResponseSchema = z
  .object({
    id_token: z.string().min(16).max(16_384),
    access_token: z.string().max(16_384).optional(),
    token_type: z.string().max(64).optional(),
  })
  .loose();

export async function exchangeCode(
  ctx: AppContext,
  input: TokenExchangeInput,
): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: input.code,
    redirect_uri: input.redirectUri,
    client_id: input.clientId,
    code_verifier: input.codeVerifier,
  });
  const headers: Record<string, string> = {
    'content-type': 'application/x-www-form-urlencoded',
    accept: 'application/json',
  };
  if (input.clientSecret) {
    const methods = input.discovery.token_endpoint_auth_methods_supported;
    const usePost = Array.isArray(methods) && !methods.includes('client_secret_basic');
    if (usePost) body.set('client_secret', input.clientSecret);
    else {
      const basic = Buffer.from(
        `${encodeURIComponent(input.clientId)}:${encodeURIComponent(input.clientSecret)}`,
      ).toString('base64');
      headers.authorization = `Basic ${basic}`;
    }
  }
  const res = await safeFetch(ctx, input.discovery.token_endpoint, {
    method: 'POST',
    headers,
    body: body.toString(),
    errorCode: 'LSE-AUTH-004',
    timeoutMs: ctx.env.SSO_HTTP_TIMEOUT_MS,
    maxResponseBytes: MAX_METADATA_BYTES,
  });
  if (!res.ok) {
    throw new AppError('LSE-AUTH-011', {
      devMessage: `token endpoint returned status ${res.status}`,
    });
  }
  let json: unknown;
  try {
    json = (await res.json()) as unknown;
  } catch (cause) {
    throw new AppError('LSE-AUTH-011', { devMessage: 'token response was not JSON', cause });
  }
  const parsed = tokenResponseSchema.safeParse(json);
  if (!parsed.success) {
    throw new AppError('LSE-AUTH-011', { devMessage: 'token response has no id_token' });
  }
  return parsed.data;
}
