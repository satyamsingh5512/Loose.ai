/**
 * OIDC ID-token verification with `node:crypto` only (no jose/jsonwebtoken dependency).
 *
 * Accepted algorithms: RS256 and ES256 (`SSO_ID_TOKEN_ALGS`). `alg: none`, HMAC algorithms and
 * anything else are refused, so an IdP response can never pick its own verification scheme.
 * Checked: signature, `iss`, `aud` (must contain our client id), `azp` when `aud` is an array,
 * `exp` / `iat` / `nbf` with `SSO_CLOCK_SKEW_SEC` tolerance, and `nonce`.
 * Every failure throws LSE-AUTH-011 with a dev-only reason.
 */
import { createPublicKey, verify as cryptoVerify, type KeyObject } from 'node:crypto';
import { SSO_CLOCK_SKEW_SEC, SSO_ID_TOKEN_ALGS, type SsoIdTokenAlg } from '@loose/shared';
import { AppError } from '../../lib/errors';
import { safeEqual } from '../../lib/crypto';

export interface Jwk {
  kty: string;
  kid?: string;
  alg?: string;
  use?: string;
  key_ops?: string[];
  n?: string;
  e?: string;
  crv?: string;
  x?: string;
  y?: string;
  [extra: string]: unknown;
}

export interface JwkSet {
  keys: Jwk[];
}

export interface JwsHeader {
  alg: string;
  kid?: string;
  typ?: string;
}

export interface IdTokenClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat?: number;
  nbf?: number;
  azp?: string;
  nonce?: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
  preferred_username?: string;
  [extra: string]: unknown;
}

function fail(reason: string): never {
  throw new AppError('LSE-AUTH-011', { devMessage: reason });
}

function decodeJsonSegment(segment: string, what: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
  } catch {
    fail(`id_token ${what} is not valid JSON`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    fail(`id_token ${what} is not an object`);
  }
  return parsed as Record<string, unknown>;
}

export interface DecodedJws {
  header: JwsHeader;
  claims: IdTokenClaims;
  /** `<header>.<payload>` — the bytes that were signed. */
  signingInput: string;
  signature: Buffer;
}

/** Parse a compact JWS without verifying it. Throws LSE-AUTH-011 on malformed input. */
export function decodeJws(token: string): DecodedJws {
  const parts = token.split('.');
  if (parts.length !== 3) fail('id_token is not a compact JWS');
  const [h = '', p = '', s = ''] = parts;
  if (h.length === 0 || p.length === 0) fail('id_token has empty segments');
  const header = decodeJsonSegment(h, 'header') as unknown as JwsHeader;
  if (typeof header.alg !== 'string') fail('id_token header has no alg');
  const claims = decodeJsonSegment(p, 'claims') as unknown as IdTokenClaims;
  const signature = Buffer.from(s, 'base64url');
  if (signature.length === 0) fail('id_token has no signature');
  return { header, claims, signingInput: `${h}.${p}`, signature };
}

export function isAcceptedAlg(alg: string): alg is SsoIdTokenAlg {
  return (SSO_ID_TOKEN_ALGS as readonly string[]).includes(alg);
}

function publicKeyFor(jwk: Jwk, alg: SsoIdTokenAlg): KeyObject {
  if (alg === 'RS256' && jwk.kty !== 'RSA') fail('JWK type does not match RS256');
  if (alg === 'ES256' && (jwk.kty !== 'EC' || jwk.crv !== 'P-256')) {
    fail('JWK type does not match ES256');
  }
  if (jwk.alg !== undefined && jwk.alg !== alg) fail('JWK alg does not match the id_token alg');
  if (jwk.use !== undefined && jwk.use !== 'sig') fail('JWK is not a signing key');
  try {
    // `JsonWebKey` is a lib.dom type; the server does not include it, so cast the whole input.
    return createPublicKey({ key: jwk, format: 'jwk' } as Parameters<typeof createPublicKey>[0]);
  } catch {
    return fail('JWK could not be imported');
  }
}

/** Verify the signature of a decoded JWS against one JWK. Never throws for a bad signature. */
export function verifyJwsWithJwk(decoded: DecodedJws, jwk: Jwk): boolean {
  const alg = decoded.header.alg;
  if (!isAcceptedAlg(alg)) fail(`id_token alg ${alg} is not accepted`);
  const key = publicKeyFor(jwk, alg);
  const data = Buffer.from(decoded.signingInput, 'ascii');
  if (alg === 'ES256') {
    if (decoded.signature.length !== 64) return false;
    return cryptoVerify('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, decoded.signature);
  }
  return cryptoVerify('sha256', data, key, decoded.signature);
}

/** Keys that could have signed this token (`kid` match first, then every usable key). */
export function candidateKeys(jwks: JwkSet, header: JwsHeader): Jwk[] {
  const keys = Array.isArray(jwks.keys) ? jwks.keys : [];
  const usable = keys.filter((k) => k && typeof k.kty === 'string' && k.use !== 'enc');
  if (header.kid) {
    const byKid = usable.filter((k) => k.kid === header.kid);
    return byKid;
  }
  return usable;
}

export interface VerifyIdTokenInput {
  token: string;
  jwks: JwkSet;
  issuer: string;
  audience: string;
  nonce: string;
  now?: number;
  clockSkewSec?: number;
  /** Called when no key matches the token's `kid`; must return a freshly fetched JWKS. */
  refreshJwks?: () => Promise<JwkSet | null>;
}

function normalizeIssuer(value: string): string {
  return value.replace(/\/+$/, '');
}

export async function verifyIdToken(input: VerifyIdTokenInput): Promise<IdTokenClaims> {
  const decoded = decodeJws(input.token);
  if (!isAcceptedAlg(decoded.header.alg)) {
    fail(`id_token alg ${decoded.header.alg} is not accepted`);
  }
  let keys = candidateKeys(input.jwks, decoded.header);
  if (keys.length === 0 && input.refreshJwks) {
    // Key rotation: the IdP signed with a kid we have not cached yet.
    const fresh = await input.refreshJwks();
    if (fresh) keys = candidateKeys(fresh, decoded.header);
  }
  if (keys.length === 0) fail('no JWKS key matches the id_token kid');
  let verified = false;
  for (const jwk of keys) {
    if (verifyJwsWithJwk(decoded, jwk)) {
      verified = true;
      break;
    }
  }
  if (!verified) fail('id_token signature is invalid');

  const c = decoded.claims;
  if (typeof c.iss !== 'string' || normalizeIssuer(c.iss) !== normalizeIssuer(input.issuer)) {
    fail('id_token issuer mismatch');
  }
  if (typeof c.sub !== 'string' || c.sub.length === 0 || c.sub.length > 255) {
    fail('id_token has no usable sub');
  }
  const audiences = Array.isArray(c.aud) ? c.aud : typeof c.aud === 'string' ? [c.aud] : [];
  if (!audiences.some((a) => safeEqual(a, input.audience))) fail('id_token audience mismatch');
  if (audiences.length > 1 && !safeEqual(c.azp, input.audience)) {
    fail('id_token azp does not match the client id');
  }
  const skew = input.clockSkewSec ?? SSO_CLOCK_SKEW_SEC;
  const nowSec = Math.floor((input.now ?? Date.now()) / 1000);
  if (typeof c.exp !== 'number' || !Number.isFinite(c.exp)) fail('id_token has no exp');
  if (c.exp + skew <= nowSec) fail('id_token has expired');
  if (typeof c.iat === 'number' && c.iat - skew > nowSec) fail('id_token iat is in the future');
  if (typeof c.nbf === 'number' && c.nbf - skew > nowSec) fail('id_token is not valid yet');
  if (!safeEqual(c.nonce, input.nonce)) fail('id_token nonce mismatch');
  return c;
}
