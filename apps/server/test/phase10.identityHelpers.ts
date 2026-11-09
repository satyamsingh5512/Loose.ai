/**
 * Phase 10 / W1 test helpers: a mock OIDC identity provider (real RSA + EC keys, JWKS, discovery
 * and token endpoint) and a fake DNS resolver for domain verification.
 *
 * The IdP is reached through the injected `ctx.fetch` (see `mswFetch`), and its host is a public
 * IP literal so the SSRF guard accepts it without a DNS lookup.
 */
import { generateKeyPairSync, sign as cryptoSign, type KeyObject } from 'node:crypto';
import { http, HttpResponse, type RequestHandler } from 'msw';
import type { DnsResolver, ResolvedAddress } from '../src/lib/net/dns';

// A public (non-special-use) IP literal: the SSRF guard blocks documentation ranges such as
// 203.0.113.0/24 (P10-SEC-012). MSW intercepts every request, nothing reaches the network.
export const IDP_ORIGIN = 'https://93.184.216.34';
export const IDP_ISSUER = `${IDP_ORIGIN}/idp`;
export const IDP_CLIENT_ID = 'loose-test-client';
export const IDP_CLIENT_SECRET = 'idp-client-secret-value';

export interface IdpKey {
  kid: string;
  alg: 'RS256' | 'ES256';
  privateKey: KeyObject;
  jwk: Record<string, unknown>;
}

function publicJwk(publicKey: KeyObject, kid: string, alg: string): Record<string, unknown> {
  const jwk = publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
  return { ...jwk, kid, alg, use: 'sig' };
}

export function makeRsaKey(kid: string): IdpKey {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return { kid, alg: 'RS256', privateKey, jwk: publicJwk(publicKey, kid, 'RS256') };
}

export function makeEcKey(kid: string): IdpKey {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { kid, alg: 'ES256', privateKey, jwk: publicJwk(publicKey, kid, 'ES256') };
}

const b64 = (value: unknown): string =>
  Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');

export interface SignOptions {
  /** Override the JOSE header (e.g. a wrong `kid` or an unaccepted `alg`). */
  header?: Record<string, unknown>;
  /** Corrupt the signature after signing. */
  tamper?: boolean;
}

/** Sign a compact JWS with one of the IdP's keys. */
export function signJwt(
  key: IdpKey,
  claims: Record<string, unknown>,
  opts: SignOptions = {},
): string {
  const header = { alg: key.alg, kid: key.kid, typ: 'JWT', ...opts.header };
  const signingInput = `${b64(header)}.${b64(claims)}`;
  const signature =
    key.alg === 'ES256'
      ? cryptoSign('sha256', Buffer.from(signingInput), {
          key: key.privateKey,
          dsaEncoding: 'ieee-p1363',
        })
      : cryptoSign('sha256', Buffer.from(signingInput), key.privateKey);
  let encoded = signature.toString('base64url');
  if (opts.tamper) {
    const flipped = encoded[0] === 'A' ? 'B' : 'A';
    encoded = `${flipped}${encoded.slice(1)}`;
  }
  return `${signingInput}.${encoded}`;
}

export interface IdTokenInput {
  key: IdpKey;
  nonce: string;
  sub?: string;
  email?: string | null;
  emailVerified?: boolean | null;
  name?: string;
  issuer?: string;
  audience?: string | string[];
  azp?: string;
  expiresInSec?: number;
  issuedAtOffsetSec?: number;
  sign?: SignOptions;
}

export function makeIdToken(input: IdTokenInput): string {
  const nowSec = Math.floor(Date.now() / 1000);
  const claims: Record<string, unknown> = {
    iss: input.issuer ?? IDP_ISSUER,
    aud: input.audience ?? IDP_CLIENT_ID,
    sub: input.sub ?? 'idp-subject-1',
    nonce: input.nonce,
    iat: nowSec + (input.issuedAtOffsetSec ?? 0),
    exp: nowSec + (input.expiresInSec ?? 300),
  };
  if (input.azp !== undefined) claims.azp = input.azp;
  if (input.email !== null) claims.email = input.email ?? 'sso-user@acme.test';
  // Real IdPs assert `email_verified: true`; `null` omits the claim (P10-SEC-001 tests).
  const emailVerified = input.emailVerified === undefined ? true : input.emailVerified;
  if (emailVerified !== null) claims.email_verified = emailVerified;
  if (input.name !== undefined) claims.name = input.name;
  return signJwt(input.key, claims, input.sign);
}

export interface MockIdp {
  keys: IdpKey[];
  /** The next `id_token` the token endpoint returns (set it after reading the nonce). */
  nextIdToken: string | null;
  /** HTTP status of the next token-endpoint response. */
  tokenStatus: number;
  /** Bodies the token endpoint received (to assert PKCE / client auth). */
  tokenRequests: { body: Record<string, string>; authorization: string | null }[];
  discoveryStatus: number;
  /** Extra/overriding discovery fields. */
  discoveryOverrides: Record<string, unknown>;
  handlers(): RequestHandler[];
}

export function createMockIdp(keys: IdpKey[] = [makeRsaKey('rsa-1')]): MockIdp {
  const idp: MockIdp = {
    keys,
    nextIdToken: null,
    tokenStatus: 200,
    tokenRequests: [],
    discoveryStatus: 200,
    discoveryOverrides: {},
    handlers() {
      return [
        http.get(`${IDP_ISSUER}/.well-known/openid-configuration`, () => {
          if (idp.discoveryStatus !== 200) {
            return HttpResponse.json({ error: 'nope' }, { status: idp.discoveryStatus });
          }
          return HttpResponse.json({
            issuer: IDP_ISSUER,
            authorization_endpoint: `${IDP_ISSUER}/authorize`,
            token_endpoint: `${IDP_ISSUER}/token`,
            jwks_uri: `${IDP_ISSUER}/jwks`,
            response_types_supported: ['code'],
            id_token_signing_alg_values_supported: ['RS256', 'ES256'],
            code_challenge_methods_supported: ['S256'],
            token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
            ...idp.discoveryOverrides,
          });
        }),
        http.get(`${IDP_ISSUER}/jwks`, () =>
          HttpResponse.json({ keys: idp.keys.map((k) => k.jwk) }),
        ),
        http.post(`${IDP_ISSUER}/token`, async ({ request }) => {
          const text = await request.text();
          idp.tokenRequests.push({
            body: Object.fromEntries(new URLSearchParams(text)),
            authorization: request.headers.get('authorization'),
          });
          if (idp.tokenStatus !== 200) {
            return HttpResponse.json({ error: 'invalid_grant' }, { status: idp.tokenStatus });
          }
          return HttpResponse.json({
            token_type: 'Bearer',
            access_token: 'idp-access-token',
            id_token: idp.nextIdToken ?? '',
          });
        }),
      ];
    },
  };
  return idp;
}

// ---- DNS -------------------------------------------------------------------------------------

export interface FakeDns extends DnsResolver {
  /** `name` → TXT records (each record is a list of chunks). */
  txt: Map<string, string[][]>;
  addresses: ResolvedAddress[];
}

export function createFakeDns(): FakeDns {
  const dns: FakeDns = {
    txt: new Map(),
    addresses: [{ address: '93.184.216.34', family: 4 }],
    async lookup() {
      return dns.addresses;
    },
    async resolveTxt(host: string) {
      const records = dns.txt.get(host);
      if (!records) {
        const err = new Error(`queryTxt ENOTFOUND ${host}`) as Error & { code?: string };
        err.code = 'ENOTFOUND';
        throw err;
      }
      return records;
    },
  };
  return dns;
}

/** Parse the query of the 302 the SSO start endpoint issues. */
export function authorizeParams(location: string): URLSearchParams {
  return new URL(location).searchParams;
}
