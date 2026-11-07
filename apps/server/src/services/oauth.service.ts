/**
 * Hand-rolled OAuth 2.0 clients (arctic is deprecated).
 * - Google: authorization code + PKCE (S256) + state; OIDC userinfo; requires email_verified.
 * - GitHub: authorization code + state; scopes `read:user user:email repo`;
 *   primary verified email from /user/emails.
 * All HTTP goes through an injectable fetch so tests can mock providers.
 */
import { createHash } from 'node:crypto';
import type { OAuthProvider } from '@loose/shared';
import type { Env } from '../config/env';
import { AppError } from '../lib/errors';

export interface OAuthTokens {
  accessToken: string;
  refreshToken?: string | undefined;
  expiresAt?: Date | undefined;
  scopes: string[];
}

export interface OAuthProfile {
  providerAccountId: string;
  email: string;
  emailVerified: boolean;
  name: string | null;
  avatarUrl: string | null;
}

export interface OAuthClient {
  readonly provider: OAuthProvider;
  readonly usesPkce: boolean;
  authorizationUrl(state: string, codeVerifier?: string): URL;
  exchangeCode(code: string, codeVerifier?: string): Promise<OAuthTokens>;
  fetchProfile(tokens: OAuthTokens): Promise<OAuthProfile>;
}

export const GOOGLE_AUTHORIZE_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
export const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
export const GOOGLE_USERINFO_URL = 'https://openidconnect.googleapis.com/v1/userinfo';
export const GITHUB_AUTHORIZE_URL = 'https://github.com/login/oauth/authorize';
export const GITHUB_TOKEN_URL = 'https://github.com/login/oauth/access_token';
export const GITHUB_API_URL = 'https://api.github.com';
export const GITHUB_SCOPES = ['read:user', 'user:email', 'repo'];

const HTTP_TIMEOUT_MS = 10_000;

export function pkceChallenge(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
}

function unavailable(provider: string, detail: string, cause?: unknown): AppError {
  return new AppError('LSE-AUTH-004', { devMessage: `${provider}: ${detail}`, cause });
}

async function httpJson(
  fetchFn: typeof fetch,
  provider: string,
  url: string,
  init: RequestInit,
): Promise<{ status: number; json: unknown }> {
  let res: Response;
  try {
    res = await fetchFn(url, { ...init, signal: AbortSignal.timeout(HTTP_TIMEOUT_MS) });
  } catch (cause) {
    throw unavailable(provider, `request to ${new URL(url).host} failed`, cause);
  }
  let json: unknown = null;
  try {
    json = await res.json();
  } catch {
    json = null;
  }
  if (res.status >= 500) throw unavailable(provider, `${new URL(url).host} answered ${res.status}`);
  return { status: res.status, json };
}

const str = (v: unknown): string | undefined =>
  typeof v === 'string' && v.length > 0 ? v : undefined;

export class GoogleOAuthClient implements OAuthClient {
  readonly provider = 'google' as const;
  readonly usesPkce = true;
  constructor(
    private readonly clientId: string,
    private readonly clientSecret: string,
    private readonly redirectUri: string,
    private readonly fetchFn: typeof fetch,
  ) {}

  authorizationUrl(state: string, codeVerifier?: string): URL {
    if (!codeVerifier) throw new Error('PKCE verifier required');
    const url = new URL(GOOGLE_AUTHORIZE_URL);
    url.searchParams.set('client_id', this.clientId);
    url.searchParams.set('redirect_uri', this.redirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', 'openid email profile');
    url.searchParams.set('state', state);
    url.searchParams.set('code_challenge', pkceChallenge(codeVerifier));
    url.searchParams.set('code_challenge_method', 'S256');
    url.searchParams.set('prompt', 'select_account');
    return url;
  }

  async exchangeCode(code: string, codeVerifier?: string): Promise<OAuthTokens> {
    if (!codeVerifier) throw new AppError('LSE-AUTH-002', { devMessage: 'Missing PKCE verifier' });
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: this.redirectUri,
      client_id: this.clientId,
      client_secret: this.clientSecret,
      code_verifier: codeVerifier,
    });
    const { status, json } = await httpJson(this.fetchFn, 'google', GOOGLE_TOKEN_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body,
    });
    const j = (json ?? {}) as Record<string, unknown>;
    const accessToken = str(j.access_token);
    if (status !== 200 || !accessToken) {
      // invalid_grant etc. — the code/verifier didn't check out.
      throw new AppError('LSE-AUTH-002', {
        devMessage: `google token exchange failed (${status} ${str(j.error) ?? ''})`,
      });
    }
    const expiresIn = typeof j.expires_in === 'number' ? j.expires_in : undefined;
    return {
      accessToken,
      refreshToken: str(j.refresh_token),
      expiresAt: expiresIn ? new Date(Date.now() + expiresIn * 1000) : undefined,
      scopes: (str(j.scope) ?? '').split(' ').filter(Boolean),
    };
  }

  async fetchProfile(tokens: OAuthTokens): Promise<OAuthProfile> {
    const { status, json } = await httpJson(this.fetchFn, 'google', GOOGLE_USERINFO_URL, {
      headers: { authorization: `Bearer ${tokens.accessToken}`, accept: 'application/json' },
    });
    const j = (json ?? {}) as Record<string, unknown>;
    const sub = str(j.sub);
    const email = str(j.email);
    if (status !== 200 || !sub || !email)
      throw unavailable('google', `userinfo failed (${status})`);
    return {
      providerAccountId: sub,
      email: email.toLowerCase(),
      emailVerified: j.email_verified === true || j.email_verified === 'true',
      name: str(j.name) ?? null,
      avatarUrl: str(j.picture) ?? null,
    };
  }
}

export class GitHubOAuthClient implements OAuthClient {
  readonly provider = 'github' as const;
  readonly usesPkce = false;
  constructor(
    private readonly clientId: string,
    private readonly clientSecret: string,
    private readonly redirectUri: string,
    private readonly fetchFn: typeof fetch,
  ) {}

  authorizationUrl(state: string): URL {
    const url = new URL(GITHUB_AUTHORIZE_URL);
    url.searchParams.set('client_id', this.clientId);
    url.searchParams.set('redirect_uri', this.redirectUri);
    url.searchParams.set('scope', GITHUB_SCOPES.join(' '));
    url.searchParams.set('state', state);
    url.searchParams.set('allow_signup', 'true');
    return url;
  }

  async exchangeCode(code: string): Promise<OAuthTokens> {
    const { status, json } = await httpJson(this.fetchFn, 'github', GITHUB_TOKEN_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({
        client_id: this.clientId,
        client_secret: this.clientSecret,
        code,
        redirect_uri: this.redirectUri,
      }),
    });
    const j = (json ?? {}) as Record<string, unknown>;
    const accessToken = str(j.access_token);
    if (status !== 200 || !accessToken) {
      throw new AppError('LSE-AUTH-002', {
        devMessage: `github token exchange failed (${status} ${str(j.error) ?? ''})`,
      });
    }
    return {
      accessToken,
      refreshToken: str(j.refresh_token),
      expiresAt:
        typeof j.expires_in === 'number' ? new Date(Date.now() + j.expires_in * 1000) : undefined,
      scopes: (str(j.scope) ?? '').split(/[ ,]+/).filter(Boolean),
    };
  }

  async fetchProfile(tokens: OAuthTokens): Promise<OAuthProfile> {
    const headers = {
      authorization: `Bearer ${tokens.accessToken}`,
      accept: 'application/vnd.github+json',
      'x-github-api-version': '2022-11-28',
      'user-agent': 'loose.ai',
    };
    const user = await httpJson(this.fetchFn, 'github', `${GITHUB_API_URL}/user`, { headers });
    const u = (user.json ?? {}) as Record<string, unknown>;
    if (user.status !== 200 || (typeof u.id !== 'number' && typeof u.id !== 'string')) {
      throw unavailable('github', `GET /user failed (${user.status})`);
    }
    const emails = await httpJson(this.fetchFn, 'github', `${GITHUB_API_URL}/user/emails`, {
      headers,
    });
    if (emails.status !== 200 || !Array.isArray(emails.json)) {
      throw unavailable('github', `GET /user/emails failed (${emails.status})`);
    }
    const primary = (emails.json as Array<Record<string, unknown>>).find(
      (e) => e.primary === true && e.verified === true && typeof e.email === 'string',
    );
    return {
      providerAccountId: String(u.id),
      email: primary ? String(primary.email).toLowerCase() : '',
      emailVerified: Boolean(primary),
      name: str(u.name) ?? str(u.login) ?? null,
      avatarUrl: str(u.avatar_url) ?? null,
    };
  }
}

export type OAuthClients = Partial<Record<OAuthProvider, OAuthClient>>;

/** Build clients for configured providers only. */
export function createOAuthClients(env: Env, fetchFn: typeof fetch): OAuthClients {
  const cb = (p: OAuthProvider) => `${env.API_URL.replace(/\/$/, '')}/api/v1/auth/${p}/callback`;
  const clients: OAuthClients = {};
  if (env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET) {
    clients.google = new GoogleOAuthClient(
      env.GOOGLE_CLIENT_ID,
      env.GOOGLE_CLIENT_SECRET,
      cb('google'),
      fetchFn,
    );
  }
  if (env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET) {
    clients.github = new GitHubOAuthClient(
      env.GITHUB_CLIENT_ID,
      env.GITHUB_CLIENT_SECRET,
      cb('github'),
      fetchFn,
    );
  }
  return clients;
}
