/**
 * GitHub access with the user's OAuth token (spec §10.3, §14).
 * Octokit errors are normalized to LSE-GH-* codes.
 */
import { Octokit } from '@octokit/rest';
import { githubRepoDtoSchema, type GithubRepoDto } from '@loose/shared';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';
import { getGithubAccessToken } from './user.service';

interface OctokitLikeError {
  status?: number;
  message?: string;
  response?: { headers?: Record<string, string | number | undefined> };
}

export function mapGithubError(err: unknown): AppError {
  if (err instanceof AppError) return err;
  const e = (err ?? {}) as OctokitLikeError;
  const status = typeof e.status === 'number' ? e.status : 0;
  const headers = e.response?.headers ?? {};
  const message = typeof e.message === 'string' ? e.message.slice(0, 200) : '';
  const devMessage = `GitHub ${status || 'network error'}${message ? `: ${message}` : ''}`;
  const remaining = headers['x-ratelimit-remaining'];
  const retryAfter = headers['retry-after'];
  const retryHeaders = retryAfter !== undefined ? { 'Retry-After': String(retryAfter) } : undefined;

  if (status === 401) return new AppError('LSE-GH-001', { devMessage, cause: err });
  if (status === 403 || status === 429) {
    if (String(remaining) === '0') {
      const reset = Number(headers['x-ratelimit-reset']);
      const secs = Number.isFinite(reset) ? Math.max(1, Math.ceil(reset - Date.now() / 1000)) : 60;
      return new AppError('LSE-GH-010', {
        devMessage,
        cause: err,
        headers: { 'Retry-After': String(secs) },
      });
    }
    if (retryAfter !== undefined || /rate limit/i.test(message)) {
      return new AppError('LSE-GH-009', {
        devMessage,
        cause: err,
        ...(retryHeaders ? { headers: retryHeaders } : {}),
      });
    }
    if (status === 429) return new AppError('LSE-GH-010', { devMessage, cause: err });
    return new AppError('LSE-GH-002', { devMessage, cause: err });
  }
  if (status === 404) return new AppError('LSE-GH-003', { devMessage, cause: err });
  return new AppError('LSE-GH-011', { devMessage, cause: err });
}

interface RawRepo {
  full_name: string;
  name: string;
  owner: { login: string };
  private: boolean;
  default_branch?: string;
  html_url: string;
  description: string | null;
  updated_at?: string | null;
}

export function toRepoDto(r: RawRepo): GithubRepoDto {
  return githubRepoDtoSchema.parse({
    fullName: r.full_name,
    name: r.name,
    owner: r.owner.login,
    private: r.private,
    defaultBranch: r.default_branch ?? 'main',
    htmlUrl: r.html_url,
    description: r.description ?? null,
    updatedAt: r.updated_at ?? null,
  });
}

export async function githubClientFor(ctx: AppContext, userId: string): Promise<Octokit> {
  const token = await getGithubAccessToken(ctx, userId);
  if (!token) {
    throw new AppError('LSE-GH-001', {
      devMessage: 'No GitHub account linked',
      title: 'Connect GitHub',
      userMessage: 'Connect your GitHub account to see your repositories.',
      action: { type: 'link', label: 'Connect GitHub', href: '/api/v1/auth/github?link=1' },
    });
  }
  // Octokit logs failed requests via console by default; route through pino instead.
  const log = {
    debug: () => undefined,
    info: () => undefined,
    warn: (msg: string) => ctx.logger.debug({ source: 'octokit' }, msg),
    error: (msg: string) => ctx.logger.debug({ source: 'octokit' }, msg),
  };
  return new Octokit({ auth: token, userAgent: 'loose.ai', request: { fetch: ctx.fetch }, log });
}

export async function listRepos(
  ctx: AppContext,
  userId: string,
  opts: { page: number; perPage: number; q?: string | undefined },
): Promise<{ data: GithubRepoDto[]; nextCursor: string | null }> {
  const octokit = await githubClientFor(ctx, userId);
  try {
    const res = await octokit.rest.repos.listForAuthenticatedUser({
      per_page: opts.perPage,
      page: opts.page,
      sort: 'updated',
    });
    const hasNext = /rel="next"/.test(String(res.headers.link ?? ''));
    let repos = (res.data as RawRepo[]).map(toRepoDto);
    if (opts.q) {
      const needle = opts.q.toLowerCase();
      repos = repos.filter((r) => r.fullName.toLowerCase().includes(needle));
    }
    return { data: repos, nextCursor: hasNext ? String(opts.page + 1) : null };
  } catch (err) {
    throw mapGithubError(err);
  }
}

export async function getRepo(
  ctx: AppContext,
  userId: string,
  owner: string,
  repo: string,
): Promise<GithubRepoDto> {
  const octokit = await githubClientFor(ctx, userId);
  try {
    const res = await octokit.rest.repos.get({ owner, repo });
    return toRepoDto(res.data as RawRepo);
  } catch (err) {
    throw mapGithubError(err);
  }
}
