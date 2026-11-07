/**
 * Git remote + short-lived credentials for clone/push inside sandboxes (spec §13.3, §14).
 * Preference: GitHub App installation token (repo-scoped, ~1 h) → the user's OAuth
 * token. The token is handed to git ONLY via process env (GIT_CONFIG_* → an
 * `http.<github>.extraheader`), never on the command line and never written to disk.
 */
import { createAppAuth } from '@octokit/auth-app';
import { Octokit } from '@octokit/rest';
import type { Organization } from '@prisma/client';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';
import { getGithubAccessToken } from './user.service';

export interface GitAccess {
  remoteUrl: string;
  token: string | null;
  source: 'override' | 'installation' | 'oauth';
}

const SEGMENT_RE = /^[A-Za-z0-9_.-]+$/;

/** POSIX single-quote a value for `bash -c`. */
export function shq(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

/** Env vars that make git send the token to github.com only. */
export function gitAuthEnv(token: string | null): Record<string, string> {
  const base = { GIT_TERMINAL_PROMPT: '0' };
  if (!token) return base;
  const basic = Buffer.from(`x-access-token:${token}`).toString('base64');
  return {
    ...base,
    GIT_CONFIG_COUNT: '1',
    GIT_CONFIG_KEY_0: 'http.https://github.com/.extraheader',
    GIT_CONFIG_VALUE_0: `Authorization: Basic ${basic}`,
  };
}

export function remoteUrlFor(
  ctx: AppContext,
  repoFullName: string,
): { url: string; override: boolean } {
  const [owner = '', repo = ''] = repoFullName.split('/');
  if (!SEGMENT_RE.test(owner) || !SEGMENT_RE.test(repo) || owner === '..' || repo === '..') {
    throw new AppError('LSE-GH-003', { devMessage: 'Invalid repository name' });
  }
  const override = ctx.env.NODE_ENV !== 'production' ? ctx.env.DEV_GIT_REMOTE_OVERRIDE : undefined;
  if (override) {
    return {
      url: override.replaceAll('{owner}', owner).replaceAll('{repo}', repo),
      override: true,
    };
  }
  return { url: `https://github.com/${owner}/${repo}.git`, override: false };
}

async function installationToken(
  ctx: AppContext,
  installationId: string,
  repo: string,
): Promise<string> {
  const privateKey = (ctx.env.GITHUB_APP_PRIVATE_KEY ?? '').replace(/\\n/g, '\n');
  const request = new Octokit({ request: { fetch: ctx.fetch } }).request;
  const auth = createAppAuth({ appId: ctx.env.GITHUB_APP_ID ?? '', privateKey, request });
  const res = await auth({
    type: 'installation',
    installationId: Number(installationId),
    repositoryNames: [repo],
  });
  return res.token;
}

export async function resolveGitAccess(
  ctx: AppContext,
  input: { org: Organization; userId: string; repoFullName: string },
): Promise<GitAccess> {
  const { url, override } = remoteUrlFor(ctx, input.repoFullName);
  if (ctx.env.GITHUB_APP_ID && ctx.env.GITHUB_APP_PRIVATE_KEY && input.org.githubInstallationId) {
    try {
      const repo = input.repoFullName.split('/')[1] ?? '';
      const token = await installationToken(ctx, input.org.githubInstallationId, repo);
      return { remoteUrl: url, token, source: 'installation' };
    } catch (err) {
      ctx.logger.warn(
        { err: { message: (err as Error).message } },
        'GitHub App token failed; falling back to OAuth',
      );
    }
  }
  const token = await getGithubAccessToken(ctx, input.userId);
  if (token) return { remoteUrl: url, token, source: override ? 'override' : 'oauth' };
  if (override) return { remoteUrl: url, token: null, source: 'override' };
  throw new AppError('LSE-GH-001', {
    devMessage: 'No GitHub credentials (no App installation and no linked GitHub account)',
    action: { type: 'link', label: 'Connect GitHub', href: '/api/v1/auth/github?link=1' },
  });
}
