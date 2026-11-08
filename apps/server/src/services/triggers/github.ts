/**
 * GitHub triggers (spec §8.15): `issues` labeled with the project's configured label, and
 * `issue_comment` on a pull request containing the configured mention (default `@loose`).
 * Dispatched from `routes/github.ts` (signature already verified there).
 */
import { Octokit } from '@octokit/rest';
import { parseTriggerConfig, type GithubAuthorAssociation, type RunSource } from '@loose/shared';
import type { Trigger } from '@prisma/client';
import type { AppContext } from '../../context';
import { getGithubAccessToken } from '../user.service';

interface GithubLabel {
  name?: string;
}
interface GithubIssuesEvent {
  action?: string;
  issue?: {
    number?: number;
    title?: string;
    body?: string | null;
    html_url?: string;
    pull_request?: unknown; // present on issue events for PRs; absent on real issues
  };
  label?: GithubLabel;
  repository?: { full_name?: string };
  sender?: { login?: string };
}
interface GithubIssueCommentEvent {
  action?: string;
  issue?: {
    number?: number;
    html_url?: string;
    pull_request?: { url?: string } | null;
  };
  comment?: {
    id?: number;
    body?: string;
    user?: { login?: string; type?: string };
    author_association?: string;
  };
  repository?: { full_name?: string };
}

/** Octokit for a project's run-as user (the trigger's `runAsUser`, same as runs/sessions). */
async function octokitFor(ctx: AppContext, userId: string): Promise<Octokit | null> {
  const token = await getGithubAccessToken(ctx, userId);
  if (!token) return null;
  const log = {
    debug: () => undefined,
    info: () => undefined,
    warn: (msg: string) => ctx.logger.debug({ source: 'octokit' }, msg),
    error: (msg: string) => ctx.logger.debug({ source: 'octokit' }, msg),
  };
  return new Octokit({ auth: token, userAgent: 'loose.ai', request: { fetch: ctx.fetch }, log });
}

async function findTriggers(
  ctx: AppContext,
  kind: 'GITHUB_ISSUE_LABEL' | 'GITHUB_PR_COMMENT',
  repoFullName: string,
): Promise<(Trigger & { project: { githubRepoFullName: string } })[]> {
  return ctx.prisma.trigger.findMany({
    where: { kind, enabled: true, project: { githubRepoFullName: repoFullName } },
    include: { project: { select: { githubRepoFullName: true } } },
  });
}

// ---- issues.labeled ----------------------------------------------------------------------

async function handleIssuesLabeled(
  ctx: AppContext,
  deliveryId: string | undefined,
  payload: GithubIssuesEvent,
): Promise<boolean> {
  if (payload.action !== 'labeled') return false;
  const repo = payload.repository?.full_name;
  const issue = payload.issue;
  const labelName = payload.label?.name;
  if (!repo || !issue?.number || !labelName || issue.pull_request) return false;

  const triggers = await findTriggers(ctx, 'GITHUB_ISSUE_LABEL', repo);
  let fired = false;
  for (const trigger of triggers) {
    const cfg = parseTriggerConfig('GITHUB_ISSUE_LABEL', trigger.config);
    if (!cfg || cfg.label !== labelName) continue;
    const dedupeKey = `issue:${repo}#${issue.number}:${labelName}`;
    const vars = {
      title: issue.title ?? '',
      body: issue.body ?? '',
      number: String(issue.number),
      url: issue.html_url ?? '',
      author: payload.sender?.login ?? '',
      repo,
    };
    await ctx.jobs.enqueue(
      'trigger-fire',
      {
        triggerId: trigger.id,
        dedupeKey,
        vars,
        source: 'GITHUB_ISSUE' satisfies RunSource,
        externalRef: { repo, issueNumber: issue.number, deliveryId: deliveryId ?? null },
        overrideOptions: { createPr: true, draft: false, prNotes: `Closes #${issue.number}` },
      },
      { jobId: `trigger-fire:${trigger.id}:${dedupeKey}` },
    );
    fired = true;
  }
  return fired;
}

// ---- issue_comment on a PR, mentioning the trigger ---------------------------------------

const DEFAULT_ALLOWED: readonly GithubAuthorAssociation[] = ['OWNER', 'MEMBER', 'COLLABORATOR'];

async function handlePrCommentMention(
  ctx: AppContext,
  deliveryId: string | undefined,
  payload: GithubIssueCommentEvent,
): Promise<boolean> {
  if (payload.action !== 'created') return false;
  const repo = payload.repository?.full_name;
  const issue = payload.issue;
  const comment = payload.comment;
  if (!repo || !issue?.number || !issue.pull_request || !comment?.body || !comment.id) {
    return false;
  }
  if (comment.user?.type === 'Bot') return false;

  const triggers = await findTriggers(ctx, 'GITHUB_PR_COMMENT', repo);
  if (triggers.length === 0) return false;

  let fired = false;
  for (const trigger of triggers) {
    const cfg = parseTriggerConfig('GITHUB_PR_COMMENT', trigger.config);
    if (!cfg) continue;
    const idx = comment.body.indexOf(cfg.mention);
    if (idx === -1) continue;
    const allowed = cfg.allowedAssociations.length > 0 ? cfg.allowedAssociations : DEFAULT_ALLOWED;
    const association = (comment.author_association ?? 'NONE') as GithubAuthorAssociation;
    if (!allowed.includes(association)) {
      ctx.logger.info(
        { repo, prNumber: issue.number, association, triggerId: trigger.id },
        'github PR comment trigger: commenter lacks the required association',
      );
      continue;
    }
    const octokit = await octokitFor(ctx, trigger.runAsUserId);
    if (!octokit) continue;
    const [owner, name] = repo.split('/');
    let pr: {
      number: number;
      html_url: string;
      head: { ref: string; repo: { full_name: string } | null };
      base: { repo: { full_name: string } };
    };
    try {
      const res = await octokit.rest.pulls.get({
        owner: owner!,
        repo: name!,
        pull_number: issue.number,
      });
      pr = res.data as typeof pr;
    } catch {
      continue;
    }
    // Only fix PRs whose head is in the same repo (no forks: pushing back needs write access there).
    if (pr.base.repo.full_name !== repo || pr.head.repo?.full_name !== repo) continue;

    const instruction = comment.body.slice(idx + cfg.mention.length).trim() || comment.body;
    const dedupeKey = `comment:${comment.id}`;
    await ctx.jobs.enqueue(
      'trigger-fire',
      {
        triggerId: trigger.id,
        dedupeKey,
        vars: {
          comment: instruction,
          text: instruction,
          number: String(issue.number),
          url: pr.html_url,
          branch: pr.head.ref,
          repo,
          author: comment.user?.login ?? '',
        },
        source: 'GITHUB_COMMENT' satisfies RunSource,
        externalRef: {
          repo,
          prNumber: issue.number,
          commentId: comment.id,
          deliveryId: deliveryId ?? null,
        },
        overrideOptions: { branch: pr.head.ref, createPr: true, draft: false },
      },
      { jobId: `trigger-fire:${trigger.id}:${dedupeKey}` },
    );
    fired = true;
  }
  return fired;
}

/** Dispatch an `issues` or `issue_comment` webhook event. Returns whether a trigger matched. */
export async function handleGithubTriggerFire(
  ctx: AppContext,
  event: string,
  deliveryId: string | undefined,
  payload: unknown,
): Promise<boolean> {
  if (event === 'issues') {
    return handleIssuesLabeled(ctx, deliveryId, payload as GithubIssuesEvent);
  }
  if (event === 'issue_comment') {
    return handlePrCommentMention(ctx, deliveryId, payload as GithubIssueCommentEvent);
  }
  return false;
}

// ---- run.completed post-back ---------------------------------------------------------------

interface RunCompletedData {
  runId: string;
  status: string;
  prUrl: string | null;
  errorCode: string | null;
  summary: string | null;
  externalRef: Record<string, unknown> | null;
}

function resultComment(data: RunCompletedData): string {
  if (data.status === 'SUCCEEDED' && data.prUrl) {
    return `I opened a pull request: ${data.prUrl}`;
  }
  if (data.status === 'SUCCEEDED') {
    return data.summary
      ? `Done — no pull request was needed.\n\n${data.summary}`
      : 'Done — no pull request was needed.';
  }
  if (data.status === 'CANCELLED') return 'This run was cancelled.';
  return `I couldn't finish this (${data.errorCode ?? 'error'}).`;
}

/** Comment back on the originating issue or pull request once the run has settled. */
export async function postGithubRunResult(
  ctx: AppContext,
  trigger: Trigger,
  data: RunCompletedData,
): Promise<void> {
  const ref = data.externalRef ?? {};
  const repo = typeof ref.repo === 'string' ? ref.repo : null;
  const number =
    typeof ref.issueNumber === 'number'
      ? ref.issueNumber
      : typeof ref.prNumber === 'number'
        ? ref.prNumber
        : null;
  if (!repo || !number) return;
  const octokit = await octokitFor(ctx, trigger.runAsUserId);
  if (!octokit) return;
  const [owner, name] = repo.split('/');
  await octokit.rest.issues.createComment({
    owner: owner!,
    repo: name!,
    issue_number: number,
    body: resultComment(data),
  });
}
