/**
 * Review & delivery (spec §7.4, §14; Phase 6): diff (Pro), create PR, commit to main,
 * discard, and the inbound `pull_request` webhook. All three delivery actions stop the
 * sandbox. Git runs inside the sandbox with a short-lived token passed only via env
 * (`gitAuthEnv`); GitHub REST calls use Octokit with the same token.
 */
import { Octokit } from '@octokit/rest';
import type { Organization, Prisma, Project, Session } from '@prisma/client';
import {
  assessRisk,
  diffDtoSchema,
  diffStats,
  gateForFile,
  isAdminRole,
  parseOrgPolicy,
  scrubSecrets,
  type ApprovalGate,
  type ChatMessageMetadata,
  type CommitToMainBody,
  type CreatePrBody,
  type DeliveryResultDto,
  type DiffDto,
  type DiffFile,
  type Outcome,
  type RiskAssessment,
} from '@loose/shared';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';
import { emitPrCreated } from '../lib/events/platformEvents';
import { publicArtifactUrl, signArtifactToken } from '../lib/publicArtifacts';
import { withRetry } from '../lib/resilience';
import type { SandboxHandle } from '../lib/sandbox';
import {
  gitAuthEnv,
  remoteUrlFor,
  resolveGitAccess,
  shq,
  type GitAccess,
} from './gitAccess.service';
import { mapGithubError } from './github.service';
import { runLifecycleHooks } from './hooks.service';
import {
  baseRef,
  capDiff,
  commitsAhead,
  gitStatus,
  headSha,
  parseUnifiedDiff,
  workingDiff,
} from './gitWorkspace.service';
import { decryptProjectEnv } from './project.service';
import {
  assertCanAct,
  assertTokenScope,
  getOrConnectSandbox,
  loadSessionForParticipant,
  saveArtifact,
  sessionInclude,
  stopSession,
  toSessionDto,
  type Caller,
  type SessionAccess,
} from './sessionLifecycle.service';
import { secretValuesOf } from './workspace.service';

type FullProject = Project & { org: Organization };

interface Delivery {
  access: SessionAccess;
  session: Session;
  project: FullProject;
  sandbox: SandboxHandle;
  git: GitAccess;
  secrets: string[];
  owner: string;
  repo: string;
}

const BOT_NAME = 'loose.ai';
const BOT_EMAIL = 'bot@loose.ai';

function octokitFor(ctx: AppContext, token: string): Octokit {
  const log = {
    debug: () => undefined,
    info: () => undefined,
    warn: (msg: string) => ctx.logger.debug({ source: 'octokit' }, msg),
    error: (msg: string) => ctx.logger.debug({ source: 'octokit' }, msg),
  };
  return new Octokit({ auth: token, userAgent: 'loose.ai', request: { fetch: ctx.fetch }, log });
}

function splitRepo(fullName: string): { owner: string; repo: string } {
  const [owner = '', repo = ''] = fullName.split('/');
  return { owner, repo };
}

async function runGit(
  d: Pick<Delivery, 'sandbox' | 'git' | 'secrets'>,
  cmd: string,
  timeoutMs = 120_000,
) {
  const r = await d.sandbox.run(cmd, {
    cwd: d.sandbox.paths.workspace,
    envs: gitAuthEnv(d.git.token),
    timeoutMs,
  });
  const secrets = d.git.token ? [...d.secrets, d.git.token] : d.secrets;
  return { ...r, stdout: scrubSecrets(r.stdout, secrets), stderr: scrubSecrets(r.stderr, secrets) };
}

async function prepare(ctx: AppContext, caller: Caller, sessionId: string): Promise<Delivery> {
  assertTokenScope(caller, 'write');
  const access = await loadSessionForParticipant(ctx, caller, sessionId);
  assertCanAct(access, 'deliver sessions');
  const session = access.session;
  if (session.status !== 'RUNNING') {
    throw new AppError('LSE-CONF-001', { devMessage: `Session is ${session.status}, not RUNNING` });
  }
  if (session.prUrl && session.outcome) {
    throw new AppError('LSE-GH-008', {
      devMessage: 'A pull request already exists for this session',
      action: { type: 'link', label: 'Open pull request', href: session.prUrl },
    });
  }
  if (ctx.agent.isBusy(session.id)) {
    throw new AppError('LSE-AGT-011', { devMessage: 'Wait for the agent to finish its turn' });
  }
  const row = await ctx.prisma.project.findUniqueOrThrow({
    where: { id: session.projectId },
    include: { org: true },
  });
  // Phase 9: a session started from another branch diffs against / opens its PR into it.
  const project = session.baseBranch ? { ...row, defaultBranch: session.baseBranch } : row;
  const sandbox = await getOrConnectSandbox(ctx, session);
  if (!sandbox || !(await sandbox.isRunning().catch(() => false))) {
    throw new AppError('LSE-SBX-010', { devMessage: 'The session sandbox is not reachable' });
  }
  const git = await resolveGitAccess(ctx, {
    org: project.org,
    userId: session.userId,
    repoFullName: project.githubRepoFullName,
  });
  const env = await decryptProjectEnv(ctx, project);
  return {
    access,
    session,
    project,
    sandbox,
    git,
    secrets: secretValuesOf(env),
    ...splitRepo(project.githubRepoFullName),
  };
}

// ---- diff ----------------------------------------------------------------------------------

async function sessionDiffFiles(
  sandbox: SandboxHandle,
  defaultBranch: string,
): Promise<DiffFile[]> {
  const base = await baseRef(sandbox, defaultBranch);
  return parseUnifiedDiff(await workingDiff(sandbox, base));
}

/** `GET /sessions/:id/diff` — Pro sessions, or org ADMIN+. */
export async function getDiff(
  ctx: AppContext,
  caller: Caller,
  sessionId: string,
): Promise<DiffDto> {
  assertTokenScope(caller, 'read');
  const { session, isAdmin } = await loadSessionForParticipant(ctx, caller, sessionId);
  if (session.mode !== 'PRO' && !isAdmin) {
    throw new AppError('LSE-ORG-002', { devMessage: 'The diff is available in Pro mode only' });
  }
  const project = await ctx.prisma.project.findUniqueOrThrow({ where: { id: session.projectId } });
  const secrets = secretValuesOf(await decryptProjectEnv(ctx, project));
  let files: DiffFile[] | null = null;
  const sandbox = session.status === 'RUNNING' ? await getOrConnectSandbox(ctx, session) : null;
  if (sandbox && (await sandbox.isRunning().catch(() => false))) {
    files = await sessionDiffFiles(sandbox, session.baseBranch ?? project.defaultBranch);
  } else {
    // Ended sessions: the diff captured at delivery time.
    const art = await ctx.prisma.artifact.findFirst({
      where: { sessionId, kind: 'diff' },
      orderBy: { createdAt: 'desc' },
    });
    const obj = art?.storageKey ? await ctx.storage.get(art.storageKey) : null;
    if (obj) {
      const chunks: Buffer[] = [];
      for await (const c of obj.stream) chunks.push(Buffer.from(c as Uint8Array));
      files = parseUnifiedDiff(Buffer.concat(chunks).toString('utf8'));
    }
  }
  const scrubbed = (files ?? []).map((f) => ({ ...f, patch: scrubSecrets(f.patch, secrets) }));
  const capped = capDiff(scrubbed);
  return diffDtoSchema.parse({
    files: capped.files,
    ...(capped.truncated ? { truncated: true } : {}),
  });
}

// ---- risk gate -----------------------------------------------------------------------------

/**
 * HIGH-risk changes need an admin unless every high-risk file is covered by an APPROVED
 * gate in this session (e.g. a dependency change the admin approved). LSE-AGT-013.
 */
async function assertRiskApproved(
  ctx: AppContext,
  d: Delivery,
  files: DiffFile[],
): Promise<RiskAssessment> {
  const changed = files.filter((f) => f.status !== 'deleted').map((f) => f.path);
  const deleted = files.filter((f) => f.status === 'deleted').map((f) => f.path);
  const risk = assessRisk({ files: changed, deletedFiles: deleted });
  if (risk.level !== 'HIGH' || d.access.isAdmin) return risk;
  const approved = new Set(
    (
      await ctx.prisma.toolApproval.findMany({
        where: { sessionId: d.session.id, status: 'APPROVED', gate: { not: null } },
        select: { gate: true },
      })
    ).map((a) => a.gate as ApprovalGate),
  );
  const uncovered = [
    ...changed.filter((f) => {
      const r = assessRisk({ files: [f] });
      if (r.level !== 'HIGH') return false;
      const gate = gateForFile(f);
      return !gate || !approved.has(gate);
    }),
    ...(approved.has('deletes') ? [] : deleted),
  ];
  if (uncovered.length) {
    throw new AppError('LSE-AGT-013', {
      devMessage: `High-risk changes need an admin: ${uncovered.slice(0, 10).join(', ')}`,
    });
  }
  return risk;
}

// ---- commit & push -------------------------------------------------------------------------

function oneLine(s: string, max: number): string {
  const t = s.replace(/\s+/g, ' ').trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

function trailerValue(s: string): string {
  return s.replace(/[\r\n<>]/g, ' ').trim();
}

async function changeSummaries(ctx: AppContext, sessionId: string): Promise<string[]> {
  const rows = await ctx.prisma.chatMessage.findMany({
    where: { sessionId, role: 'ASSISTANT' },
    orderBy: { createdAt: 'desc' },
    take: 20,
    select: { content: true, metadata: true },
  });
  return rows
    .filter(
      (r) => (r.metadata as ChatMessageMetadata | null)?.kind === 'change_summary' && r.content,
    )
    .map((r) => r.content)
    .slice(0, 5)
    .reverse();
}

function commitTitle(d: Delivery, summaries: string[], title?: string): string {
  const conventional = /conventional commits?/i.test(
    `${d.project.contextInstructions}\n${d.project.looseMd ?? ''}`,
  );
  const base = title ?? summaries[summaries.length - 1] ?? 'Update from loose.ai';
  const clean = oneLine(base.replace(/^I\s+/i, '').replace(/\.$/, ''), 64);
  return conventional ? `feat: ${clean}` : `loose: ${clean}`;
}

async function commitAndPush(
  ctx: AppContext,
  d: Delivery,
  caller: Caller,
  title: string,
): Promise<string | null> {
  const status = await gitStatus(d.sandbox);
  if (status.length) {
    const user = await ctx.prisma.user.findUniqueOrThrow({ where: { id: d.session.userId } });
    const coAuthors = [
      `Co-authored-by: ${trailerValue(user.name ?? user.email)} <${trailerValue(user.email)}>`,
      ...(caller.user.id !== user.id
        ? [
            `Co-authored-by: ${trailerValue(caller.user.name ?? caller.user.email)} <${trailerValue(caller.user.email)}>`,
          ]
        : []),
      `Co-authored-by: ${BOT_NAME} <${BOT_EMAIL}>`,
    ];
    const message = scrubSecrets(
      `${title}\n\nSession: ${d.session.id}\n\n${coAuthors.join('\n')}\n`,
      d.secrets,
    );
    const msgPath = `${d.sandbox.paths.state}/commit-msg.txt`;
    await d.sandbox.writeFile(msgPath, message);
    const c = await runGit(d, `git add -A && git commit -q --no-verify -F ${shq(msgPath)}`);
    if (c.exitCode !== 0) {
      throw new AppError('LSE-GH-005', {
        devMessage: `git commit failed (exit ${c.exitCode}): ${oneLine(c.stderr || c.stdout, 300)}`,
      });
    }
  }
  const push = await runGit(
    d,
    `git push -q origin ${shq(`HEAD:refs/heads/${d.session.branchName}`)}`,
  );
  if (push.exitCode !== 0) {
    throw new AppError('LSE-GH-005', {
      devMessage: `git push was rejected (exit ${push.exitCode}): ${oneLine(push.stderr, 300)}`,
    });
  }
  return headSha(d.sandbox);
}

// ---- PR ------------------------------------------------------------------------------------

async function screenshotLinks(
  ctx: AppContext,
  sessionId: string,
): Promise<{ before?: string; after?: string }> {
  const shots = await ctx.prisma.artifact.findMany({
    where: { sessionId, kind: 'screenshot' },
    orderBy: { createdAt: 'asc' },
  });
  const phase = (a: (typeof shots)[number]) => (a.meta as { phase?: string } | null)?.phase;
  const before = shots.find((a) => phase(a) === 'before');
  const after = [...shots].reverse().find((a) => phase(a) === 'after');
  const link = (id: string) =>
    publicArtifactUrl(ctx.env.API_URL, signArtifactToken(ctx.env.SESSION_SECRET, id));
  return {
    ...(before ? { before: link(before.id) } : {}),
    ...(after ? { after: link(after.id) } : {}),
  };
}

export async function buildPrBody(
  ctx: AppContext,
  d: Pick<Delivery, 'session' | 'secrets'>,
  input: { summaries: string[]; files: DiffFile[]; risk: RiskAssessment; notes?: string },
): Promise<string> {
  const stats = diffStats(input.files);
  const shots = await screenshotLinks(ctx, d.session.id);
  const lines: string[] = [];
  lines.push('## Summary', '');
  if (input.summaries.length) for (const s of input.summaries) lines.push(`- ${oneLine(s, 500)}`);
  else lines.push('- Changes made in a loose.ai session.');
  lines.push('', '## Technical summary', '');
  lines.push(`${input.files.length} file(s) changed, +${stats.additions} −${stats.deletions}`, '');
  for (const f of input.files.slice(0, 100)) {
    lines.push(`- \`${f.path}\` (${f.status}, +${f.additions} −${f.deletions})`);
  }
  if (input.files.length > 100) lines.push(`- …and ${input.files.length - 100} more`);
  lines.push('', '## Risk', '');
  lines.push(`**${input.risk.level}**`);
  for (const r of input.risk.reasons.slice(0, 10)) lines.push(`- ${r}`);
  if (shots.before || shots.after) {
    lines.push('', '## Screenshots', '');
    if (shots.before) lines.push(`Before: ![before](${shots.before})`);
    if (shots.after) lines.push(`After: ![after](${shots.after})`);
    lines.push('', '_Screenshot links expire after 7 days._');
  }
  if (input.notes) lines.push('', '## Notes', '', input.notes);
  lines.push('', '## Session', '');
  lines.push(`[Open in loose.ai](${ctx.env.APP_URL.replace(/\/+$/, '')}/session/${d.session.id})`);
  lines.push(`Cost: $${Number(d.session.totalCostUsd).toFixed(2)}`);
  return scrubSecrets(lines.join('\n'), d.secrets);
}

interface PrRef {
  number: number;
  url: string;
}

async function openOrReusePr(
  ctx: AppContext,
  d: Delivery,
  input: { title: string; body: string; draft: boolean },
): Promise<PrRef> {
  if (!d.git.token) {
    throw new AppError('LSE-GH-001', {
      devMessage: 'No GitHub token to open a pull request',
      action: { type: 'link', label: 'Connect GitHub', href: '/api/v1/auth/github?link=1' },
    });
  }
  const gh = octokitFor(ctx, d.git.token);
  try {
    return await withRetry(
      async () => {
        const existing = await gh.rest.pulls.list({
          owner: d.owner,
          repo: d.repo,
          head: `${d.owner}:${d.session.branchName}`,
          state: 'open',
          per_page: 1,
        });
        const open = existing.data[0];
        if (open) {
          if (d.session.prNumber === open.number)
            return { number: open.number, url: open.html_url };
          throw new AppError('LSE-GH-008', {
            devMessage: `Pull request #${open.number} already exists for this branch`,
            action: { type: 'link', label: 'Open pull request', href: open.html_url },
          });
        }
        const res = await gh.rest.pulls.create({
          owner: d.owner,
          repo: d.repo,
          title: input.title,
          head: d.session.branchName,
          base: d.project.defaultBranch,
          body: input.body,
          draft: input.draft,
        });
        return { number: res.data.number, url: res.data.html_url };
      },
      {
        isRetryable: (err) => {
          const status = (err as { status?: unknown } | null)?.status;
          return typeof status !== 'number' || status >= 500;
        },
      },
    );
  } catch (err) {
    if (err instanceof AppError) throw err;
    const e = err as { status?: number; message?: string };
    if (e.status === 422 && /already exists/i.test(e.message ?? '')) {
      throw new AppError('LSE-GH-008', { devMessage: 'A pull request already exists', cause: err });
    }
    if (e.status === 422 && /no commits between/i.test(e.message ?? '')) {
      throw new AppError('LSE-GH-008', { devMessage: 'Nothing to submit', cause: err });
    }
    throw mapGithubError(err);
  }
}

interface Submitted {
  pr: PrRef;
  sha: string | null;
  files: DiffFile[];
  diffText: string;
}

async function submit(
  ctx: AppContext,
  d: Delivery,
  caller: Caller,
  opts: { title?: string; draft: boolean; notes?: string },
): Promise<Submitted> {
  const base = await baseRef(d.sandbox, d.project.defaultBranch);
  const status = await gitStatus(d.sandbox);
  const ahead = await commitsAhead(d.sandbox, base);
  if (!status.length && ahead === 0) {
    throw new AppError('LSE-GH-008', {
      devMessage: 'Nothing to submit: no changes in this session',
    });
  }
  const diffText = await workingDiff(d.sandbox, base);
  const files = parseUnifiedDiff(diffText);
  const risk = await assertRiskApproved(ctx, d, files);
  const summaries = await changeSummaries(ctx, d.session.id);
  const title = commitTitle(d, summaries, opts.title);
  const sha = await commitAndPush(ctx, d, caller, title);
  const body = await buildPrBody(ctx, d, {
    summaries,
    files,
    risk,
    ...(opts.notes ? { notes: opts.notes } : {}),
  });
  const pr = await openOrReusePr(ctx, d, {
    title: opts.title ?? title,
    body,
    draft: opts.draft,
  });
  await ctx.prisma.session.update({
    where: { id: d.session.id },
    data: {
      prUrl: pr.url,
      prNumber: pr.number,
      prState: 'open',
      ...(d.session.prNumber === pr.number ? {} : { prCreatedAt: new Date() }),
      commitSha: sha,
    },
  });
  if (d.session.prNumber !== pr.number) {
    await ctx.audit.record({
      orgId: d.project.orgId,
      actorId: caller.user.id,
      action: 'session.pr_created',
      target: d.session.id,
      meta: { prNumber: pr.number, prUrl: pr.url, risk: risk.level, files: files.length },
      ip: caller.ip,
    });
    // `Notification` hooks (spec §8.9): Slack / webhook handlers run on the server.
    await runLifecycleHooks(ctx, {
      sessionId: d.session.id,
      orgId: d.project.orgId,
      projectId: d.project.id,
      event: 'Notification',
      message: `A pull request was created for ${d.project.name}`,
      context: {
        prUrl: pr.url,
        prNumber: pr.number,
        risk: risk.level,
        files: files.length,
        repo: d.project.githubRepoFullName,
      },
    });
    await emitPrCreated(ctx, d.session.id, {
      url: pr.url,
      number: pr.number,
      repo: d.project.githubRepoFullName,
      head: d.session.branchName,
      base: d.project.defaultBranch,
    });
  }
  return { pr, sha, files, diffText };
}

async function finish(
  ctx: AppContext,
  d: Delivery,
  caller: Caller,
  outcome: Outcome,
  extra: Prisma.SessionUpdateInput,
  diffText?: string,
): Promise<DeliveryResultDto> {
  if (diffText) {
    await saveArtifact(ctx, {
      sessionId: d.session.id,
      kind: 'diff',
      data: scrubSecrets(diffText, d.secrets),
      contentType: 'text/x-diff',
      meta: { phase: 'delivery', outcome },
    }).catch((err: unknown) =>
      ctx.logger.warn({ err, sessionId: d.session.id }, 'diff artifact failed'),
    );
  }
  await ctx.prisma.session.update({ where: { id: d.session.id }, data: { outcome, ...extra } });
  await stopSession(ctx, d.session.id, {
    to: 'COMPLETED',
    reason: 'completed',
    pushWip: false,
    actorId: caller.user.id,
    from: [d.session.status],
  });
  const fresh = await ctx.prisma.session.findUniqueOrThrow({
    where: { id: d.session.id },
    include: sessionInclude,
  });
  return {
    session: toSessionDto(ctx, fresh),
    prUrl: fresh.prUrl,
    prNumber: fresh.prNumber,
    commitSha: fresh.commitSha,
  };
}

/** `POST /sessions/:id/create-pr` (owner or ADMIN+). */
export async function createPr(
  ctx: AppContext,
  caller: Caller,
  sessionId: string,
  body: CreatePrBody,
): Promise<DeliveryResultDto> {
  const d = await prepare(ctx, caller, sessionId);
  const s = await submit(ctx, d, caller, {
    ...(body.title ? { title: body.title } : {}),
    ...(body.notes ? { notes: body.notes } : {}),
    draft: body.draft,
  });
  return finish(ctx, d, caller, 'PR_CREATED', {}, s.diffText);
}

function mergeError(err: unknown): AppError {
  const e = (err ?? {}) as { status?: number; message?: string };
  const msg = e.message ?? '';
  const devMessage = `GitHub merge failed (${e.status ?? 'network'}): ${oneLine(msg, 200)}`;
  if (
    /status check|checks? (?:are |is )?(?:failing|pending|expected|required)|required status/i.test(
      msg,
    )
  ) {
    return new AppError('LSE-GH-013', { devMessage, cause: err });
  }
  if (e.status === 405) return new AppError('LSE-GH-007', { devMessage, cause: err });
  if (e.status === 409) return new AppError('LSE-GH-006', { devMessage, cause: err });
  return mapGithubError(err);
}

/** `POST /sessions/:id/commit-to-main` (ADMIN+ and org policy `commitToMainEnabled`). */
export async function commitToMain(
  ctx: AppContext,
  caller: Caller,
  sessionId: string,
  body: CommitToMainBody,
): Promise<DeliveryResultDto> {
  assertTokenScope(caller, 'write');
  const pre = await loadSessionForParticipant(ctx, caller, sessionId);
  if (!isAdminRole(pre.membership.role)) {
    throw new AppError('LSE-ORG-002', { devMessage: 'Only org admins can commit to main' });
  }
  const org = await ctx.prisma.organization.findUniqueOrThrow({
    where: { id: pre.session.project.orgId },
  });
  if (!parseOrgPolicy(org.policy).commitToMainEnabled) {
    throw new AppError('LSE-ORG-009', {
      devMessage: 'commitToMainEnabled is off in the org policy',
    });
  }
  const d = await prepare(ctx, caller, sessionId);
  const s = await submit(ctx, d, caller, { draft: false });
  const gh = octokitFor(ctx, d.git.token!);
  let mergeSha: string | null = null;
  try {
    const res = await gh.rest.pulls.merge({
      owner: d.owner,
      repo: d.repo,
      pull_number: s.pr.number,
      merge_method: body.mergeMethod,
    });
    if (!res.data.merged) throw Object.assign(new Error(res.data.message), { status: 405 });
    mergeSha = res.data.sha;
  } catch (err) {
    // The PR stays open and the session keeps running so the user can act on it.
    throw mergeError(err);
  }
  await ctx.audit.record({
    orgId: d.project.orgId,
    actorId: caller.user.id,
    action: 'session.committed_to_main',
    target: d.session.id,
    meta: { prNumber: s.pr.number, mergeMethod: body.mergeMethod, sha: mergeSha },
    ip: caller.ip,
  });
  return finish(
    ctx,
    d,
    caller,
    'COMMITTED_TO_MAIN',
    { commitSha: mergeSha, prState: 'merged', prMergedAt: new Date() },
    s.diffText,
  );
}

/** `POST /sessions/:id/discard` (owner or ADMIN+): delete the pushed branch, stop, DISCARDED. */
export async function discardSession(
  ctx: AppContext,
  caller: Caller,
  sessionId: string,
): Promise<DeliveryResultDto> {
  assertTokenScope(caller, 'write');
  const access = await loadSessionForParticipant(ctx, caller, sessionId);
  assertCanAct(access, 'discard sessions');
  const session = access.session;
  const allowed = ['RUNNING', 'PAUSED', 'ERRORED', 'TIMED_OUT'];
  if (!allowed.includes(session.status) || session.outcome) {
    throw new AppError('LSE-CONF-001', {
      devMessage: `Cannot discard a ${session.status} session`,
    });
  }
  const project = await ctx.prisma.project.findUniqueOrThrow({
    where: { id: session.projectId },
    include: { org: true },
  });
  const git = await resolveGitAccess(ctx, {
    org: project.org,
    userId: session.userId,
    repoFullName: project.githubRepoFullName,
  }).catch(() => null);
  const refs = [`refs/heads/${session.branchName}`, ...(session.wipRef ? [session.wipRef] : [])];
  const sandbox = session.status === 'RUNNING' ? await getOrConnectSandbox(ctx, session) : null;
  if (git && sandbox && (await sandbox.isRunning().catch(() => false))) {
    const d = { sandbox, git, secrets: [] as string[] };
    for (const ref of refs) {
      const ls = await runGit(d, `git ls-remote --exit-code origin ${shq(ref)}`, 60_000);
      if (ls.exitCode === 0) await runGit(d, `git push -q origin --delete ${shq(ref)}`, 60_000);
    }
  } else if (git?.token && !remoteUrlFor(ctx, project.githubRepoFullName).override) {
    const { owner, repo } = splitRepo(project.githubRepoFullName);
    const gh = octokitFor(ctx, git.token);
    for (const ref of refs) {
      await gh.rest.git
        .deleteRef({ owner, repo, ref: ref.replace(/^refs\//, '') })
        .catch((err: unknown) => {
          const st = (err as { status?: number }).status;
          if (st !== 404 && st !== 422)
            ctx.logger.warn(
              { err: mapGithubError(err).devMessage, sessionId },
              'branch delete failed',
            );
        });
    }
  }
  await ctx.prisma.session.update({ where: { id: session.id }, data: { outcome: 'DISCARDED' } });
  await stopSession(ctx, session.id, {
    to: 'COMPLETED',
    reason: 'completed',
    pushWip: false,
    actorId: caller.user.id,
    from: [session.status],
  });
  await ctx.audit.record({
    orgId: project.orgId,
    actorId: caller.user.id,
    action: 'session.discarded',
    target: session.id,
    meta: { branch: session.branchName },
    ip: caller.ip,
  });
  const fresh = await ctx.prisma.session.findUniqueOrThrow({
    where: { id: session.id },
    include: sessionInclude,
  });
  return {
    session: toSessionDto(ctx, fresh),
    prUrl: fresh.prUrl,
    prNumber: fresh.prNumber,
    commitSha: fresh.commitSha,
  };
}

// ---- inbound webhook -----------------------------------------------------------------------

interface PullRequestEvent {
  action?: string;
  pull_request?: {
    number?: number;
    merged?: boolean;
    html_url?: string;
    head?: { ref?: string };
    merge_commit_sha?: string | null;
  };
  repository?: { full_name?: string };
}

/** `pull_request` closed/merged → update the matching session (audited). */
export async function handlePullRequestEvent(
  ctx: AppContext,
  payload: PullRequestEvent,
): Promise<boolean> {
  const pr = payload.pull_request;
  const repoName = payload.repository?.full_name;
  if (payload.action !== 'closed' || !pr?.number || !repoName) return false;
  const session = await ctx.prisma.session.findFirst({
    where: {
      project: { githubRepoFullName: repoName },
      OR: [
        { prNumber: pr.number },
        ...(pr.head?.ref ? [{ branchName: pr.head.ref, prNumber: null }] : []),
      ],
    },
    include: { project: { select: { orgId: true } } },
    orderBy: { createdAt: 'desc' },
  });
  if (!session) return false;
  const merged = pr.merged === true;
  await ctx.prisma.session.update({
    where: { id: session.id },
    data: {
      prNumber: pr.number,
      prState: merged ? 'merged' : 'closed',
      ...(merged ? { prMergedAt: new Date() } : {}),
      ...(pr.html_url && !session.prUrl ? { prUrl: pr.html_url } : {}),
    },
  });
  await ctx.audit.record({
    orgId: session.project.orgId,
    actorId: null,
    action: merged ? 'session.pr_merged' : 'session.pr_closed',
    target: session.id,
    meta: { prNumber: pr.number, repo: repoName },
  });
  return true;
}
