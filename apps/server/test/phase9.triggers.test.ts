/**
 * Phase 9 / W4 — triggers: admin CRUD, GitHub PR-comment flow + permission rejection, Slack
 * slash command (signature valid/invalid/stale), Linear and Jira webhooks, scheduled/cron
 * firing (due-once semantics), and the new error codes (LSE-AUTH-009, LSE-SYS-007 disabled).
 */
import { createHmac } from 'node:crypto';
import { http as mswHttp, HttpResponse, type RequestHandler } from 'msw';
import request from 'supertest';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { nextCronRun } from '@loose/shared';
import {
  FakeGit,
  installFakeRunner,
  mswFetch,
  playTurn,
  waitFor,
  type RunnerScript,
} from './agentHelpers';
import {
  addMember,
  createOrg,
  expectError,
  GITHUB_API,
  linkGithub,
  login,
  makeApp,
  resetDb,
  testPrisma,
  type Client,
} from './helpers';
import { addApiKey, createReadyProject, fakeSandbox } from './sessionHelpers';
import { scheduleTick } from '../src/services/triggers.service';
import { verifySlackSignature } from '../src/services/triggers/slack';

const prisma = testPrisma();
const handlers: { current: RequestHandler[] } = { current: [] };
const WEBHOOK_SECRET = 'whsec_test_secret_value';
const SLACK_SECRET = 'slack-signing-secret';
const LINEAR_SECRET = 'linear-webhook-secret';
const JIRA_SECRET = 'jira-webhook-secret';
const { app, ctx } = makeApp({
  context: { fetch: mswFetch(handlers) },
  env: {
    GITHUB_WEBHOOK_SECRET: WEBHOOK_SECRET,
    SLACK_SIGNING_SECRET: SLACK_SECRET,
    LINEAR_WEBHOOK_SECRET: LINEAR_SECRET,
    JIRA_WEBHOOK_SECRET: JIRA_SECRET,
  },
});
const fake = fakeSandbox(ctx);
const script: { current: RunnerScript } = { current: () => undefined };
let git: FakeGit;
const REPO = `${GITHUB_API}/repos/acme/web`;
const FILE = 'src/components/Header.tsx';

function sign(body: string): string {
  return `sha256=${createHmac('sha256', WEBHOOK_SECRET).update(body).digest('hex')}`;
}

function sendGithub(
  event: string,
  payload: object,
  deliveryId = `dlv_${Math.random().toString(36).slice(2)}`,
) {
  const body = JSON.stringify(payload);
  return request(app)
    .post('/api/v1/github/webhook')
    .set('x-github-event', event)
    .set('x-github-delivery', deliveryId)
    .set('x-hub-signature-256', sign(body))
    .set('Content-Type', 'application/json')
    .send(body);
}

function prCommentPayload(opts: {
  commentId: number;
  body: string;
  association?: string;
  login?: string;
  botType?: string;
}) {
  return {
    action: 'created',
    issue: {
      number: 12,
      html_url: 'https://github.com/acme/web/pull/12',
      pull_request: { url: 'x' },
    },
    comment: {
      id: opts.commentId,
      body: opts.body,
      author_association: opts.association ?? 'OWNER',
      user: { login: opts.login ?? 'reviewer', type: opts.botType ?? 'User' },
    },
    repository: { full_name: 'acme/web' },
  };
}

function prGetHandler(headRef = 'feature/x', headRepo = 'acme/web') {
  return mswHttp.get(`${REPO}/pulls/:number`, () =>
    HttpResponse.json({
      number: 12,
      html_url: 'https://github.com/acme/web/pull/12',
      head: { ref: headRef, repo: { full_name: headRepo } },
      base: { repo: { full_name: 'acme/web' } },
    }),
  );
}

function prCreateHandlers() {
  const comments: Record<string, unknown>[] = [];
  handlers.current = [
    prGetHandler(),
    mswHttp.get(`${REPO}/pulls`, () => HttpResponse.json([])),
    mswHttp.post(`${REPO}/pulls`, () =>
      HttpResponse.json(
        { number: 55, html_url: 'https://github.com/acme/web/pull/55' },
        { status: 201 },
      ),
    ),
    mswHttp.post(`${REPO}/issues/:number/comments`, async ({ request: req }) => {
      comments.push((await req.json()) as Record<string, unknown>);
      return HttpResponse.json({ id: 1 }, { status: 201 });
    }),
  ];
  return comments;
}

async function world() {
  const admin = await login(app, undefined, 'Ada Admin');
  const org = await createOrg(admin);
  const owner = await login(app, undefined, 'Mo Member');
  const viewer = await login(app, undefined, 'Vi Viewer');
  await addMember(org.id, owner.user.id, 'MEMBER');
  await addMember(org.id, viewer.user.id, 'VIEWER');
  await linkGithub(ctx, owner.user.id);
  await addApiKey(ctx, owner.user.id);
  const project = await createReadyProject(ctx, org.id);
  return { admin, owner, viewer, orgId: org.id, projectId: project.id };
}

async function createTrigger(c: Client, orgId: string, body: Record<string, unknown>) {
  return c.post(`/api/v1/orgs/${orgId}/triggers`, body);
}

beforeEach(async () => {
  await ctx.agent.shutdownAll();
  await ctx.jobs.onIdle();
  fake.reset();
  installFakeRunner(fake, script);
  git = new FakeGit().install(fake);
  script.current = (cmd, r) => {
    if (cmd.type === 'user_message') {
      git.set(FILE, ' M', ['<h1>fixed</h1>']);
      playTurn(r, { text: 'Fixed as requested.', files: [FILE] });
    }
  };
  handlers.current = [];
  await resetDb();
  ctx.platformEvents.clearHistory();
});

afterAll(async () => {
  await ctx.agent.idle();
  await ctx.jobs.onIdle();
  await prisma.$disconnect();
});

// ---- admin CRUD -----------------------------------------------------------------------------

describe('trigger admin CRUD', () => {
  it('creates, lists, updates, fires manually and deletes a trigger', async () => {
    const w = await world();
    const created = await createTrigger(w.admin, w.orgId, {
      projectId: w.projectId,
      kind: 'GITHUB_ISSUE_LABEL',
      name: 'Label trigger',
      config: { label: 'ai-fix' },
    });
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    const dto = created.body.data!;
    expect(dto.runAsUserId).toBe(w.admin.user.id); // defaults to the creator
    expect(dto.configured).toBe(true);
    expect(dto.webhookUrl).toBeNull();

    const list = await w.admin.get(`/api/v1/orgs/${w.orgId}/triggers`);
    expect(list.body.data).toHaveLength(1);

    const updated = await w.admin.put(`/api/v1/orgs/${w.orgId}/triggers/${dto.id}`, {
      enabled: false,
      runAsUserId: w.owner.user.id,
    });
    expect(updated.status, JSON.stringify(updated.body)).toBe(200);
    expect(updated.body.data.enabled).toBe(false);
    expect(updated.body.data.runAsUserId).toBe(w.owner.user.id);

    // Disabled trigger: manual fire is rejected.
    expectError(
      await w.admin.post(`/api/v1/orgs/${w.orgId}/triggers/${dto.id}/fire`, {}),
      'LSE-CONF-001',
      409,
    );

    await w.admin.put(`/api/v1/orgs/${w.orgId}/triggers/${dto.id}`, { enabled: true });
    const del = await w.admin.delete(`/api/v1/orgs/${w.orgId}/triggers/${dto.id}`);
    expect(del.status).toBe(204);
    expect(await prisma.trigger.count()).toBe(0);
  });

  it('runAsUserId must be a MEMBER+ of the org (VIEWER rejected)', async () => {
    const w = await world();
    const res = await createTrigger(w.admin, w.orgId, {
      projectId: w.projectId,
      kind: 'GITHUB_ISSUE_LABEL',
      name: 'Bad run-as',
      config: { label: 'loose' },
      runAsUserId: w.viewer.user.id,
    });
    expectError(res, 'LSE-VAL-001', 400);
  });

  it('manual fire runs the trigger and GET …/runs lists it', async () => {
    const w = await world();
    const created = await createTrigger(w.admin, w.orgId, {
      projectId: w.projectId,
      kind: 'SLACK_COMMAND',
      name: 'Manual',
      config: { teamId: 'T1' },
      runAsUserId: w.owner.user.id,
      promptTemplate: '{{text}}',
    });
    prCreateHandlers();
    const fire = await w.admin.post(
      `/api/v1/orgs/${w.orgId}/triggers/${created.body.data!.id}/fire`,
      { text: 'fix the thing' },
    );
    expect(fire.status, JSON.stringify(fire.body)).toBe(202);
    expect(fire.body.data.runId).not.toBeNull();
    await ctx.jobs.onIdle();
    await ctx.agent.idle();

    const runs = await w.admin.get(
      `/api/v1/orgs/${w.orgId}/triggers/${created.body.data!.id}/runs`,
    );
    expect(runs.body.data).toHaveLength(1);
    expect(runs.body.data[0].id).toBe(fire.body.data.runId);
  });
});

// ---- GitHub PR comment -----------------------------------------------------------------------

describe('GitHub PR comment trigger (@loose fix this)', () => {
  async function withTrigger(cfg: Record<string, unknown> = {}) {
    const w = await world();
    const created = await createTrigger(w.admin, w.orgId, {
      projectId: w.projectId,
      kind: 'GITHUB_PR_COMMENT',
      name: 'PR fix',
      config: {
        mention: '@loose',
        allowedAssociations: ['OWNER', 'MEMBER', 'COLLABORATOR'],
        ...cfg,
      },
      runAsUserId: w.owner.user.id,
    });
    return { ...w, triggerId: created.body.data!.id as string };
  }

  it('@loose <instruction> on a PR fixes it on the PR branch and replies with the PR link', async () => {
    const w = await withTrigger();
    const comments = prCreateHandlers();
    const res = await sendGithub(
      'issue_comment',
      prCommentPayload({ commentId: 1, body: '@loose please fix the header color' }),
    );
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(res.body.data.handled).toBe(true);

    const fire = await waitFor(
      () =>
        prisma.triggerFire.findFirst({
          where: { triggerId: w.triggerId, runId: { not: null } },
        }),
      { label: 'trigger fire with a run id', timeoutMs: 10_000 },
    );
    expect(fire.runId).not.toBeNull();
    const run = await waitFor(async () => {
      const r = await prisma.run.findUniqueOrThrow({ where: { id: fire.runId! } });
      return r.status === 'SUCCEEDED' || r.status === 'FAILED' ? r : null;
    });
    expect(run.status, JSON.stringify(run)).toBe('SUCCEEDED');
    expect(run.source).toBe('GITHUB_COMMENT');
    const options = run.options as Record<string, unknown>;
    expect(options.branch).toBe('feature/x');
    expect(run.prompt).toContain('please fix the header color');

    await ctx.jobs.onIdle();
    await waitFor(() => comments.length > 0);
    expect(String(comments[0]!.body)).toContain('pull/55');
  });

  it('a commenter without the required association is rejected (no run)', async () => {
    const w = await withTrigger();
    prCreateHandlers();
    const res = await sendGithub(
      'issue_comment',
      prCommentPayload({ commentId: 2, body: '@loose fix this', association: 'NONE' }),
    );
    expect(res.status).toBe(202);
    expect(res.body.data.handled).toBe(false);
    await ctx.jobs.onIdle();
    expect(await prisma.triggerFire.count({ where: { triggerId: w.triggerId } })).toBe(0);
  });

  it('a bot comment is ignored', async () => {
    const w = await withTrigger();
    prCreateHandlers();
    const res = await sendGithub(
      'issue_comment',
      prCommentPayload({ commentId: 3, body: '@loose fix this', botType: 'Bot' }),
    );
    expect(res.body.data.handled).toBe(false);
    await ctx.jobs.onIdle();
    expect(await prisma.triggerFire.count({ where: { triggerId: w.triggerId } })).toBe(0);
  });

  it('a comment without the mention does not fire', async () => {
    await withTrigger();
    prCreateHandlers();
    const res = await sendGithub(
      'issue_comment',
      prCommentPayload({ commentId: 4, body: 'nice work' }),
    );
    expect(res.body.data.handled).toBe(false);
    await ctx.jobs.onIdle();
    expect(await prisma.triggerFire.count()).toBe(0);
  });

  it('ignores a PR comment when the head branch belongs to a fork', async () => {
    const w = await withTrigger();
    handlers.current = [prGetHandler('feature/x', 'outsider/web')];
    const res = await sendGithub(
      'issue_comment',
      prCommentPayload({ commentId: 6, body: '@loose fix this' }),
    );
    expect(res.status).toBe(202);
    expect(res.body.data.handled).toBe(false);
    await ctx.jobs.onIdle();
    expect(await prisma.triggerFire.count({ where: { triggerId: w.triggerId } })).toBe(0);
  });

  it('allows the same GitHub delivery to retry after transient dispatch failure', async () => {
    const w = await withTrigger();
    prCreateHandlers();
    const payload = prCommentPayload({ commentId: 7, body: '@loose fix this' });
    const enqueue = vi
      .spyOn(ctx.jobs, 'enqueue')
      .mockRejectedValueOnce(new Error('queue unavailable'));
    const first = await sendGithub('issue_comment', payload, 'dlv-pr-retry');
    enqueue.mockRestore();
    expect(first.body.data.handled).toBe(false);

    const second = await sendGithub('issue_comment', payload, 'dlv-pr-retry');
    expect(second.body.data.handled).toBe(true);
    expect(second.body.data.duplicate).toBeUndefined();
    await ctx.jobs.onIdle();
    expect(await prisma.triggerFire.count({ where: { triggerId: w.triggerId } })).toBe(1);
  });

  it('duplicate delivery id of the same comment event does not double-fire', async () => {
    const w = await withTrigger();
    prCreateHandlers();
    const payload = prCommentPayload({ commentId: 5, body: '@loose fix this' });
    const first = await sendGithub('issue_comment', payload, 'dlv-pr-dup');
    expect(first.body.data.handled).toBe(true);
    await ctx.jobs.onIdle();
    expect(await prisma.triggerFire.count({ where: { triggerId: w.triggerId } })).toBe(1);

    const second = await sendGithub('issue_comment', payload, 'dlv-pr-dup');
    expect(second.body.data.duplicate).toBe(true);
    await ctx.jobs.onIdle();
    expect(await prisma.triggerFire.count({ where: { triggerId: w.triggerId } })).toBe(1);
  });
});

// ---- Slack -------------------------------------------------------------------------------

describe('Slack slash command trigger', () => {
  function slackBody(text = 'fix the bug') {
    return new URLSearchParams({
      team_id: 'T123',
      channel_id: 'C1',
      text,
      user_name: 'alice',
      response_url: 'https://hooks.slack.com/commands/1/2/3',
      command: '/loose',
    }).toString();
  }

  function slackSign(ts: string, body: string): string {
    return `v0=${createHmac('sha256', SLACK_SECRET).update(`v0:${ts}:${body}`).digest('hex')}`;
  }

  async function withSlackTrigger() {
    const w = await world();
    const created = await createTrigger(w.admin, w.orgId, {
      projectId: w.projectId,
      kind: 'SLACK_COMMAND',
      name: 'Slack',
      config: { teamId: 'T123' },
      runAsUserId: w.owner.user.id,
    });
    return { ...w, triggerId: created.body.data!.id as string };
  }

  it('valid signature acks immediately and later posts the result to response_url', async () => {
    const w = await withSlackTrigger();
    prCreateHandlers();
    let posted: Record<string, unknown> | null = null;
    handlers.current.push(
      mswHttp.post('https://hooks.slack.com/commands/1/2/3', async ({ request: req }) => {
        posted = (await req.json()) as Record<string, unknown>;
        return HttpResponse.json({ ok: true });
      }),
    );
    const body = slackBody();
    const ts = String(Math.floor(Date.now() / 1000));
    const res = await request(app)
      .post('/api/v1/integrations/slack/commands')
      .set('x-slack-request-timestamp', ts)
      .set('x-slack-signature', slackSign(ts, body))
      .type('form')
      .send(body);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.text).toMatch(/working/i);

    await waitFor(() => prisma.triggerFire.findFirst({ where: { triggerId: w.triggerId } }));
    await ctx.jobs.onIdle();
    await ctx.agent.idle();
    await ctx.jobs.onIdle();
    await waitFor(() => posted !== null, { label: 'slack response_url posted' });
    expect(String(posted!.text)).toMatch(/pull\/55|Done/);
  });

  it('dedupes a retry of the same signed Slack command', async () => {
    const w = await withSlackTrigger();
    prCreateHandlers();
    handlers.current.push(
      mswHttp.post('https://hooks.slack.com/commands/1/2/3', () => HttpResponse.json({ ok: true })),
    );
    const body = slackBody();
    const ts = String(Math.floor(Date.now() / 1000));
    const send = () =>
      request(app)
        .post('/api/v1/integrations/slack/commands')
        .set('x-slack-request-timestamp', ts)
        .set('x-slack-signature', slackSign(ts, body))
        .type('form')
        .send(body);

    expect((await send()).status).toBe(200);
    await waitFor(() => prisma.triggerFire.count({ where: { triggerId: w.triggerId } }));
    expect((await send()).status).toBe(200);
    await ctx.jobs.onIdle();
    expect(await prisma.triggerFire.count({ where: { triggerId: w.triggerId } })).toBe(1);
  });

  it('invalid signature → LSE-AUTH-009', async () => {
    await withSlackTrigger();
    const body = slackBody();
    const ts = String(Math.floor(Date.now() / 1000));
    const res = await request(app)
      .post('/api/v1/integrations/slack/commands')
      .set('x-slack-request-timestamp', ts)
      .set('x-slack-signature', 'v0=deadbeef')
      .type('form')
      .send(body);
    expectError(res, 'LSE-AUTH-009', 401);
  });

  it('stale timestamp → LSE-AUTH-009', async () => {
    await withSlackTrigger();
    const body = slackBody();
    const ts = String(Math.floor(Date.now() / 1000) - 60 * 60); // 1h old
    const res = await request(app)
      .post('/api/v1/integrations/slack/commands')
      .set('x-slack-request-timestamp', ts)
      .set('x-slack-signature', slackSign(ts, body))
      .type('form')
      .send(body);
    expectError(res, 'LSE-AUTH-009', 401);
  });

  it('verifySlackSignature helper: valid, tampered body, and stale all behave', () => {
    const body = slackBody();
    const ts = String(Math.floor(Date.now() / 1000));
    expect(verifySlackSignature(SLACK_SECRET, ts, slackSign(ts, body), body)).toBe(true);
    expect(verifySlackSignature(SLACK_SECRET, ts, slackSign(ts, body), `${body}x`)).toBe(false);
    const old = String(Math.floor(Date.now() / 1000) - 600);
    expect(verifySlackSignature(SLACK_SECRET, old, slackSign(old, body), body)).toBe(false);
  });

  it('missing SLACK_SIGNING_SECRET → 503 LSE-SYS-007', async () => {
    const { app: appNoSecret } = makeApp({ context: { fetch: mswFetch(handlers) } });
    const body = slackBody();
    const res = await request(appNoSecret)
      .post('/api/v1/integrations/slack/commands')
      .type('form')
      .send(body);
    expectError(res, 'LSE-SYS-007', 503);
  });
});

// ---- Linear --------------------------------------------------------------------------------

describe('Linear webhook trigger', () => {
  /** P10-SEC-007: the URL and the signing secret are per trigger (from the trigger DTO). */
  function linearSign(secret: string, body: string): string {
    return createHmac('sha256', secret).update(body).digest('hex');
  }
  function webhookPath(url: string): string {
    return new URL(url).pathname;
  }

  it('issue create with the configured label fires a run; signature is verified', async () => {
    const w = await world();
    const created = await createTrigger(w.admin, w.orgId, {
      projectId: w.projectId,
      kind: 'LINEAR',
      name: 'Linear',
      config: { label: 'loose' },
      runAsUserId: w.owner.user.id,
    });
    const dto = created.body.data as { webhookUrl: string; webhookSecret: string };
    prCreateHandlers();
    const payload = {
      action: 'create',
      type: 'Issue',
      data: {
        id: 'issue-1',
        identifier: 'ENG-1',
        title: 'Fix the thing',
        description: 'Details',
        url: 'https://linear.app/acme/issue/ENG-1',
        labels: { nodes: [{ name: 'loose' }] },
      },
    };
    const body = JSON.stringify(payload);
    const res = await request(app)
      .post(webhookPath(dto.webhookUrl))
      .set('linear-signature', linearSign(dto.webhookSecret, body))
      .set('Content-Type', 'application/json')
      .send(body);
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(res.body.data.handled).toBe(true);
    await waitFor(() => prisma.triggerFire.count().then((n) => n > 0));
  });

  it('bad signature → LSE-AUTH-009', async () => {
    const w = await world();
    const created = await createTrigger(w.admin, w.orgId, {
      projectId: w.projectId,
      kind: 'LINEAR',
      name: 'Linear',
      config: { label: 'loose' },
      runAsUserId: w.owner.user.id,
    });
    const dto = created.body.data as { webhookUrl: string };
    const body = JSON.stringify({ action: 'create', type: 'Issue', data: { id: 'x' } });
    const res = await request(app)
      .post(webhookPath(dto.webhookUrl))
      .set('linear-signature', 'deadbeef')
      .set('Content-Type', 'application/json')
      .send(body);
    expectError(res, 'LSE-AUTH-009', 401);
  });

  it('the global (untokenised) endpoint is rejected → LSE-AUTH-009 (P10-SEC-007)', async () => {
    const body = JSON.stringify({ action: 'create' });
    const res = await request(app)
      .post('/api/v1/integrations/linear/webhook')
      .set('linear-signature', linearSign(LINEAR_SECRET, body))
      .set('Content-Type', 'application/json')
      .send(body);
    expectError(res, 'LSE-AUTH-009', 401);
  });
});

// ---- Jira ----------------------------------------------------------------------------------

describe('Jira webhook trigger', () => {
  /** P10-SEC-007: the URL and the signing secret are per trigger (from the trigger DTO). */
  function jiraSign(secret: string, body: string): string {
    return `sha256=${createHmac('sha256', secret).update(body).digest('hex')}`;
  }
  function webhookPath(url: string): string {
    return new URL(url).pathname;
  }

  it('issue created with the configured label fires a run; signature is verified', async () => {
    const w = await world();
    const created = await createTrigger(w.admin, w.orgId, {
      projectId: w.projectId,
      kind: 'JIRA',
      name: 'Jira',
      config: { label: 'loose', projectKey: 'WEB' },
      runAsUserId: w.owner.user.id,
    });
    const dto = created.body.data as { webhookUrl: string; webhookSecret: string };
    prCreateHandlers();
    const payload = {
      webhookEvent: 'jira:issue_created',
      issue: {
        key: 'WEB-1',
        self: 'https://acme.atlassian.net/rest/api/2/issue/10001',
        fields: {
          summary: 'Fix the thing',
          description: 'Details',
          project: { key: 'WEB' },
          labels: ['loose'],
        },
      },
    };
    const body = JSON.stringify(payload);
    const res = await request(app)
      .post(webhookPath(dto.webhookUrl))
      .set('x-hub-signature', jiraSign(dto.webhookSecret, body))
      .set('Content-Type', 'application/json')
      .send(body);
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(res.body.data.handled).toBe(true);
    await waitFor(() => prisma.triggerFire.count().then((n) => n > 0));
  });

  it('does not refire an already-labelled Jira issue on a later update', async () => {
    const w = await world();
    const created = await createTrigger(w.admin, w.orgId, {
      projectId: w.projectId,
      kind: 'JIRA',
      name: 'Jira',
      config: { label: 'loose', projectKey: 'WEB' },
      runAsUserId: w.owner.user.id,
    });
    prCreateHandlers();
    const issue = {
      key: 'WEB-2',
      fields: {
        summary: 'Fix the thing',
        project: { key: 'WEB' },
        labels: ['loose'],
      },
    };
    const dto = created.body.data as { webhookUrl: string; webhookSecret: string };
    const send = async (webhookEvent: string) => {
      const body = JSON.stringify({ webhookEvent, issue });
      return request(app)
        .post(webhookPath(dto.webhookUrl))
        .set('x-hub-signature', jiraSign(dto.webhookSecret, body))
        .set('Content-Type', 'application/json')
        .send(body);
    };

    expect((await send('jira:issue_created')).status).toBe(202);
    await waitFor(() => prisma.triggerFire.count({ where: { triggerId: created.body.data!.id } }));
    expect((await send('jira:issue_updated')).status).toBe(202);
    expect(await prisma.triggerFire.count({ where: { triggerId: created.body.data!.id } })).toBe(1);
  });

  it('bad signature → LSE-AUTH-009', async () => {
    const w = await world();
    const created = await createTrigger(w.admin, w.orgId, {
      projectId: w.projectId,
      kind: 'JIRA',
      name: 'Jira',
      config: { label: 'loose' },
      runAsUserId: w.owner.user.id,
    });
    const dto = created.body.data as { webhookUrl: string };
    const body = JSON.stringify({ webhookEvent: 'jira:issue_created', issue: { key: 'WEB-1' } });
    const res = await request(app)
      .post(webhookPath(dto.webhookUrl))
      .set('x-hub-signature', 'sha256=deadbeef')
      .set('Content-Type', 'application/json')
      .send(body);
    expectError(res, 'LSE-AUTH-009', 401);
  });

  it('the global (untokenised) endpoint is rejected → LSE-AUTH-009 (P10-SEC-007)', async () => {
    const body = JSON.stringify({ webhookEvent: 'jira:issue_created' });
    const res = await request(app)
      .post('/api/v1/integrations/jira/webhook')
      .set('x-hub-signature', jiraSign(JIRA_SECRET, body))
      .set('Content-Type', 'application/json')
      .send(body);
    expectError(res, 'LSE-AUTH-009', 401);
  });
});

// ---- Scheduled / cron triggers --------------------------------------------------------------

describe('scheduled (cron) triggers', () => {
  it('fires exactly once for a due slot even if the tick runs twice (claim via updateMany)', async () => {
    const w = await world();
    prCreateHandlers();
    const created = await createTrigger(w.admin, w.orgId, {
      projectId: w.projectId,
      kind: 'SCHEDULE',
      name: 'Nightly',
      config: { cron: '*/15 * * * *', timezone: 'UTC' },
      runAsUserId: w.owner.user.id,
      promptTemplate: 'Run the nightly cleanup',
    });
    const triggerId = created.body.data!.id as string;
    const before = await prisma.trigger.findUniqueOrThrow({ where: { id: triggerId } });
    expect(before.nextRunAt).not.toBeNull();

    const dueAt = before.nextRunAt!;
    const result1 = await scheduleTick(ctx, dueAt);
    const result2 = await scheduleTick(ctx, dueAt);
    expect(result1.fired).toContain(triggerId);
    expect(result2.fired).not.toContain(triggerId);

    expect(await prisma.triggerFire.count({ where: { triggerId } })).toBe(1);
    const after = await prisma.trigger.findUniqueOrThrow({ where: { id: triggerId } });
    expect(after.nextRunAt!.getTime()).toBeGreaterThan(dueAt.getTime());
    expect(after.nextRunAt!.getTime()).toBe(nextCronRun('*/15 * * * *', dueAt, 'UTC')!.getTime());
    await ctx.jobs.onIdle();
    await ctx.agent.idle();
  });

  it('a disabled schedule trigger never gets a nextRunAt and never fires', async () => {
    const w = await world();
    const created = await createTrigger(w.admin, w.orgId, {
      projectId: w.projectId,
      kind: 'SCHEDULE',
      name: 'Off',
      enabled: false,
      config: { cron: '0 * * * *', timezone: 'UTC' },
      runAsUserId: w.owner.user.id,
      promptTemplate: 'noop',
    });
    expect(created.body.data!.nextRunAt).toBeNull();
    const result = await scheduleTick(ctx, new Date(Date.now() + 3_600_000));
    expect(result.fired).toEqual([]);
  });
});
