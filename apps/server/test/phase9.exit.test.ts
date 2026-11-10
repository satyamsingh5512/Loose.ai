/**
 * Phase 9 EXIT CRITERION — "Issue label → PR automation works":
 * GitHub `issues.labeled` webhook → run → session (fake sandbox + mock runner edits a file)
 * → PR created (MSW GitHub) → issue comment with the PR link.
 */
import { createHmac } from 'node:crypto';
import { http as mswHttp, HttpResponse, type RequestHandler } from 'msw';
import request from 'supertest';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { verifyGithubSignature } from '../src/routes/github';
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
} from './helpers';
import { addApiKey, createReadyProject, fakeSandbox } from './sessionHelpers';

const prisma = testPrisma();
const handlers: { current: RequestHandler[] } = { current: [] };
const WEBHOOK_SECRET = 'whsec_test_secret_value';
const { app, ctx } = makeApp({
  context: { fetch: mswFetch(handlers) },
  env: { GITHUB_WEBHOOK_SECRET: WEBHOOK_SECRET },
});
const fake = fakeSandbox(ctx);
const script: { current: RunnerScript } = { current: () => undefined };
let git: FakeGit;
const REPO = `${GITHUB_API}/repos/acme/web`;
const FILE = 'src/components/Header.tsx';

function sign(body: string): string {
  return `sha256=${createHmac('sha256', WEBHOOK_SECRET).update(body).digest('hex')}`;
}

function sendWebhook(
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

function issuesLabeledPayload(label: string, number = 7) {
  return {
    action: 'labeled',
    issue: {
      number,
      title: 'Button is the wrong color',
      body: 'It should be blue.',
      html_url: `https://github.com/acme/web/issues/${number}`,
    },
    label: { name: label },
    repository: { full_name: 'acme/web' },
    sender: { login: 'reporter' },
  };
}

function prHandlers() {
  const createComments: Record<string, unknown>[] = [];
  const createdPrs: Record<string, unknown>[] = [];
  handlers.current = [
    mswHttp.get(`${REPO}/pulls`, () => HttpResponse.json([])),
    mswHttp.post(`${REPO}/pulls`, async ({ request: req }) => {
      createdPrs.push((await req.json()) as Record<string, unknown>);
      return HttpResponse.json(
        { number: 99, html_url: 'https://github.com/acme/web/pull/99' },
        { status: 201 },
      );
    }),
    mswHttp.post(`${REPO}/issues/:number/comments`, async ({ request: req }) => {
      createComments.push((await req.json()) as Record<string, unknown>);
      return HttpResponse.json({ id: 1 }, { status: 201 });
    }),
  ];
  return { createComments, createdPrs };
}

async function world(opts: { label?: string } = {}) {
  const admin = await login(app, undefined, 'Ada Admin');
  const org = await createOrg(admin);
  const owner = await login(app, undefined, 'Mo Member');
  await addMember(org.id, owner.user.id, 'MEMBER');
  await linkGithub(ctx, owner.user.id);
  await addApiKey(ctx, owner.user.id);
  const project = await createReadyProject(ctx, org.id);
  const res = await admin.post(`/api/v1/orgs/${org.id}/triggers`, {
    projectId: project.id,
    kind: 'GITHUB_ISSUE_LABEL',
    name: 'Fix labeled issues',
    config: { label: opts.label ?? 'loose' },
    runAsUserId: owner.user.id,
  });
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  return {
    admin,
    owner,
    orgId: org.id,
    projectId: project.id,
    triggerId: res.body.data.id as string,
  };
}

beforeEach(async () => {
  await ctx.agent.shutdownAll();
  await ctx.jobs.onIdle();
  fake.reset();
  installFakeRunner(fake, script);
  git = new FakeGit().install(fake);
  script.current = (cmd, r) => {
    if (cmd.type === 'user_message') {
      git.set(FILE, ' M', ['<h1 class="blue">Howdy</h1>']);
      playTurn(r, { text: 'Changed the button color to blue.', files: [FILE] });
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

describe('exit criterion: issue label → PR automation', () => {
  it('issues.labeled → run → session edits a file → PR created → issue comment with the PR link', async () => {
    const w = await world();
    const { createComments, createdPrs } = prHandlers();

    const res = await sendWebhook('issues', issuesLabeledPayload('loose'));
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(res.body.data.handled).toBe(true);

    await ctx.jobs.onIdle();
    const fire = await waitFor(
      async () =>
        prisma.triggerFire.findFirst({
          where: { triggerId: w.triggerId, runId: { not: null } },
        }),
      { label: 'trigger fire recorded', timeoutMs: 10_000 },
    );
    expect(fire.runId).not.toBeNull();
    const runId = fire.runId!;

    const run = await waitFor(
      async () => {
        const r = await prisma.run.findUniqueOrThrow({ where: { id: runId } });
        return r.status === 'SUCCEEDED' || r.status === 'FAILED' ? r : null;
      },
      { label: 'run settled', timeoutMs: 10_000 },
    );
    expect(run.status, JSON.stringify(run)).toBe('SUCCEEDED');
    expect(run.source).toBe('GITHUB_ISSUE');
    expect(run.prUrl).toBe('https://github.com/acme/web/pull/99');
    expect(run.prNumber).toBe(99);
    expect(createdPrs).toHaveLength(1);
    expect(String(createdPrs[0]!.body)).toContain('Closes #7');

    await ctx.jobs.onIdle();
    await waitFor(() => createComments.length > 0, { label: 'issue comment posted' });
    expect(createComments).toHaveLength(1);
    expect(String(createComments[0]!.body)).toContain('https://github.com/acme/web/pull/99');

    const trigger = await prisma.trigger.findUniqueOrThrow({ where: { id: w.triggerId } });
    expect(trigger.lastRunId).toBe(runId);
    expect(trigger.lastFiredAt).not.toBeNull();

    const auditFire = await prisma.auditLog.findFirst({
      where: { action: 'trigger.fire', target: w.triggerId },
    });
    expect(auditFire).not.toBeNull();
  });

  it('a label that does not match the trigger config does not fire', async () => {
    await world({ label: 'loose' });
    const res = await sendWebhook('issues', issuesLabeledPayload('bug'));
    expect(res.status).toBe(202);
    expect(res.body.data.handled).toBe(false);
    await ctx.jobs.onIdle();
    expect(await prisma.triggerFire.count()).toBe(0);
  });

  it('bad signature → LSE-GH-014; redelivery of the same delivery id is a no-op', async () => {
    const w = await world();
    prHandlers();
    const body = JSON.stringify(issuesLabeledPayload('loose'));
    const bad = await request(app)
      .post('/api/v1/github/webhook')
      .set('x-github-event', 'issues')
      .set('x-github-delivery', 'dlv-1')
      .set('x-hub-signature-256', 'sha256=0000')
      .set('Content-Type', 'application/json')
      .send(body);
    expectError(bad, 'LSE-GH-014', 400);
    await ctx.jobs.onIdle();
    expect(await prisma.triggerFire.count()).toBe(0);

    const first = await sendWebhook('issues', issuesLabeledPayload('loose'), 'dlv-dup');
    expect(first.status).toBe(202);
    expect(first.body.data.handled).toBe(true);
    await ctx.jobs.onIdle();
    expect(await prisma.triggerFire.count({ where: { triggerId: w.triggerId } })).toBe(1);

    // The exact same delivery id, redelivered by GitHub: no second trigger fire.
    const second = await sendWebhook('issues', issuesLabeledPayload('loose'), 'dlv-dup');
    expect(second.status).toBe(202);
    expect(second.body.data.duplicate).toBe(true);
    expect(second.body.data.handled).toBe(false);
    await ctx.jobs.onIdle();
    expect(await prisma.triggerFire.count({ where: { triggerId: w.triggerId } })).toBe(1);
  });
});

describe('verifyGithubSignature', () => {
  it('accepts the exact signature and rejects a tampered one', () => {
    const body = '{"a":1}';
    expect(verifyGithubSignature(WEBHOOK_SECRET, Buffer.from(body), sign(body))).toBe(true);
    expect(verifyGithubSignature(WEBHOOK_SECRET, Buffer.from(body), sign(body + 'x'))).toBe(false);
    expect(verifyGithubSignature(WEBHOOK_SECRET, Buffer.from(body), undefined)).toBe(false);
  });
});
