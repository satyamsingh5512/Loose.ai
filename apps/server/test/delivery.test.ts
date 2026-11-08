/**
 * Phase 6: review & delivery — diff (Pro gate), create PR (MSW GitHub: success, nothing to
 * submit, existing PR, push rejected, high-risk gate, idempotency), commit-to-main
 * (policy, protected branch → GH-007, success), discard, pull_request webhook, public
 * screenshot links.
 */
import { createHmac } from 'node:crypto';
import { http, HttpResponse, type RequestHandler } from 'msw';
import request from 'supertest';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { signArtifactToken } from '../src/lib/publicArtifacts';
import { saveArtifact } from '../src/services/sessionLifecycle.service';
import {
  busEvents,
  FakeGit,
  installFakeRunner,
  lastSandbox,
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
  TEST_SECRETS,
  testPrisma,
  type Client,
} from './helpers';
import { addApiKey, createReadyProject, fakeSandbox, settle } from './sessionHelpers';

const prisma = testPrisma();
const handlers: { current: RequestHandler[] } = { current: [] };
const calls: Request[] = [];
const { app, ctx } = makeApp({ context: { fetch: mswFetch(handlers, calls) } });
const fake = fakeSandbox(ctx);
const script: { current: RunnerScript } = {
  current: (cmd, r) => {
    if (cmd.type === 'user_message')
      playTurn(r, { text: 'I updated the header.', files: ['src/components/Header.tsx'] });
  },
};
let git: FakeGit;

const REPO = `${GITHUB_API}/repos/acme/web`;

interface PrCapture {
  bodies: Record<string, unknown>[];
}

function githubHandlers(
  opts: { existing?: boolean; mergeStatus?: number; mergeMessage?: string } = {},
): PrCapture {
  const cap: PrCapture = { bodies: [] };
  handlers.current = [
    http.get(`${REPO}/pulls`, () =>
      HttpResponse.json(
        opts.existing ? [{ number: 7, html_url: 'https://github.com/acme/web/pull/7' }] : [],
      ),
    ),
    http.post(`${REPO}/pulls`, async ({ request: req }) => {
      cap.bodies.push((await req.json()) as Record<string, unknown>);
      return HttpResponse.json(
        { number: 42, html_url: 'https://github.com/acme/web/pull/42' },
        { status: 201 },
      );
    }),
    http.put(`${REPO}/pulls/42/merge`, () =>
      opts.mergeStatus && opts.mergeStatus !== 200
        ? HttpResponse.json(
            { message: opts.mergeMessage ?? 'Base branch is protected' },
            { status: opts.mergeStatus },
          )
        : HttpResponse.json({ merged: true, sha: 'c'.repeat(40), message: 'merged' }),
    ),
    http.delete(`${REPO}/git/refs/:ref*`, () => new HttpResponse(null, { status: 204 })),
  ];
  return cap;
}

afterAll(async () => {
  await ctx.agent.idle();
  await ctx.jobs.onIdle();
  await prisma.$disconnect();
});

beforeEach(async () => {
  await ctx.agent.shutdownAll();
  await ctx.jobs.onIdle();
  fake.reset();
  installFakeRunner(fake, script);
  git = new FakeGit().install(fake);
  handlers.current = [];
  calls.length = 0;
  await resetDb();
});

interface World {
  owner: Client;
  admin: Client;
  orgId: string;
  sessionId: string;
}

async function world(
  opts: { mode?: 'SIMPLE' | 'PRO'; ownerRole?: 'MEMBER' | 'ADMIN' } = {},
): Promise<World> {
  const admin = await login(app, undefined, 'Ada Admin');
  const org = await createOrg(admin);
  const owner = await login(app, undefined, 'Mo Member');
  await addMember(org.id, owner.user.id, opts.ownerRole ?? 'MEMBER');
  await linkGithub(ctx, owner.user.id);
  await addApiKey(ctx, owner.user.id);
  const project = await createReadyProject(ctx, org.id, {
    env: { TOKEN: 'super-secret-token-value' },
  });
  const res = await owner.post('/api/v1/sessions', {
    projectId: project.id,
    mode: opts.mode ?? 'SIMPLE',
  });
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  const s = await settle(ctx, res.body.data.id as string);
  expect(s.status).toBe('RUNNING');
  await waitFor(() => ctx.agent.hasRuntime(s.id));
  return { owner, admin, orgId: org.id, sessionId: s.id };
}

async function doTurn(w: World) {
  git.set('src/components/Header.tsx', ' M', ['<h1>Howdy</h1>']);
  const r = await w.owner.post(`/api/v1/sessions/${w.sessionId}/messages`, {
    content: 'Change it',
  });
  expect(r.status).toBe(202);
  await waitFor(
    async () =>
      (await prisma.chatMessage.count({
        where: {
          sessionId: w.sessionId,
          role: 'ASSISTANT',
          rawContent: { path: ['pending'], equals: false },
        },
      })) === 1,
  );
  await ctx.agent.idle(w.sessionId);
}

describe('GET /sessions/:id/diff', () => {
  it('Pro session owner gets the diff; Simple member is refused; admin always allowed', async () => {
    const pro = await world({ mode: 'PRO' });
    git.set('src/a.ts', ' M', ['const a = 1;']).set('new.md', '??', ['# hi']);
    const res = await pro.owner.get(`/api/v1/sessions/${pro.sessionId}/diff`);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.data.files).toEqual([
      expect.objectContaining({ path: 'src/a.ts', status: 'modified', additions: 1, deletions: 1 }),
      expect.objectContaining({ path: 'new.md', status: 'added', additions: 1, deletions: 0 }),
    ]);
    expect(res.body.data.files[0].patch).toContain('+const a = 1;');
  });

  it('Simple session: member owner → LSE-ORG-002, admin → 200', async () => {
    const w = await world();
    expectError(await w.owner.get(`/api/v1/sessions/${w.sessionId}/diff`), 'LSE-ORG-002', 403);
    expect((await w.admin.get(`/api/v1/sessions/${w.sessionId}/diff`)).status).toBe(200);
  });
});

describe('POST /sessions/:id/create-pr', () => {
  it('commits, pushes, opens a PR with summary/risk/screenshots, completes the session (idempotent)', async () => {
    const w = await world();
    await doTurn(w);
    await saveArtifact(ctx, {
      sessionId: w.sessionId,
      kind: 'screenshot',
      data: Buffer.from('89504e470d0a1a0a', 'hex'),
      contentType: 'image/png',
      meta: { viewport: 'desktop', phase: 'after' },
    });
    const cap = githubHandlers();
    const url = `/api/v1/sessions/${w.sessionId}/create-pr`;
    const res = await w.owner.post(url, { title: 'Say Howdy' }).set('Idempotency-Key', 'pr-1');
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.data).toMatchObject({
      prUrl: 'https://github.com/acme/web/pull/42',
      prNumber: 42,
    });
    expect(res.body.data.session).toMatchObject({ status: 'COMPLETED', outcome: 'PR_CREATED' });

    const again = await w.owner.post(url, { title: 'Say Howdy' }).set('Idempotency-Key', 'pr-1');
    expect(again.status).toBe(200);
    expect(again.headers['idempotent-replayed']).toBe('true');
    expect(cap.bodies).toHaveLength(1);

    const pr = cap.bodies[0]!;
    expect(pr).toMatchObject({
      title: 'Say Howdy',
      head: `loose/session-${w.sessionId}`,
      base: 'main',
      draft: false,
    });
    const body = String(pr.body);
    expect(body).toContain('## Summary');
    expect(body).toContain('I updated the header.');
    expect(body).toContain('## Technical summary');
    expect(body).toContain('`src/components/Header.tsx` (modified, +1 −1)');
    expect(body).toContain('## Risk');
    expect(body).toContain('**MEDIUM**');
    expect(body).toMatch(
      /!\[after\]\(http:\/\/localhost:4000\/api\/v1\/public-artifacts\/[\w-]+\.\d+\.[\w-]+\)/,
    );
    expect(body).toContain(`http://localhost:5173/session/${w.sessionId}`);
    expect(body).not.toContain('super-secret-token-value');

    const cmds = lastSandbox(ctx).commandLines();
    const commit = cmds.find((c) => c.includes('git commit'));
    expect(commit).toBeDefined();
    const msg = lastSandbox(ctx).files.get('/home/user/.loose/commit-msg.txt')!;
    expect(msg).toMatch(/^loose: Say Howdy/);
    expect(msg).toContain(`Co-authored-by: Mo Member <${w.owner.user.email}>`);
    expect(msg).toContain('Co-authored-by: loose.ai <bot@loose.ai>');
    expect(cmds).toContain(`git push -q origin 'HEAD:refs/heads/loose/session-${w.sessionId}'`);
    // The token reaches git only through env, never the command line.
    expect(cmds.join('\n')).not.toContain('gho_');

    const s = await prisma.session.findUniqueOrThrow({ where: { id: w.sessionId } });
    expect(s).toMatchObject({
      status: 'COMPLETED',
      outcome: 'PR_CREATED',
      prNumber: 42,
      prState: 'open',
      sandboxId: null,
    });
    expect(s.commitSha).toBe('b'.repeat(40));
    const ended = (await busEvents(ctx, w.sessionId))
      .filter((e) => e.message.type === 'session_ended')
      .at(-1)!;
    expect(ended.message.payload).toMatchObject({
      status: 'COMPLETED',
      outcome: 'PR_CREATED',
      prUrl: 'https://github.com/acme/web/pull/42',
    });
    expect(
      await prisma.auditLog.count({ where: { action: 'session.pr_created', target: w.sessionId } }),
    ).toBe(1);
    expect(await prisma.artifact.count({ where: { sessionId: w.sessionId, kind: 'diff' } })).toBe(
      1,
    );
    // After the sandbox is gone the diff comes from the stored artifact.
    const diff = await w.admin.get(`/api/v1/sessions/${w.sessionId}/diff`);
    expect(diff.body.data.files.map((f: { path: string }) => f.path)).toEqual([
      'src/components/Header.tsx',
    ]);
  });

  it('nothing to submit → LSE-GH-008', async () => {
    const w = await world();
    githubHandlers();
    expectError(
      await w.owner.post(`/api/v1/sessions/${w.sessionId}/create-pr`, {}),
      'LSE-GH-008',
      422,
    );
  });

  it('existing PR → LSE-GH-008 with a link', async () => {
    const w = await world();
    await doTurn(w);
    githubHandlers({ existing: true });
    const res = await w.owner.post(`/api/v1/sessions/${w.sessionId}/create-pr`, {});
    expectError(res, 'LSE-GH-008', 422);
    expect(res.body.error.action).toMatchObject({ href: 'https://github.com/acme/web/pull/7' });
    expect((await prisma.session.findUniqueOrThrow({ where: { id: w.sessionId } })).status).toBe(
      'RUNNING',
    );
  });

  it('push rejected → LSE-GH-005, session keeps running', async () => {
    const w = await world();
    await doTurn(w);
    githubHandlers();
    git.pushExit = 1;
    git.pushStderr = '! [remote rejected] protected branch hook declined';
    expectError(
      await w.owner.post(`/api/v1/sessions/${w.sessionId}/create-pr`, {}),
      'LSE-GH-005',
      422,
    );
    expect((await prisma.session.findUniqueOrThrow({ where: { id: w.sessionId } })).status).toBe(
      'RUNNING',
    );
  });

  it('unapproved HIGH-risk change: member → LSE-AGT-013, admin may submit', async () => {
    const w = await world();
    git.set('src/auth/login.ts', ' M', ['return true;']);
    githubHandlers();
    expectError(
      await w.owner.post(`/api/v1/sessions/${w.sessionId}/create-pr`, {}),
      'LSE-AGT-013',
      422,
    );
    const res = await w.admin.post(`/api/v1/sessions/${w.sessionId}/create-pr`, {});
    expect(res.status, JSON.stringify(res.body)).toBe(200);
  });

  it('refuses while the agent is busy (LSE-AGT-011)', async () => {
    const w = await world();
    script.current = () => undefined;
    try {
      await w.owner.post(`/api/v1/sessions/${w.sessionId}/messages`, { content: 'work' });
      await waitFor(() => ctx.agent.isBusy(w.sessionId));
      git.set('a.md', ' M');
      expectError(
        await w.owner.post(`/api/v1/sessions/${w.sessionId}/create-pr`, {}),
        'LSE-AGT-011',
        409,
      );
    } finally {
      script.current = (cmd, r) => {
        if (cmd.type === 'user_message')
          playTurn(r, { text: 'I updated the header.', files: ['src/components/Header.tsx'] });
      };
    }
  });
});

describe('POST /sessions/:id/commit-to-main', () => {
  it('member → LSE-ORG-002; admin with policy off → LSE-ORG-009', async () => {
    const w = await world();
    expectError(
      await w.owner.post(`/api/v1/sessions/${w.sessionId}/commit-to-main`, {}),
      'LSE-ORG-002',
      403,
    );
    expectError(
      await w.admin.post(`/api/v1/sessions/${w.sessionId}/commit-to-main`, {}),
      'LSE-ORG-009',
      403,
    );
  });

  it('protected branch → LSE-GH-007 (PR kept, session running); then success → COMMITTED_TO_MAIN', async () => {
    const w = await world();
    await prisma.organization.update({
      where: { id: w.orgId },
      data: { policy: { commitToMainEnabled: true } },
    });
    await doTurn(w);
    const cap = githubHandlers({ mergeStatus: 405, mergeMessage: 'Base branch is protected' });
    const url = `/api/v1/sessions/${w.sessionId}/commit-to-main`;
    expectError(await w.admin.post(url, { mergeMethod: 'squash' }), 'LSE-GH-007', 405);
    let s = await prisma.session.findUniqueOrThrow({ where: { id: w.sessionId } });
    expect(s).toMatchObject({
      status: 'RUNNING',
      prNumber: 42,
      prUrl: 'https://github.com/acme/web/pull/42',
      outcome: null,
    });

    // Required checks → GH-013.
    handlers.current = [
      http.get(`${REPO}/pulls`, () =>
        HttpResponse.json([{ number: 42, html_url: 'https://github.com/acme/web/pull/42' }]),
      ),
      http.put(`${REPO}/pulls/42/merge`, () =>
        HttpResponse.json({ message: 'Required status check "ci" is expected.' }, { status: 405 }),
      ),
    ];
    expectError(await w.admin.post(url, {}), 'LSE-GH-013', 422);

    handlers.current = [
      http.get(`${REPO}/pulls`, () =>
        HttpResponse.json([{ number: 42, html_url: 'https://github.com/acme/web/pull/42' }]),
      ),
      http.put(`${REPO}/pulls/42/merge`, async ({ request: req }) => {
        expect(await req.json()).toMatchObject({ merge_method: 'rebase' });
        return HttpResponse.json({ merged: true, sha: 'c'.repeat(40), message: 'ok' });
      }),
    ];
    const ok = await w.admin.post(url, { mergeMethod: 'rebase' });
    expect(ok.status, JSON.stringify(ok.body)).toBe(200);
    expect(cap.bodies).toHaveLength(1); // the PR was reused, not re-created
    s = await prisma.session.findUniqueOrThrow({ where: { id: w.sessionId } });
    expect(s).toMatchObject({
      status: 'COMPLETED',
      outcome: 'COMMITTED_TO_MAIN',
      commitSha: 'c'.repeat(40),
      prState: 'merged',
    });
    expect(await prisma.auditLog.count({ where: { action: 'session.committed_to_main' } })).toBe(1);
  });
});

describe('POST /sessions/:id/discard', () => {
  it('deletes the pushed branch, stops the sandbox, DISCARDED', async () => {
    const w = await world();
    git.remoteRefs.add(`refs/heads/loose/session-${w.sessionId}`);
    const sbx = lastSandbox(ctx);
    const res = await w.owner.post(`/api/v1/sessions/${w.sessionId}/discard`, {});
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.data.session).toMatchObject({ status: 'COMPLETED', outcome: 'DISCARDED' });
    expect(sbx.commandLines()).toContain(
      `git push -q origin --delete 'refs/heads/loose/session-${w.sessionId}'`,
    );
    expect(sbx.killed).toBe(true);
    expect(await prisma.auditLog.count({ where: { action: 'session.discarded' } })).toBe(1);
    expectError(
      await w.owner.post(`/api/v1/sessions/${w.sessionId}/discard`, {}),
      'LSE-CONF-001',
      409,
    );
  });

  it('a PAUSED session without a sandbox deletes refs through the GitHub API', async () => {
    const w = await world();
    await ctx.agent.shutdownAll();
    await prisma.session.update({
      where: { id: w.sessionId },
      data: { status: 'PAUSED', sandboxId: null, wipRef: `refs/loose/wip/${w.sessionId}` },
    });
    githubHandlers();
    const res = await w.owner.post(`/api/v1/sessions/${w.sessionId}/discard`, {});
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    // Octokit percent-encodes the `{ref}` segment; GitHub decodes it.
    const deletes = calls
      .filter((c) => c.method === 'DELETE')
      .map((c) => decodeURIComponent(new URL(c.url).pathname));
    expect(deletes).toEqual([
      `/repos/acme/web/git/refs/heads/loose/session-${w.sessionId}`,
      `/repos/acme/web/git/refs/loose/wip/${w.sessionId}`,
    ]);
  });
});

describe('github pull_request webhook', () => {
  const sign = (body: string) =>
    `sha256=${createHmac('sha256', TEST_SECRETS.GITHUB_WEBHOOK_SECRET).update(body).digest('hex')}`;

  it('merged → prState merged + audit; closed → prState closed', async () => {
    const w = await world();
    await prisma.session.update({
      where: { id: w.sessionId },
      data: { prNumber: 42, prState: 'open' },
    });
    const send = (payload: object) => {
      const body = JSON.stringify(payload);
      return request(app)
        .post('/api/v1/github/webhook')
        .set('content-type', 'application/json')
        .set('x-github-event', 'pull_request')
        .set('x-hub-signature-256', sign(body))
        .send(body);
    };
    const merged = await send({
      action: 'closed',
      pull_request: {
        number: 42,
        merged: true,
        html_url: 'https://github.com/acme/web/pull/42',
        head: { ref: 'x' },
      },
      repository: { full_name: 'acme/web' },
    });
    expect(merged.body.data).toEqual({ received: true, handled: true });
    let s = await prisma.session.findUniqueOrThrow({ where: { id: w.sessionId } });
    expect(s.prState).toBe('merged');
    expect(s.prMergedAt).toBeInstanceOf(Date);
    expect(await prisma.auditLog.count({ where: { action: 'session.pr_merged' } })).toBe(1);

    await prisma.session.update({
      where: { id: w.sessionId },
      data: { prNumber: null, prState: null },
    });
    const closed = await send({
      action: 'closed',
      pull_request: { number: 9, merged: false, head: { ref: `loose/session-${w.sessionId}` } },
      repository: { full_name: 'acme/web' },
    });
    expect(closed.body.data.handled).toBe(true);
    s = await prisma.session.findUniqueOrThrow({ where: { id: w.sessionId } });
    expect(s).toMatchObject({ prNumber: 9, prState: 'closed' });
    const other = await send({
      action: 'closed',
      pull_request: { number: 9 },
      repository: { full_name: 'evil/repo' },
    });
    expect(other.body.data.handled).toBe(false);
  });
});

describe('public artifact links', () => {
  it('serves screenshots for valid tokens only', async () => {
    const w = await world();
    const png = Buffer.from('89504e470d0a1a0a00', 'hex');
    const art = await saveArtifact(ctx, {
      sessionId: w.sessionId,
      kind: 'screenshot',
      data: png,
      contentType: 'image/png',
      meta: { viewport: 'desktop', phase: 'after' },
    });
    const token = signArtifactToken(ctx.env.SESSION_SECRET, art.id);
    const ok = await request(app).get(`/api/v1/public-artifacts/${token}`).buffer(true);
    expect(ok.status).toBe(200);
    expect(ok.headers['content-type']).toBe('image/png');
    expect(Buffer.from(ok.body as Buffer).equals(png)).toBe(true);
    const tampered = token.replace(/.$/, (c) => (c === 'A' ? 'B' : 'A'));
    expectError(await request(app).get(`/api/v1/public-artifacts/${tampered}`), 'LSE-NF-001', 404);
    const expired = signArtifactToken(ctx.env.SESSION_SECRET, art.id, Date.now() - 8 * 86_400_000);
    expectError(await request(app).get(`/api/v1/public-artifacts/${expired}`), 'LSE-NF-001', 404);
    const diffArt = await saveArtifact(ctx, {
      sessionId: w.sessionId,
      kind: 'diff',
      data: 'x',
      contentType: 'text/x-diff',
    });
    const diffToken = signArtifactToken(ctx.env.SESSION_SECRET, diffArt.id);
    expectError(await request(app).get(`/api/v1/public-artifacts/${diffToken}`), 'LSE-NF-001', 404);
  });
});
