/**
 * TRUE end-to-end: LocalSandboxProvider (DEV-ONLY, host processes) + the REAL built runner
 * (`packages/runner/dist/cli.js`, mock agent mode) + a temp bare git repo used as the
 * remote via DEV_GIT_REMOTE_OVERRIDE + MSW handlers for the GitHub REST API.
 *
 * start session → RUNNING → WS join → `change "Hello" to "Howdy"` → agent_status /
 * agent_streaming / change_summary / cost_update (Simple payloads carry no paths) →
 * create-pr (branch pushed to the bare repo; PR body has summary + risk) → COMPLETED.
 *
 * Skipped (with a message) when git or the runner build is unavailable:
 *   bun run --cwd packages/runner build
 */
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { http, HttpResponse, type RequestHandler } from 'msw';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { WebSocket } from 'ws';
import { buildClientMessage, CSRF_HEADER, SESSION_COOKIE, type ServerMessage } from '@loose/shared';
import { leakCheck } from '../src/services/translation';
import { attachWsGateway, type WsGateway } from '../src/ws/gateway';
import { mswFetch, waitFor } from './agentHelpers';
import { csrfFor, GITHUB_API, linkGithub, makeApp, resetDb, testPrisma } from './helpers';
import { addApiKey, createReadyProject } from './sessionHelpers';

const RUNNER_ENTRY = resolve(
  fileURLToPath(new URL('.', import.meta.url)),
  '../../../packages/runner/dist/cli.js',
);

function gitAvailable(): boolean {
  try {
    execFileSync('git', ['--version'], { stdio: 'ignore', timeout: 10_000 });
    return true;
  } catch {
    return false;
  }
}

const hasGit = gitAvailable();
const hasRunner = existsSync(RUNNER_ENTRY);
const skipReason = !hasGit
  ? 'git is not installed'
  : !hasRunner
    ? `runner build missing at ${RUNNER_ENTRY} (run: bun run --cwd packages/runner build)`
    : '';
if (skipReason) console.warn(`[e2e.local] SKIPPED: ${skipReason}`);

const root = mkdtempSync(join(tmpdir(), 'loose-e2e-'));
const bare = join(root, 'remotes', 'acme', 'web.git');
if (skipReason) rmSync(root, { recursive: true, force: true });

function git(args: string[], cwd: string) {
  return execFileSync('git', args, {
    cwd,
    encoding: 'utf8',
    timeout: 30_000,
    env: { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: root, GIT_TERMINAL_PROMPT: '0' },
  });
}

const handlers: { current: RequestHandler[] } = { current: [] };
const prBodies: Record<string, unknown>[] = [];
const prisma = testPrisma();
const { app, ctx } = makeApp({
  env: {
    SANDBOX_PROVIDER: 'local',
    LOCAL_SANDBOX_DIR: join(root, 'sandboxes'),
    RUNNER_ENTRY,
    RUNNER_MOCK: 'true',
    DEV_GIT_REMOTE_OVERRIDE: join(root, 'remotes', '{owner}', '{repo}.git'),
    SANDBOX_COMMAND_TIMEOUT_SEC: '60',
  },
  context: { fetch: mswFetch(handlers) },
});

let server: Server;
let gateway: WsGateway;
let wsUrl = '';

describe.skipIf(Boolean(skipReason))('e2e (local sandbox + real runner, mock agent)', () => {
  beforeAll(async () => {
    expect(ctx.sandboxKind).toBe('local');
    await resetDb();
    // Bare remote with a tiny site.
    mkdirSync(bare, { recursive: true });
    git(['init', '-q', '--bare', '-b', 'main', bare], root);
    const seed = join(root, 'seed');
    mkdirSync(seed);
    git(['init', '-q', '-b', 'main'], seed);
    writeFileSync(
      join(seed, 'index.html'),
      '<!doctype html>\n<html><body><h1>Hello</h1></body></html>\n',
    );
    writeFileSync(join(seed, 'README.md'), '# Site\n');
    git(['add', '-A'], seed);
    git(
      ['-c', 'user.name=Seed', '-c', 'user.email=seed@example.com', 'commit', '-q', '-m', 'init'],
      seed,
    );
    git(['push', '-q', bare, 'main'], seed);

    server = createServer(app);
    gateway = attachWsGateway(server, ctx);
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
    wsUrl = `ws://127.0.0.1:${(server.address() as AddressInfo).port}/ws`;
  }, 60_000);

  afterAll(async () => {
    await ctx.agent.shutdownAll().catch(() => undefined);
    await gateway?.close();
    await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
    await ctx.jobs.onIdle();
    rmSync(root, { recursive: true, force: true });
  }, 60_000);

  it('runs a turn with the real runner and delivers a PR from the pushed branch', async () => {
    // ---- user, org, project ----------------------------------------------------------------
    const agent = request.agent(app);
    const csrf = await csrfFor(agent);
    const login = await agent
      .post('/api/v1/auth/dev-login')
      .set(CSRF_HEADER, csrf)
      .send({ email: `e2e-${randomBytes(4).toString('hex')}@example.com`, name: 'Eve Ender' });
    expect(login.status).toBe(200);
    const user = login.body.data as { id: string };
    const cookie = ([] as string[])
      .concat(login.headers['set-cookie'] ?? [])
      .find((c) => c.startsWith(`${SESSION_COOKIE}=`))!
      .split(';')[0]!;
    const org = await agent.post('/api/v1/orgs').set(CSRF_HEADER, csrf).send({ name: 'E2E Org' });
    expect(org.status).toBe(201);
    await linkGithub(ctx, user.id);
    await addApiKey(ctx, user.id);
    const project = await createReadyProject(ctx, org.body.data.id as string);

    // ---- start session → RUNNING ---------------------------------------------------------
    const start = await agent
      .post('/api/v1/sessions')
      .set(CSRF_HEADER, csrf)
      .send({ projectId: project.id, mode: 'SIMPLE' });
    expect(start.status, JSON.stringify(start.body)).toBe(201);
    const sessionId = start.body.data.id as string;
    const running = await waitFor(
      async () => {
        const s = await prisma.session.findUniqueOrThrow({ where: { id: sessionId } });
        if (s.status === 'ERRORED') throw new Error(`session errored: ${s.errorCode}`);
        return s.status === 'RUNNING' ? s : null;
      },
      { timeoutMs: 30_000, intervalMs: 50, label: 'RUNNING' },
    );
    expect(running.branchName).toBe(`loose/session-${sessionId}`);
    await waitFor(() => ctx.agent.hasRuntime(sessionId), { timeoutMs: 15_000, label: 'runner' });

    // ---- WS join + chat ------------------------------------------------------------------
    const messages: ServerMessage[] = [];
    const ws = new WebSocket(wsUrl, { headers: { cookie, origin: 'http://localhost:5173' } });
    ws.on('message', (d) => messages.push(JSON.parse(String(d)) as ServerMessage));
    await new Promise<void>((r, j) => ws.once('open', () => r()).once('error', j));
    const next = (pred: (m: ServerMessage) => boolean, label: string, timeoutMs = 30_000) =>
      waitFor(() => messages.find(pred), { timeoutMs, intervalMs: 25, label });
    try {
      ws.send(JSON.stringify(buildClientMessage('join_session', sessionId, {})));
      await next((m) => m.type === 'replay_complete', 'replay_complete', 10_000);
      ws.send(
        JSON.stringify(
          buildClientMessage('chat_message', sessionId, {
            clientMessageId: 'e2e-1',
            content: 'change "Hello" to "Howdy"',
          }),
        ),
      );
      const isAssistant = (m: ServerMessage) =>
        m.type === 'chat_message' &&
        (m.payload as { message: { role: string } }).message.role === 'ASSISTANT';
      await next(isAssistant, 'assistant message', 45_000);
      await next(
        (m) => m.type === 'agent_status' && (m.payload as { state: string }).state === 'idle',
        'idle',
      );
      const types = new Set(messages.map((m) => m.type));
      for (const t of ['agent_status', 'agent_streaming', 'change_summary', 'cost_update'])
        expect(types, `missing ${t}`).toContain(t);
      expect(types).not.toContain('tool_event');
      expect(types).not.toContain('terminal_output');

      const summary = messages.find((m) => m.type === 'change_summary')!.payload as {
        summary: string;
        areas: string[];
        risk: string;
        files?: unknown;
      };
      expect(summary.files).toBeUndefined();
      expect(summary.risk).toBe('LOW');
      expect(summary.areas).toEqual(['the home page']);
      // Simple-mode payloads never carry paths/code.
      const agentText = messages
        .filter(
          (m) =>
            ['agent_status', 'agent_streaming', 'change_summary'].includes(m.type) ||
            isAssistant(m),
        )
        .map((m) => {
          const p = m.payload as {
            label?: string;
            delta?: string;
            summary?: string;
            message?: { content: string };
          };
          return p.label ?? p.delta ?? p.summary ?? p.message?.content ?? '';
        });
      for (const t of agentText) expect(leakCheck(t), t).toEqual([]);
      expect(
        JSON.stringify(messages.filter((m) => m.type !== 'chat_message' || isAssistant(m))),
      ).not.toMatch(/index\.html|\/workspace|\.git\b/);
      const cost = messages.filter((m) => m.type === 'cost_update').at(-1)!.payload as {
        totalCostUsd: number;
      };
      expect(cost.totalCostUsd).toBeGreaterThan(0);
      expect(await prisma.usageEvent.count({ where: { sessionId } })).toBe(1);

      // ---- create PR ----------------------------------------------------------------------
      handlers.current = [
        http.get(`${GITHUB_API}/repos/acme/web/pulls`, () => HttpResponse.json([])),
        http.post(`${GITHUB_API}/repos/acme/web/pulls`, async ({ request: req }) => {
          prBodies.push((await req.json()) as Record<string, unknown>);
          return HttpResponse.json(
            { number: 1, html_url: 'https://github.com/acme/web/pull/1' },
            { status: 201 },
          );
        }),
      ];
      const pr = await agent
        .post(`/api/v1/sessions/${sessionId}/create-pr`)
        .set(CSRF_HEADER, csrf)
        .send({ title: 'Say Howdy' });
      expect(pr.status, JSON.stringify(pr.body)).toBe(200);
      expect(pr.body.data).toMatchObject({
        prUrl: 'https://github.com/acme/web/pull/1',
        prNumber: 1,
      });

      // Push landed in the bare repo on the session branch.
      const branch = `loose/session-${sessionId}`;
      expect(git(['--git-dir', bare, 'show', `${branch}:index.html`], root)).toContain(
        '<h1>Howdy</h1>',
      );
      expect(git(['--git-dir', bare, 'show', 'main:index.html'], root)).toContain('<h1>Hello</h1>');
      const log = git(['--git-dir', bare, 'log', '-1', '--format=%B', branch], root);
      expect(log).toContain('loose: Say Howdy');
      expect(log).toContain('Co-authored-by: Eve Ender');
      expect(git(['--git-dir', bare, 'show', '--stat', '--format=', branch], root)).not.toContain(
        '.env',
      );

      expect(prBodies).toHaveLength(1);
      const body = String(prBodies[0]!.body);
      expect(prBodies[0]).toMatchObject({ head: branch, base: 'main', title: 'Say Howdy' });
      expect(body).toContain('## Summary');
      expect(body).toContain('## Risk');
      expect(body).toContain('**LOW**');
      expect(body).toContain('`index.html` (modified');

      const done = await prisma.session.findUniqueOrThrow({ where: { id: sessionId } });
      expect(done).toMatchObject({
        status: 'COMPLETED',
        outcome: 'PR_CREATED',
        prUrl: 'https://github.com/acme/web/pull/1',
        sandboxId: null,
      });
      await next(
        (m) =>
          m.type === 'session_ended' && (m.payload as { status: string }).status === 'COMPLETED',
        'session_ended',
        10_000,
      );
      expect(ctx.agent.hasRuntime(sessionId)).toBe(false);
      expect(existsSync(join(root, 'sandboxes', running.sandboxId!))).toBe(false);
    } finally {
      ws.terminate();
    }
  }, 120_000);
});
