/**
 * LocalSandboxProvider integration (DEV ONLY provider): real git clone from a temp bare
 * repo via DEV_GIT_REMOTE_OVERRIDE, a real `node -e` HTTP server as the app, a real
 * health check, WIP push on pause, recover, and cleanup. All waits are bounded.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { innerProvider, LocalSandboxProvider } from '../src/lib/sandbox';
import { stopSession } from '../src/services/sessionLifecycle.service';
import { createOrg, login, makeApp, resetDb, testPrisma } from './helpers';
import { addApiKey, createReadyProject, settle } from './sessionHelpers';

const base = mkdtempSync(join(tmpdir(), 'loose-local-it-'));
const remote = join(base, 'remotes', 'acme', 'web.git');
const sbxDir = join(base, 'sandboxes');
const prisma = testPrisma();
const { app, ctx } = makeApp({
  env: {
    SANDBOX_PROVIDER: 'local',
    LOCAL_SANDBOX_DIR: sbxDir,
    DEV_GIT_REMOTE_OVERRIDE: join(base, 'remotes', '{owner}', '{repo}.git'),
    SANDBOX_COMMAND_TIMEOUT_SEC: '60',
  },
});

const git = (args: string[], cwd?: string) =>
  execFileSync('git', args, {
    cwd,
    timeout: 30_000,
    stdio: 'pipe',
    env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_CONFIG_NOSYSTEM: '1' },
  }).toString();

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address() as { port: number };
      srv.close(() => resolve(port));
    });
  });
}

async function portIsFree(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const srv = createServer();
    srv.once('error', () => resolve(false));
    srv.listen(port, '127.0.0.1', () => srv.close(() => resolve(true)));
  });
}

let port = 0;

beforeAll(async () => {
  await resetDb();
  git(['init', '--bare', '-q', '-b', 'main', remote]);
  const work = join(base, 'work');
  git(['init', '-q', '-b', 'main', work]);
  writeFileSync(join(work, 'README.md'), '# Demo app\n');
  git(['add', '-A'], work);
  git(['-c', 'user.name=t', '-c', 'user.email=t@example.com', 'commit', '-q', '-m', 'init'], work);
  git(['push', '-q', remote, 'main'], work);
  port = await freePort();
});

afterAll(async () => {
  await ctx.jobs.onIdle();
  for (const rt of ctx.sessionRuntime.list()) await rt.sandbox.kill().catch(() => undefined);
  rmSync(base, { recursive: true, force: true });
  await prisma.$disconnect();
});

describe('LocalSandboxProvider (dev only)', () => {
  it(
    'clones, starts the app, health-checks it, pushes WIP on pause and recovers',
    { timeout: 90_000 },
    async () => {
      expect(innerProvider(ctx.sandbox)).toBeInstanceOf(LocalSandboxProvider);
      const admin = await login(app);
      const org = await createOrg(admin);
      await addApiKey(ctx, admin.user.id);
      const appCmd = `node -e "require('http').createServer((q,s)=>s.end(process.env.APP_URL||'none')).listen(${port},'127.0.0.1')"`;
      const project = await createReadyProject(ctx, org.id, {
        env: { GREETING: 'hello-world-value' },
        startupCommands: ['test -f README.md', appCmd],
        portMap: [{ name: 'web', port, public: true, envVar: 'APP_URL' }],
        healthCheck: { path: '/', port, timeoutSec: 20 },
      });

      const res = await admin.post('/api/v1/sessions', { projectId: project.id });
      expect(res.status, JSON.stringify(res.body)).toBe(201);
      const s = await settle(ctx, res.body.data.id);
      expect(s.status, `errorCode=${s.errorCode}`).toBe('RUNNING');
      expect(s.previewUrl).toBe(`http://localhost:${port}`);

      const ws = join(sbxDir, s.sandboxId!, 'workspace');
      expect(readFileSync(join(ws, 'README.md'), 'utf8')).toContain('Demo app');
      expect(git(['rev-parse', '--abbrev-ref', 'HEAD'], ws).trim()).toBe(`loose/session-${s.id}`);
      const env = readFileSync(join(ws, '.env'), 'utf8');
      expect(env).toContain(`APP_URL="http://localhost:${port}"`);
      expect(env).toContain('GREETING="hello-world-value"');
      expect(git(['status', '--porcelain'], ws)).not.toContain('.env'); // excluded from commits
      expect(existsSync(join(sbxDir, s.sandboxId!, 'state', 'config.json'))).toBe(true);

      // The app got the resolved env and answers on the port.
      const body = await (
        await fetch(`http://127.0.0.1:${port}/`, { signal: AbortSignal.timeout(5000) })
      ).text();
      expect(body).toBe(`http://localhost:${port}`);

      // Env is scrubbed: server process env does not leak into sandbox commands.
      const sbx = ctx.sessionRuntime.get(s.id)!.sandbox;
      const printed = await sbx.run('env', { timeoutMs: 10_000 });
      expect(printed.stdout).not.toContain('TEST_DATABASE_URL');
      expect(printed.stdout).toContain(`HOME=${join(sbxDir, s.sandboxId!)}`);
      await expect(sbx.run('true', { cwd: '/etc' })).rejects.toThrow(/outside/);

      // Work in progress → pause → WIP ref on the remote, sandbox + app gone.
      writeFileSync(join(ws, 'NEW.md'), 'agent change\n');
      expect(await stopSession(ctx, s.id, { to: 'PAUSED', reason: 'stopped', pushWip: true })).toBe(
        true,
      );
      expect(git(['show-ref'], remote)).toContain(`refs/loose/wip/${s.id}`);
      expect(git(['show', `refs/loose/wip/${s.id}:NEW.md`], remote)).toBe('agent change\n');
      expect(existsSync(join(sbxDir, s.sandboxId!))).toBe(false);
      expect(await portIsFree(port)).toBe(true);

      // Recover → fresh sandbox with the WIP restored as uncommitted changes.
      const rec = await admin.post(`/api/v1/sessions/${s.id}/recover`);
      expect(rec.status, JSON.stringify(rec.body)).toBe(202);
      const r = await settle(ctx, s.id);
      expect(r.status, `errorCode=${r.errorCode}`).toBe('RUNNING');
      const ws2 = join(sbxDir, r.sandboxId!, 'workspace');
      expect(readFileSync(join(ws2, 'NEW.md'), 'utf8')).toBe('agent change\n');
      expect(git(['rev-parse', '--abbrev-ref', 'HEAD'], ws2).trim()).toBe(`loose/session-${s.id}`);
      expect(git(['status', '--porcelain'], ws2)).toContain('NEW.md');

      // Stop for good.
      expect(
        await stopSession(ctx, s.id, { to: 'COMPLETED', reason: 'completed', pushWip: false }),
      ).toBe(true);
      expect(existsSync(join(sbxDir, r.sandboxId!))).toBe(false);
      expect(await portIsFree(port)).toBe(true);
    },
  );

  it(
    "refuses to start when the app's host port is already taken (no false-healthy preview)",
    { timeout: 60_000 },
    async () => {
      // Something else (e.g. another session of this project) already answers on the port.
      const squatter = createServer((sock) => {
        sock.on('error', () => undefined); // probes connect then reset; not a test failure
        sock.end('HTTP/1.1 200 OK\r\n\r\nother app');
      });
      await new Promise<void>((r) => squatter.listen(port, '127.0.0.1', () => r()));
      try {
        const admin = await login(app);
        const org = await createOrg(admin);
        await addApiKey(ctx, admin.user.id);
        const project = await createReadyProject(ctx, org.id, {
          startupCommands: [`node -e "require('http').createServer().listen(${port},'127.0.0.1')"`],
          portMap: [{ name: 'web', port, public: true }],
          healthCheck: { path: '/', port, timeoutSec: 10 },
        });
        const res = await admin.post('/api/v1/sessions', { projectId: project.id });
        expect(res.status, JSON.stringify(res.body)).toBe(201);
        const s = await settle(ctx, res.body.data.id);
        expect(s.status).toBe('ERRORED');
        expect(s.errorCode).toBe('LSE-SBX-004');
        expect(s.sandboxId === null || !existsSync(join(sbxDir, s.sandboxId))).toBe(true);
      } finally {
        await new Promise<void>((r) => squatter.close(() => r()));
      }
    },
  );
});
