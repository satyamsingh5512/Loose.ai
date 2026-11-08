/**
 * Workspace preparation steps shared by session provisioning and smoke tests
 * (spec §7.3, §13.2): clone → branch → .env with resolved public URLs →
 * services → startup commands → health check → preview.
 * Each step failure is a `StepFailure` carrying the smoke-test step name and the
 * catalog AppError (LSE-SBX-00x). Command output is secret-scrubbed before it
 * reaches logs, errors or the caller.
 */
import { connect } from 'node:net';
import type { Project } from '@prisma/client';
import {
  healthCheckSchema,
  portMapItemSchema,
  scrubSecrets,
  type ErrorCode,
  type HealthCheck,
  type PortMapItem,
  type SmokeTestStep,
} from '@loose/shared';
import { z } from 'zod';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';
import { sleep } from '../lib/resilience';
import type { BackgroundProcess, RunResult, SandboxHandle } from '../lib/sandbox';
import { serviceStartCommands } from '../lib/sandbox/templateSpec';
import { gitAuthEnv, shq, type GitAccess } from './gitAccess.service';

export class StepFailure extends Error {
  constructor(
    readonly step: SmokeTestStep,
    readonly error: AppError,
  ) {
    super(error.message, { cause: error });
    this.name = 'StepFailure';
  }
}

export interface StepReporter {
  /** Free-form log line (already scrubbed). */
  log(line: string): void;
}

export interface WorkspaceContext {
  ctx: AppContext;
  sandbox: SandboxHandle;
  project: Project;
  /** Exact values to redact from any output (env values, tokens). */
  secrets: string[];
  reporter: StepReporter;
}

const LOG_TAIL_LINES = 40;
export const HEALTH_POLL_MS = 1000;

/**
 * Exact values to redact for a project env: every value (≥ 6 chars) plus the
 * password embedded in URL-style values (`postgres://user:pass@host`), which
 * tools often print on its own.
 */
export function secretValuesOf(env: Record<string, string>): string[] {
  const out = new Set<string>();
  for (const v of Object.values(env)) {
    if (v.length >= 6) out.add(v);
    const m = /^[a-z][a-z0-9+.-]*:\/\/[^:/@\s]*:([^@\s]+)@/i.exec(v);
    if (m?.[1]) {
      let pass = m[1];
      try {
        pass = decodeURIComponent(pass);
      } catch {
        /* keep raw */
      }
      if (pass.length >= 6) out.add(pass);
      if (m[1].length >= 6) out.add(m[1]);
    }
  }
  return [...out];
}

export function scrubber(secrets: readonly string[]) {
  return (s: string) => scrubSecrets(s, secrets);
}

export function tail(text: string, lines = LOG_TAIL_LINES): string[] {
  return text
    .split(/\r?\n/)
    .map((l) => l.trimEnd())
    .filter(Boolean)
    .slice(-lines)
    .map((l) => (l.length > 500 ? `${l.slice(0, 500)}…` : l));
}

function fail(step: SmokeTestStep, code: ErrorCode, devMessage: string): never {
  throw new StepFailure(step, new AppError(code, { devMessage }));
}

function commandTimeoutMs(ctx: AppContext) {
  return ctx.env.SANDBOX_COMMAND_TIMEOUT_SEC * 1000;
}

async function runLogged(
  w: WorkspaceContext,
  cmd: string,
  opts: Parameters<SandboxHandle['run']>[1] = {},
) {
  const scrub = scrubber(w.secrets);
  const r = await w.sandbox.run(cmd, {
    cwd: w.sandbox.paths.workspace,
    timeoutMs: commandTimeoutMs(w.ctx),
    ...opts,
  });
  const out: RunResult = { exitCode: r.exitCode, stdout: scrub(r.stdout), stderr: scrub(r.stderr) };
  for (const l of tail(`${out.stdout}\n${out.stderr}`, 20)) w.reporter.log(l);
  return out;
}

// ---- clone & branch --------------------------------------------------------------------

export async function cloneRepo(w: WorkspaceContext, access: GitAccess): Promise<void> {
  const env = gitAuthEnv(access.token);
  const secrets = access.token ? [...w.secrets, access.token] : w.secrets;
  const wc = { ...w, secrets };
  w.reporter.log(`Cloning ${w.project.githubRepoFullName} (${w.project.defaultBranch})`);
  const r = await runLogged(
    wc,
    `git clone --no-tags --branch ${shq(w.project.defaultBranch)} -- ${shq(access.remoteUrl)} .`,
    { envs: env },
  );
  if (r.exitCode !== 0) {
    fail(
      'clone',
      'LSE-SBX-003',
      `git clone failed (exit ${r.exitCode}): ${tail(r.stderr, 5).join(' | ')}`,
    );
  }
  // Identity for WIP snapshots; keep the generated .env out of commits.
  await runLogged(
    wc,
    "git config user.name 'loose.ai' && git config user.email 'bot@loose.ai' && printf '\\n.env\\n' >> .git/info/exclude",
  );
}

/**
 * Create `base` (or `base-2`, `base-3`… when it already exists on the remote,
 * LSE-GH-004 → suffix retry). Returns the branch actually created.
 */
export async function createSessionBranch(
  w: WorkspaceContext,
  access: GitAccess,
  base: string,
  maxAttempts = 5,
): Promise<string> {
  const env = gitAuthEnv(access.token);
  const wc = { ...w, secrets: access.token ? [...w.secrets, access.token] : w.secrets };
  for (let i = 0; i < maxAttempts; i += 1) {
    const name = i === 0 ? base : `${base}-${i + 1}`;
    const ls = await runLogged(wc, `git ls-remote --exit-code --heads origin ${shq(name)}`, {
      envs: env,
      timeoutMs: 60_000,
    });
    if (ls.exitCode === 0) {
      w.ctx.logger.info(
        { code: 'LSE-GH-004', branch: name },
        'session branch exists; trying a suffix',
      );
      w.reporter.log(`Branch ${name} already exists (LSE-GH-004); trying another name`);
      continue;
    }
    if (ls.exitCode !== 2) {
      fail('clone', 'LSE-SBX-003', `git ls-remote failed (exit ${ls.exitCode})`);
    }
    const co = await runLogged(wc, `git checkout -b ${shq(name)}`);
    if (co.exitCode === 0) return name;
    w.reporter.log(`Could not create branch ${name}; trying another name`);
  }
  throw new StepFailure(
    'clone',
    new AppError('LSE-GH-004', {
      devMessage: `No free branch name for ${base} after ${maxAttempts} attempts`,
    }),
  );
}

/**
 * Recover: restore the WIP snapshot (`refs/loose/wip/<id>`) onto `branch` with the
 * snapshot's changes left uncommitted in the working tree.
 */
export async function restoreWip(
  w: WorkspaceContext,
  access: GitAccess,
  wipRef: string,
  branch: string,
): Promise<void> {
  const env = gitAuthEnv(access.token);
  const wc = { ...w, secrets: access.token ? [...w.secrets, access.token] : w.secrets };
  const fetch = await runLogged(
    wc,
    `git fetch --no-tags origin ${shq(`+${wipRef}:refs/loose/wip`)}`,
    {
      envs: env,
    },
  );
  if (fetch.exitCode !== 0) {
    fail(
      'clone',
      'LSE-SBX-003',
      `Could not fetch the saved work (${wipRef}), exit ${fetch.exitCode}`,
    );
  }
  const r = await runLogged(
    wc,
    `git checkout -q -B ${shq(branch)} 'refs/loose/wip^' && git read-tree -u --reset refs/loose/wip && git reset -q`,
  );
  if (r.exitCode !== 0)
    fail('clone', 'LSE-SBX-003', `Could not restore saved work (exit ${r.exitCode})`);
  w.reporter.log('Restored saved work in progress');
}

/**
 * Snapshot the working tree (incl. untracked files) to `wipRef` on the remote
 * WITHOUT touching the branch or index: temp index → write-tree → commit-tree.
 */
export async function pushWip(
  w: WorkspaceContext,
  access: GitAccess,
  wipRef: string,
): Promise<boolean> {
  const env = gitAuthEnv(access.token);
  const wc = { ...w, secrets: access.token ? [...w.secrets, access.token] : w.secrets };
  const script = [
    'set -e',
    'export GIT_INDEX_FILE="$(git rev-parse --git-dir)/loose-wip-index"',
    'rm -f "$GIT_INDEX_FILE"',
    'git add -A',
    'tree=$(git write-tree)',
    'commit=$(git commit-tree "$tree" -p HEAD -m "loose.ai: work in progress")',
    'rm -f "$GIT_INDEX_FILE"',
    `git push -q --force origin "$commit:${wipRef}"`,
  ].join('\n');
  const r = await runLogged(wc, script, { envs: env, timeoutMs: 120_000 });
  return r.exitCode === 0;
}

/**
 * Resume / fork from a pushed branch (spec §8.14): fetch `remoteBranch` and check it out as
 * `localBranch` at its tip. Unlike `restoreWip` nothing is un-committed, so an existing PR's
 * history stays intact and further work lands on top of it.
 */
export async function restoreBranch(
  w: WorkspaceContext,
  access: GitAccess,
  remoteBranch: string,
  localBranch: string,
): Promise<void> {
  const env = gitAuthEnv(access.token);
  const wc = { ...w, secrets: access.token ? [...w.secrets, access.token] : w.secrets };
  const fetched = await runLogged(
    wc,
    `git fetch --no-tags origin ${shq(`+refs/heads/${remoteBranch}:refs/loose/resume`)}`,
    { envs: env },
  );
  if (fetched.exitCode !== 0) {
    fail(
      'clone',
      'LSE-SBX-003',
      `Could not fetch branch ${remoteBranch} (exit ${fetched.exitCode})`,
    );
  }
  const r = await runLogged(wc, `git checkout -q -B ${shq(localBranch)} refs/loose/resume`);
  if (r.exitCode !== 0) {
    fail('clone', 'LSE-SBX-003', `Could not continue on ${localBranch} (exit ${r.exitCode})`);
  }
  w.reporter.log(`Continuing the work on ${remoteBranch}`);
}

/**
 * Publish a sandbox-local ref (e.g. a checkpoint snapshot `refs/loose/checkpoints/<id>`) to
 * the remote as `targetRef`, so another sandbox can restore it. Fork source step (spec §8.14).
 */
export async function pushRef(
  w: WorkspaceContext,
  access: GitAccess,
  sourceRef: string,
  targetRef: string,
): Promise<boolean> {
  const env = gitAuthEnv(access.token);
  const wc = { ...w, secrets: access.token ? [...w.secrets, access.token] : w.secrets };
  const r = await runLogged(wc, `git push -q --force origin ${shq(`${sourceRef}:${targetRef}`)}`, {
    envs: env,
    timeoutMs: 120_000,
  });
  return r.exitCode === 0;
}

// ---- env & services ----------------------------------------------------------------------

export function parsePortMap(p: Project): PortMapItem[] {
  const r = z.array(portMapItemSchema).safeParse(p.portMap ?? []);
  return r.success ? r.data : [];
}

export function parseHealthCheck(p: Project): HealthCheck | null {
  if (!p.healthCheck) return null;
  const r = healthCheckSchema.safeParse(p.healthCheck);
  return r.success ? r.data : null;
}

export function firstPublicPort(p: Project): PortMapItem | undefined {
  return parsePortMap(p).find((x) => x.public);
}

/** Project env + resolved public URLs for every port with an `envVar` (+ CORS_ORIGIN). */
export function resolveSessionEnv(
  project: Project,
  sandbox: SandboxHandle,
  projectEnv: Record<string, string>,
): Record<string, string> {
  const vars = { ...projectEnv };
  const ports = parsePortMap(project);
  for (const p of ports) if (p.envVar) vars[p.envVar] = sandbox.getUrl(p.port);
  const front = ports.find((p) => p.public);
  if (front && !ports.some((p) => p.envVar === 'CORS_ORIGIN')) {
    vars.CORS_ORIGIN = sandbox.getUrl(front.port);
  }
  return vars;
}

export function formatDotenv(vars: Record<string, string>): string {
  const esc = (v: string) => v.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\r?\n/g, '\\n');
  return `${Object.keys(vars)
    .sort()
    .map((k) => `${k}="${esc(vars[k] ?? '')}"`)
    .join('\n')}\n`;
}

export async function writeEnvFile(w: WorkspaceContext, vars: Record<string, string>) {
  try {
    await w.sandbox.writeFile(`${w.sandbox.paths.workspace}/.env`, formatDotenv(vars));
  } catch (err) {
    throw new StepFailure(
      'clone',
      new AppError('LSE-SBX-002', { devMessage: 'Could not write .env', cause: err }),
    );
  }
  w.reporter.log(`Wrote .env (${Object.keys(vars).length} variables)`);
}

export async function startServices(w: WorkspaceContext): Promise<void> {
  const services = serviceStartCommands(w.project.requiredServices);
  if (!services.length) return;
  if (w.sandbox.kind === 'local') {
    w.reporter.log('Local dev sandbox: skipping service start (start them on your machine)');
    return;
  }
  for (const s of services) {
    w.reporter.log(`Starting ${s.label}`);
    const r = await runLogged(w, s.cmd, { timeoutMs: 120_000 });
    if (r.exitCode !== 0) {
      fail('start_services', 'LSE-SBX-004', `${s.label} failed to start (exit ${r.exitCode})`);
    }
  }
}

// ---- startup & health --------------------------------------------------------------------

export interface StartupResult {
  appProcesses: BackgroundProcess[];
}

/**
 * Run startup commands in order. When the project serves an app (health check or
 * public port), the LAST command is the long-running dev server and runs in the
 * background; all others must exit 0.
 */
export async function runStartupCommands(
  w: WorkspaceContext,
  envs: Record<string, string>,
  onPhase: (phase: 'installing' | 'starting_app', index: number) => Promise<void>,
): Promise<StartupResult> {
  const cmds = w.project.startupCommands;
  const servesApp =
    parseHealthCheck(w.project) !== null || firstPublicPort(w.project) !== undefined;
  const scrub = scrubber(w.secrets);
  const appProcesses: BackgroundProcess[] = [];
  for (const [i, cmd] of cmds.entries()) {
    const background = servesApp && i === cmds.length - 1;
    const label = `step ${i + 1}/${cmds.length}`;
    if (background) {
      await assertLocalPortsFree(w);
      await onPhase('starting_app', i);
      w.reporter.log(`Starting the app (${label})`);
      const proc = await w.sandbox.runBackground(cmd, {
        cwd: w.sandbox.paths.workspace,
        envs,
        onStdout: (c) => tail(scrub(c), 5).forEach((l) => w.reporter.log(l)),
        onStderr: (c) => tail(scrub(c), 5).forEach((l) => w.reporter.log(l)),
      });
      appProcesses.push(proc);
    } else {
      await onPhase('installing', i);
      w.reporter.log(`Running ${label}`);
      const r = await runLogged(w, cmd, { envs });
      if (r.exitCode !== 0) {
        fail(
          'startup_commands',
          'LSE-SBX-004',
          `Startup ${label} failed (exit ${r.exitCode}): ${tail(r.stderr || r.stdout, 5).join(' | ')}`,
        );
      }
    }
  }
  return { appProcesses };
}

/** True when something already accepts TCP connections on 127.0.0.1:`port`. */
function hostPortInUse(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = connect({ host: '127.0.0.1', port });
    sock.setTimeout(1000);
    sock.once('connect', () => {
      sock.destroy();
      resolve(true);
    });
    sock.once('timeout', () => {
      sock.destroy();
      resolve(false);
    });
    sock.once('error', () => resolve(false));
  });
}

/**
 * Local (DEV ONLY) sandboxes use host ports. If the app's port is already taken (e.g. a
 * second session of the same project), the new app cannot bind it, yet the health check
 * would succeed against the OTHER app and the preview would show someone else's workspace.
 * Refuse up front instead. e2b sandboxes have their own network namespace, so this is a no-op.
 */
export async function assertLocalPortsFree(w: WorkspaceContext): Promise<void> {
  if (w.sandbox.kind !== 'local') return;
  const target = healthTarget(w.project);
  // Only the app's own ports: non-public entries may be services (e.g. Postgres) that local
  // sandboxes expect the developer to run on the host.
  const ports = new Set(
    parsePortMap(w.project)
      .filter((p) => p.public)
      .map((p) => p.port),
  );
  if (target) ports.add(target.port);
  for (const port of ports) {
    if (await hostPortInUse(port)) {
      fail(
        'startup_commands',
        'LSE-SBX-004',
        `Port ${port} is already in use on this machine (local dev sandbox; another session ` +
          `of this project or another app is using it). Stop it and try again.`,
      );
    }
  }
}

export function healthTarget(p: Project): HealthCheck | null {
  const hc = parseHealthCheck(p);
  if (hc) return hc;
  const front = firstPublicPort(p);
  return front ? { path: '/', port: front.port, timeoutSec: 60 } : null;
}

export function healthProbeCommand(port: number, path: string): string {
  const url = JSON.stringify(`http://127.0.0.1:${port}${path}`);
  const js = `fetch(${url},{signal:AbortSignal.timeout(5000)}).then(r=>process.exit(r.status<500?0:1),()=>process.exit(1))`;
  return `node -e ${shq(js)}`;
}

export async function waitForHealthy(
  w: WorkspaceContext,
  appProcesses: readonly BackgroundProcess[],
  pollMs = HEALTH_POLL_MS,
): Promise<void> {
  const target = healthTarget(w.project);
  if (!target) return;
  const deadline = Date.now() + target.timeoutSec * 1000;
  const probe = healthProbeCommand(target.port, target.path);
  w.reporter.log(`Waiting for the app on port ${target.port}${target.path}`);
  for (;;) {
    const crashed = appProcesses.find((p) => p.exitCode !== undefined);
    if (crashed) {
      const r = await crashed.wait();
      fail(
        'startup_commands',
        'LSE-SBX-004',
        `The app exited during startup (exit ${r.exitCode}): ${tail(scrubber(w.secrets)(r.stderr || r.stdout), 5).join(' | ')}`,
      );
    }
    const r = await w.sandbox.run(probe, { cwd: w.sandbox.paths.workspace, timeoutMs: 10_000 });
    if (r.exitCode === 0) {
      w.reporter.log('App is healthy');
      return;
    }
    if (Date.now() + pollMs > deadline) {
      fail(
        'health_check',
        'LSE-SBX-005',
        `No healthy response on port ${target.port} within ${target.timeoutSec}s`,
      );
    }
    await sleep(pollMs);
  }
}

/** Server-side check that the public preview URL answers (smoke test). */
export async function checkPreview(ctx: AppContext, url: string): Promise<void> {
  try {
    const res = await ctx.fetch(url, { signal: AbortSignal.timeout(15_000), redirect: 'manual' });
    if (res.status >= 500) fail('preview', 'LSE-TPL-006', `Preview answered HTTP ${res.status}`);
  } catch (err) {
    if (err instanceof StepFailure) throw err;
    fail('preview', 'LSE-TPL-006', 'Preview URL did not respond');
  }
}
