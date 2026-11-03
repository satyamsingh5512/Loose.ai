/**
 * LocalSandboxProvider — DEVELOPMENT ONLY. UNSAFE: there is NO isolation.
 *
 * Each "sandbox" is a directory under LOCAL_SANDBOX_DIR (default: OS temp dir)
 * with `workspace/` (the clone) and `state/` (runner state). Commands run on the
 * host with child_process, with cwd confined to the sandbox directory and a
 * scrubbed environment (only PATH/HOME/LANG + explicitly passed vars), but they
 * can still reach the whole machine and network. Never enable outside local dev:
 * the env schema rejects SANDBOX_PROVIDER=local in production.
 *
 * Ports are the host's ports, so two local sessions of the same project clash.
 */
import { spawn, type ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import type { Logger } from '../logger';
import {
  SandboxProviderError,
  type BackgroundProcess,
  type BackgroundRunOptions,
  type CreateSandboxOptions,
  type RunOptions,
  type RunResult,
  type SandboxHandle,
  type SandboxInfo,
  type SandboxPaths,
  type SandboxProvider,
  type TemplateBuilder,
  type TemplateBuildLog,
  type TemplateSpec,
} from './types';

const ID_RE = /^local-[a-f0-9]{12}$/;
const META_FILE = '.loose-sandbox.json';
const MAX_CAPTURE = 1024 * 1024;

export interface LocalSandboxOptions {
  baseDir?: string;
  runnerEntry?: string;
  logger?: Logger;
}

function killGroup(child: ChildProcess, signal: NodeJS.Signals) {
  if (child.pid === undefined || child.exitCode !== null || child.signalCode !== null) return;
  try {
    process.kill(-child.pid, signal);
  } catch {
    try {
      child.kill(signal);
    } catch {
      /* already gone */
    }
  }
}

function append(buf: string, chunk: string) {
  const next = buf + chunk;
  return next.length > MAX_CAPTURE ? next.slice(-MAX_CAPTURE) : next;
}

class LocalProcess implements BackgroundProcess {
  #exitCode: number | undefined;
  readonly #done: Promise<RunResult>;
  stdout = '';
  stderr = '';

  constructor(
    readonly child: ChildProcess,
    opts: RunOptions,
  ) {
    child.stdout?.setEncoding('utf8');
    child.stderr?.setEncoding('utf8');
    child.stdout?.on('data', (c: string) => {
      this.stdout = append(this.stdout, c);
      opts.onStdout?.(c);
    });
    child.stderr?.on('data', (c: string) => {
      this.stderr = append(this.stderr, c);
      opts.onStderr?.(c);
    });
    // stdin may be closed by the child; ignore EPIPE.
    child.stdin?.on('error', () => undefined);
    this.#done = new Promise((resolveDone) => {
      const finish = (code: number) => {
        if (this.#exitCode !== undefined) return;
        this.#exitCode = code;
        resolveDone({ exitCode: code, stdout: this.stdout, stderr: this.stderr });
      };
      child.on('error', () => finish(127));
      child.on('close', (code, signal) => finish(code ?? (signal ? 128 + 9 : 1)));
    });
  }

  get pid() {
    return this.child.pid ?? -1;
  }

  get exitCode() {
    return this.#exitCode;
  }

  async sendStdin(data: string) {
    const stdin = this.child.stdin;
    if (!stdin || stdin.destroyed || this.#exitCode !== undefined) {
      throw new SandboxProviderError('not_found', 'process stdin is closed');
    }
    await new Promise<void>((res, rej) => stdin.write(data, (err) => (err ? rej(err) : res())));
  }

  async kill() {
    if (this.#exitCode !== undefined) return;
    killGroup(this.child, 'SIGTERM');
    const t = setTimeout(() => killGroup(this.child, 'SIGKILL'), 2000);
    t.unref();
    await this.#done;
    clearTimeout(t);
  }

  wait() {
    return this.#done;
  }
}

export class LocalSandbox implements SandboxHandle {
  readonly kind = 'local' as const;
  readonly paths: SandboxPaths;
  readonly #procs = new Set<LocalProcess>();
  #killTimer: NodeJS.Timeout | undefined;
  #killed = false;

  constructor(
    readonly id: string,
    readonly root: string,
    runnerEntry: string,
    private readonly baseEnv: Record<string, string>,
  ) {
    this.paths = { workspace: join(root, 'workspace'), state: join(root, 'state'), runnerEntry };
  }

  /** Resolve a path and refuse anything outside the sandbox directory. */
  #confine(p: string): string {
    const abs = isAbsolute(p) ? resolve(p) : resolve(this.paths.workspace, p);
    const rel = relative(this.root, abs);
    if (rel.startsWith('..') || isAbsolute(rel)) {
      throw new SandboxProviderError('start_failed', 'path is outside the local sandbox');
    }
    return abs;
  }

  #env(extra?: Record<string, string>): Record<string, string> {
    return {
      PATH: process.env.PATH ?? '/usr/local/bin:/usr/bin:/bin',
      HOME: this.root,
      LANG: 'C.UTF-8',
      TMPDIR: join(this.root, 'tmp'),
      GIT_TERMINAL_PROMPT: '0',
      ...this.baseEnv,
      ...extra,
    };
  }

  #spawn(cmd: string, opts: RunOptions, stdin: boolean): LocalProcess {
    if (this.#killed) throw new SandboxProviderError('not_found', `sandbox ${this.id} is gone`);
    const child = spawn('/bin/bash', ['-c', cmd], {
      cwd: this.#confine(opts.cwd ?? this.paths.workspace),
      env: this.#env(opts.envs),
      detached: true,
      stdio: [stdin ? 'pipe' : 'ignore', 'pipe', 'pipe'],
    });
    const proc = new LocalProcess(child, opts);
    this.#procs.add(proc);
    void proc.wait().then(() => this.#procs.delete(proc));
    return proc;
  }

  async run(cmd: string, opts: RunOptions = {}): Promise<RunResult> {
    const proc = this.#spawn(cmd, opts, false);
    let timedOut = false;
    const timer = opts.timeoutMs
      ? setTimeout(() => {
          timedOut = true;
          void proc.kill();
        }, opts.timeoutMs)
      : undefined;
    timer?.unref();
    const res = await proc.wait();
    if (timer) clearTimeout(timer);
    return timedOut ? { ...res, exitCode: 124 } : res;
  }

  async runBackground(cmd: string, opts: BackgroundRunOptions = {}) {
    return this.#spawn(cmd, opts, opts.stdin === true);
  }

  async writeFile(path: string, data: string | Uint8Array) {
    const abs = this.#confine(path);
    await mkdir(dirname(abs), { recursive: true });
    await writeFile(abs, data, { mode: 0o600 });
  }

  async readFile(path: string) {
    try {
      return await readFile(this.#confine(path), 'utf8');
    } catch (err) {
      throw new SandboxProviderError('not_found', `cannot read ${path}`, { cause: err });
    }
  }

  getHost(port: number) {
    return `localhost:${port}`;
  }

  getUrl(port: number) {
    return `http://localhost:${port}`;
  }

  async setTimeout(ms: number) {
    if (this.#killTimer) clearTimeout(this.#killTimer);
    this.#killTimer = setTimeout(() => void this.kill(), ms);
    this.#killTimer.unref();
  }

  async isRunning() {
    return !this.#killed && existsSync(join(this.root, META_FILE));
  }

  async kill() {
    this.#killed = true;
    if (this.#killTimer) clearTimeout(this.#killTimer);
    await Promise.allSettled([...this.#procs].map((p) => p.kill()));
    await rm(this.root, { recursive: true, force: true });
  }
}

export class LocalSandboxProvider implements SandboxProvider {
  readonly kind = 'local' as const;
  readonly baseDir: string;
  readonly #runnerEntry: string;
  /** Live handles created by this process (keeps track of spawned processes). */
  readonly #live = new Map<string, LocalSandbox>();

  constructor(opts: LocalSandboxOptions = {}) {
    this.baseDir = resolve(opts.baseDir ?? join(tmpdir(), 'loose-sandboxes'));
    this.#runnerEntry =
      opts.runnerEntry ?? resolve(process.cwd(), '../../packages/runner/dist/cli.js');
    opts.logger?.warn(
      { baseDir: this.baseDir },
      'LocalSandboxProvider is DEV ONLY: commands run on this machine without isolation',
    );
  }

  #open(id: string, envs: Record<string, string> = {}) {
    const sbx = new LocalSandbox(id, join(this.baseDir, id), this.#runnerEntry, envs);
    this.#live.set(id, sbx);
    return sbx;
  }

  async createFromTemplate(templateId: string, opts: CreateSandboxOptions) {
    const id = `local-${randomBytes(6).toString('hex')}`;
    const root = join(this.baseDir, id);
    try {
      await mkdir(join(root, 'workspace'), { recursive: true });
      await mkdir(join(root, 'state'), { recursive: true });
      await mkdir(join(root, 'tmp'), { recursive: true });
      await writeFile(
        join(root, META_FILE),
        JSON.stringify({ templateId, metadata: opts.metadata ?? {}, createdAt: new Date() }),
      );
    } catch (err) {
      throw new SandboxProviderError('start_failed', 'could not create local sandbox dir', {
        cause: err,
      });
    }
    const sbx = this.#open(id, opts.envs);
    await sbx.setTimeout(opts.timeoutMs);
    return sbx;
  }

  async connect(sandboxId: string) {
    if (!ID_RE.test(sandboxId)) return null;
    const live = this.#live.get(sandboxId);
    if (live) return (await live.isRunning()) ? live : null;
    if (!existsSync(join(this.baseDir, sandboxId, META_FILE))) return null;
    return this.#open(sandboxId);
  }

  async kill(sandboxId: string) {
    const sbx = await this.connect(sandboxId);
    if (!sbx) return false;
    await sbx.kill();
    this.#live.delete(sandboxId);
    return true;
  }

  async list(): Promise<SandboxInfo[]> {
    let entries: string[];
    try {
      entries = await readdir(this.baseDir);
    } catch {
      return [];
    }
    const out: SandboxInfo[] = [];
    for (const id of entries.filter((e) => ID_RE.test(e))) {
      try {
        const meta = JSON.parse(await readFile(join(this.baseDir, id, META_FILE), 'utf8')) as {
          metadata?: Record<string, string>;
        };
        out.push({ id, metadata: meta.metadata ?? {} });
      } catch {
        /* half-deleted dir */
      }
    }
    return out;
  }
}

/** Dev "builder": validates the spec and logs the steps; nothing is installed. */
export class LocalTemplateBuilder implements TemplateBuilder {
  readonly kind = 'local' as const;

  async build(spec: TemplateSpec, opts: { onLog: (l: TemplateBuildLog) => void }) {
    const log = (line: string) => opts.onLog({ ts: new Date(), stream: 'system', line });
    log(`[local] template ${spec.name} (base ${spec.baseImage})`);
    log('[local] dev mode: system packages and services are NOT installed on the host');
    for (const cmd of spec.runCommands) log(`[local] skip: ${cmd}`);
    return { templateId: `local-${spec.name}` };
  }
}
