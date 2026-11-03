/**
 * In-memory, scriptable sandbox + template builder for tests. No processes are
 * spawned; commands are answered by registered handlers (default: exit 0).
 */
import { randomBytes } from 'node:crypto';
import {
  SandboxProviderError,
  TemplateBuildError,
  type BackgroundProcess,
  type BackgroundRunOptions,
  type CreateSandboxOptions,
  type RunOptions,
  type RunResult,
  type SandboxErrorKind,
  type SandboxHandle,
  type SandboxInfo,
  type SandboxPaths,
  type SandboxProvider,
  type TemplateBuilder,
  type TemplateBuildErrorKind,
  type TemplateBuildLog,
  type TemplateSpec,
} from './types';

export interface FakeCommandRecord {
  cmd: string;
  opts: RunOptions;
  background: boolean;
}

type Matcher = string | RegExp | ((cmd: string) => boolean);
export type FakeCommandHandler = (
  cmd: string,
  opts: RunOptions,
  sandbox: FakeSandbox,
) => Partial<RunResult> | void | Promise<Partial<RunResult> | void>;
export type FakeBackgroundHandler = (
  proc: FakeProcess,
  cmd: string,
  opts: BackgroundRunOptions,
  sandbox: FakeSandbox,
) => void;

function matches(m: Matcher, cmd: string): boolean {
  if (typeof m === 'string') return cmd.includes(m);
  if (m instanceof RegExp) return m.test(cmd);
  return m(cmd);
}

export class FakeProcess implements BackgroundProcess {
  readonly stdin: string[] = [];
  stdout = '';
  stderr = '';
  #exitCode: number | undefined;
  #resolve!: (r: RunResult) => void;
  readonly #done: Promise<RunResult>;
  /** Called for every stdin write (e.g. a fake runner reacting to commands). */
  onStdin: ((data: string) => void) | undefined;

  constructor(
    readonly pid: number,
    readonly cmd: string,
    private readonly opts: BackgroundRunOptions,
  ) {
    this.#done = new Promise((r) => (this.#resolve = r));
  }

  get exitCode() {
    return this.#exitCode;
  }

  emitStdout(chunk: string) {
    this.stdout += chunk;
    this.opts.onStdout?.(chunk);
  }

  emitStderr(chunk: string) {
    this.stderr += chunk;
    this.opts.onStderr?.(chunk);
  }

  exit(code: number) {
    if (this.#exitCode !== undefined) return;
    this.#exitCode = code;
    this.#resolve({ exitCode: code, stdout: this.stdout, stderr: this.stderr });
  }

  async sendStdin(data: string) {
    if (this.#exitCode !== undefined) throw new Error('process has exited');
    this.stdin.push(data);
    this.onStdin?.(data);
  }

  async kill() {
    this.exit(137);
  }

  wait() {
    return this.#done;
  }
}

export class FakeSandbox implements SandboxHandle {
  readonly kind = 'fake' as const;
  readonly files = new Map<string, string>();
  readonly commands: FakeCommandRecord[] = [];
  readonly processes: FakeProcess[] = [];
  readonly paths: SandboxPaths = {
    workspace: '/home/user/workspace',
    state: '/home/user/.loose',
    runnerEntry: '/sandbox-agent/runner/dist/cli.js',
  };
  killed = false;
  /** Simulates the provider losing the VM (isRunning false, connect → null). */
  lost = false;
  timeoutMs: number;
  #pid = 100;

  constructor(
    readonly id: string,
    readonly templateId: string,
    readonly createOpts: CreateSandboxOptions,
    private readonly provider: FakeSandboxProvider,
  ) {
    this.timeoutMs = createOpts.timeoutMs;
  }

  get alive() {
    return !this.killed && !this.lost;
  }

  #assertAlive() {
    if (!this.alive) throw new SandboxProviderError('not_found', `sandbox ${this.id} is gone`);
  }

  async run(cmd: string, opts: RunOptions = {}): Promise<RunResult> {
    this.#assertAlive();
    this.commands.push({ cmd, opts, background: false });
    const handler = this.provider.findHandler(cmd);
    const out = (await handler?.(cmd, opts, this)) ?? {};
    const result = {
      exitCode: out.exitCode ?? 0,
      stdout: out.stdout ?? '',
      stderr: out.stderr ?? '',
    };
    if (result.stdout) opts.onStdout?.(result.stdout);
    if (result.stderr) opts.onStderr?.(result.stderr);
    return result;
  }

  async runBackground(cmd: string, opts: BackgroundRunOptions = {}): Promise<BackgroundProcess> {
    this.#assertAlive();
    this.commands.push({ cmd, opts, background: true });
    const proc = new FakeProcess((this.#pid += 1), cmd, opts);
    this.processes.push(proc);
    this.provider.findBackgroundHandler(cmd)?.(proc, cmd, opts, this);
    return proc;
  }

  async writeFile(path: string, data: string | Uint8Array) {
    this.#assertAlive();
    this.files.set(path, typeof data === 'string' ? data : Buffer.from(data).toString('utf8'));
  }

  async readFile(path: string) {
    this.#assertAlive();
    const v = this.files.get(path);
    if (v === undefined) throw new SandboxProviderError('not_found', `no such file: ${path}`);
    return v;
  }

  getHost(port: number) {
    return `${port}-${this.id}.fake.sandbox`;
  }

  getUrl(port: number) {
    return `https://${this.getHost(port)}`;
  }

  async setTimeout(ms: number) {
    this.#assertAlive();
    this.timeoutMs = ms;
  }

  async isRunning() {
    return this.alive;
  }

  async kill() {
    this.killed = true;
    for (const p of this.processes) p.exit(137);
  }

  /** Commands run so far (foreground + background), as strings. */
  commandLines(): string[] {
    return this.commands.map((c) => c.cmd);
  }
}

export class FakeSandboxProvider implements SandboxProvider {
  readonly kind = 'fake' as const;
  readonly sandboxes = new Map<string, FakeSandbox>();
  readonly createCalls: { templateId: string; opts: CreateSandboxOptions }[] = [];
  #handlers: { match: Matcher; handler: FakeCommandHandler }[] = [];
  #bgHandlers: { match: Matcher; handler: FakeBackgroundHandler }[] = [];
  #createFailures: SandboxErrorKind[] = [];

  /** Answer matching foreground commands. Later registrations win. */
  onCommand(match: Matcher, handler: FakeCommandHandler): this {
    this.#handlers.unshift({ match, handler });
    return this;
  }

  /** Script matching background processes (e.g. emit runner stdout). Later registrations win. */
  onBackground(match: Matcher, handler: FakeBackgroundHandler): this {
    this.#bgHandlers.unshift({ match, handler });
    return this;
  }

  /** Make the next `times` creates fail with `kind`. */
  failNextCreate(kind: SandboxErrorKind, times = 1): this {
    for (let i = 0; i < times; i += 1) this.#createFailures.push(kind);
    return this;
  }

  reset(): void {
    this.sandboxes.clear();
    this.createCalls.length = 0;
    this.#handlers = [];
    this.#bgHandlers = [];
    this.#createFailures = [];
  }

  findHandler(cmd: string): FakeCommandHandler | undefined {
    const h = this.#handlers.find((x) => matches(x.match, cmd))?.handler;
    if (h) return h;
    // Realistic default: remote branches don't exist (`--exit-code` → 2).
    if (cmd.startsWith('git ls-remote --exit-code')) return () => ({ exitCode: 2 });
    return undefined;
  }

  findBackgroundHandler(cmd: string) {
    return this.#bgHandlers.find((h) => matches(h.match, cmd))?.handler;
  }

  /** The most recently created sandbox (test convenience). */
  last(): FakeSandbox | undefined {
    return [...this.sandboxes.values()].at(-1);
  }

  async createFromTemplate(templateId: string, opts: CreateSandboxOptions) {
    this.createCalls.push({ templateId, opts });
    const failure = this.#createFailures.shift();
    if (failure) throw new SandboxProviderError(failure, `fake create failure (${failure})`);
    const id = `fake-${randomBytes(6).toString('hex')}`;
    const sbx = new FakeSandbox(id, templateId, opts, this);
    this.sandboxes.set(id, sbx);
    return sbx;
  }

  async connect(sandboxId: string) {
    const s = this.sandboxes.get(sandboxId);
    return s?.alive ? s : null;
  }

  async kill(sandboxId: string) {
    const s = this.sandboxes.get(sandboxId);
    if (!s?.alive) return false;
    await s.kill();
    return true;
  }

  async list(): Promise<SandboxInfo[]> {
    return [...this.sandboxes.values()]
      .filter((s) => s.alive)
      .map((s) => ({ id: s.id, metadata: s.createOpts.metadata ?? {} }));
  }
}

// ---- templates -------------------------------------------------------------------------

export interface FakeBuildScript {
  logs?: (string | Omit<TemplateBuildLog, 'ts'>)[];
  error?: { kind: TemplateBuildErrorKind; message: string };
  templateId?: string;
  /** Build waits for this promise before finishing (to observe BUILDING). */
  gate?: Promise<void>;
  /** Lines emitted after the gate opens (live streaming tests). */
  logsAfterGate?: string[];
}

export class FakeTemplateBuilder implements TemplateBuilder {
  readonly kind = 'fake' as const;
  readonly specs: TemplateSpec[] = [];
  #script: FakeBuildScript[] = [];
  #n = 0;

  /** Queue results for the next builds (default: success with a generated id). */
  enqueue(...scripts: FakeBuildScript[]): this {
    this.#script.push(...scripts);
    return this;
  }

  reset(): void {
    this.specs.length = 0;
    this.#script = [];
  }

  async build(spec: TemplateSpec, opts: { onLog: (l: TemplateBuildLog) => void }) {
    this.specs.push(spec);
    const step = this.#script.shift() ?? {};
    opts.onLog({ ts: new Date(), stream: 'system', line: `building ${spec.name}` });
    for (const l of step.logs ?? []) {
      opts.onLog(
        typeof l === 'string'
          ? { ts: new Date(), stream: 'stdout', line: l }
          : { ts: new Date(), ...l },
      );
    }
    if (step.gate) await step.gate;
    for (const l of step.logsAfterGate ?? [])
      opts.onLog({ ts: new Date(), stream: 'stdout', line: l });
    if (step.error) throw new TemplateBuildError(step.error.kind, step.error.message);
    this.#n += 1;
    return {
      templateId: step.templateId ?? `tpl-fake-${this.#n}-${randomBytes(3).toString('hex')}`,
    };
  }
}
