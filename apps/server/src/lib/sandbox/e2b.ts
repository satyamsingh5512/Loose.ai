/**
 * e2b implementation (production). Signatures verified against e2b 2.52
 * (node_modules/e2b/dist/index.d.ts). The API key is passed per call and never logged.
 */
import {
  AuthenticationError,
  BuildError,
  CommandExitError,
  NotFoundError,
  RateLimitError,
  Sandbox,
  ServiceBusyError,
  Template,
  TimeoutError,
  type CommandHandle,
  type CommandResult,
} from 'e2b';
import {
  SandboxProviderError,
  TemplateBuildError,
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

export const E2B_PATHS: SandboxPaths = {
  workspace: '/home/user/workspace',
  state: '/home/user/.loose',
  runnerEntry: '/sandbox-agent/runner/dist/cli.js',
};

export interface E2bOptions {
  apiKey: string;
  domain?: string;
}

function toResult(r: CommandResult): RunResult {
  return { exitCode: r.exitCode, stdout: r.stdout, stderr: r.stderr };
}

/** Map SDK errors to provider error kinds (messages carry no secrets). */
export function mapE2bError(
  err: unknown,
  fallback: 'start_failed' | 'transient',
): SandboxProviderError {
  if (err instanceof SandboxProviderError) return err;
  const msg = err instanceof Error ? err.message.slice(0, 300) : 'unknown e2b error';
  if (err instanceof RateLimitError || err instanceof ServiceBusyError)
    return new SandboxProviderError('capacity', msg, { cause: err });
  if (err instanceof NotFoundError)
    return new SandboxProviderError('not_found', msg, { cause: err });
  if (err instanceof TimeoutError) return new SandboxProviderError('timeout', msg, { cause: err });
  if (err instanceof AuthenticationError)
    return new SandboxProviderError('start_failed', 'e2b authentication failed', { cause: err });
  return new SandboxProviderError(fallback, msg, { cause: err });
}

class E2bProcess implements BackgroundProcess {
  #exitCode: number | undefined;
  readonly #done: Promise<RunResult>;

  constructor(private readonly handle: CommandHandle) {
    this.#done = handle.wait().then(
      (r) => {
        this.#exitCode = r.exitCode;
        return toResult(r);
      },
      (err: unknown) => {
        const r =
          err instanceof CommandExitError
            ? toResult(err)
            : { exitCode: 1, stdout: handle.stdout, stderr: handle.stderr };
        this.#exitCode = r.exitCode;
        return r;
      },
    );
  }

  get pid() {
    return this.handle.pid;
  }

  get exitCode() {
    return this.#exitCode;
  }

  async sendStdin(data: string) {
    await this.handle.sendStdin(data);
  }

  async kill() {
    await this.handle.kill();
  }

  wait() {
    return this.#done;
  }
}

class E2bSandbox implements SandboxHandle {
  readonly kind = 'e2b' as const;
  readonly paths = E2B_PATHS;

  constructor(private readonly sbx: Sandbox) {}

  get id() {
    return this.sbx.sandboxId;
  }

  async run(cmd: string, opts: RunOptions = {}): Promise<RunResult> {
    try {
      const r = await this.sbx.commands.run(cmd, {
        cwd: opts.cwd ?? this.paths.workspace,
        envs: opts.envs,
        timeoutMs: opts.timeoutMs ?? 0,
        onStdout: opts.onStdout,
        onStderr: opts.onStderr,
      });
      return toResult(r);
    } catch (err) {
      if (err instanceof CommandExitError) return toResult(err);
      if (err instanceof TimeoutError) return { exitCode: 124, stdout: '', stderr: err.message };
      throw mapE2bError(err, 'transient');
    }
  }

  async runBackground(cmd: string, opts: BackgroundRunOptions = {}) {
    try {
      const handle = await this.sbx.commands.run(cmd, {
        background: true,
        stdin: opts.stdin ?? false,
        cwd: opts.cwd ?? this.paths.workspace,
        envs: opts.envs,
        timeoutMs: opts.timeoutMs ?? 0,
        onStdout: opts.onStdout,
        onStderr: opts.onStderr,
      });
      return new E2bProcess(handle);
    } catch (err) {
      throw mapE2bError(err, 'transient');
    }
  }

  async writeFile(path: string, data: string | Uint8Array) {
    try {
      await this.sbx.files.write(
        path,
        typeof data === 'string' ? data : (Buffer.from(data).buffer as ArrayBuffer),
      );
    } catch (err) {
      throw mapE2bError(err, 'transient');
    }
  }

  async readFile(path: string) {
    try {
      return await this.sbx.files.read(path);
    } catch (err) {
      throw mapE2bError(err, 'transient');
    }
  }

  getHost(port: number) {
    return this.sbx.getHost(port);
  }

  getUrl(port: number) {
    return `https://${this.getHost(port)}`;
  }

  async setTimeout(ms: number) {
    try {
      await this.sbx.setTimeout(ms);
    } catch (err) {
      throw mapE2bError(err, 'transient');
    }
  }

  async isRunning() {
    try {
      return await this.sbx.isRunning();
    } catch {
      return false;
    }
  }

  async kill() {
    try {
      await this.sbx.kill();
    } catch (err) {
      const mapped = mapE2bError(err, 'transient');
      if (mapped.kind !== 'not_found') throw mapped;
    }
  }
}

export class E2bSandboxProvider implements SandboxProvider {
  readonly kind = 'e2b' as const;

  constructor(private readonly opts: E2bOptions) {}

  get #conn() {
    return { apiKey: this.opts.apiKey, ...(this.opts.domain ? { domain: this.opts.domain } : {}) };
  }

  async createFromTemplate(templateId: string, o: CreateSandboxOptions) {
    try {
      const sbx = await Sandbox.create(templateId, {
        ...this.#conn,
        timeoutMs: o.timeoutMs,
        envs: o.envs,
        metadata: { app: 'loose', ...o.metadata },
      });
      return new E2bSandbox(sbx);
    } catch (err) {
      throw mapE2bError(err, 'start_failed');
    }
  }

  async connect(sandboxId: string) {
    try {
      return new E2bSandbox(await Sandbox.connect(sandboxId, this.#conn));
    } catch (err) {
      const mapped = mapE2bError(err, 'transient');
      if (mapped.kind === 'not_found') return null;
      throw mapped;
    }
  }

  async kill(sandboxId: string) {
    try {
      return await Sandbox.kill(sandboxId, this.#conn);
    } catch (err) {
      const mapped = mapE2bError(err, 'transient');
      if (mapped.kind === 'not_found') return false;
      throw mapped;
    }
  }

  async ping(): Promise<void> {
    // A bounded authenticated list call proves API/DNS/TLS/token reachability without exposing data.
    const pager = Sandbox.list({ ...this.#conn, query: { metadata: { app: 'loose' } } });
    if (pager.hasNext) await pager.nextItems();
  }

  async list(): Promise<SandboxInfo[]> {
    try {
      const pager = Sandbox.list({ ...this.#conn, query: { metadata: { app: 'loose' } } });
      const out: SandboxInfo[] = [];
      // Bounded: at most 50 pages.
      for (let i = 0; i < 50 && pager.hasNext; i += 1) {
        for (const s of await pager.nextItems())
          out.push({ id: s.sandboxId, metadata: s.metadata });
      }
      return out;
    } catch (err) {
      throw mapE2bError(err, 'transient');
    }
  }
}

export class E2bTemplateBuilder implements TemplateBuilder {
  readonly kind = 'e2b' as const;

  constructor(private readonly opts: E2bOptions) {}

  async build(spec: TemplateSpec, o: { onLog: (l: TemplateBuildLog) => void }) {
    let t = Template(spec.runnerBundleDir ? { fileContextPath: spec.runnerBundleDir } : undefined)
      .fromImage(spec.baseImage)
      .aptInstall(spec.aptPackages);
    if (spec.runnerBundleDir) t = t.copy('.', '/sandbox-agent/runner/dist');
    if (spec.runCommands.length) t = t.runCmd(spec.runCommands, { user: 'root' });
    if (Object.keys(spec.envs).length) t = t.setEnvs(spec.envs);
    try {
      const info = await Template.build(t, spec.name, {
        apiKey: this.opts.apiKey,
        ...(this.opts.domain ? { domain: this.opts.domain } : {}),
        onBuildLogs: (e) =>
          o.onLog({
            ts: e.timestamp,
            stream: e.level === 'error' ? 'stderr' : 'stdout',
            line: e.message,
          }),
      });
      return { templateId: info.templateId };
    } catch (err) {
      const msg = err instanceof Error ? err.message.slice(0, 500) : 'template build failed';
      if (err instanceof BuildError) throw new TemplateBuildError('user', msg, { cause: err });
      if (err instanceof TimeoutError) throw new TemplateBuildError('timeout', msg, { cause: err });
      throw new TemplateBuildError('infra', msg, { cause: err });
    }
  }
}
