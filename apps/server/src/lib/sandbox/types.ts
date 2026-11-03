/**
 * Sandbox abstraction (spec §13). Three implementations:
 * - E2bSandboxProvider — real e2b microVMs (production)
 * - LocalSandboxProvider — DEV ONLY, runs commands on the host in a temp dir (no isolation)
 * - FakeSandboxProvider — in-memory, scriptable (tests)
 *
 * `run()` never throws on a non-zero exit code; it resolves with `exitCode`.
 * Provider/infra failures throw `SandboxProviderError`.
 */

export type SandboxKind = 'e2b' | 'local' | 'fake';

export interface RunOptions {
  /** Working directory (absolute, inside the sandbox). Default: the workspace dir. */
  cwd?: string;
  envs?: Record<string, string>;
  timeoutMs?: number;
  onStdout?: (chunk: string) => void;
  onStderr?: (chunk: string) => void;
}

export interface RunResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export interface BackgroundRunOptions extends RunOptions {
  /** Keep stdin open so `sendStdin` works (runner NDJSON commands). */
  stdin?: boolean;
}

export interface BackgroundProcess {
  readonly pid: number;
  sendStdin(data: string): Promise<void>;
  kill(): Promise<void>;
  /** Resolves when the process exits (never rejects on non-zero exit). */
  wait(): Promise<RunResult>;
  /** Exit code once finished, else undefined. */
  readonly exitCode: number | undefined;
}

export interface SandboxPaths {
  /** Cloned repository (agent cwd). */
  workspace: string;
  /** Runner state dir (`LOOSE_STATE_DIR`: config.json, events.ndjson). Outside the repo. */
  state: string;
  /** Runner entry point (`node <runnerEntry>`). */
  runnerEntry: string;
}

export interface SandboxHandle {
  readonly id: string;
  readonly kind: SandboxKind;
  readonly paths: SandboxPaths;
  run(cmd: string, opts?: RunOptions): Promise<RunResult>;
  runBackground(cmd: string, opts?: BackgroundRunOptions): Promise<BackgroundProcess>;
  writeFile(path: string, data: string | Uint8Array): Promise<void>;
  readFile(path: string): Promise<string>;
  /** Public host for a port, without scheme (e2b: `3000-<id>.e2b.app`). */
  getHost(port: number): string;
  /** Full public URL for a port (https for e2b; http://localhost for local dev). */
  getUrl(port: number): string;
  /** Reset the sandbox's remaining lifetime (keep-alive). */
  setTimeout(ms: number): Promise<void>;
  isRunning(): Promise<boolean>;
  kill(): Promise<void>;
}

export interface CreateSandboxOptions {
  timeoutMs: number;
  envs?: Record<string, string>;
  metadata?: Record<string, string>;
}

export interface SandboxInfo {
  id: string;
  metadata: Record<string, string>;
}

export interface SandboxProvider {
  readonly kind: SandboxKind;
  createFromTemplate(templateId: string, opts: CreateSandboxOptions): Promise<SandboxHandle>;
  /** Reattach to a running sandbox; null when it no longer exists. */
  connect(sandboxId: string): Promise<SandboxHandle | null>;
  /** Resolves false when the sandbox did not exist. */
  kill(sandboxId: string): Promise<boolean>;
  /** Running sandboxes created by loose.ai (metadata `app=loose`). */
  list(): Promise<SandboxInfo[]>;
  /** Cheap authenticated provider reachability probe used by `/readyz` (optional for legacy fakes). */
  ping?(): Promise<void>;
}

export type SandboxErrorKind =
  /** No capacity / provider rate limit (→ LSE-SBX-001). */
  | 'capacity'
  /** Could not start (→ LSE-SBX-002). */
  | 'start_failed'
  | 'not_found'
  | 'timeout'
  /** Network / 5xx — safe to retry. */
  | 'transient';

export class SandboxProviderError extends Error {
  constructor(
    readonly kind: SandboxErrorKind,
    message: string,
    opts?: { cause?: unknown },
  ) {
    super(message, opts);
    this.name = 'SandboxProviderError';
  }
}

export const isTransientSandboxError = (err: unknown) =>
  err instanceof SandboxProviderError && (err.kind === 'transient' || err.kind === 'capacity');

// ---- templates ----------------------------------------------------------------------

export interface TemplateSpec {
  /** Unique template name (`loose-<projectId>-v<n>`). */
  name: string;
  baseImage: string;
  aptPackages: string[];
  /** Shell commands run as root, in order. */
  runCommands: string[];
  envs: Record<string, string>;
  /** Host directory with the runner bundle, copied to /sandbox-agent/runner. */
  runnerBundleDir?: string;
}

export interface TemplateBuildLog {
  ts: Date;
  stream: 'stdout' | 'stderr' | 'system';
  line: string;
}

export type TemplateBuildErrorKind =
  /** Bad project config / failing install step: not retried (→ LSE-TPL-002). */
  | 'user'
  /** Infra hiccup: retried once (→ LSE-TPL-002 if it persists). */
  | 'infra'
  | 'timeout'
  | 'unsupported';

export class TemplateBuildError extends Error {
  constructor(
    readonly kind: TemplateBuildErrorKind,
    message: string,
    opts?: { cause?: unknown },
  ) {
    super(message, opts);
    this.name = 'TemplateBuildError';
  }
}

export interface TemplateBuilder {
  readonly kind: SandboxKind;
  build(
    spec: TemplateSpec,
    opts: { onLog: (log: TemplateBuildLog) => void; signal?: AbortSignal },
  ): Promise<{ templateId: string }>;
}
