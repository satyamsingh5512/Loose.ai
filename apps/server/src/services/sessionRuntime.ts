/**
 * In-process session runtime registry + lifecycle hooks — EXTENSION POINTS for the
 * orchestrator (server-agent stage).
 *
 * - `SessionRuntimeRegistry` maps sessionId → live sandbox handle and processes for
 *   sessions provisioned by THIS process. After a restart, entries are rebuilt
 *   lazily via `SandboxProvider.connect(session.sandboxId)` (`getOrConnectRuntime`).
 * - `SessionHookRegistry` lets the orchestrator react to lifecycle transitions:
 *   `onSessionReady` (sandbox healthy → start the runner), `onSessionStopping`
 *   (before the sandbox is killed → shut the runner down, flush events) and
 *   `isBusy` (agent mid-turn → never idle-pause).
 */
import type { Project, Session } from '@prisma/client';
import {
  RUNNER_MOCK_ENV,
  RUNNER_STATE_DIR_ENV,
  type AgentState,
  type RunnerConfig,
} from '@loose/shared';
import type { BackgroundProcess, SandboxHandle } from '../lib/sandbox';

export interface SessionRuntime {
  sessionId: string;
  sandbox: SandboxHandle;
  /** Long-running app processes started from the project's startup commands. */
  appProcesses: BackgroundProcess[];
  /** The runner process, set by the orchestrator once started. */
  runner?: BackgroundProcess;
  /** Free-form per-session state owned by extensions (orchestrator, WS gateway). */
  extensions: Map<string, unknown>;
}

export class SessionRuntimeRegistry {
  readonly #map = new Map<string, SessionRuntime>();

  get(sessionId: string): SessionRuntime | undefined {
    return this.#map.get(sessionId);
  }
  set(runtime: SessionRuntime): void {
    this.#map.set(runtime.sessionId, runtime);
  }
  delete(sessionId: string): void {
    this.#map.delete(sessionId);
  }
  list(): SessionRuntime[] {
    return [...this.#map.values()];
  }
}

/** How to launch the runner inside the sandbox (no secrets: the orchestrator adds ANTHROPIC_API_KEY). */
export interface RunnerLaunch {
  command: string;
  cwd: string;
  envs: Record<string, string>;
  configPath: string;
}

export function runnerLaunchFor(sandbox: SandboxHandle, mock: boolean): RunnerLaunch {
  return {
    command: `node ${sandbox.paths.runnerEntry}`,
    cwd: sandbox.paths.workspace,
    envs: {
      [RUNNER_STATE_DIR_ENV]: sandbox.paths.state,
      ...(mock ? { [RUNNER_MOCK_ENV]: '1' } : {}),
    },
    configPath: `${sandbox.paths.state}/config.json`,
  };
}

export type StopReason =
  'idle' | 'timeout' | 'stopped' | 'budget' | 'error' | 'lost' | 'completed' | 'recover';

export interface SessionReadyContext {
  session: Session;
  project: Project;
  runtime: SessionRuntime;
  /** Exactly what was written to `$LOOSE_STATE_DIR/config.json`. */
  runnerConfig: RunnerConfig;
  runnerLaunch: RunnerLaunch;
  /** True when the workspace was restored from a WIP ref (Recover). */
  recovered: boolean;
}

export interface SessionLifecycleHooks {
  /**
   * Sandbox is healthy and the session is RUNNING. Throwing an AppError marks the
   * session ERRORED with that code (WIP preserved).
   */
  onSessionReady?(c: SessionReadyContext): Promise<void>;
  /** Called before the sandbox is killed (pause, timeout, stop, error, lost). */
  onSessionStopping?(
    sessionId: string,
    reason: StopReason,
    runtime?: SessionRuntime,
  ): Promise<void>;
  /** True while the agent is mid-turn (prevents idle pause). */
  isBusy?(sessionId: string): boolean;
  /** Live agent state for `SessionDto.agentState` (RUNNING sessions). */
  agentState?(sessionId: string): AgentState | undefined;
}

export class SessionHookRegistry {
  readonly #hooks: SessionLifecycleHooks[] = [];

  register(h: SessionLifecycleHooks): () => void {
    this.#hooks.push(h);
    return () => {
      const i = this.#hooks.indexOf(h);
      if (i >= 0) this.#hooks.splice(i, 1);
    };
  }

  async ready(c: SessionReadyContext): Promise<void> {
    for (const h of this.#hooks) await h.onSessionReady?.(c);
  }

  /** Never throws: stopping must proceed even if a hook fails. */
  async stopping(
    sessionId: string,
    reason: StopReason,
    runtime: SessionRuntime | undefined,
    onError: (err: unknown) => void,
  ): Promise<void> {
    for (const h of this.#hooks) {
      try {
        await h.onSessionStopping?.(sessionId, reason, runtime);
      } catch (err) {
        onError(err);
      }
    }
  }

  isBusy(sessionId: string): boolean {
    return this.#hooks.some((h) => h.isBusy?.(sessionId) === true);
  }

  agentState(sessionId: string): AgentState | undefined {
    for (const h of this.#hooks) {
      const s = h.agentState?.(sessionId);
      if (s) return s;
    }
    return undefined;
  }
}
