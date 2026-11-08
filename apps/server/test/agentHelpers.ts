/**
 * Agent/orchestrator test helpers: a scriptable fake runner process (speaks the real
 * NDJSON protocol over the FakeSandbox background process) and a fake git working tree
 * answering the git commands the orchestrator / delivery services run.
 */
import { getResponse, type RequestHandler } from 'msw';
import { expect } from 'vitest';
import {
  makeRunnerEvent,
  parseRunnerCommandLine,
  type RunnerCommand,
  type RunnerEventDataInput,
  type RunnerEventType,
} from '@loose/shared';
import type { AppContext } from '../src/context';
import type { FakeProcess, FakeSandbox, FakeSandboxProvider } from '../src/lib/sandbox';
import { fakeSandbox } from './sessionHelpers';

export class FakeRunner {
  seq = 0;
  readonly commands: RunnerCommand[] = [];

  constructor(readonly proc: FakeProcess) {}

  emit<T extends RunnerEventType>(type: T, data: RunnerEventDataInput<T>) {
    const ev = makeRunnerEvent(type, data, ++this.seq);
    this.proc.emitStdout(`${JSON.stringify(ev)}\n`);
  }

  raw(text: string) {
    this.proc.emitStdout(text);
  }

  of<T extends RunnerCommand['type']>(type: T): Extract<RunnerCommand, { type: T }>[] {
    return this.commands.filter((c): c is Extract<RunnerCommand, { type: T }> => c.type === type);
  }
}

export type RunnerScript = (cmd: RunnerCommand, r: FakeRunner) => void | Promise<void>;

/** Every runner started in a fake sandbox becomes a FakeRunner driven by `script`. */
export function installFakeRunner(
  provider: FakeSandboxProvider,
  script: { current: RunnerScript },
) {
  const runners: FakeRunner[] = [];
  provider.onBackground('/sandbox-agent/runner/dist/cli.js', (proc) => {
    const r = new FakeRunner(proc);
    runners.push(r);
    proc.onStdin = (data) => {
      for (const line of data.split('\n')) {
        if (!line.trim()) continue;
        const parsed = parseRunnerCommandLine(line);
        if (!parsed.ok) continue;
        r.commands.push(parsed.command);
        if (parsed.command.type === 'shutdown') {
          queueMicrotask(() => proc.exit(0));
          continue;
        }
        void script.current(parsed.command, r);
      }
    };
    queueMicrotask(() => r.emit('ready', { runnerVersion: 'test', mock: true }));
  });
  return runners;
}

export interface TurnSpec {
  text?: string;
  deltas?: string[];
  tools?: { name: string; input: Record<string, unknown>; isError?: boolean; output?: string }[];
  files?: string[];
  usage?: { in?: number; out?: number; costUsd?: number; model?: string };
  stopReason?: string;
  beforeComplete?: (r: FakeRunner) => void;
  /** Conversation anchor reported by turn_complete. */
  anchor?: string;
  /** Plan-mode turn: emits plan_proposed with this Markdown. */
  plan?: string;
}

/** Emit a realistic turn for a user_message. */
export function playTurn(r: FakeRunner, spec: TurnSpec = {}) {
  if (r.of('user_message').length === 1) {
    r.emit('session_init', { agentSessionId: 'agent-sess-1', model: 'claude-sonnet-4-5' });
  }
  const mid = `m${r.seq}`;
  for (const d of spec.deltas ?? [spec.text ?? 'Done.']) {
    r.emit('assistant_text_delta', { messageId: mid, text: d });
  }
  let n = 0;
  for (const t of spec.tools ?? []) {
    const id = `tool_${r.seq}_${(n += 1)}`;
    r.emit('tool_use', { id, name: t.name, input: t.input });
    r.emit('tool_result', {
      id,
      isError: t.isError ?? false,
      summary: t.isError ? 'failed' : 'ok',
      ...(t.output ? { output: t.output } : {}),
    });
  }
  r.emit('assistant_text', {
    messageId: mid,
    text: spec.text ?? (spec.deltas ?? ['Done.']).join(''),
  });
  const u = spec.usage ?? {};
  r.emit('usage', {
    in: u.in ?? 1200,
    out: u.out ?? 340,
    cacheRead: 9000,
    costUsd: u.costUsd ?? 0.0123,
    model: u.model ?? 'claude-sonnet-4-5',
  });
  if (spec.plan) r.emit('plan_proposed', { id: `plan_${r.seq}`, plan: spec.plan });
  spec.beforeComplete?.(r);
  r.emit('turn_complete', {
    filesChanged: spec.files ?? [],
    stopReason: spec.stopReason ?? 'end_turn',
    ...(spec.anchor ? { conversationAnchor: spec.anchor } : {}),
  });
}

// ---- fake git working tree ---------------------------------------------------------------

interface FakeFile {
  code: string;
  added: string[];
}

function patchFor(path: string, f: FakeFile): string {
  const isNew = f.code === '??' || f.code.startsWith('A');
  const isDel = f.code.includes('D');
  const lines = [`diff --git a/${path} b/${path}`];
  if (isNew) lines.push('new file mode 100644', '--- /dev/null', `+++ b/${path}`);
  else if (isDel) lines.push('deleted file mode 100644', `--- a/${path}`, '+++ /dev/null');
  else lines.push(`--- a/${path}`, `+++ b/${path}`);
  lines.push(`@@ -1,1 +1,${f.added.length} @@`);
  if (!isNew) lines.push('-old line');
  for (const a of isDel ? [] : f.added) lines.push(`+${a}`);
  return lines.join('\n');
}

export class FakeGit {
  readonly files = new Map<string, FakeFile>();
  readonly committed = new Map<string, FakeFile>();
  pushExit = 0;
  pushStderr = '';
  remoteRefs = new Set<string>();
  sha = 'a'.repeat(40);

  set(path: string, code = ' M', added: string[] = ['new line']) {
    this.files.set(path, { code, added });
    return this;
  }

  clear() {
    this.files.clear();
    this.committed.clear();
  }

  porcelain(): string {
    return [...this.files.entries()].map(([p, f]) => `${f.code} ${p}\0`).join('');
  }

  diff(includeCommitted: boolean): string {
    const all = new Map([...(includeCommitted ? this.committed : []), ...this.files]);
    return [...all.entries()].map(([p, f]) => patchFor(p, f)).join('\n');
  }

  install(provider: FakeSandboxProvider) {
    provider
      .onCommand('status --porcelain=v1 -z', () => ({ stdout: this.porcelain() }))
      .onCommand(
        (c) => c.includes(' diff ') && c.includes('ls-files --others'),
        (c) => ({ stdout: this.diff(!c.includes("diff 'HEAD'")) }),
      )
      .onCommand('rev-parse --verify -q', () => ({ exitCode: 0 }))
      .onCommand('rev-list --count', () => ({ stdout: `${this.committed.size ? 1 : 0}\n` }))
      .onCommand('rev-parse HEAD', () => ({ stdout: `${this.sha}\n` }))
      .onCommand(
        (c) => /rm -rf -- '|checkout -q HEAD -- '/.test(c) && !c.includes('commit-tree'),
        (c) => {
          for (const m of c.matchAll(/(?:rm -rf|checkout -q HEAD) -- '([^']+)'/g))
            this.files.delete(m[1]!);
          return {};
        },
      )
      .onCommand('git add -A && git commit', () => {
        for (const [p, f] of this.files) this.committed.set(p, f);
        this.files.clear();
        this.sha = 'b'.repeat(40);
        return {};
      })
      .onCommand(
        (c) => c.startsWith('git push -q origin') && !c.includes('--delete'),
        () => ({ exitCode: this.pushExit, stderr: this.pushStderr }),
      )
      .onCommand('git ls-remote --exit-code origin', (c) => {
        const ref = /origin '([^']+)'/.exec(c)?.[1] ?? '';
        return { exitCode: this.remoteRefs.has(ref) ? 0 : 2 };
      });
    return this;
  }
}

// ---- misc --------------------------------------------------------------------------------

export async function waitFor<T>(
  fn: () => Promise<T | undefined | null | false> | T | undefined | null | false,
  { timeoutMs = 5000, intervalMs = 10, label = 'condition' } = {},
): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${label}`);
    await new Promise((r) => setTimeout(r, intervalMs));
  }
}

export function lastSandbox(ctx: AppContext): FakeSandbox {
  const s = fakeSandbox(ctx).last();
  expect(s).toBeDefined();
  return s!;
}

export async function busEvents(ctx: AppContext, sessionId: string) {
  return (await ctx.sessionEvents.replay(sessionId, 0)).entries;
}

/**
 * A `fetch` answered by MSW request handlers without patching Node's http stack
 * (keeps WebSocket upgrades and local HTTP untouched). Unhandled requests fail loudly.
 * `AbortSignal`s are honoured so timeouts can be exercised.
 */
export function mswFetch(
  handlers: { current: RequestHandler[] },
  calls: Request[] = [],
): typeof fetch {
  return async (input, init) => {
    const req = new Request(input as string | URL | Request, init);
    calls.push(req.clone());
    const pending = getResponse(handlers.current, req);
    const res = req.signal ? await Promise.race([pending, aborted(req.signal)]) : await pending;
    if (!res)
      throw new Error(
        `unhandled outbound request ${req.method} ${new URL(req.url).origin}${new URL(req.url).pathname}`,
      );
    return res;
  };
}

/** Rejects with the signal's reason (a `TimeoutError`/`AbortError` DOMException). */
function aborted(signal: AbortSignal): Promise<never> {
  return new Promise((_resolve, reject) => {
    if (signal.aborted) {
      reject(signal.reason as Error);
      return;
    }
    signal.addEventListener('abort', () => reject(signal.reason as Error), { once: true });
  });
}
