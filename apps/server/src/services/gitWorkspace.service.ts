/**
 * Git inspection helpers run inside the session sandbox (post-turn validation, diff view,
 * delivery). All paths are repo-relative POSIX paths; every path that reaches a shell is
 * single-quoted with `shq`.
 */
import { MAX_DIFF_PATCH_BYTES, type DiffFile, type DiffFileStatus } from '@loose/shared';
import type { SandboxHandle } from '../lib/sandbox';
import { shq } from './gitAccess.service';

export interface StatusEntry {
  /** Two-letter porcelain code (`??` untracked, ` M`, `A `, `D `, `R `…). */
  code: string;
  path: string;
  /** Rename/copy source. */
  origPath?: string;
}

const GIT = 'git -c core.quotePath=false';

/** `git status --porcelain=v1 -z` (untracked files listed individually). */
export async function gitStatus(sandbox: SandboxHandle): Promise<StatusEntry[]> {
  const r = await sandbox.run(`${GIT} status --porcelain=v1 -z --untracked-files=all`, {
    cwd: sandbox.paths.workspace,
    timeoutMs: 60_000,
  });
  if (r.exitCode !== 0) throw new Error(`git status failed (exit ${r.exitCode})`);
  return parsePorcelainZ(r.stdout);
}

export function parsePorcelainZ(out: string): StatusEntry[] {
  const parts = out.split('\0');
  const entries: StatusEntry[] = [];
  for (let i = 0; i < parts.length; i += 1) {
    const p = parts[i]!;
    if (p.length < 4) continue;
    const code = p.slice(0, 2);
    const path = p.slice(3);
    if (code[0] === 'R' || code[0] === 'C') {
      entries.push({ code, path, origPath: parts[i + 1] ?? '' });
      i += 1;
    } else {
      entries.push({ code, path });
    }
  }
  return entries;
}

export function statusKind(e: StatusEntry): DiffFileStatus {
  if (e.code === '??' || e.code[0] === 'A') return 'added';
  if (e.code.includes('D')) return 'deleted';
  if (e.code[0] === 'R') return 'renamed';
  return 'modified';
}

/**
 * Unified diff of the working tree vs `base` (default HEAD), including untracked files
 * (as additions).
 * The generated `.env` is excluded via `.git/info/exclude`.
 */
export async function workingDiff(sandbox: SandboxHandle, base = 'HEAD'): Promise<string> {
  const script = [
    `${GIT} diff ${shq(base)} --no-color --no-ext-diff -M -- .`,
    `${GIT} ls-files --others --exclude-standard -z | while IFS= read -r -d '' f; do ${GIT} diff --no-color --no-ext-diff --no-index -- /dev/null "$f"; done`,
    'true',
  ].join('\n');
  const r = await sandbox.run(script, { cwd: sandbox.paths.workspace, timeoutMs: 120_000 });
  return r.stdout;
}

function unquote(p: string): string {
  const t = p.trim();
  if (t.startsWith('"') && t.endsWith('"')) {
    try {
      return JSON.parse(t) as string;
    } catch {
      return t.slice(1, -1);
    }
  }
  return t;
}

function stripPrefix(p: string): string {
  return p.replace(/^[ab]\//, '');
}

/** Parse `git diff` output into per-file entries (patch text kept per file). */
export function parseUnifiedDiff(text: string): DiffFile[] {
  if (!text.trim()) return [];
  const chunks = text.split(/^(?=diff --git )/m).filter((c) => c.startsWith('diff --git '));
  const files: DiffFile[] = [];
  for (const chunk of chunks) {
    const lines = chunk.split('\n');
    let oldPath: string | undefined;
    let newPath: string | undefined;
    let status: DiffFileStatus = 'modified';
    let binary = false;
    let additions = 0;
    let deletions = 0;
    let inHunk = false;
    for (const line of lines) {
      if (!inHunk) {
        if (line.startsWith('--- ')) {
          const p = unquote(line.slice(4));
          if (p === '/dev/null') status = 'added';
          else oldPath = stripPrefix(p);
        } else if (line.startsWith('+++ ')) {
          const p = unquote(line.slice(4));
          if (p === '/dev/null') status = 'deleted';
          else newPath = stripPrefix(p);
        } else if (line.startsWith('new file mode')) status = 'added';
        else if (line.startsWith('deleted file mode')) status = 'deleted';
        else if (line.startsWith('rename from ')) {
          status = 'renamed';
          oldPath = unquote(line.slice('rename from '.length));
        } else if (line.startsWith('rename to '))
          newPath = unquote(line.slice('rename to '.length));
        else if (line.startsWith('Binary files ')) {
          binary = true;
          const m = / and (?:"?b\/)?(.+?)"? differ$/.exec(line);
          if (m && m[1] !== '/dev/null') newPath ??= m[1];
          if (/^Binary files \/dev\/null /.test(line)) status = 'added';
        }
      }
      if (line.startsWith('@@')) {
        inHunk = true;
        continue;
      }
      if (inHunk) {
        if (line.startsWith('+')) additions += 1;
        else if (line.startsWith('-')) deletions += 1;
      }
    }
    if (!newPath && !oldPath) {
      const m = /^diff --git (?:"?a\/)(.+?)"? (?:"?b\/)(.+?)"?$/.exec(lines[0] ?? '');
      newPath = m?.[2];
    }
    const path = status === 'deleted' ? (oldPath ?? newPath) : (newPath ?? oldPath);
    if (!path) continue;
    files.push({
      path,
      ...(status === 'renamed' && oldPath && oldPath !== path ? { oldPath } : {}),
      status,
      additions,
      deletions,
      patch: binary ? '' : chunk.replace(/\n$/, ''),
      ...(binary ? { binary: true } : {}),
    });
  }
  return files;
}

/** Keep the total patch size under the API cap (later patches are emptied). */
export function capDiff(
  files: DiffFile[],
  max = MAX_DIFF_PATCH_BYTES,
): { files: DiffFile[]; truncated: boolean } {
  let used = 0;
  let truncated = false;
  const out = files.map((f) => {
    if (used + f.patch.length <= max) {
      used += f.patch.length;
      return f;
    }
    truncated = true;
    return { ...f, patch: '' };
  });
  return { files: out, truncated };
}

/** Lines added by a file's patch (without the leading `+`). */
export function addedLines(patch: string): string[] {
  const out: string[] = [];
  let inHunk = false;
  for (const line of patch.split('\n')) {
    if (line.startsWith('@@')) inHunk = true;
    else if (inHunk && line.startsWith('+')) out.push(line.slice(1));
  }
  return out;
}

/**
 * Undo working-tree changes to `paths` (tracked files are restored from HEAD, new files
 * removed). Returns the paths that were reverted.
 */
export async function revertPaths(
  sandbox: SandboxHandle,
  entries: readonly StatusEntry[],
): Promise<string[]> {
  if (!entries.length) return [];
  const cmds: string[] = [];
  const reverted: string[] = [];
  for (const e of entries) {
    const p = shq(e.path);
    if (e.code === '??') cmds.push(`rm -rf -- ${p}`);
    else if (e.code[0] === 'A')
      cmds.push(`${GIT} rm -q --cached -f -- ${p} >/dev/null 2>&1; rm -rf -- ${p}`);
    else if (e.code[0] === 'R' && e.origPath) {
      cmds.push(`${GIT} rm -q --cached -f -- ${p} >/dev/null 2>&1; rm -rf -- ${p}`);
      cmds.push(`${GIT} checkout -q HEAD -- ${shq(e.origPath)}`);
    } else cmds.push(`${GIT} reset -q -- ${p} >/dev/null 2>&1; ${GIT} checkout -q HEAD -- ${p}`);
    reverted.push(e.path);
  }
  await sandbox.run(cmds.join('\n'), { cwd: sandbox.paths.workspace, timeoutMs: 60_000 });
  return reverted;
}

/** `origin/<branch>` when it exists in the clone, else HEAD (diff base for delivery). */
export async function baseRef(sandbox: SandboxHandle, defaultBranch: string): Promise<string> {
  const ref = `origin/${defaultBranch}`;
  const r = await sandbox.run(`${GIT} rev-parse --verify -q ${shq(`${ref}^{commit}`)}`, {
    cwd: sandbox.paths.workspace,
    timeoutMs: 30_000,
  });
  return r.exitCode === 0 ? ref : 'HEAD';
}

/** Number of commits on HEAD that are not on `base`. */
export async function commitsAhead(sandbox: SandboxHandle, base: string): Promise<number> {
  if (base === 'HEAD') return 0;
  const r = await sandbox.run(`${GIT} rev-list --count ${shq(`${base}..HEAD`)}`, {
    cwd: sandbox.paths.workspace,
    timeoutMs: 30_000,
  });
  return r.exitCode === 0 ? Number(r.stdout.trim()) || 0 : 0;
}

export async function headSha(sandbox: SandboxHandle): Promise<string | null> {
  const r = await sandbox.run(`${GIT} rev-parse HEAD`, {
    cwd: sandbox.paths.workspace,
    timeoutMs: 30_000,
  });
  const sha = r.stdout.trim();
  return r.exitCode === 0 && /^[0-9a-f]{40}$/.test(sha) ? sha : null;
}
