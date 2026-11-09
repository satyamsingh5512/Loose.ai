/**
 * Minimal recursive test-file finder for `error-code-gate.ts` — avoids adding a glob dependency
 * (BRIEF.md hard rule 4: prefer node builtins). Not a real glob engine: it only understands the
 * small set of patterns `error-code-gate.ts` actually uses (`dir/**\/*.test.ts` /
 * `dir/**\/*.test.tsx`), by walking the directory tree under the pattern's static prefix and
 * filtering on the file-name suffix.
 */
import { readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const SKIP_DIRS = new Set(['node_modules', 'dist', '.git', 'build', 'out', '.turbo']);

function walk(dir: string, suffix: string, out: string[]): void {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      walk(full, suffix, out);
    } else if (st.isFile() && entry.endsWith(suffix)) {
      out.push(full);
    }
  }
}

/**
 * Resolve a list of `<staticPrefix>/**\/*<suffix>` glob patterns (relative to `repoRoot`) into
 * absolute file paths. Patterns that don't match this exact shape throw — this is intentionally
 * narrow, not a general glob implementation.
 */
export default function findTestFiles(patterns: string[], repoRoot: string): string[] {
  const out: string[] = [];
  for (const pattern of patterns) {
    const starIdx = pattern.indexOf('**');
    if (starIdx === -1)
      throw new Error(`phase10.gateGlob: unsupported pattern "${pattern}" (expected "**")`);
    const prefix = pattern.slice(0, starIdx).replace(/\/+$/, '');
    const rest = pattern.slice(starIdx + 2); // '/*.test.ts' or similar
    const suffixMatch = /\/\*(\.[\w.]+)$/.exec(rest);
    if (!suffixMatch)
      throw new Error(`phase10.gateGlob: unsupported pattern "${pattern}" (expected "**/*.ext")`);
    const suffix = suffixMatch[1]!;
    walk(join(repoRoot, prefix), suffix, out);
  }
  return [...new Set(out)].sort();
}
