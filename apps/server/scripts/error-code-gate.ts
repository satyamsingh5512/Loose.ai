#!/usr/bin/env tsx
/**
 * Error-code quality gate (Phase 10 §7.4, W4): every code in the shared error catalog must be
 * exercised by at least one test that both (a) references the code literally and (b) asserts
 * against it (not just mentions it in a comment or string template).
 *
 * Usage:
 *   bunx tsx apps/server/scripts/error-code-gate.ts          # human-readable report, exit 1 on gaps
 *   bunx tsx apps/server/scripts/error-code-gate.ts --json    # machine-readable report on stdout
 *
 * Also used by `test/phase10.error-gate.test.ts` (imported as a library, not spawned) so the gap
 * list participates in the normal test run.
 *
 * Scanned test roots (every one that exists on disk is scanned; a repo without a package simply
 * contributes no files):
 *   apps/server/test/**\/*.test.ts
 *   packages/shared/src/**\/*.test.ts
 *   apps/web/src/**\/*.test.ts(x)
 *   packages/runner/src/**\/*.test.ts
 *
 * A code counts as covered when a scanned file contains the literal code string AND, within
 * {@link ASSERTION_WINDOW} characters of an occurrence, one of {@link ASSERTION_PATTERNS}
 * matches (so `// LSE-FOO-001 is handled elsewhere` does not count, but
 * `expectError(res, 'LSE-FOO-001', 404)` or `expect(err.code).toBe('LSE-FOO-001')` does).
 */
import { readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import findTestFiles from '../test/phase10.gateGlob';
import { ERROR_CODE_LIST, ERROR_CODES, type ErrorCode } from '@loose/shared';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const REPO_ROOT = join(__dirname, '..', '..', '..');

/**
 * Catalog-declared reservations are capabilities intentionally absent from v1. They are reported
 * separately and are checked by the shared catalog invariant, rather than counted as missing
 * trigger paths.
 */
export const RESERVED_ERROR_CODES: Record<string, string> = Object.fromEntries(
  ERROR_CODE_LIST.flatMap((code) => {
    const definition = ERROR_CODES[code];
    return definition.reserved && definition.reservedReason
      ? [[code, definition.reservedReason]]
      : [];
  }),
);

const TEST_GLOBS = [
  'apps/server/test/**/*.test.ts',
  'packages/shared/src/**/*.test.ts',
  'apps/web/src/**/*.test.ts',
  'apps/web/src/**/*.test.tsx',
  'packages/runner/src/**/*.test.ts',
  'packages/runner/test/**/*.test.ts',
];

/** Window (characters) around a code occurrence searched for an adjacent assertion form. */
const ASSERTION_WINDOW = 120;

/**
 * This codebase has two legitimate shapes for asserting an error code, and both must count:
 *
 * 1. Adjacent: the literal sits right next to the assertion call, e.g.
 *    `expectError(res, 'LSE-FOO-001', 404)`, `.toBe('LSE-FOO-001')`, `code: 'LSE-FOO-001'`.
 * 2. Table-driven: the literal is one column of an `it.each([...])` row or a loop-consumed
 *    tuple array (`const failures: [string, ...][] = [['LSE-FOO-001', ...], ...]`), destructured
 *    into a variable (conventionally `code`) that is asserted *elsewhere* in the same `it`/loop
 *    body via `expectError(res, code, ...)`, `errorCode: code`, `.code).toBe(code)`, etc. The
 *    literal and the assertion are not textually adjacent, so this requires file-level evidence:
 *    the file both contains the code as a bare array/tuple element AND uses one of the known
 *    "assert the loop variable" idioms somewhere (not necessarily near the literal).
 */
const ADJACENT_BEFORE_FORMS = [
  /expectError\s*\(\s*[\w.]+\s*,\s*['"]?$/i,
  /\.(?:toBe|toEqual|toContain|toMatch)\s*\(\s*$/i,
  /code['"]?\s*[:=]=?=?\s*$/i, // `code:`, `errorCode:`, `.code ===`, `.code ==`, `.code =`
  /x-loose-error-code['"]?\]\s*\)\.toBe\s*\(\s*$/i,
  /codeOf\s*\([^)]*\)\s*===\s*$/i, // `codeOf(m) === 'CODE'` WS filter idiom
];
const ADJACENT_AFTER_FORMS = [/^['"]?\s*\)/];
const ADJACENT_CONTEXT_RE =
  /\b(expect|toBe|toEqual|toContain|describe\.each|it\.each|ERROR_CODES|getErrorDefinition)\b/;

/** A bare array/tuple element: `'CODE'` preceded by `[` or `,` and (eventually) followed by `,` or `]`. */
const TABLE_ELEMENT_BEFORE_RE = /[[,]\s*$/;
const TABLE_ELEMENT_AFTER_RE = /^\s*[,\]]/;

/** File-level idioms proving a table's destructured error-code column is actually asserted. */
const TABLE_ASSERTION_IDIOMS = [
  /expectError\s*\(/,
  /errorCode\s*:\s*code\b/,
  /\.code\s*\)\.toBe\s*\(\s*code\b/,
  /errorCode\s*\)\.toBe\s*\(\s*code\b/,
  /\btoBe\s*\(\s*code\s*\)/,
];

/**
 * Embedded-in-string form: the code appears as a substring of a *longer* quoted string (e.g.
 * `'http://localhost:5173/auth/callback/google?error=LSE-AUTH-005'`,
 * `` `${BASE}?error=LSE-AUTH-004` ``) that itself sits inside a known assertion call
 * (`toBe(`, `toContain(`, `.toEqual(`, `expect(...).toMatch(`). Found independently of the
 * exact-quoted-literal scan above, by locating the bare code substring and then checking whether
 * it is enclosed in a string literal that is itself an argument to one of those calls.
 */
const EMBEDDED_ASSERTION_CALL_RE = /\.(?:toBe|toEqual|toContain|toMatch)\s*\(\s*[`'"][^`'"]*$/i;

function hasEmbeddedAssertion(text: string, codeIndex: number): boolean {
  // Walk back to the start of the enclosing string literal (same quote char, no escape).
  let i = codeIndex - 1;
  while (i >= 0 && !'`\'"'.includes(text[i]!)) i -= 1;
  if (i < 0) return false;
  const before = text.slice(Math.max(0, i - ASSERTION_WINDOW), i + 1);
  return EMBEDDED_ASSERTION_CALL_RE.test(before);
}

interface FileHit {
  file: string;
  line: number;
  snippet: string;
}

export interface GateResult {
  totalCodes: number;
  covered: ErrorCode[];
  reserved: ErrorCode[];
  uncovered: ErrorCode[];
  hits: Record<string, FileHit[]>;
}

/**
 * `quoteIndex` = index of the opening quote char; `innerLength` = length of the code string
 * itself (without quotes). `before` ends exactly at the opening quote (exclusive) and `after`
 * starts exactly at the closing quote (exclusive) — neither window includes a quote character,
 * so `\(\s*$` / `^\s*\)` forms match cleanly against `expectError(res, 'CODE', ...)`-shaped code.
 */
function hasAdjacentAssertion(text: string, quoteIndex: number, innerLength: number): boolean {
  const start = Math.max(0, quoteIndex - ASSERTION_WINDOW);
  const closingQuoteIndex = quoteIndex + 1 + innerLength;
  const end = Math.min(text.length, closingQuoteIndex + 1 + ASSERTION_WINDOW);
  const before = text.slice(start, quoteIndex);
  const after = text.slice(closingQuoteIndex + 1, end);

  if (ADJACENT_BEFORE_FORMS.some((re) => re.test(before))) return true;
  if (
    ADJACENT_AFTER_FORMS.some((re) => re.test(after)) &&
    ADJACENT_CONTEXT_RE.test(before + after)
  ) {
    return true;
  }
  return false;
}

/** Is this occurrence a bare element of an array/tuple literal (`it.each` row or loop table)? */
function isTableElement(text: string, quoteIndex: number, totalMatchLength: number): boolean {
  const beforeWindow = text.slice(Math.max(0, quoteIndex - 10), quoteIndex);
  const afterWindow = text.slice(
    quoteIndex + totalMatchLength,
    Math.min(text.length, quoteIndex + totalMatchLength + 10),
  );
  return TABLE_ELEMENT_BEFORE_RE.test(beforeWindow) && TABLE_ELEMENT_AFTER_RE.test(afterWindow);
}

export function runGate(repoRoot: string = REPO_ROOT): GateResult {
  const files = findTestFiles(TEST_GLOBS, repoRoot);
  const hits: Record<string, FileHit[]> = {};
  for (const code of ERROR_CODE_LIST) hits[code] = [];

  for (const absPath of files) {
    let text: string;
    try {
      text = readFileSync(absPath, 'utf8');
    } catch {
      continue;
    }
    if (!text.includes('LSE-')) continue;
    const relPath = relative(repoRoot, absPath);
    const fileHasTableAssertionIdiom = TABLE_ASSERTION_IDIOMS.some((re) => re.test(text));

    for (const code of ERROR_CODE_LIST) {
      const quoted = [`'${code}'`, `"${code}"`, `\`${code}\``];
      let searchFrom = 0;
      for (;;) {
        let found = -1;
        let matchLen = 0;
        for (const q of quoted) {
          const idx = text.indexOf(q, searchFrom);
          if (idx !== -1 && (found === -1 || idx < found)) {
            found = idx;
            matchLen = q.length;
          }
        }
        if (found === -1) break;
        const matched =
          hasAdjacentAssertion(text, found, code.length) ||
          (fileHasTableAssertionIdiom && isTableElement(text, found, matchLen));
        if (matched) {
          const line = text.slice(0, found).split('\n').length;
          hits[code]!.push({
            file: relPath,
            line,
            snippet: text
              .slice(Math.max(0, found - 20), found + matchLen + 20)
              .replace(/\s+/g, ' '),
          });
        }
        searchFrom = found + matchLen;
      }

      // Second pass: bare (unquoted-boundary) occurrences, for the embedded-in-longer-string
      // assertion form (e.g. a full callback URL containing `?error=LSE-AUTH-005`).
      let bareFrom = 0;
      for (;;) {
        const bareIdx = text.indexOf(code, bareFrom);
        if (bareIdx === -1) break;
        bareFrom = bareIdx + code.length;
        // Skip exact-quoted occurrences already handled above (quote immediately surrounds it).
        const charBefore = text[bareIdx - 1];
        const charAfter = text[bareIdx + code.length];
        const exactlyQuoted =
          charBefore !== undefined &&
          charAfter !== undefined &&
          '`\'"'.includes(charBefore) &&
          charBefore === charAfter;
        if (exactlyQuoted) continue;
        if (hasEmbeddedAssertion(text, bareIdx)) {
          const line = text.slice(0, bareIdx).split('\n').length;
          hits[code]!.push({
            file: relPath,
            line,
            snippet: text
              .slice(Math.max(0, bareIdx - 30), bareIdx + code.length + 10)
              .replace(/\s+/g, ' '),
          });
        }
      }
    }
  }

  const covered: ErrorCode[] = [];
  const uncovered: ErrorCode[] = [];
  const reserved: ErrorCode[] = [];
  for (const code of ERROR_CODE_LIST) {
    const isReserved = Object.prototype.hasOwnProperty.call(RESERVED_ERROR_CODES, code);
    if (isReserved) {
      reserved.push(code);
      continue;
    }
    if (hits[code]!.length > 0) covered.push(code);
    else uncovered.push(code);
  }

  return { totalCodes: ERROR_CODE_LIST.length, covered, reserved, uncovered, hits };
}

function main(): void {
  const result = runGate();
  const asJson = process.argv.includes('--json');
  if (asJson) {
    process.stdout.write(
      JSON.stringify(
        {
          totalCodes: result.totalCodes,
          coveredCount: result.covered.length,
          uncoveredCount: result.uncovered.length,
          uncovered: result.uncovered,
          reserved: result.reserved,
        },
        null,
        2,
      ) + '\n',
    );
  } else {
    console.log(
      `error-code gate: ${result.covered.length}/${result.totalCodes - result.reserved.length} non-reserved codes covered`,
    );
    if (result.reserved.length) {
      console.log(
        `reserved (no trigger path required, catalog test still counts): ${result.reserved.join(', ')}`,
      );
    }
    if (result.uncovered.length) {
      console.log(`\nUNCOVERED (${result.uncovered.length}):`);
      for (const code of result.uncovered) console.log(`  - ${code}`);
    } else {
      console.log('\nAll catalog codes have at least one asserting test reference.');
    }
  }
  if (result.uncovered.length > 0) process.exitCode = 1;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
