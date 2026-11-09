/**
 * Error-code quality gate as a test (Phase 10 §7.4, W4): wraps `scripts/error-code-gate.ts` so
 * the gap list participates in the normal `vitest run` and fails CI the same way any other
 * regression would, independent of a separate CI step invoking the script directly.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { ERROR_CODE_LIST, ERROR_CODES } from '@loose/shared';
import { runGate, RESERVED_ERROR_CODES } from '../scripts/error-code-gate';

describe('error-code quality gate', () => {
  it('every reserved code is still a real catalog entry', () => {
    const result = runGate();
    for (const code of Object.keys(RESERVED_ERROR_CODES)) {
      expect(result.reserved).toContain(code);
    }
  });

  it('has an asserting trigger-path test for every non-reserved catalog code', () => {
    const result = runGate();
    expect(result.uncovered).toEqual([]);
    expect(result.reserved.sort()).toEqual(Object.keys(RESERVED_ERROR_CODES).sort());
    expect(result.covered).toHaveLength(result.totalCodes - result.reserved.length);
  });

  it('covers at least 85% of the catalog with a literal, asserted test reference', () => {
    const result = runGate();
    const ratio = result.covered.length / (result.totalCodes - result.reserved.length);
    expect(ratio).toBe(1);
  });

  it('reserved codes have no trigger site in server source', () => {
    const reserved = ERROR_CODE_LIST.filter((code) => ERROR_CODES[code].reserved);
    expect(reserved.length).toBeGreaterThan(0);
    const serverRoot = fileURLToPath(new URL('../src/', import.meta.url));
    const source: string[] = [];
    const collect = (dir: string) => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const path = join(dir, entry.name);
        if (entry.isDirectory()) collect(path);
        else if (entry.name.endsWith('.ts')) source.push(readFileSync(path, 'utf8'));
      }
    };
    collect(serverRoot);
    const serverSource = source.join('\n');
    for (const code of reserved) expect(serverSource, code).not.toContain(code);
  });
});
