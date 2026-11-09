/**
 * Creates the `loose_test` database if needed and applies migrations to it.
 * Never touches the dev database beyond a read of pg_database.
 */
import { execFileSync } from 'node:child_process';
import { readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PrismaClient } from '@prisma/client';

const here = dirname(fileURLToPath(import.meta.url));
const serverDir = resolve(here, '..');

export default async function setup() {
  const testUrl =
    process.env.TEST_DATABASE_URL ?? 'postgresql://loose:loose@127.0.0.1:5432/loose_test';
  const url = new URL(testUrl);
  const dbName = url.pathname.replace(/^\//, '');
  if (!/^[a-z0-9_]+$/.test(dbName) || !dbName.includes('test')) {
    throw new Error(`Refusing to use "${dbName}" as a test database (name must contain "test")`);
  }
  const adminUrl = new URL(testUrl);
  adminUrl.pathname = '/postgres';
  const admin = new PrismaClient({ datasources: { db: { url: adminUrl.toString() } } });
  try {
    const rows = await admin.$queryRaw<{ exists: boolean }[]>`
      SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = ${dbName}) AS "exists"`;
    if (!rows[0]?.exists) await admin.$executeRawUnsafe(`CREATE DATABASE "${dbName}"`);
  } finally {
    await admin.$disconnect();
  }
  execFileSync(resolve(serverDir, 'node_modules/.bin/prisma'), ['migrate', 'deploy'], {
    cwd: serverDir,
    env: { ...process.env, DATABASE_URL: testUrl },
    stdio: 'pipe',
  });
  return teardown;
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === 'EPERM';
  }
}

/** Remove per-worker artifact dirs (`TEST_ARTIFACT_DIR`) whose worker process has exited. */
function teardown() {
  for (const name of readdirSync(tmpdir())) {
    const m = /^loose-test-artifacts-(\d+)$/.exec(name);
    if (m && !pidAlive(Number(m[1])))
      rmSync(join(tmpdir(), name), { recursive: true, force: true });
  }
}
