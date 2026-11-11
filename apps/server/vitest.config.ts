import { defineConfig } from 'vitest/config';

const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? 'postgresql://loose:loose@127.0.0.1:5432/loose_test';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    globalSetup: ['test/globalSetup.ts'],
    // Files share one test database and truncate it, so they run one at a time.
    fileParallelism: false,
    pool: 'forks',
    maxWorkers: 2, // Vitest 4: replaces poolOptions.forks.maxForks
    testTimeout: 20_000,
    hookTimeout: 60_000,
    env: { NODE_ENV: 'test', TEST_DATABASE_URL },
  },
});
