import { describe, expect, it } from 'vitest';
import { EnvError, isDevLoginEnabled, loadEnv } from '../src/config/env';
import { TEST_SECRETS } from './helpers';

const base = {
  DATABASE_URL: 'postgresql://x@localhost/db',
  REDIS_URL: 'redis://localhost:6379',
  SESSION_SECRET: TEST_SECRETS.SESSION_SECRET,
  LOCAL_KMS_MASTER_KEY: TEST_SECRETS.LOCAL_KMS_MASTER_KEY,
};

describe('env config', () => {
  it('applies defaults', () => {
    const env = loadEnv(base);
    expect(env.PORT).toBe(4000);
    expect(env.APP_URL).toBe('http://localhost:5173');
    expect(env.API_URL).toBe('http://localhost:4000');
    expect(env.KMS_PROVIDER).toBe('local');
    expect(env.DEV_LOGIN_ENABLED).toBe(false);
    expect(env.RATE_LIMIT_AUTH_MAX).toBe(20);
    expect(env.DEFAULT_MAX_BUDGET_USD).toBe(5);
    expect(env.GOOGLE_CLIENT_ID).toBeUndefined();
  });

  it('fails fast listing every bad variable without echoing values', () => {
    let err: unknown;
    try {
      loadEnv({ SESSION_SECRET: 'short-secret-value', LOCAL_KMS_MASTER_KEY: 'bm90LTMyLWJ5dGVz' });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(EnvError);
    const msg = (err as Error).message;
    expect(msg).toContain('DATABASE_URL');
    expect(msg).toContain('REDIS_URL');
    expect(msg).toContain('SESSION_SECRET');
    expect(msg).toContain('LOCAL_KMS_MASTER_KEY');
    expect(msg).not.toContain('short-secret-value');
  });

  it('requires LOCAL_KMS_MASTER_KEY for the local provider only', () => {
    expect(() => loadEnv({ ...base, LOCAL_KMS_MASTER_KEY: '' })).toThrow(/LOCAL_KMS_MASTER_KEY/);
    expect(loadEnv({ ...base, LOCAL_KMS_MASTER_KEY: '', KMS_PROVIDER: 'aws' }).KMS_PROVIDER).toBe(
      'aws',
    );
  });

  it('dev login is never enabled in production', () => {
    expect(isDevLoginEnabled(loadEnv({ ...base, DEV_LOGIN_ENABLED: 'true' }))).toBe(true);
    expect(isDevLoginEnabled(loadEnv({ ...base, DEV_LOGIN_ENABLED: 'false' }))).toBe(false);
    expect(
      isDevLoginEnabled(
        loadEnv({ ...base, NODE_ENV: 'production', DEV_LOGIN_ENABLED: 'true', E2B_API_KEY: 'x' }),
      ),
    ).toBe(false);
  });
});
