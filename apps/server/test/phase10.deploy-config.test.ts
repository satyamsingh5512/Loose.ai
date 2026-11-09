/**
 * The reference production compose must boot: the api and worker environments it declares are
 * fed through the server's real env validation (`loadEnv`) with placeholder operator values.
 * Regression for the acceptance/security audit blocker "docker-compose.prod.example.yml sets
 * S3_ENDPOINT=http://minio:9000, which production validation rejects".
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { EnvError, loadEnv } from '../src/config/env';
import { TEST_SECRETS } from './helpers';

const compose = readFileSync(
  new URL('../../../docker-compose.prod.example.yml', import.meta.url),
  'utf8',
);

/** Parse `KEY: value` lines of the mapping that starts after `header` at `indent` spaces. */
function mapping(header: RegExp, indent: number, from = 0): Record<string, string> {
  const lines = compose.split('\n');
  const start = lines.findIndex((l, i) => i >= from && header.test(l));
  expect(start, String(header)).toBeGreaterThanOrEqual(0);
  const out: Record<string, string> = {};
  for (const line of lines.slice(start + 1)) {
    if (line.trim() === '' || line.trim().startsWith('#')) continue;
    const lead = line.length - line.trimStart().length;
    if (lead < indent) break;
    if (lead > indent) continue;
    const m = /^\s*([A-Z0-9_<]+):\s*(.*)$/.exec(line);
    if (!m) continue;
    out[m[1]!] = m[2]!.replace(/^'(.*)'$/, '$1');
  }
  return out;
}

function serviceEnv(name: string): Record<string, string> {
  const lines = compose.split('\n');
  const at = lines.findIndex((l) => l === `  ${name}:`);
  expect(at, name).toBeGreaterThan(0);
  const raw = mapping(/^ {4}environment:\s*$/, 6, at);
  const { '<<': merge, ...own } = raw;
  return merge === '*common-env' ? { ...mapping(/^x-common-env:/, 2), ...own } : own;
}

/** Docker compose interpolation: `${VAR}`, `${VAR:-default}`, `${VAR:?message}`. */
function interpolate(env: Record<string, string>, operator: Record<string, string>) {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) {
    out[key] = value.replace(
      /\$\{([A-Z0-9_]+)(?:(:-|:\?)([^}]*))?\}/g,
      (_m, name: string, op?: string, arg?: string) => {
        const v = operator[name];
        if (v !== undefined && v !== '') return v;
        if (op === ':?') throw new Error(`compose would refuse to start: ${name} (${arg})`);
        return op === ':-' ? (arg ?? '') : '';
      },
    );
  }
  return out;
}

const operator = {
  POSTGRES_PASSWORD: 'pg-password',
  SESSION_SECRET: TEST_SECRETS.SESSION_SECRET,
  LOCAL_KMS_MASTER_KEY: TEST_SECRETS.LOCAL_KMS_MASTER_KEY,
  APP_URL: 'https://app.example.com',
  API_URL: 'https://api.example.com',
  E2B_API_KEY: 'e2b_placeholder',
  S3_ACCESS_KEY_ID: 'minio-user',
  S3_SECRET_ACCESS_KEY: 'minio-password-placeholder',
  S3_ENDPOINT: 'https://s3.example.com',
  LOOSE_APP_DB_PASSWORD: 'app-password',
};

describe('docker-compose.prod.example.yml', () => {
  it.each(['api', 'worker'])('the %s environment passes production env validation', (svc) => {
    const env = interpolate(serviceEnv(svc), operator);
    expect(env.NODE_ENV).toBe('production');
    expect(env.ARTIFACT_STORAGE).toBe('s3');
    try {
      loadEnv(env);
    } catch (err) {
      if (err instanceof EnvError) expect.fail(`${svc}: ${err.problems.join('; ')}`);
      throw err;
    }
  });

  it('requires the operator to supply an https S3 endpoint instead of plain http://minio', () => {
    expect(compose).not.toMatch(/S3_ENDPOINT:\s*http:/);
    const { S3_ENDPOINT: _omit, ...withoutEndpoint } = operator;
    expect(() => interpolate(serviceEnv('api'), withoutEndpoint)).toThrow(/S3_ENDPOINT/);
    expect(() =>
      loadEnv(interpolate(serviceEnv('api'), { ...operator, S3_ENDPOINT: 'http://minio:9000' })),
    ).toThrow(EnvError);
  });

  it('runs the API and worker as the least-privilege runtime role, never the table owner (P10-SEC-006)', () => {
    const user = (svc: string) =>
      new URL(interpolate(serviceEnv(svc), operator).DATABASE_URL!).username;
    expect(user('api')).toBe('loose_app');
    expect(user('worker')).toBe('loose_app');
    expect(user('migrate')).toBe('loose');
    // The runtime role password is mandatory; the owner password never reaches api/worker.
    const { LOOSE_APP_DB_PASSWORD: _omit, ...withoutAppPassword } = operator;
    expect(() => interpolate(serviceEnv('api'), withoutAppPassword)).toThrow(
      /LOOSE_APP_DB_PASSWORD/,
    );
    for (const svc of ['api', 'worker']) {
      expect(JSON.stringify(interpolate(serviceEnv(svc), operator))).not.toContain(
        operator.POSTGRES_PASSWORD,
      );
    }
    // db-roles (grants) runs as the owner after migrate, and api/worker wait for it.
    const roles = serviceEnv('db-roles');
    expect(roles.PGUSER).toBe('loose');
    expect(compose).toMatch(/db-roles:[\s\S]*?\/sql\/apply-runtime-role\.sh/);
    const block = (svc: string) => {
      const lines = compose.split('\n');
      const at = lines.findIndex((l) => l === `  ${svc}:`);
      const end = lines.findIndex((l, i) => i > at && /^ {2}[a-z-]+:\s*$/.test(l));
      return lines.slice(at, end === -1 ? undefined : end).join('\n');
    };
    expect(block('db-roles')).toMatch(/migrate:\s*\n\s*condition: service_completed_successfully/);
    for (const svc of ['api', 'worker']) {
      expect(block(svc)).toMatch(/db-roles:\s*\n\s*condition: service_completed_successfully/);
    }
  });

  it('no longer passes the deprecated global Linear/Jira webhook secrets', () => {
    expect(compose).not.toMatch(/LINEAR_WEBHOOK_SECRET|JIRA_WEBHOOK_SECRET/);
  });
});
