/**
 * Server configuration (spec §23.1). Parsed with Zod at boot; any problem
 * aborts startup with a readable list of offending variables (fail fast).
 */
import { z } from 'zod';
import {
  DEFAULT_DATA_EXPORT_TTL_HOURS,
  DEFAULT_DELETION_GRACE_DAYS,
  DEFAULT_MAX_BUDGET_USD,
  DEFAULT_MAX_SESSION_DURATION_MIN,
  MAX_DELETION_GRACE_DAYS,
  RATE_LIMITS,
  TOTP_DEFAULT_ISSUER,
  parseFeatureFlagEnv,
  type FeatureFlagOverrides,
} from '@loose/shared';
import { isLoopbackHost } from '../lib/net/ip';

const emptyToUndefined = (v: unknown) => (typeof v === 'string' && v.trim() === '' ? undefined : v);
const optionalString = z.preprocess(emptyToUndefined, z.string().min(1).optional());
const boolFlag = z.preprocess(
  emptyToUndefined,
  z
    .enum(['true', 'false', '1', '0'])
    .default('false')
    .transform((v) => v === 'true' || v === '1'),
);
const positiveInt = (def: number) =>
  z.preprocess(emptyToUndefined, z.coerce.number().int().positive().default(def));

const base64Key32 = z.string().refine((v) => {
  try {
    return Buffer.from(v, 'base64').length === 32;
  } catch {
    return false;
  }
}, 'Must be base64 encoding of exactly 32 bytes');

export const envSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.preprocess(emptyToUndefined, z.coerce.number().int().min(0).max(65535).default(4000)),
    APP_URL: z.preprocess(emptyToUndefined, z.url().default('http://localhost:5173')),
    API_URL: z.preprocess(emptyToUndefined, z.url().default('http://localhost:4000')),
    /**
     * Number of trusted reverse-proxy hops (`X-Forwarded-For` is read that many entries from the
     * right). A hop count trusts *whatever* reaches the API with fewer proxies than configured, so
     * a spoofed header on any direct path is accepted (IP allowlists!). In production a non-zero
     * value therefore needs `TRUST_PROXY_HOPS_ACKNOWLEDGED=true`, confirming the API is reachable
     * only through exactly that many overwriting proxies (P10-SEC-015).
     */
    TRUST_PROXY: z.preprocess(emptyToUndefined, z.coerce.number().int().min(0).default(0)),
    TRUST_PROXY_HOPS_ACKNOWLEDGED: boolFlag,
    DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
    REDIS_URL: z.string().min(1, 'REDIS_URL is required'),
    SESSION_SECRET: z.string().min(32, 'SESSION_SECRET must be at least 32 characters'),
    KMS_PROVIDER: z.enum(['local', 'aws']).default('local'),
    KMS_KEY_ID: optionalString,
    LOCAL_KMS_MASTER_KEY: z.preprocess(emptyToUndefined, base64Key32.optional()),
    GOOGLE_CLIENT_ID: optionalString,
    GOOGLE_CLIENT_SECRET: optionalString,
    GITHUB_CLIENT_ID: optionalString,
    GITHUB_CLIENT_SECRET: optionalString,
    GITHUB_WEBHOOK_SECRET: optionalString,
    // ---- Phase 9 inbound integrations (optional; the trigger kind is disabled when absent) ----
    /** Slack app signing secret (slash command triggers). */
    SLACK_SIGNING_SECRET: optionalString,
    /** Linear webhook signing secret. */
    LINEAR_WEBHOOK_SECRET: optionalString,
    /** Jira webhook secret (`x-hub-signature: sha256=…`). */
    JIRA_WEBHOOK_SECRET: optionalString,
    /** DEV ONLY — see routes/auth.ts. Ignored in production. */
    DEV_LOGIN_ENABLED: boolFlag,
    DEFAULT_MAX_BUDGET_USD: z.preprocess(
      emptyToUndefined,
      z.coerce.number().positive().default(DEFAULT_MAX_BUDGET_USD),
    ),
    DEFAULT_MAX_SESSION_MIN: positiveInt(DEFAULT_MAX_SESSION_DURATION_MIN),
    RATE_LIMIT_AUTH_MAX: positiveInt(RATE_LIMITS.auth.max),
    RATE_LIMIT_KEY_VALIDATION_MAX: positiveInt(RATE_LIMITS.keyValidation.max),
    RATE_LIMIT_GENERAL_MAX: positiveInt(RATE_LIMITS.general.max),
    RATE_LIMIT_SESSION_CREATE_MAX: positiveInt(RATE_LIMITS.sessionCreate.max),
    LOG_LEVEL: z
      .enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'])
      .default('info'),

    // ---- GitHub App (optional; preferred over user OAuth tokens for clone/push) -------
    GITHUB_APP_ID: optionalString,
    /** PEM private key; literal `\n` sequences are accepted. */
    GITHUB_APP_PRIVATE_KEY: optionalString,

    // ---- sandboxes (spec §13) -------------------------------------------------------
    /** Default: e2b in production, local in development, fake in test. */
    SANDBOX_PROVIDER: z.preprocess(emptyToUndefined, z.enum(['e2b', 'local', 'fake']).optional()),
    E2B_API_KEY: optionalString,
    E2B_DOMAIN: optionalString,
    /** DEV ONLY: allow falling back to the local provider when e2b has no API key. */
    LOCAL_SANDBOX_ALLOW_FALLBACK: boolFlag,
    /** DEV ONLY: where LocalSandboxProvider creates workspaces (default: OS temp dir). */
    LOCAL_SANDBOX_DIR: optionalString,
    /** DEV ONLY: runner entry used by the local provider (default packages/runner/dist/cli.js). */
    LOCAL_RUNNER_ENTRY: optionalString,
    /** DEV ONLY: alias of LOCAL_RUNNER_ENTRY (takes precedence), e.g. packages/runner/dist/cli.js. */
    RUNNER_ENTRY: optionalString,
    /**
     * DEV ONLY: clone/push from a local path template instead of github.com,
     * e.g. `/tmp/loose-remotes/{owner}/{repo}.git`. Rejected in production.
     */
    DEV_GIT_REMOTE_OVERRIDE: optionalString,
    /** Sandbox lifetime; extended by keep-alive while the session is active. */
    SANDBOX_TIMEOUT_MIN: positiveInt(30),
    /** Per startup command timeout. */
    SANDBOX_COMMAND_TIMEOUT_SEC: positiveInt(600),
    /** Base delay for jittered retries around sandbox provider calls (spec §16.4). */
    SANDBOX_RETRY_BASE_MS: z.preprocess(
      emptyToUndefined,
      z.coerce.number().int().min(0).default(500),
    ),
    TEMPLATE_BUILD_TIMEOUT_MIN: positiveInt(30),
    /** Directory with the built runner bundle copied into templates. */
    RUNNER_BUNDLE_DIR: optionalString,
    /** Run the deterministic mock agent (default: true unless SANDBOX_PROVIDER=e2b). */
    RUNNER_MOCK: z.preprocess(emptyToUndefined, z.enum(['true', 'false', '1', '0']).optional()),
    /** Capture before/after preview screenshots per turn (default: true only with e2b). */
    AGENT_SCREENSHOTS: z.preprocess(
      emptyToUndefined,
      z.enum(['true', 'false', '1', '0']).optional(),
    ),

    // ---- jobs & storage ----------------------------------------------------------------
    /** Run queue jobs in-process (default true outside production; production uses src/worker.ts). */
    JOBS_INLINE: z.preprocess(emptyToUndefined, z.enum(['true', 'false', '1', '0']).optional()),
    ARTIFACT_STORAGE: z.enum(['local', 's3']).default('local'),
    ARTIFACT_DIR: z.preprocess(emptyToUndefined, z.string().default('./.data/artifacts')),

    // ---- Phase 10: object storage (ARTIFACT_STORAGE=s3; MinIO-compatible) ------------------
    S3_BUCKET: optionalString,
    S3_REGION: z.preprocess(emptyToUndefined, z.string().min(1).default('us-east-1')),
    /** Non-AWS endpoint (MinIO, R2, …). */
    S3_ENDPOINT: z.preprocess(emptyToUndefined, z.url({ protocol: /^https?$/ }).optional()),
    /** Both or neither; when absent the default AWS credential chain is used. */
    S3_ACCESS_KEY_ID: optionalString,
    S3_SECRET_ACCESS_KEY: optionalString,
    S3_FORCE_PATH_STYLE: boolFlag,
    /** Key prefix inside the bucket (e.g. `prod/`). */
    S3_PREFIX: z.preprocess(
      emptyToUndefined,
      z
        .string()
        .regex(/^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*\/?$/, 'Use a path like prod/')
        .optional(),
    ),
    S3_SIGNED_URL_TTL_SEC: z.preprocess(
      emptyToUndefined,
      z.coerce.number().int().min(30).max(3600).default(300),
    ),

    // ---- Phase 10: identity (W1) -------------------------------------------------------------
    /** Issuer label shown in authenticator apps. */
    TOTP_ISSUER: z.preprocess(
      emptyToUndefined,
      z.string().min(1).max(64).default(TOTP_DEFAULT_ISSUER),
    ),
    /** Timeout of OIDC discovery / JWKS / token calls. */
    SSO_HTTP_TIMEOUT_MS: z.preprocess(
      emptyToUndefined,
      z.coerce.number().int().min(500).max(30_000).default(5000),
    ),

    // ---- Phase 10: governance (W2) -----------------------------------------------------------
    /** HMAC key of the audit hash chain (default: derived from SESSION_SECRET). Set in production. */
    AUDIT_CHAIN_SECRET: z.preprocess(
      emptyToUndefined,
      z.string().min(32, 'AUDIT_CHAIN_SECRET must be at least 32 characters').optional(),
    ),
    /** Days between an account/org deletion request and its execution (0 = next sweep). */
    DELETION_GRACE_DAYS: z.preprocess(
      emptyToUndefined,
      z.coerce
        .number()
        .int()
        .min(0)
        .max(MAX_DELETION_GRACE_DAYS)
        .default(DEFAULT_DELETION_GRACE_DAYS),
    ),
    DATA_EXPORT_TTL_HOURS: z.preprocess(
      emptyToUndefined,
      z.coerce.number().int().min(1).max(720).default(DEFAULT_DATA_EXPORT_TTL_HOURS),
    ),

    // ---- Phase 10: observability & reliability (W3) ------------------------------------------
    /** Stable id of this process (presence / cross-instance command routing). */
    INSTANCE_ID: z.preprocess(
      emptyToUndefined,
      z
        .string()
        .regex(/^[A-Za-z0-9_.-]{1,64}$/)
        .optional(),
    ),
    /** `flag=on,other=off` (see FEATURE_FLAGS in @loose/shared). */
    FEATURE_FLAGS: optionalString,
    /** Bearer token for `GET /metrics` on the main port (absent → /metrics is 404 there). */
    METRICS_TOKEN: z.preprocess(
      emptyToUndefined,
      z.string().min(32, 'METRICS_TOKEN must be at least 32 characters').optional(),
    ),
    /** Separate internal metrics listener (API and worker). */
    METRICS_PORT: z.preprocess(
      emptyToUndefined,
      z.coerce.number().int().min(1).max(65535).optional(),
    ),
    METRICS_HOST: z.preprocess(emptyToUndefined, z.string().min(1).default('127.0.0.1')),
    /** `/readyz` also checks e2b reachability (default: true when SANDBOX_PROVIDER=e2b). */
    READYZ_CHECK_E2B: z.preprocess(
      emptyToUndefined,
      z.enum(['true', 'false', '1', '0']).optional(),
    ),
    /** Reserved (spec §23.1): OpenTelemetry export is not wired (see phase10-design.md §1). */
    OTEL_EXPORTER_OTLP_ENDPOINT: z.preprocess(emptyToUndefined, z.url().optional()),
  })
  .superRefine((env, ctx) => {
    if (env.KMS_PROVIDER === 'local' && !env.LOCAL_KMS_MASTER_KEY) {
      ctx.addIssue({
        code: 'custom',
        path: ['LOCAL_KMS_MASTER_KEY'],
        message: 'Required when KMS_PROVIDER=local',
      });
    }
    if (env.NODE_ENV === 'production') {
      if (env.SANDBOX_PROVIDER === 'local' || env.SANDBOX_PROVIDER === 'fake') {
        ctx.addIssue({
          code: 'custom',
          path: ['SANDBOX_PROVIDER'],
          message: 'local/fake sandboxes are not allowed in production',
        });
      }
      if ((env.SANDBOX_PROVIDER ?? 'e2b') === 'e2b' && !env.E2B_API_KEY) {
        ctx.addIssue({
          code: 'custom',
          path: ['E2B_API_KEY'],
          message: 'Required in production (SANDBOX_PROVIDER=e2b)',
        });
      }
      if (env.DEV_GIT_REMOTE_OVERRIDE) {
        ctx.addIssue({
          code: 'custom',
          path: ['DEV_GIT_REMOTE_OVERRIDE'],
          message: 'Not allowed in production',
        });
      }
    }
    if (env.ARTIFACT_STORAGE === 's3' && !env.S3_BUCKET) {
      ctx.addIssue({
        code: 'custom',
        path: ['S3_BUCKET'],
        message: 'Required when ARTIFACT_STORAGE=s3',
      });
    }
    if (Boolean(env.S3_ACCESS_KEY_ID) !== Boolean(env.S3_SECRET_ACCESS_KEY)) {
      ctx.addIssue({
        code: 'custom',
        path: [env.S3_ACCESS_KEY_ID ? 'S3_SECRET_ACCESS_KEY' : 'S3_ACCESS_KEY_ID'],
        message: 'Set both S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY, or neither',
      });
    }
    if (env.NODE_ENV === 'production' && env.S3_ENDPOINT?.startsWith('http:')) {
      ctx.addIssue({
        code: 'custom',
        path: ['S3_ENDPOINT'],
        message: 'Must use https in production',
      });
    }
    if (
      env.NODE_ENV === 'production' &&
      env.TRUST_PROXY > 0 &&
      !env.TRUST_PROXY_HOPS_ACKNOWLEDGED
    ) {
      ctx.addIssue({
        code: 'custom',
        path: ['TRUST_PROXY'],
        message:
          'A numeric hop count trusts any shorter path to the API (spoofable X-Forwarded-For). ' +
          'In production set TRUST_PROXY_HOPS_ACKNOWLEDGED=true once the API is reachable only ' +
          'through exactly that many proxies that overwrite X-Forwarded-For',
      });
    }
    if (env.METRICS_PORT && !isLoopbackHost(env.METRICS_HOST) && !env.METRICS_TOKEN) {
      ctx.addIssue({
        code: 'custom',
        path: ['METRICS_TOKEN'],
        message:
          'Required when METRICS_HOST is not a loopback address (the metrics listener would ' +
          'otherwise be unauthenticated on the network)',
      });
    }
    if (env.FEATURE_FLAGS) {
      try {
        parseFeatureFlagEnv(env.FEATURE_FLAGS);
      } catch (err) {
        ctx.addIssue({
          code: 'custom',
          path: ['FEATURE_FLAGS'],
          message: err instanceof Error ? err.message : 'Invalid feature flags',
        });
      }
    }
    if (env.GITHUB_APP_ID && !env.GITHUB_APP_PRIVATE_KEY) {
      ctx.addIssue({
        code: 'custom',
        path: ['GITHUB_APP_PRIVATE_KEY'],
        message: 'Required when GITHUB_APP_ID is set',
      });
    }
  })
  .transform((env) => {
    const sandboxProvider =
      env.SANDBOX_PROVIDER ??
      (env.NODE_ENV === 'production' ? 'e2b' : env.NODE_ENV === 'test' ? 'fake' : 'local');
    const flag = (v: string | undefined, def: boolean) =>
      v === undefined ? def : v === 'true' || v === '1';
    return {
      ...env,
      SANDBOX_PROVIDER: sandboxProvider,
      RUNNER_MOCK: flag(env.RUNNER_MOCK, sandboxProvider !== 'e2b'),
      AGENT_SCREENSHOTS: flag(env.AGENT_SCREENSHOTS, sandboxProvider === 'e2b'),
      LOCAL_RUNNER_ENTRY: env.RUNNER_ENTRY ?? env.LOCAL_RUNNER_ENTRY,
      JOBS_INLINE: flag(env.JOBS_INLINE, env.NODE_ENV !== 'production'),
      READYZ_CHECK_E2B: flag(env.READYZ_CHECK_E2B, sandboxProvider === 'e2b'),
      /** Parsed `FEATURE_FLAGS` (validated above). */
      FEATURE_FLAG_OVERRIDES: (env.FEATURE_FLAGS
        ? parseFeatureFlagEnv(env.FEATURE_FLAGS)
        : {}) as FeatureFlagOverrides,
      // Never honoured in production (also rejected above).
      DEV_GIT_REMOTE_OVERRIDE:
        env.NODE_ENV === 'production' ? undefined : env.DEV_GIT_REMOTE_OVERRIDE,
    };
  });

export type Env = z.infer<typeof envSchema>;
export type SandboxProviderKind = Env['SANDBOX_PROVIDER'];

export class EnvError extends Error {
  constructor(public readonly problems: string[]) {
    super(`Invalid server configuration:\n  - ${problems.join('\n  - ')}`);
    this.name = 'EnvError';
  }
}

/** Parse and validate the environment. Throws EnvError (never logs values). */
export function loadEnv(source: Record<string, string | undefined> = process.env): Env {
  const result = envSchema.safeParse(source);
  if (!result.success) {
    throw new EnvError(
      result.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`),
    );
  }
  return result.data;
}

/** Dev login is mounted only outside production AND when explicitly enabled. */
export function isDevLoginEnabled(env: Pick<Env, 'NODE_ENV' | 'DEV_LOGIN_ENABLED'>): boolean {
  return env.NODE_ENV !== 'production' && env.DEV_LOGIN_ENABLED === true;
}
