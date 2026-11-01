/**
 * Express app factory. `createApp(ctx)` wires middleware in this order:
 * requestId → pino-http → security headers → /metrics → health → raw webhooks (GitHub,
 * integrations) → SCIM → cookies → /api/v1 (rate limit, content-type, JSON 1mb, CSRF, routes)
 * → 404 → errorHandler.
 * Phase 10 workstreams plug in through the `mount*Routes` functions (phase10-design.md §5.1).
 */
import { randomBytes } from 'node:crypto';
import { hostname } from 'node:os';
import cookieParser from 'cookie-parser';
import express, { Router, type Express } from 'express';
import { pinoHttp } from 'pino-http';
import { API_PREFIX } from '@loose/shared';
import type { PrismaClient } from '@prisma/client';
import type { Env } from './config/env';
import type { AppContext } from './context';
import { EnvelopeCrypto } from './lib/crypto';
import { PlatformEventBus } from './lib/events/platformEvents';
import {
  InMemorySessionEventBus,
  RedisSessionEventBus,
  type SessionEventBus,
} from './lib/events/sessionEventBus';
import {
  MemoryTemplateLogStore,
  RedisTemplateLogStore,
  type TemplateLogStore,
} from './lib/events/templateLogs';
import { FeatureFlags } from './lib/featureFlags';
import { BullJobRunner, InlineJobRunner, type JobRunner } from './lib/jobs';
import { createKmsProvider, type KmsProvider } from './lib/kms';
import type { Logger } from './lib/logger';
import { safeUrlForLog } from './lib/logger';
import { createMetricsRegistry, type MetricsRegistry } from './lib/metrics';
import { systemDns, type DnsResolver } from './lib/net/dns';
import { MemoryKvStore, RedisKvStore, type KvStore, type Redis } from './lib/redis';
import {
  createSandboxServices,
  type SandboxKind,
  type SandboxProvider,
  type TemplateBuilder,
} from './lib/sandbox';
import {
  LocalObjectStorage,
  S3ObjectStorage,
  s3ConfigFromEnv,
  type ObjectStorage,
} from './lib/storage';
import { csrfProtection } from './middleware/csrf';
import { errorHandler, notFoundHandler } from './middleware/errorHandler';
import { createRateLimiters } from './middleware/rateLimit';
import { requestId } from './middleware/requestId';
import { securityHeaders } from './middleware/securityHeaders';
import { requireJsonBody } from './middleware/validate';
import { registerPlatform, type PlatformRole } from './platform/register';
import { AnthropicAdapter } from './providers/anthropic';
import type { ProviderAdapter } from './providers/adapter';
import { authRouter } from './routes/auth';
import { githubRouter, githubWebhookHandler } from './routes/github';
import { mountGovernanceApiRoutes } from './routes/governance';
import { healthRouter } from './routes/health';
import { mountIdentityApiRoutes, mountIdentityRawRoutes } from './routes/identity';
import { integrationsRouter } from './routes/integrations';
import { mountObservabilityApiRoutes, mountObservabilityRoutes } from './routes/observability';
import { orgsRouter } from './routes/orgs';
import { publicArtifactsRouter } from './routes/publicArtifacts';
import { runsRouter } from './routes/runs';
import { sessionsRouter } from './routes/sessions';
import { usersRouter } from './routes/users';
import { AuditService } from './services/audit.service';
import { createOAuthClients, type OAuthClients } from './services/oauth.service';
import { Orchestrator } from './services/orchestrator.service';
import { SessionService } from './services/session.service';
import { registerJobHandlers } from './services/sessionJobs.service';
import { SessionHookRegistry, SessionRuntimeRegistry } from './services/sessionRuntime';
import './types/express';

export const JSON_BODY_LIMIT = '1mb';

export interface BuildContextInput {
  env: Env;
  prisma: PrismaClient;
  logger: Logger;
  redis?: Redis | null;
  kv?: KvStore;
  kms?: KmsProvider;
  fetch?: typeof fetch;
  anthropic?: ProviderAdapter;
  /** Overrides (tests): sandbox provider/builder, job runner, event stores, storage. */
  sandbox?: SandboxProvider;
  templateBuilder?: TemplateBuilder;
  jobs?: JobRunner;
  templateLogs?: TemplateLogStore;
  sessionEvents?: SessionEventBus;
  storage?: ObjectStorage;
  /**
   * Install the agent orchestrator's lifecycle hooks (start runners when sessions become
   * RUNNING). The API process does; the background worker does not (runners are attached
   * lazily by the API process that serves the session's WebSocket).
   */
  agentHooks?: boolean;
  /** Process role for Phase 9 subscribers (default: `api` unless agentHooks is false). */
  platformRole?: PlatformRole;
  /** Override the platform event bus (tests). */
  platformEvents?: PlatformEventBus;
  /** Phase 10 overrides (tests): metrics registry, DNS resolver, instance id. */
  metrics?: MetricsRegistry;
  dns?: DnsResolver;
  instanceId?: string;
}

export function defaultInstanceId(): string {
  return `${hostname()
    .replace(/[^A-Za-z0-9_.-]/g, '-')
    .slice(0, 40)}-${process.pid}-${randomBytes(3).toString('hex')}`;
}

export function buildContext(input: BuildContextInput): AppContext {
  const { env, logger } = input;
  const redis = input.redis ?? null;
  const fetchFn = input.fetch ?? ((...args: Parameters<typeof fetch>) => globalThis.fetch(...args));
  let sandbox = input.sandbox;
  let templateBuilder = input.templateBuilder;
  let sandboxKind: SandboxKind = sandbox?.kind ?? env.SANDBOX_PROVIDER;
  if (!sandbox || !templateBuilder) {
    const services = createSandboxServices(env, logger);
    sandbox ??= services.provider;
    templateBuilder ??= services.templateBuilder;
    sandboxKind = sandbox.kind;
  }
  const ctx: AppContext = {
    env,
    prisma: input.prisma,
    redis,
    kv: input.kv ?? (redis ? new RedisKvStore(redis) : new MemoryKvStore()),
    logger,
    crypto: new EnvelopeCrypto(input.kms ?? createKmsProvider(env)),
    fetch: fetchFn,
    providers: { anthropic: input.anthropic ?? new AnthropicAdapter({ fetch: fetchFn }) },
    sessions: new SessionService(input.prisma),
    audit: new AuditService(input.prisma, logger),
    sandbox,
    sandboxKind,
    templateBuilder,
    jobs:
      input.jobs ??
      (env.JOBS_INLINE ? new InlineJobRunner(logger) : new BullJobRunner(env.REDIS_URL, logger)),
    templateLogs:
      input.templateLogs ??
      (redis ? new RedisTemplateLogStore(redis, logger) : new MemoryTemplateLogStore()),
    sessionEvents:
      input.sessionEvents ??
      (redis
        ? // P10-SEC-004: authenticated cluster envelopes on the session event channel.
          new RedisSessionEventBus(redis, logger, {
            secret: env.SESSION_SECRET,
            instanceId: input.instanceId ?? env.INSTANCE_ID ?? undefined,
          })
        : new InMemorySessionEventBus()),
    sessionRuntime: new SessionRuntimeRegistry(),
    sessionHooks: new SessionHookRegistry(),
    storage:
      input.storage ??
      (env.ARTIFACT_STORAGE === 's3'
        ? new S3ObjectStorage(s3ConfigFromEnv(env))
        : new LocalObjectStorage(env.ARTIFACT_DIR)),
    // Assigned right below (the orchestrator needs the finished context).
    agent: undefined as unknown as Orchestrator,
    platformEvents: input.platformEvents ?? new PlatformEventBus(logger),
    platformRole: input.platformRole ?? (input.agentHooks === false ? 'worker' : 'api'),
    instanceId: input.instanceId ?? env.INSTANCE_ID ?? defaultInstanceId(),
    metrics: input.metrics ?? createMetricsRegistry(),
    featureFlags: new FeatureFlags(env.FEATURE_FLAG_OVERRIDES),
    dns: input.dns ?? systemDns,
  };
  ctx.agent = new Orchestrator(ctx);
  if (input.agentHooks !== false) ctx.agent.install();
  registerJobHandlers(ctx);
  registerPlatform(ctx);
  return ctx;
}

export interface CreateAppOptions {
  oauthClients?: OAuthClients;
  /** Test hook: extra routes mounted under /api/v1 before the 404 handler. */
  extraApiRoutes?: (router: Router) => void;
}

export function createApp(ctx: AppContext, opts: CreateAppOptions = {}): Express {
  const app = express();
  const production = ctx.env.NODE_ENV === 'production';
  app.disable('x-powered-by');
  app.set('trust proxy', ctx.env.TRUST_PROXY);

  app.use(requestId);
  app.use(
    pinoHttp({
      logger: ctx.logger,
      genReqId: (req) => (req as express.Request).requestId,
      customLogLevel: (_req, res, err) => (err || res.statusCode >= 500 ? 'warn' : 'info'),
      serializers: {
        req: (req: { id?: unknown; method?: string; url?: string }) => ({
          id: req.id,
          method: req.method,
          url: safeUrlForLog(req.url),
        }),
        res: (res: { statusCode?: number }) => ({ statusCode: res.statusCode }),
      },
      autoLogging: {
        ignore: (req) => req.url === '/healthz' || req.url === '/readyz' || req.url === '/metrics',
      },
    }),
  );
  app.use(securityHeaders(ctx.env));

  // Phase 10 (W3): Prometheus `/metrics` (bearer METRICS_TOKEN; 404 when not configured).
  mountObservabilityRoutes(app, ctx);
  app.use(healthRouter(ctx));

  // Inbound GitHub webhook: raw body for HMAC verification; no cookies/CSRF.
  app.post(
    `${API_PREFIX}/github/webhook`,
    express.raw({ type: () => true, limit: JSON_BODY_LIMIT }),
    githubWebhookHandler(ctx),
  );
  // Inbound integrations (Slack / Linear / Jira triggers): raw bodies, signature-verified.
  app.use(`${API_PREFIX}/integrations`, integrationsRouter(ctx));
  // Phase 10 (W1): SCIM 2.0 (bearer SCIM tokens, application/scim+json; no cookies/CSRF).
  mountIdentityRawRoutes(app, ctx);

  app.use(cookieParser());

  const limiters = createRateLimiters(ctx);
  const oauth = opts.oauthClients ?? createOAuthClients(ctx.env, ctx.fetch);
  const api = Router();
  api.use(limiters.general);
  api.use(requireJsonBody);
  api.use(express.json({ limit: JSON_BODY_LIMIT }));
  api.use(csrfProtection(ctx.env));
  // Phase 10: identity (/auth/sso, /auth/2fa, /users/me/2fa), privacy (/users/me/privacy),
  // feature flags. Mounted before /auth and /users so `/auth/:provider` doesn't swallow them.
  mountIdentityApiRoutes(api, ctx, limiters);
  mountGovernanceApiRoutes(api, ctx, limiters);
  mountObservabilityApiRoutes(api, ctx);
  api.use('/auth', authRouter(ctx, limiters, oauth));
  api.use('/users', usersRouter(ctx, limiters));
  api.use('/orgs', orgsRouter(ctx, limiters));
  api.use('/sessions', sessionsRouter(ctx, limiters));
  api.use('/runs', runsRouter(ctx, limiters));
  api.use('/public-artifacts', publicArtifactsRouter(ctx));
  api.use('/github', githubRouter(ctx));
  opts.extraApiRoutes?.(api);
  app.use(API_PREFIX, api);

  app.use(notFoundHandler);
  app.use(errorHandler(ctx.logger, production));
  return app;
}
