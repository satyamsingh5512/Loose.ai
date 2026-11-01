/** Dependency container passed to every router/middleware factory. */
import type { PrismaClient } from '@prisma/client';
import type { Env } from './config/env';
import type { EnvelopeCrypto } from './lib/crypto';
import type { PlatformEventBus } from './lib/events/platformEvents';
import type { SessionEventBus } from './lib/events/sessionEventBus';
import type { TemplateLogStore } from './lib/events/templateLogs';
import type { FeatureFlags } from './lib/featureFlags';
import type { JobRunner } from './lib/jobs';
import type { MetricsRegistry } from './lib/metrics';
import type { DnsResolver } from './lib/net/dns';
import type { Logger } from './lib/logger';
import type { KvStore, Redis } from './lib/redis';
import type { SandboxKind, SandboxProvider, TemplateBuilder } from './lib/sandbox';
import type { ObjectStorage } from './lib/storage';
import type { PlatformRole } from './platform/register';
import type { ProviderAdapter } from './providers/adapter';
import type { AuditService } from './services/audit.service';
import type { Orchestrator } from './services/orchestrator.service';
import type { SessionService } from './services/session.service';
import type { SessionHookRegistry, SessionRuntimeRegistry } from './services/sessionRuntime';

export interface AppContext {
  env: Env;
  prisma: PrismaClient;
  /** null in tests / when Redis is not wired (rate limits fall back to memory). */
  redis: Redis | null;
  kv: KvStore;
  logger: Logger;
  crypto: EnvelopeCrypto;
  /** Outbound HTTP (OAuth, GitHub). Injected in tests. */
  fetch: typeof fetch;
  providers: { anthropic: ProviderAdapter };
  /** Auth (cookie) sessions — not agent sessions. */
  sessions: SessionService;
  audit: AuditService;

  // ---- Phases 3–4: templates & agent sessions -------------------------------------
  /** Sandbox provider (wrapped with retries + circuit breaker). */
  sandbox: SandboxProvider;
  sandboxKind: SandboxKind;
  templateBuilder: TemplateBuilder;
  jobs: JobRunner;
  templateLogs: TemplateLogStore;
  /** EXTENSION POINT: per-session event log + fan-out (WS gateway subscribes here). */
  sessionEvents: SessionEventBus;
  /** EXTENSION POINT: live sandbox/runner handles of sessions provisioned by this process. */
  sessionRuntime: SessionRuntimeRegistry;
  /** EXTENSION POINT: lifecycle hooks (orchestrator registers onSessionReady/onSessionStopping/isBusy). */
  sessionHooks: SessionHookRegistry;
  /** Artifact storage (screenshots, logs, diffs). */
  storage: ObjectStorage;

  // ---- Phases 5–6: chat & agent, review & delivery ---------------------------------------
  /** Agent orchestrator: runner processes, turn flow, OTL, approvals, budgets. */
  agent: Orchestrator;

  // ---- Phase 9: platform -------------------------------------------------------------------
  /** Typed business events (webhooks, runs, triggers subscribe; see platform/register.ts). */
  platformEvents: PlatformEventBus;
  /** `api` = serves HTTP/WS and hosts runners; `worker` = background jobs only. */
  platformRole: PlatformRole;

  // ---- Phase 10: hardening & GA ---------------------------------------------------------------
  /** Stable id of this process (`INSTANCE_ID` or `<host>-<pid>-<rand>`); presence / routing. */
  instanceId: string;
  /** Prometheus registry (W3). */
  metrics: MetricsRegistry;
  /** Feature flags: env `FEATURE_FLAGS` + per-org overrides. */
  featureFlags: FeatureFlags;
  /** DNS (SSRF pinning, domain verification). Injected in tests. */
  dns: DnsResolver;
}
