/**
 * Template builds & smoke tests (spec §7.2 steps 8–9, §13.1, Phase 3).
 *
 * Build lifecycle: PENDING → BUILDING → READY | FAILED. Blue/green: `e2bTemplateId`
 * keeps pointing at the last good template until a new build is READY, so sessions
 * keep working during (and after a failed) rebuild. Infra errors are retried once;
 * user errors are not. Failures store a sanitized `templateErrorDetail`
 * {code, message, logTail} — logs are scrubbed of known secret formats AND the
 * project's own env values.
 */
import { randomBytes } from 'node:crypto';
import { Prisma, type Organization, type Project } from '@prisma/client';
import {
  getErrorDefinition,
  scrubSecrets,
  templateErrorDtoSchema,
  templateStatusDtoSchema,
  type ErrorCode,
  type SmokeTestResultDto,
  type SmokeTestStep,
  type TemplateErrorDto,
  type TemplateLogLine,
  type TemplateStatusDto,
} from '@loose/shared';
import { resolve } from 'node:path';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';
import { TemplateBuildError, type SandboxHandle } from '../lib/sandbox';
import { buildTemplateSpec, templateInputsHash } from '../lib/sandbox/templateSpec';
import { resolveGitAccess } from './gitAccess.service';
import type { Actor } from './org.service';
import { decryptProjectEnv, findProject } from './project.service';
import {
  checkPreview,
  cloneRepo,
  firstPublicPort,
  resolveSessionEnv,
  runStartupCommands,
  secretValuesOf,
  startServices,
  StepFailure,
  tail,
  waitForHealthy,
  writeEnvFile,
  type WorkspaceContext,
} from './workspace.service';

const LOG_TAIL = 40;

export function toTemplateStatusDto(p: Project): TemplateStatusDto {
  const err = templateErrorDtoSchema.safeParse(p.templateErrorDetail);
  return templateStatusDtoSchema.parse({
    status: p.templateStatus,
    version: p.templateVersion,
    templateId: p.e2bTemplateId,
    error: p.templateStatus === 'FAILED' ? (err.success ? err.data : null) : null,
    buildStartedAt: p.templateBuildStartedAt,
    buildFinishedAt: p.templateBuildFinishedAt,
    smokeTest: p.smokeTestStatus
      ? {
          status: p.smokeTestStatus,
          failedStep: p.smokeTestFailedStep,
          finishedAt: p.smokeTestStatus === 'RUNNING' ? null : p.smokeTestAt,
        }
      : null,
  });
}

/** Values to redact from build/smoke-test output: every project env value. */
async function projectSecrets(
  ctx: AppContext,
  p: Project,
): Promise<{ env: Record<string, string>; values: string[] }> {
  const env = await decryptProjectEnv(ctx, p);
  return { env, values: secretValuesOf(env) };
}

// ---- build -------------------------------------------------------------------------------

export async function getTemplateStatus(
  ctx: AppContext,
  orgId: string,
  projectId: string,
  actor: Actor,
) {
  return toTemplateStatusDto(await findProject(ctx, orgId, projectId, actor.role));
}

export async function requestTemplateBuild(
  ctx: AppContext,
  orgId: string,
  projectId: string,
  actor: Actor,
): Promise<TemplateStatusDto> {
  const p = await findProject(ctx, orgId, projectId, actor.role);
  const buildId = `bld_${randomBytes(9).toString('base64url')}`;
  // Atomic claim: only one build per project at a time.
  const claimed = await ctx.prisma.project.updateMany({
    where: { id: p.id, templateStatus: { not: 'BUILDING' } },
    data: {
      templateStatus: 'BUILDING',
      templateBuildId: buildId,
      templateBuildStartedAt: new Date(),
      templateBuildFinishedAt: null,
      templateError: null,
      templateErrorDetail: Prisma.DbNull,
    },
  });
  if (claimed.count === 0) {
    const current = await ctx.prisma.project.findUniqueOrThrow({ where: { id: p.id } });
    throw new AppError('LSE-TPL-007', {
      devMessage: `Build ${current.templateBuildId ?? '?'} is in progress (started ${current.templateBuildStartedAt?.toISOString() ?? '?'})`,
    });
  }
  await ctx.templateLogs.reset(p.id);
  await ctx.audit.record({
    orgId,
    actorId: actor.userId,
    action: 'template.build',
    target: p.id,
    meta: { buildId, version: p.templateVersion + 1, services: p.requiredServices },
    ip: actor.ip,
  });
  const updated = await ctx.prisma.project.findUniqueOrThrow({ where: { id: p.id } });
  const dto = toTemplateStatusDto(updated);
  await ctx.templateLogs.publishStatus(p.id, dto);
  await ctx.jobs.enqueue('template-builds', { projectId: p.id, buildId }, { jobId: buildId });
  return dto;
}

function buildFailure(err: unknown): { code: ErrorCode; message: string } {
  if (err instanceof TemplateBuildError) {
    const code: ErrorCode =
      err.kind === 'unsupported'
        ? 'LSE-TPL-003'
        : err.kind === 'timeout'
          ? 'LSE-TPL-004'
          : 'LSE-TPL-002';
    return { code, message: err.message };
  }
  return { code: 'LSE-TPL-002', message: 'Unexpected build error' };
}

async function withTimeout<T>(p: Promise<T>, ms: number, onTimeout: () => void): Promise<T> {
  let t: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    t = setTimeout(() => {
      onTimeout();
      reject(new TemplateBuildError('timeout', `Build exceeded ${Math.round(ms / 60000)} min`));
    }, ms);
    t.unref();
  });
  try {
    return await Promise.race([p, timeout]);
  } finally {
    if (t) clearTimeout(t);
  }
}

/** Job handler for `template-builds`. Safe to call directly (tests). */
export async function runTemplateBuild(
  ctx: AppContext,
  data: { projectId: string; buildId: string },
): Promise<void> {
  const p = await ctx.prisma.project.findUnique({ where: { id: data.projectId } });
  if (!p || p.templateBuildId !== data.buildId || p.templateStatus !== 'BUILDING') return; // stale
  const { values } = await projectSecrets(ctx, p);
  const scrub = (s: string) => scrubSecrets(s, values);
  const lines: string[] = [];
  const log = async (stream: TemplateLogLine['stream'], line: string) => {
    for (const l of line.split(/\r?\n/)) {
      if (!l.trim()) continue;
      const clean = scrub(l).slice(0, 10_000);
      lines.push(clean);
      if (lines.length > 500) lines.shift();
      await ctx.templateLogs.append(p.id, { ts: new Date().toISOString(), stream, line: clean });
    }
  };
  const pending: Promise<void>[] = [];
  const onLog = (l: { ts: Date; stream: TemplateLogLine['stream']; line: string }) => {
    pending.push(log(l.stream, l.line).catch(() => undefined));
  };

  const version = p.templateVersion + 1;
  let templateId: string | undefined;
  let failure: { code: ErrorCode; message: string } | undefined;
  try {
    const spec = buildTemplateSpec(p, {
      version,
      runnerBundleDir: ctx.env.RUNNER_BUNDLE_DIR ? resolve(ctx.env.RUNNER_BUNDLE_DIR) : undefined,
    });
    await log('system', `Building template v${version} (${ctx.templateBuilder.kind})`);
    const timeoutMs = ctx.env.TEMPLATE_BUILD_TIMEOUT_MIN * 60_000;
    for (let attempt = 0; ; attempt += 1) {
      const abort = new AbortController();
      try {
        const res = await withTimeout(
          ctx.templateBuilder.build(spec, { onLog, signal: abort.signal }),
          timeoutMs,
          () => abort.abort(),
        );
        templateId = res.templateId;
        break;
      } catch (err) {
        if (err instanceof TemplateBuildError && err.kind === 'infra' && attempt === 0) {
          await Promise.all(pending);
          await log('system', 'Infrastructure error; retrying the build once');
          continue;
        }
        throw err;
      }
    }
  } catch (err) {
    failure = buildFailure(err);
    if (!(err instanceof TemplateBuildError))
      ctx.logger.error({ err, projectId: p.id }, 'template build crashed');
  }
  await Promise.all(pending);

  if (templateId) {
    const res = await ctx.prisma.project.updateMany({
      where: { id: p.id, templateBuildId: data.buildId },
      data: {
        templateStatus: 'READY',
        previousTemplateId: p.e2bTemplateId,
        e2bTemplateId: templateId,
        templateVersion: version,
        templateBuildFinishedAt: new Date(),
        templateSpecHash: templateInputsHash(p),
        templateError: null,
        templateErrorDetail: Prisma.DbNull,
      },
    });
    if (res.count) await log('system', `Template v${version} is ready`);
  } else {
    const f = failure ?? { code: 'LSE-TPL-002' as ErrorCode, message: 'Build failed' };
    const def = getErrorDefinition(f.code);
    const detail: TemplateErrorDto = {
      code: f.code,
      message: scrub(f.message).slice(0, 1000),
      logTail: tail(lines.join('\n'), LOG_TAIL).map(scrub),
    };
    await log('system', `Build failed: ${def.title}`);
    await ctx.prisma.project.updateMany({
      where: { id: p.id, templateBuildId: data.buildId },
      data: {
        templateStatus: 'FAILED',
        templateBuildFinishedAt: new Date(),
        templateError: def.userMessage,
        templateErrorDetail: detail as unknown as Prisma.InputJsonValue,
      },
    });
    await ctx.audit.record({
      orgId: p.orgId,
      action: 'template.build_failed',
      target: p.id,
      meta: { buildId: data.buildId, code: f.code, version },
    });
  }
  const final = await ctx.prisma.project.findUnique({ where: { id: p.id } });
  if (final) await ctx.templateLogs.publishStatus(p.id, toTemplateStatusDto(final));
}

/** True when the project's build inputs changed since the active template (LSE-TPL-008). */
export function isTemplateOutdated(p: Project): boolean {
  return p.templateSpecHash !== null && p.templateSpecHash !== templateInputsHash(p);
}

// ---- smoke test -------------------------------------------------------------------------

const SMOKE_LOCK_TTL_SEC = 30 * 60;

export async function runSmokeTest(
  ctx: AppContext,
  org: Organization,
  projectId: string,
  actor: Actor,
): Promise<SmokeTestResultDto> {
  const p = await findProject(ctx, org.id, projectId, actor.role);
  if (!p.e2bTemplateId) {
    throw new AppError('LSE-TPL-001', {
      devMessage: 'Build the template before running a smoke test',
    });
  }
  const lockKey = `smoke:${p.id}`;
  if (!(await ctx.kv.setIfAbsent(lockKey, '1', SMOKE_LOCK_TTL_SEC))) {
    throw new AppError('LSE-TPL-007', {
      devMessage: 'A smoke test is already running for this project',
    });
  }
  const startedAt = new Date();
  const logLines: string[] = [];
  let sandbox: SandboxHandle | undefined;
  let failedStep: SmokeTestStep | null = null;
  let failure: AppError | undefined;
  try {
    await ctx.prisma.project.update({
      where: { id: p.id },
      data: { smokeTestStatus: 'RUNNING', smokeTestFailedStep: null, smokeTestAt: startedAt },
    });
    const { env, values } = await projectSecrets(ctx, p);
    const step = async <T>(name: SmokeTestStep, fn: () => Promise<T>): Promise<T> => {
      try {
        return await fn();
      } catch (err) {
        if (err instanceof StepFailure) throw err;
        throw new StepFailure(
          name,
          err instanceof AppError
            ? err
            : new AppError('LSE-TPL-006', { devMessage: 'Unexpected error', cause: err }),
        );
      }
    };
    sandbox = await step('create_sandbox', async () => {
      try {
        return await ctx.sandbox.createFromTemplate(p.e2bTemplateId!, {
          timeoutMs: 20 * 60_000,
          metadata: { kind: 'smoke-test', projectId: p.id, orgId: org.id },
        });
      } catch (err) {
        throw new StepFailure('create_sandbox', sandboxCreateError(err));
      }
    });
    const w: WorkspaceContext = {
      ctx,
      sandbox,
      project: p,
      secrets: values,
      reporter: { log: (l) => logLines.push(l) },
    };
    const access = await step('clone', () =>
      resolveGitAccess(ctx, { org, userId: actor.userId, repoFullName: p.githubRepoFullName }),
    );
    await step('clone', () => cloneRepo(w, access));
    const vars = resolveSessionEnv(p, sandbox, env);
    await step('clone', () => writeEnvFile(w, vars));
    await step('start_services', () => startServices(w));
    const { appProcesses } = await step('startup_commands', () =>
      runStartupCommands(w, vars, async () => undefined),
    );
    await step('health_check', () => waitForHealthy(w, appProcesses));
    const front = firstPublicPort(p);
    if (front) await step('preview', () => checkPreview(ctx, sandbox!.getUrl(front.port)));
  } catch (err) {
    if (err instanceof StepFailure) {
      failedStep = err.step;
      failure = err.error;
    } else {
      failedStep = 'create_sandbox';
      failure = err instanceof AppError ? err : new AppError('LSE-TPL-006', { cause: err });
    }
  } finally {
    if (sandbox) await sandbox.kill().catch(() => undefined);
    await ctx.kv.del(lockKey).catch(() => undefined);
  }

  const finishedAt = new Date();
  const status = failure ? 'FAILED' : 'PASSED';
  await ctx.prisma.project.update({
    where: { id: p.id },
    data: { smokeTestStatus: status, smokeTestFailedStep: failedStep, smokeTestAt: finishedAt },
  });
  await ctx.audit.record({
    orgId: org.id,
    actorId: actor.userId,
    action: 'template.smoke_test',
    target: p.id,
    meta: { status, failedStep, code: failure?.code ?? null },
    ip: actor.ip,
  });
  if (failure) {
    const detail = scrubSecrets(failure.devMessage ?? failure.title);
    throw new AppError('LSE-TPL-006', {
      devMessage: `Smoke test failed at "${failedStep}" (${failure.code}): ${detail}`,
      fields: { failedStep: [failedStep ?? 'unknown'], logTail: tail(logLines.join('\n'), 20) },
    });
  }
  return {
    status: 'PASSED',
    failedStep: null,
    message: null,
    logTail: tail(logLines.join('\n'), 20),
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
  };
}

/** Map a provider create failure to LSE-SBX-001 (capacity) / LSE-SBX-002. */
export function sandboxCreateError(err: unknown): AppError {
  if (err instanceof AppError) return err;
  const kind = (err as { kind?: string }).kind;
  const msg = err instanceof Error ? err.message : 'sandbox create failed';
  return new AppError(kind === 'capacity' ? 'LSE-SBX-001' : 'LSE-SBX-002', {
    devMessage: msg,
    cause: err,
  });
}
