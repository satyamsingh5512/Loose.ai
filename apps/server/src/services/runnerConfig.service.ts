/**
 * Runner config preparation (spec §8.2, §8.6–§8.11): builds `config.json` with the
 * memory hierarchy, the session's skills (written as a local plugin outside the repo),
 * MCP servers (credentials replaced by `${LOOSE_MCP_SECRET_n}` placeholders), subagents,
 * the hooks the runner evaluates itself and the events it must ask the server about, and
 * returns the secret env the runner process needs. Called at provisioning and before
 * every runner (re)start.
 */
import { remainingBudgetUsd, type RunnerConfig } from '@loose/shared';
import type { Session } from '@prisma/client';
import type { AppContext } from '../context';
import type { SandboxHandle } from '../lib/sandbox';
import {
  resolveSessionExtensions,
  writeSkillsPlugin,
  type SessionExtensions,
} from './extensions.service';
import {
  runnerHooksOf,
  serverHookEventsOf,
  serverHookFailMode,
  serverHookTimeoutMs,
} from './hooks.service';
import { buildRunnerConfig } from './sessionLifecycle.service';

export interface PreparedRunnerConfig {
  config: RunnerConfig;
  /** Runner process env with MCP secrets (never written to disk). */
  mcpEnv: Record<string, string>;
  /** MCP server name → McpServer id (status recording). */
  mcpIds: Map<string, string>;
  extensions: SessionExtensions;
}

export async function prepareRunnerConfig(
  ctx: AppContext,
  s: Session,
  sandbox: SandboxHandle,
  opts: { configPath?: string; capToRemainingBudget?: boolean } = {},
): Promise<PreparedRunnerConfig> {
  const project = await ctx.prisma.project.findUniqueOrThrow({
    where: { id: s.projectId },
    include: { org: true },
  });
  const user = await ctx.prisma.user.findUnique({
    where: { id: s.userId },
    select: { memory: true },
  });
  const extensions = await resolveSessionExtensions(ctx, {
    orgId: project.orgId,
    projectId: project.id,
    userId: s.userId,
  });
  if (extensions.skippedSkills.length) {
    ctx.logger.warn(
      { sessionId: s.id, code: 'LSE-AGT-015', skills: extensions.skippedSkills },
      'invalid skills skipped',
    );
  }
  if (extensions.pluginWarnings.length) {
    ctx.logger.warn(
      { sessionId: s.id, code: 'LSE-EXT-007', warnings: extensions.pluginWarnings },
      'plugin contents partially skipped',
    );
  }
  const pluginDir = await writeSkillsPlugin(sandbox, extensions.skills);
  const config = buildRunnerConfig(ctx, s, project, project.org, sandbox, {
    userMemory: user?.memory ?? null,
    ...(pluginDir ? { pluginDir } : {}),
    skills: extensions.skills.map((k) => k.name),
    mcpServers: extensions.mcp.map((m) => m.config),
    subagents: extensions.subagents,
    // `http` / `notify_slack` handlers never reach the sandbox: the server runs those
    // and answers the runner's `hook_request`.
    hooks: runnerHooksOf(extensions.hooks),
    serverHookEvents: serverHookEventsOf(extensions.hooks),
    serverHookTimeoutMs: serverHookTimeoutMs(extensions.hooks),
    serverHookFailMode: serverHookFailMode(extensions.hooks),
  });
  if (opts.capToRemainingBudget) {
    const remaining = remainingBudgetUsd(
      Number(s.totalCostUsd),
      Number(s.budgetUsd ?? project.maxBudgetUsd),
    );
    if (remaining !== null) config.maxBudgetUsd = Math.min(1000, Math.max(0.01, remaining));
  }
  await sandbox.writeFile(
    opts.configPath ?? `${sandbox.paths.state}/config.json`,
    `${JSON.stringify(config, null, 2)}\n`,
  );
  return {
    config,
    mcpEnv: extensions.mcpEnv,
    mcpIds: new Map(extensions.mcp.filter((m) => !m.pluginName).map((m) => [m.name, m.id])),
    extensions,
  };
}
