/**
 * Slash commands (spec §8.6.1; Phase 7): built-ins (`/plan`, `/undo`, `/compact`,
 * `/clear`, `/cost`, `/model`, `/mode`, `/skills`, `/mcp`, `/memory`, `/review`, `/init`,
 * `/export`, `/help`) and custom Markdown commands (org / project / user) with
 * `$ARGUMENTS` / `$1…`, `@file` references and `!`cmd`` shell pre-expansion in the
 * sandbox (policy-checked). Also the command palette and the transcript export.
 */
import {
  BUILTIN_COMMANDS,
  checkPathAccess,
  classifyCommand,
  commandPolicySchema,
  approvalGatesSchema,
  expandCommandTemplate,
  INIT_PROMPT,
  isAdminRole,
  isBuiltinCommand,
  MODELS,
  parseCommandMeta,
  resolveModelId,
  reviewPrompt,
  scrubSecrets,
  toSimpleChatMessage,
  type ChatMessageDto,
  type Mode,
  type RunCommandBody,
  type RunCommandResultDto,
  type SessionExtensionsDto,
} from '@loose/shared';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';
import { viewerMode } from './agentChat.service';
import { resolveSessionExtensions, type ResolvedCommand } from './extensions.service';
import { shq } from './gitAccess.service';
import { workingDiff } from './gitWorkspace.service';
import {
  assertCanAct,
  assertTokenScope,
  loadSessionForParticipant,
  type Caller,
} from './sessionLifecycle.service';

const SHELL_TIMEOUT_MS = 30_000;
const SHELL_OUTPUT_MAX = 4_000;
const FILE_REF_MAX = 20_000;
const MAX_FILE_REFS = 5;
const REVIEW_DIFF_MAX = 60_000;
const READ_ONLY_TOOLS = ['Read', 'Grep', 'Glob', 'LS', 'TodoWrite'];

async function access(ctx: AppContext, caller: Caller, sessionId: string, need: 'read' | 'write') {
  assertTokenScope(caller, need);
  const a = await loadSessionForParticipant(ctx, caller, sessionId);
  if (need === 'write') assertCanAct(a, 'act in sessions');
  const org = await ctx.prisma.organization.findUniqueOrThrow({
    where: { id: a.session.project.orgId },
  });
  return { ...a, org, mode: viewerMode(a.session, a.membership, org) };
}

/** `GET /sessions/:id/commands`: palette entries + Simple-mode quick actions. */
export async function sessionExtensions(
  ctx: AppContext,
  caller: Caller,
  sessionId: string,
): Promise<SessionExtensionsDto> {
  const { session, membership, mode } = await access(ctx, caller, sessionId, 'read');
  const ext = await resolveSessionExtensions(ctx, {
    orgId: session.project.orgId,
    projectId: session.projectId,
    userId: session.userId,
  });
  const admin = isAdminRole(membership.role);
  const builtins = BUILTIN_COMMANDS.filter(
    (c) => (mode === 'PRO' || c.simple) && (!c.adminOnly || admin),
  ).map((c) => ({
    name: c.name,
    description: c.description,
    argumentHint: c.argumentHint ?? null,
    builtin: true,
    scope: 'BUILTIN' as const,
  }));
  const custom =
    mode === 'PRO'
      ? ext.commands.map((c) => {
          const meta = parseCommandMeta(c.body);
          return {
            name: c.name,
            description: meta.description ?? `Custom command /${c.name}`,
            argumentHint: meta.argumentHint ?? null,
            builtin: false,
            scope: c.scope,
          };
        })
      : [];
  return {
    commands: [...builtins, ...custom].sort((a, b) => a.name.localeCompare(b.name)),
    quickActions: ext.skills
      .filter((s) => s.quickAction)
      .map((s) => ({ skill: s.name, label: s.quickAction!, description: s.description })),
  };
}

function money(n: number): string {
  return `$${n.toFixed(n < 1 ? 4 : 2)}`;
}

/** Run a slash command (WS `slash_command`, `POST /sessions/:id/commands`). */
export async function runCommand(
  ctx: AppContext,
  caller: Caller,
  sessionId: string,
  body: RunCommandBody,
): Promise<RunCommandResultDto> {
  const name = body.command.replace(/^\//, '').trim().toLowerCase();
  const args = (body.args ?? '').trim();
  const a = await access(
    ctx,
    caller,
    sessionId,
    name === 'export' || name === 'help' || name === 'cost' ? 'read' : 'write',
  );
  const { session, membership, mode } = a;
  if (name !== 'export' && session.status !== 'RUNNING') {
    throw new AppError('LSE-CONF-001', { devMessage: `Session is ${session.status}, not RUNNING` });
  }
  const agent = ctx.agent;
  const display = `/${name}${args ? ` ${args}` : ''}`;
  const reply = async (text: string): Promise<RunCommandResultDto> => {
    await agent.systemMessage(sessionId, text, { kind: 'system', command: name });
    return { command: name, kind: 'reply', message: text };
  };
  const turn = async (
    req: Parameters<typeof agent.submitTurn>[1],
  ): Promise<RunCommandResultDto> => {
    await agent.submitTurn(sessionId, { command: name, ...req });
    return { command: name, kind: 'turn', message: null };
  };

  if (!isBuiltinCommand(name)) return runCustomCommand(ctx, a, name, args, display);

  const def = BUILTIN_COMMANDS.find((c) => c.name === name)!;
  if (def.adminOnly && !isAdminRole(membership.role)) {
    throw new AppError('LSE-ORG-002', { devMessage: `/${name} needs an org admin` });
  }
  switch (name) {
    case 'help': {
      const list = BUILTIN_COMMANDS.filter((c) => mode === 'PRO' || c.simple)
        .map((c) => `- /${c.name}${c.argumentHint ? ` ${c.argumentHint}` : ''} — ${c.description}`)
        .join('\n');
      return reply(`Available commands:\n${list}`);
    }
    case 'plan':
      if (!args) throw new AppError('LSE-VAL-001', { fields: { args: ['Describe what to plan'] } });
      return turn({ content: args, plan: 'manual' });
    case 'undo':
      await agent.undoLast(caller, sessionId);
      return { command: name, kind: 'action', message: null };
    case 'clear':
      await agent.clearConversation(caller, sessionId);
      return { command: name, kind: 'action', message: null };
    case 'compact':
      // Claude Code handles `/compact` itself (context compaction).
      return turn({ content: display, agentText: args ? `/compact ${args}` : '/compact' });
    case 'cost': {
      const total = Number(session.totalCostUsd);
      const budget = session.budgetUsd === null ? null : Number(session.budgetUsd);
      return reply(
        budget
          ? `This session has cost ${money(total)} of its ${money(budget)} budget (${Math.round((total / budget) * 100)}%).`
          : `This session has cost ${money(total)} so far.`,
      );
    }
    case 'model': {
      if (!args) {
        const list = MODELS.map(
          (m) => `- ${m.id}${m.id === session.model ? ' (current)' : ''}`,
        ).join('\n');
        return reply(`Current model: ${session.model}\nAvailable:\n${list}`);
      }
      const id = resolveModelId(args);
      if (!id) throw new AppError('LSE-KEY-013', { devMessage: `Unknown model ${args}` });
      await agent.setModel(caller, sessionId, id);
      return reply(`Switched the model to ${id}.`);
    }
    case 'mode': {
      const want = args.toUpperCase();
      if (want !== 'SIMPLE' && want !== 'PRO') {
        throw new AppError('LSE-VAL-001', { fields: { args: ['Use /mode simple or /mode pro'] } });
      }
      await agent.setMode(caller, sessionId, want as Mode);
      return { command: name, kind: 'action', message: null };
    }
    case 'skills': {
      const ext = await resolveSessionExtensions(ctx, {
        orgId: session.project.orgId,
        projectId: session.projectId,
        userId: session.userId,
      });
      if (!ext.skills.length) return reply('No skills are enabled for this project.');
      return reply(
        `Skills the AI can use here:\n${ext.skills.map((s) => `- ${s.name} — ${s.description}`).join('\n')}`,
      );
    }
    case 'mcp': {
      const ext = await resolveSessionExtensions(ctx, {
        orgId: session.project.orgId,
        projectId: session.projectId,
        userId: session.userId,
      });
      if (!ext.mcp.length)
        return reply('No connected tools (MCP servers) are enabled for this project.');
      const rows = await ctx.prisma.mcpServer.findMany({
        where: { id: { in: ext.mcp.map((m) => m.id) } },
        select: { name: true, lastStatus: true, lastError: true },
      });
      return reply(
        `Connected tools:\n${rows
          .map(
            (r) =>
              `- ${r.name}: ${r.lastStatus ?? 'untested'}${r.lastError ? ` (${r.lastError})` : ''}`,
          )
          .join('\n')}`,
      );
    }
    case 'memory': {
      if (args) {
        await agent.addNote(sessionId, args);
        return { command: name, kind: 'action', message: null };
      }
      const project = await ctx.prisma.project.findUniqueOrThrow({
        where: { id: session.projectId },
      });
      const user = await ctx.prisma.user.findUnique({ where: { id: session.userId } });
      const fresh = await ctx.prisma.session.findUniqueOrThrow({ where: { id: sessionId } });
      const size = (t: string | null | undefined) =>
        t?.trim() ? `${t.trim().split('\n').length} lines` : 'empty';
      return reply(
        [
          'Memory loaded for this session (in this order):',
          `- Organization memory: ${size(a.org.memory)}`,
          `- Project memory (LOOSE.md): ${size(project.looseMd)}`,
          `- Your personal memory: ${size(user?.memory)}`,
          `- Session notes: ${size(fresh.notes)}`,
          'Add a session note with /memory <note>' +
            (mode === 'PRO' ? ' or start a message with "# ".' : '.'),
        ].join('\n'),
      );
    }
    case 'review': {
      const sandbox = await agent.sandboxFor(sessionId);
      const diff = scrubSecrets(
        await workingDiff(sandbox).catch(() => ''),
        agent.scrubValuesFor(sessionId),
      );
      const clipped =
        diff.length > REVIEW_DIFF_MAX
          ? `${diff.slice(0, REVIEW_DIFF_MAX)}\n…[diff truncated]`
          : diff;
      return turn({
        content: display,
        agentText: `${reviewPrompt(args)}\n\n<session_diff>\n${clipped || '(no changes yet)'}\n</session_diff>`,
        allowedTools: READ_ONLY_TOOLS,
      });
    }
    case 'init':
      return turn({ content: display, agentText: INIT_PROMPT, allowedTools: READ_ONLY_TOOLS });
    case 'export':
      return {
        command: name,
        kind: 'action',
        message: null,
        url: `/api/v1/sessions/${sessionId}/transcript?format=markdown`,
      };
  }
  throw new AppError('LSE-NF-001', { devMessage: `Unknown command /${name}` });
}

type Access = Awaited<ReturnType<typeof access>>;

async function runCustomCommand(
  ctx: AppContext,
  a: Access,
  name: string,
  args: string,
  display: string,
): Promise<RunCommandResultDto> {
  const { session } = a;
  const ext = await resolveSessionExtensions(ctx, {
    orgId: session.project.orgId,
    projectId: session.projectId,
    userId: session.userId,
  });
  const cmd: ResolvedCommand | undefined = ext.commands.find((c) => c.name === name);
  // Custom commands are a Pro feature; Simple users get quick actions instead.
  if (!cmd || a.mode !== 'PRO') {
    throw new AppError('LSE-NF-001', {
      devMessage: `Unknown command /${name}`,
      userMessage: `There is no /${name} command here. Type /help to see what's available.`,
    });
  }
  const meta = parseCommandMeta(cmd.body);
  const expanded = expandCommandTemplate(meta.template, args);
  const sandbox = await ctx.agent.sandboxFor(session.id);
  const project = await ctx.prisma.project.findUniqueOrThrow({ where: { id: session.projectId } });
  const scrub = ctx.agent.scrubValuesFor(session.id);
  let prompt = expanded.prompt;
  const policy = commandPolicySchema.parse(project.commandPolicy ?? {});
  const gates = approvalGatesSchema.parse(project.approvalGates ?? {});
  for (const [i, shell] of expanded.shellBlocks.entries()) {
    const verdict = classifyCommand(shell, policy, gates);
    let out: string;
    if (verdict.decision !== 'allow') {
      out = `[command not run: ${verdict.reason}]`;
    } else {
      const r = await sandbox
        .run(shell, { cwd: sandbox.paths.workspace, timeoutMs: SHELL_TIMEOUT_MS })
        .catch(() => ({ exitCode: 1, stdout: '', stderr: 'command failed to start' }));
      const text = `${r.stdout}${r.stderr ? `\n${r.stderr}` : ''}`.trim();
      out =
        scrubSecrets(text.slice(0, SHELL_OUTPUT_MAX), scrub) || `(exit ${r.exitCode}, no output)`;
    }
    prompt = prompt.replace(`{{shell:${i}}}`, out);
  }
  const attached: string[] = [];
  for (const ref of expanded.fileRefs.slice(0, MAX_FILE_REFS)) {
    const check = checkPathAccess(ref, {
      allowed: [],
      denied: project.deniedFilePatterns,
    });
    if (!check.allowed || !check.normalizedPath) continue;
    const content = await sandbox
      .run(`head -c ${FILE_REF_MAX} -- ${shq(check.normalizedPath)}`, {
        cwd: sandbox.paths.workspace,
        timeoutMs: 15_000,
      })
      .catch(() => null);
    if (!content || content.exitCode !== 0) continue;
    attached.push(
      `<file path="${check.normalizedPath}">\n${scrubSecrets(content.stdout, scrub)}\n</file>`,
    );
  }
  if (attached.length) prompt = `${prompt}\n\nReferenced files:\n${attached.join('\n')}`;
  const model = meta.model ? resolveModelId(meta.model) : null;
  await ctx.agent.submitTurn(session.id, {
    content: display,
    agentText: prompt,
    command: name,
    ...(meta.allowedTools.length ? { allowedTools: meta.allowedTools } : {}),
    ...(model ? { model } : {}),
  });
  return { command: name, kind: 'turn', message: null };
}

// ---- transcript export -----------------------------------------------------------------------

function rawObj(v: unknown): Record<string, unknown> | null {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

/** `GET /sessions/:id/transcript` — mode-aware (Simple text vs Pro text), rewound turns excluded. */
export async function exportTranscript(
  ctx: AppContext,
  caller: Caller,
  sessionId: string,
  format: 'markdown' | 'json',
): Promise<{ body: string; contentType: string; filename: string }> {
  const { session, mode } = await access(ctx, caller, sessionId, 'read');
  const rows = await ctx.prisma.chatMessage.findMany({
    where: { sessionId, rewoundAt: null },
    orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
    take: 5000,
  });
  const messages: ChatMessageDto[] = rows
    .filter((r) => rawObj(r.rawContent)?.pending !== true)
    .map((r) => {
      const proText = rawObj(r.rawContent)?.proText;
      const dto: ChatMessageDto = {
        id: r.id,
        sessionId: r.sessionId,
        role: r.role,
        content:
          mode === 'PRO' && r.role === 'ASSISTANT' && typeof proText === 'string'
            ? proText
            : r.content,
        clientMessageId: r.clientMessageId,
        metadata: (rawObj(r.metadata) as ChatMessageDto['metadata']) ?? null,
        createdAt: r.createdAt.toISOString(),
      };
      return mode === 'PRO' ? dto : toSimpleChatMessage(dto);
    });
  const base = `session-${session.id}`;
  if (format === 'json') {
    return {
      body: JSON.stringify(
        {
          session: {
            id: session.id,
            project: session.project.name,
            startedAt: session.startedAt,
            model: session.model,
            totalCostUsd: Number(session.totalCostUsd),
          },
          messages,
        },
        null,
        2,
      ),
      contentType: 'application/json; charset=utf-8',
      filename: `${base}.json`,
    };
  }
  const who = { USER: 'You', ASSISTANT: 'AI', SYSTEM: 'loose.ai' } as const;
  const lines = [
    `# ${session.project.name} — session transcript`,
    '',
    `- Session: ${session.id}`,
    `- Started: ${session.startedAt?.toISOString() ?? session.createdAt.toISOString()}`,
    `- Cost: ${money(Number(session.totalCostUsd))}`,
    '',
  ];
  for (const m of messages) {
    lines.push(
      `## ${who[m.role]} · ${m.createdAt.slice(0, 16).replace('T', ' ')} UTC`,
      '',
      m.content.trim(),
      '',
    );
  }
  return {
    body: `${lines.join('\n').trim()}\n`,
    contentType: 'text/markdown; charset=utf-8',
    filename: `${base}.md`,
  };
}
