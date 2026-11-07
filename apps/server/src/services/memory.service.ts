/**
 * Memory hierarchy (spec §8.10; Phase 7): Org memory → Project LOOSE.md → User memory →
 * Session notes. Also `memory/generate` (`/init` for the settings page): a LOOSE.md draft
 * derived from the repository (via the GitHub API) and the project settings, for an
 * admin to review — nothing is saved automatically.
 */
import type { Organization, Project } from '@prisma/client';
import {
  memoryDtoSchema,
  sessionNotesDtoSchema,
  type MemoryDraftDto,
  type MemoryDto,
  type SessionNotesDto,
} from '@loose/shared';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';
import { githubClientFor } from './github.service';
import {
  assertCanAct,
  assertTokenScope,
  loadSessionForParticipant,
  type Caller,
} from './sessionLifecycle.service';
import type { Actor } from './org.service';

// ---- org & user memory ----------------------------------------------------------------------

export function orgMemoryDto(org: Pick<Organization, 'memory' | 'memoryUpdatedAt'>): MemoryDto {
  return memoryDtoSchema.parse({ memory: org.memory, updatedAt: org.memoryUpdatedAt });
}

export async function updateOrgMemory(
  ctx: AppContext,
  org: Organization,
  actor: Actor,
  memory: string | null,
): Promise<MemoryDto> {
  const value = memory?.trim() ? memory : null;
  const updated = await ctx.prisma.organization.update({
    where: { id: org.id },
    data: { memory: value, memoryUpdatedAt: new Date() },
  });
  await ctx.audit.record({
    orgId: org.id,
    actorId: actor.userId,
    action: 'memory.update',
    target: org.id,
    meta: { layer: 'org', length: value?.length ?? 0 },
    ip: actor.ip,
  });
  return orgMemoryDto(updated);
}

export async function getUserMemory(ctx: AppContext, userId: string): Promise<MemoryDto> {
  const u = await ctx.prisma.user.findUniqueOrThrow({
    where: { id: userId },
    select: { memory: true, memoryUpdatedAt: true },
  });
  return memoryDtoSchema.parse({ memory: u.memory, updatedAt: u.memoryUpdatedAt });
}

export async function updateUserMemory(
  ctx: AppContext,
  userId: string,
  memory: string | null,
): Promise<MemoryDto> {
  const value = memory?.trim() ? memory : null;
  const u = await ctx.prisma.user.update({
    where: { id: userId },
    data: { memory: value, memoryUpdatedAt: new Date() },
  });
  return memoryDtoSchema.parse({ memory: u.memory, updatedAt: u.memoryUpdatedAt });
}

// ---- session notes ------------------------------------------------------------------------------

async function sessionAccess(
  ctx: AppContext,
  caller: Caller,
  sessionId: string,
  need: 'read' | 'write',
) {
  assertTokenScope(caller, need);
  const a = await loadSessionForParticipant(ctx, caller, sessionId);
  if (need === 'write') assertCanAct(a, 'change session notes');
  return a;
}

export async function getSessionNotes(
  ctx: AppContext,
  caller: Caller,
  sessionId: string,
): Promise<SessionNotesDto> {
  const { session } = await sessionAccess(ctx, caller, sessionId, 'read');
  return sessionNotesDtoSchema.parse({ notes: session.notes });
}

/** Replace the notes (applies to the agent from its next start; quick-adds apply at once). */
export async function setSessionNotes(
  ctx: AppContext,
  caller: Caller,
  sessionId: string,
  notes: string,
): Promise<SessionNotesDto> {
  await sessionAccess(ctx, caller, sessionId, 'write');
  const s = await ctx.prisma.session.update({ where: { id: sessionId }, data: { notes } });
  return { notes: s.notes };
}

export async function addSessionNote(
  ctx: AppContext,
  caller: Caller,
  sessionId: string,
  text: string,
): Promise<SessionNotesDto> {
  const { session } = await sessionAccess(ctx, caller, sessionId, 'write');
  if (session.status !== 'RUNNING') {
    throw new AppError('LSE-CONF-001', { devMessage: `Session is ${session.status}, not RUNNING` });
  }
  return { notes: await ctx.agent.addNote(sessionId, text) };
}

// ---- LOOSE.md draft (`memory/generate`) --------------------------------------------------------

const MAX_TREE_PATHS = 5000;
const MEMORY_FILE_LINES = 60;

interface RepoFacts {
  description: string | null;
  paths: string[];
  packageJson: Record<string, unknown> | null;
  readme: string | null;
  repoMemory: { file: string; text: string } | null;
  sources: string[];
}

const STACK_DEPS: [string, string][] = [
  ['next', 'Next.js'],
  ['react', 'React'],
  ['vue', 'Vue'],
  ['svelte', 'Svelte'],
  ['@angular/core', 'Angular'],
  ['astro', 'Astro'],
  ['vite', 'Vite'],
  ['tailwindcss', 'Tailwind CSS'],
  ['express', 'Express'],
  ['fastify', 'Fastify'],
  ['@nestjs/core', 'NestJS'],
  ['prisma', 'Prisma'],
  ['@prisma/client', 'Prisma'],
  ['drizzle-orm', 'Drizzle'],
  ['typescript', 'TypeScript'],
  ['vitest', 'Vitest'],
  ['jest', 'Jest'],
  ['@playwright/test', 'Playwright'],
  ['stripe', 'Stripe'],
];

const STACK_FILES: [RegExp, string][] = [
  [/^(requirements\.txt|pyproject\.toml)$/, 'Python'],
  [/^Gemfile$/, 'Ruby'],
  [/^go\.mod$/, 'Go'],
  [/^Cargo\.toml$/, 'Rust'],
  [/^composer\.json$/, 'PHP'],
  [/^Dockerfile$/, 'Docker'],
];

const DIR_HINTS: Record<string, string> = {
  src: 'application source',
  app: 'app routes / pages',
  pages: 'pages',
  components: 'UI components',
  public: 'static assets',
  static: 'static assets',
  styles: 'styles',
  lib: 'shared code',
  server: 'server code',
  api: 'API endpoints',
  test: 'tests',
  tests: 'tests',
  __tests__: 'tests',
  docs: 'documentation',
  scripts: 'scripts',
  prisma: 'database schema and migrations',
  migrations: 'database migrations',
  '.github': 'CI workflows',
};

const SENSITIVE =
  /(^|\/)(auth|login|payments?|billing|checkout|migrations?|prisma|secrets?)(\/|$)/i;

function title(s: string): string {
  return s
    .replace(/[-_]+/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase())
    .trim();
}

async function repoFacts(ctx: AppContext, project: Project, userId: string): Promise<RepoFacts> {
  const facts: RepoFacts = {
    description: null,
    paths: [],
    packageJson: null,
    readme: null,
    repoMemory: null,
    sources: [],
  };
  const [owner = '', repo = ''] = project.githubRepoFullName.split('/');
  try {
    const gh = await githubClientFor(ctx, userId);
    const info = await gh.rest.repos.get({ owner, repo });
    facts.description = info.data.description ?? null;
    const tree = await gh.rest.git.getTree({
      owner,
      repo,
      tree_sha: project.defaultBranch,
      recursive: '1',
    });
    facts.paths = (tree.data.tree as { path?: string; type?: string }[])
      .filter((e) => e.path && (e.type === 'blob' || e.type === 'tree'))
      .map((e) => (e.type === 'tree' ? `${e.path}/` : e.path!))
      .slice(0, MAX_TREE_PATHS);
    const read = async (path: string) => {
      if (!facts.paths.includes(path)) return null;
      const r = await gh.rest.repos.getContent({ owner, repo, path, ref: project.defaultBranch });
      const c = (r.data as { content?: string }).content;
      if (typeof c !== 'string') return null;
      facts.sources.push(path);
      return Buffer.from(c, 'base64').toString('utf8');
    };
    const pkg = await read('package.json').catch(() => null);
    if (pkg) {
      try {
        facts.packageJson = JSON.parse(pkg) as Record<string, unknown>;
      } catch {
        facts.packageJson = null;
      }
    }
    facts.readme = await read('README.md').catch(() => null);
    for (const f of ['CLAUDE.md', 'AGENTS.md']) {
      const text = await read(f).catch(() => null);
      if (text) {
        facts.repoMemory = { file: f, text };
        break;
      }
    }
  } catch (err) {
    ctx.logger.info(
      { projectId: project.id, err: (err as Error).message },
      'memory draft: repository not readable, using project settings only',
    );
  }
  return facts;
}

function packageManager(paths: readonly string[]): string {
  if (paths.includes('bun.lock') || paths.includes('bun.lockb')) return 'bun';
  if (paths.includes('pnpm-lock.yaml')) return 'pnpm';
  if (paths.includes('yarn.lock')) return 'yarn';
  return 'npm';
}

/** Deterministic LOOSE.md draft. Exported for tests. */
export function draftLooseMd(project: Project, facts: RepoFacts): MemoryDraftDto {
  const pkg = facts.packageJson;
  const deps = {
    ...((pkg?.dependencies as Record<string, string> | undefined) ?? {}),
    ...((pkg?.devDependencies as Record<string, string> | undefined) ?? {}),
  };
  const topFiles = facts.paths.filter((p) => !p.includes('/'));
  const stack = [
    ...new Set([
      ...STACK_DEPS.filter(([d]) => d in deps).map(([, n]) => n),
      ...STACK_FILES.filter(([re]) => topFiles.some((f) => re.test(f))).map(([, n]) => n),
      ...(pkg ? ['Node.js'] : []),
      ...project.requiredServices.map((s) => title(s)),
    ]),
  ];
  const pm = packageManager(facts.paths);
  const scripts = (pkg?.scripts as Record<string, string> | undefined) ?? {};
  const run = (s: string) => (pm === 'npm' ? `npm run ${s}` : `${pm} run ${s}`);
  const commandLines = [
    ...(pkg ? [`- Install: \`${pm} install\``] : []),
    ...['dev', 'start', 'build', 'test', 'lint', 'typecheck', 'format']
      .filter((k) => typeof scripts[k] === 'string')
      .map((k) => `- ${title(k)}: \`${run(k)}\``),
    ...project.startupCommands.map((c) => `- Startup (preview): \`${c}\``),
  ];
  const ports = Array.isArray(project.portMap)
    ? (project.portMap as { name?: string; port?: number; public?: boolean }[])
    : [];
  const dirs = facts.paths.filter((p) => /^[^/]+\/$/.test(p)).map((p) => p.slice(0, -1));
  const dirLines = dirs
    .filter((d) => !d.startsWith('.') || d === '.github')
    .slice(0, 25)
    .map((d) => `- \`${d}/\` — ${DIR_HINTS[d] ?? title(d)}`);
  const sensitive = [
    ...new Set(
      facts.paths
        .filter((p) => p.endsWith('/') && SENSITIVE.test(p))
        .map((p) => p.slice(0, -1))
        .slice(0, 15),
    ),
  ];
  const lines: string[] = [`# ${project.name}`, ''];
  lines.push(
    '## Overview',
    '',
    facts.description ??
      `Repository \`${project.githubRepoFullName}\` (default branch \`${project.defaultBranch}\`).`,
    '',
  );
  if (stack.length) lines.push('## Stack', '', ...stack.map((s) => `- ${s}`), '');
  if (commandLines.length) lines.push('## Commands', '', ...commandLines, '');
  if (ports.length) {
    lines.push(
      '## Ports',
      '',
      ...ports.map((p) => `- ${p.name ?? 'app'}: ${p.port ?? '?'}${p.public ? ' (preview)' : ''}`),
      '',
    );
  }
  if (dirLines.length) lines.push('## Directory map', '', ...dirLines, '');
  lines.push('## Conventions', '');
  if (facts.repoMemory) {
    lines.push(
      `From the repository's ${facts.repoMemory.file}:`,
      '',
      ...facts.repoMemory.text.split('\n').slice(0, MEMORY_FILE_LINES),
      '',
    );
  } else {
    lines.push(
      '- Follow the existing code style and file layout.',
      '- Keep changes small and focused on the request.',
      '',
    );
  }
  if (sensitive.length) {
    lines.push(
      '## Handle with care',
      '',
      ...sensitive.map(
        (d) => `- \`${d}/\` — high risk (auth, payments or data); get a developer review.`,
      ),
      '',
    );
  }
  // Component labels for Simple-mode summaries: second-level UI folders.
  const labels: Record<string, string> = {};
  for (const p of facts.paths) {
    const m = /^((?:src\/)?(?:components|pages|app|sections|features)\/([^/]+))\/$/.exec(p);
    if (m && Object.keys(labels).length < 30)
      labels[`${m[1]}/**`] = `the ${title(m[2]!).toLowerCase()}`;
  }
  return {
    draft: `${lines.join('\n').trim()}\n`,
    componentLabels: labels,
    sources: facts.sources,
  };
}

export async function generateProjectMemory(
  ctx: AppContext,
  project: Project,
  actor: Actor,
): Promise<MemoryDraftDto> {
  const facts = await repoFacts(ctx, project, actor.userId);
  const draft = draftLooseMd(project, facts);
  const existing =
    project.componentLabels &&
    typeof project.componentLabels === 'object' &&
    !Array.isArray(project.componentLabels)
      ? (project.componentLabels as Record<string, string>)
      : {};
  return { ...draft, componentLabels: { ...draft.componentLabels, ...existing } };
}
