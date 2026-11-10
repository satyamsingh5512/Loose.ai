/**
 * Simple-mode 100-golden-task leak test (Phase 10 §7.3, acceptance #6): every task in
 * `test/fixtures/goldenTasks.ts` is played as a real turn through a Simple-mode session (fake
 * sandbox + scripted runner, real orchestrator + Output Translation Layer), and every piece of
 * Simple-audience content the session actually emits — assistant text, change summaries, tool
 * approval summaries — is run through `leakCheck`. None may ever leak a path, code fence, stack
 * trace, shell command, diff marker, internal URL, or secret, no matter how the agent phrased it
 * or chunked its streaming deltas.
 */
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { leakCheck } from '../src/services/translation';
import { GOLDEN_PROJECT_SECRET, GOLDEN_TASKS, type GoldenTask } from './fixtures/goldenTasks';
import {
  busEvents,
  FakeGit,
  installFakeRunner,
  playTurn,
  waitFor,
  type FakeRunner,
  type RunnerScript,
} from './agentHelpers';
import {
  addMember,
  createOrg,
  linkGithub,
  login,
  makeApp,
  resetDb,
  testPrisma,
  type Client,
} from './helpers';
import { addApiKey, createReadyProject, fakeSandbox, settle } from './sessionHelpers';

const prisma = testPrisma();
const { app, ctx } = makeApp();
const fake = fakeSandbox(ctx);

const script: { current: RunnerScript } = { current: () => undefined };
let runners: FakeRunner[] = [];

afterAll(async () => {
  await ctx.agent.idle();
  await ctx.jobs.onIdle();
  await prisma.$disconnect();
});

beforeEach(async () => {
  await ctx.agent.shutdownAll();
  await ctx.jobs.onIdle();
  fake.reset();
  runners = installFakeRunner(fake, script);
  new FakeGit().install(fake);
  await resetDb();
});

interface World {
  owner: Client;
  admin: Client;
  sessionId: string;
  runner: FakeRunner;
}

async function world(): Promise<World> {
  const admin = await login(app, undefined, 'Ada Admin');
  const org = await createOrg(admin);
  const owner = await login(app, undefined, 'Mo Member');
  await addMember(org.id, owner.user.id, 'MEMBER');
  await linkGithub(ctx, owner.user.id);
  await addApiKey(ctx, owner.user.id);
  const project = await createReadyProject(ctx, org.id, {
    env: { STRIPE_KEY: GOLDEN_PROJECT_SECRET },
    componentLabels: { 'src/components/Header*': 'the site header' },
  });
  const res = await owner.post('/api/v1/sessions', { projectId: project.id, mode: 'SIMPLE' });
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  const s = await settle(ctx, res.body.data.id as string);
  expect(s.status).toBe('RUNNING');
  const runner = await waitFor(() => runners.at(-1), { label: 'runner start' });
  await waitFor(() => ctx.agent.hasRuntime(s.id), { label: 'agent runtime' });
  return { owner, admin, sessionId: s.id, runner };
}

async function send(c: Client, sessionId: string, content: string) {
  const res = await c.post(`/api/v1/sessions/${sessionId}/messages`, { content });
  expect(res.status, JSON.stringify(res.body)).toBe(202);
  return res;
}

/** Every Simple-audience message payload's text-like fields, flattened for leak checking.
 * Only fields that are genuinely user-facing prose are collected — ids, timestamps and enum-like
 * status fields are not Simple-mode content and would produce false "leak" positives (e.g. an
 * ISO-8601 timestamp's `HH:MM:SS` segment matches the stack-trace `\w:\d+:\d+` heuristic). */
const PROSE_KEYS = new Set([
  'text',
  'content',
  'summary',
  'message',
  'reason',
  'title',
  'description',
  'plan',
]);

function simpleTextsOf(entries: Awaited<ReturnType<typeof busEvents>>): string[] {
  const out: string[] = [];
  for (const e of entries) {
    if (e.audience !== 'simple') continue;
    const payload = e.message.payload as Record<string, unknown> | undefined;
    if (!payload) continue;
    collectStrings(payload, out);
  }
  return out;
}

function collectStrings(value: unknown, out: string[], depth = 0): void {
  if (depth > 4 || !value || typeof value !== 'object') return;
  if (Array.isArray(value)) {
    for (const v of value) collectStrings(v, out, depth + 1);
    return;
  }
  for (const [key, v] of Object.entries(value)) {
    if (typeof v === 'string' && v.length > 0 && PROSE_KEYS.has(key)) {
      out.push(v);
    } else if (v && typeof v === 'object') {
      collectStrings(v, out, depth + 1);
    }
  }
}

function playGoldenTurn(r: FakeRunner, task: GoldenTask): void {
  playTurn(r, {
    ...(task.text ? { text: task.text } : {}),
    ...(task.deltas ? { deltas: task.deltas } : {}),
    tools: task.tools,
    files: task.files,
  });
}

describe('Simple Mode: 100 golden tasks never leak', () => {
  it(`fixture has exactly ${GOLDEN_TASKS.length} tasks (>= 100 required by spec §18/§21.6)`, () => {
    expect(GOLDEN_TASKS.length).toBeGreaterThanOrEqual(100);
  });

  it.each(GOLDEN_TASKS.map((t, i) => [i, t] as const))('task %i: %s', async (_i, task) => {
    const w = await world();
    script.current = (cmd, r) => {
      if (cmd.type === 'user_message') playGoldenTurn(r, task);
    };
    await send(w.owner, w.sessionId, task.prompt);
    await waitFor(
      async () =>
        (await prisma.chatMessage.count({
          where: { sessionId: w.sessionId, role: 'ASSISTANT' },
        })) >= 1,
      { label: 'assistant reply' },
    );
    await ctx.agent.idle(w.sessionId);

    const entries = await busEvents(ctx, w.sessionId);
    const texts = simpleTextsOf(entries);
    expect(texts.length).toBeGreaterThan(0);
    for (const text of texts) {
      const violations = leakCheck(text, [GOLDEN_PROJECT_SECRET]);
      expect(
        violations,
        `Simple-mode leak in task "${task.prompt}":\n${JSON.stringify(violations)}\ntext: ${text}`,
      ).toEqual([]);
    }

    // The REST transcript (what the Simple UI actually renders) must be equally clean.
    const list = await w.owner.get(`/api/v1/sessions/${w.sessionId}/messages`);
    expect(list.status).toBe(200);
    for (const m of list.body.data as { content?: string }[]) {
      if (!m.content) continue;
      expect(leakCheck(m.content, [GOLDEN_PROJECT_SECRET])).toEqual([]);
    }
  });
});
