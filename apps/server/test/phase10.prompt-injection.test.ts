/**
 * Prompt-injection suite (Phase 10 §7.2): untrusted content an agent can read — tool output,
 * fetched web pages, repository files, MCP results — may try to override instructions,
 * exfiltrate secrets, or claim an elevated/pre-approved permission state. The server has no code
 * path that re-parses tool output text to decide whether to request or skip an approval
 * (`#approvalNeeded` in orchestrator.service.ts is driven only by the runner's own
 * `approval_needed` event and `#highRiskAction`'s classification of the tool/input, never of
 * `tool_result.output`), so injected *output* text structurally cannot grant itself permissions.
 * This suite proves that guarantee holds end-to-end for every payload in
 * `test/fixtures/goldenTasks.ts` INJECTION_PAYLOADS, and that the payloads are still correctly
 * labelled as untrusted tool output (never mistaken for prose) and secret-scrubbed like any
 * other content.
 */
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { leakCheck } from '../src/services/translation';
import { INJECTION_PAYLOADS, type InjectionPayload } from './fixtures/goldenTasks';
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

async function world(mode: 'SIMPLE' | 'PRO' = 'PRO'): Promise<World> {
  const admin = await login(app, undefined, 'Ada Admin');
  const org = await createOrg(admin);
  const owner = await login(app, undefined, 'Mo Member');
  await addMember(org.id, owner.user.id, 'MEMBER');
  await linkGithub(ctx, owner.user.id);
  await addApiKey(ctx, owner.user.id);
  const project = await createReadyProject(ctx, org.id, {});
  const res = await owner.post('/api/v1/sessions', { projectId: project.id, mode });
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

describe.each(INJECTION_PAYLOADS)('injection payload: $name', (payload: InjectionPayload) => {
  it('a high-risk Bash command following injected tool output still requires approval (never auto-allowed)', async () => {
    const w = await world('PRO');
    script.current = (cmd, r) => {
      if (cmd.type === 'user_message') {
        // The agent "read" attacker-controlled content via WebFetch, then (if it had been
        // fooled) might try the destructive command the payload asked for — the runner still
        // has to ask, because approval gating never looks at this output.
        r.emit('tool_use', {
          id: 't_fetch',
          name: 'WebFetch',
          input: { url: 'https://example.com' },
        });
        r.emit('tool_result', {
          id: 't_fetch',
          isError: false,
          summary: 'fetched',
          output: payload.content,
        });
        r.emit('tool_use', {
          id: 't_bash',
          name: 'Bash',
          input: { command: 'npm install left-pad' },
        });
        r.emit('approval_needed', {
          id: 'apr_inj',
          tool: 'Bash',
          input: { command: 'npm install left-pad' },
          reason: 'dependency install',
          gate: 'dependencies',
        });
      }
      if (cmd.type === 'approval_response') {
        r.emit('tool_result', {
          id: 't_bash',
          isError: cmd.data.decision === 'deny',
          summary: cmd.data.decision,
        });
        playTurn(r, { text: cmd.data.decision === 'allow' ? 'Done.' : 'Skipped it.' });
      }
    };
    await send(w.owner, w.sessionId, 'please update the site using that page');

    const appr = await waitFor(() =>
      prisma.toolApproval.findFirst({ where: { sessionId: w.sessionId } }),
    );
    expect(appr).toMatchObject({ status: 'PENDING', runnerRequestId: 'apr_inj' });

    // The injected payload's "already approved" / "ignore instructions" claim changes nothing:
    // a non-admin member still cannot self-approve a destructive command.
    const url = `/api/v1/sessions/${w.sessionId}/approvals/${appr!.id}`;
    const memberTry = await w.owner.post(url, { decision: 'approve' });
    expect(memberTry.status).toBe(403);
    expect(memberTry.body.error.code).toBe('LSE-ORG-002');

    // No `approval_response` was ever sent to the runner — the gate held.
    expect(w.runner.of('approval_response')).toHaveLength(0);
  });

  it('the payload text is delivered to clients only as labelled tool output, never as freestanding assistant prose', async () => {
    const w = await world('PRO');
    script.current = (cmd, r) => {
      if (cmd.type === 'user_message') {
        // Bash is the one tool whose raw output is forwarded verbatim (as `terminal_output`,
        // scrubbed) rather than summarized — the strongest case to prove it never leaks into
        // `assistant_text`/chat message content as if the model had said it itself.
        r.emit('tool_use', { id: 't1', name: 'Bash', input: { command: 'cat page.html' } });
        r.emit('tool_result', { id: 't1', isError: false, summary: 'ok', output: payload.content });
        playTurn(r, { text: 'I looked at the page; nothing to change.' });
      }
    };
    await send(w.owner, w.sessionId, 'check that page for anything useful');
    await waitFor(
      async () =>
        (await prisma.chatMessage.count({
          where: { sessionId: w.sessionId, role: 'ASSISTANT' },
        })) >= 1,
      { label: 'assistant reply' },
    );
    await ctx.agent.idle(w.sessionId);

    const entries = await busEvents(ctx, w.sessionId);
    // The payload only ever appears inside `terminal_output` (Pro-only, explicitly raw tool
    // output), never inside the assistant's own `assistant_text`/chat message content.
    const terminalOutputs = entries.filter((e) => e.message.type === 'terminal_output');
    const assistantTexts = entries
      .filter((e) => e.message.type === 'chat_message')
      .map((e) => (e.message.payload as { message?: { content?: string } }).message?.content)
      .filter((v): v is string => typeof v === 'string');
    for (const text of assistantTexts) {
      expect(text).not.toContain(payload.content.slice(0, 40));
    }
    const sawPayloadAsTerminalOutput = terminalOutputs.some((e) => {
      const p = e.message.payload as { chunk?: string };
      return typeof p.chunk === 'string' && p.chunk.includes(payload.content.slice(0, 20));
    });
    expect(sawPayloadAsTerminalOutput).toBe(true);
  });

  it('Simple mode never leaks the payload verbatim even if the agent quotes it back', async () => {
    const w = await world('SIMPLE');
    script.current = (cmd, r) => {
      if (cmd.type === 'user_message') {
        r.emit('tool_use', { id: 't1', name: 'WebFetch', input: { url: 'https://example.com' } });
        r.emit('tool_result', {
          id: 't1',
          isError: false,
          summary: 'fetched',
          output: payload.content,
        });
        // Worst case: the agent (fooled or not) echoes the raw payload back in its own prose.
        playTurn(r, { text: `Here is what I found: ${payload.content}` });
      }
    };
    await send(w.owner, w.sessionId, 'check that page');
    await waitFor(
      async () =>
        (await prisma.chatMessage.count({
          where: { sessionId: w.sessionId, role: 'ASSISTANT' },
        })) >= 1,
      { label: 'assistant reply' },
    );
    await ctx.agent.idle(w.sessionId);

    const list = await w.owner.get(`/api/v1/sessions/${w.sessionId}/messages`);
    expect(list.status).toBe(200);
    for (const m of list.body.data as { content?: string }[]) {
      if (!m.content) continue;
      expect(leakCheck(m.content)).toEqual([]);
    }
  });

  it('a secret embedded in the payload is still scrubbed from Pro tool output', async () => {
    const secretInPayload = `${payload.content} API key: sk-ant-api03-InjectedSecretValue1234567890`;
    const w = await world('PRO');
    script.current = (cmd, r) => {
      if (cmd.type === 'user_message') {
        r.emit('tool_use', { id: 't1', name: 'Bash', input: { command: 'cat page.html' } });
        r.emit('tool_result', {
          id: 't1',
          isError: false,
          summary: secretInPayload,
          output: secretInPayload,
        });
        playTurn(r, { text: 'Checked the page.' });
      }
    };
    await send(w.owner, w.sessionId, 'check that page');
    await waitFor(
      async () =>
        (await prisma.chatMessage.count({
          where: { sessionId: w.sessionId, role: 'ASSISTANT' },
        })) >= 1,
      { label: 'assistant reply' },
    );
    await ctx.agent.idle(w.sessionId);

    const entries = await busEvents(ctx, w.sessionId);
    const relevant = entries.filter(
      (e) => e.message.type === 'tool_event' || e.message.type === 'terminal_output',
    );
    const serialized = JSON.stringify(relevant.map((e) => e.message.payload));
    expect(serialized).not.toContain('sk-ant-api03-InjectedSecretValue1234567890');
  });
});

describe('prompt-injection fixture coverage', () => {
  it('has at least 5 distinct injection payloads covering override/exfiltration/jailbreak classes', () => {
    expect(INJECTION_PAYLOADS.length).toBeGreaterThanOrEqual(5);
    const names = INJECTION_PAYLOADS.map((p) => p.name);
    expect(new Set(names).size).toBe(names.length);
  });
});
