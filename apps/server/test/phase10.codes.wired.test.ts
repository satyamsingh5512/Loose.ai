import type { ServerPayload } from '@loose/shared';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { busEvents, installFakeRunner, waitFor, type FakeRunner } from './agentHelpers';
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
let runners: FakeRunner[] = [];

async function createSession(client: Client, projectId: string): Promise<string> {
  const res = await client.post('/api/v1/sessions', { projectId });
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  return res.body.data.id as string;
}

async function projectWorld() {
  const owner = await login(app, undefined, 'Ada Owner');
  const org = await createOrg(owner);
  await linkGithub(ctx, owner.user.id);
  await addApiKey(ctx, owner.user.id);
  const project = await createReadyProject(ctx, org.id);
  return { owner, org, project };
}

afterAll(async () => {
  await ctx.agent.idle();
  await ctx.jobs.onIdle();
  await prisma.$disconnect();
});

beforeEach(async () => {
  await ctx.agent.shutdownAll();
  await ctx.jobs.onIdle();
  fake.reset();
  runners = installFakeRunner(fake, { current: () => undefined });
  await resetDb();
});

describe('wired Phase 10 catalog codes', () => {
  it('LSE-TPL-008: an outdated ready template emits a recoverable error event without interrupting blue/green provisioning', async () => {
    const { owner, project } = await projectWorld();
    await prisma.project.update({ where: { id: project.id }, data: { templateSpecHash: 'stale' } });

    const sessionId = await createSession(owner, project.id);
    const events = await busEvents(ctx, sessionId);
    const error = events.find((event) => event.message.type === 'error');
    expect(error?.message.payload).toMatchObject({
      error: { code: 'LSE-TPL-008' },
      recoverable: true,
    });
    expect((await settle(ctx, sessionId)).status).toBe('RUNNING');
  });

  it('LSE-SBX-014: another active session emits a typed conflict warning event', async () => {
    const { owner, org, project } = await projectWorld();
    const other = await login(app, undefined, 'Bob Collaborator');
    await addMember(org.id, other.user.id, 'MEMBER');
    await linkGithub(ctx, other.user.id);
    await addApiKey(ctx, other.user.id);

    await createSession(owner, project.id);
    const secondSessionId = await createSession(other, project.id);
    const events = await busEvents(ctx, secondSessionId);
    const warning = events.find((event) => event.message.type === 'conflict_warning');
    expect(warning?.message.payload).toMatchObject({ code: 'LSE-SBX-014' });
  });

  it('LSE-MCP-006: a runner policy denial reaches the session as its catalogued error event', async () => {
    const { owner, project } = await projectWorld();
    const sessionId = await createSession(owner, project.id);
    await settle(ctx, sessionId);
    await waitFor(() => ctx.agent.hasRuntime(sessionId), { label: 'agent runtime' });

    runners.at(-1)!.emit('error', { code: 'LSE-MCP-006', detail: 'tool disabled by policy' });
    await waitFor(
      async () => (await busEvents(ctx, sessionId)).some((event) => event.message.type === 'error'),
      { label: 'MCP denial event' },
    );
    const events = await busEvents(ctx, sessionId);
    const error = events.find((event) => event.message.type === 'error');
    const payload = error?.message.payload as ServerPayload<'error'> | undefined;
    expect(payload?.error.code).toBe('LSE-MCP-006');
  });

  it('LSE-MCP-008: runner duplicate-name status is forwarded in the MCP status event', async () => {
    const { owner, project } = await projectWorld();
    const sessionId = await createSession(owner, project.id);
    await settle(ctx, sessionId);
    await waitFor(() => ctx.agent.hasRuntime(sessionId), { label: 'agent runtime' });

    runners.at(-1)!.emit('mcp_status', {
      servers: [
        { name: 'duplicate', status: 'failed', error: 'LSE-MCP-008: duplicate server name' },
      ],
    });
    await waitFor(
      async () =>
        (await busEvents(ctx, sessionId)).some((event) => event.message.type === 'mcp_status'),
      { label: 'MCP status event' },
    );
    const events = await busEvents(ctx, sessionId);
    const status = events.find((event) => event.message.type === 'mcp_status');
    const payload = status?.message.payload as ServerPayload<'mcp_status'> | undefined;
    expect(payload?.servers[0]?.error).toContain('LSE-MCP-008');
  });
});
