/** Helpers for template/session tests (FakeSandboxProvider + FakeTemplateBuilder). */
import type { Prisma } from '@prisma/client';
import { expect } from 'vitest';
import type { AppContext } from '../src/context';
import { bytes } from '../src/lib/crypto';
import {
  innerProvider,
  type FakeSandboxProvider,
  type FakeTemplateBuilder,
} from '../src/lib/sandbox';

export function fakeSandbox(ctx: AppContext): FakeSandboxProvider {
  const p = innerProvider<FakeSandboxProvider>(ctx.sandbox);
  expect(p.kind).toBe('fake');
  return p;
}

export function fakeBuilder(ctx: AppContext): FakeTemplateBuilder {
  expect(ctx.templateBuilder.kind).toBe('fake');
  return ctx.templateBuilder as FakeTemplateBuilder;
}

export const DUMMY_ANTHROPIC_KEY = 'sk-ant-api03-test-dummy-key-0000000000';

export async function addApiKey(
  ctx: AppContext,
  userId: string,
  status: 'ACTIVE' | 'INVALID' | 'REVOKED' = 'ACTIVE',
  extra: Partial<Prisma.ApiKeyUncheckedCreateInput> = {},
) {
  const enc = await ctx.crypto.encrypt(DUMMY_ANTHROPIC_KEY, 'api-key');
  return ctx.prisma.apiKey.create({
    data: {
      userId,
      keyEnc: bytes(enc.ciphertext),
      dataKeyEnc: bytes(enc.wrappedKey),
      iv: bytes(enc.iv),
      last4: '0000',
      status,
      ...extra,
    },
  });
}

export async function createReadyProject(
  ctx: AppContext,
  orgId: string,
  opts: { env?: Record<string, string> } & Partial<Prisma.ProjectUncheckedCreateInput> = {},
) {
  const { env = {}, ...extra } = opts;
  return ctx.prisma.project.create({
    data: {
      orgId,
      name: 'Web',
      githubRepoFullName: 'acme/web',
      githubRepoUrl: 'https://github.com/acme/web',
      defaultBranch: 'main',
      envVarsEnc: await ctx.crypto.encryptPacked(JSON.stringify(env), 'project-env'),
      envVarMeta: Object.keys(env).map((name) => ({ name, secret: true })),
      templateStatus: 'READY',
      templateVersion: 1,
      e2bTemplateId: 'tpl-ready-1',
      ...extra,
    },
  });
}

/** Wait for inline jobs, then return the session row. */
export async function settle(ctx: AppContext, sessionId: string) {
  await ctx.jobs.onIdle();
  return ctx.prisma.session.findUniqueOrThrow({ where: { id: sessionId } });
}
