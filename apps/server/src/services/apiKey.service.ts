/**
 * BYOK API keys (spec §8.1). Keys are live-validated, envelope-encrypted and
 * only ever exposed as metadata (provider, label, last4, status).
 */
import type { ApiKey } from '@prisma/client';
import {
  apiKeyDtoSchema,
  last4,
  type ApiKeyDto,
  type CreateApiKeyBody,
  type ErrorCode,
} from '@loose/shared';
import type { AppContext } from '../context';
import { bytes } from '../lib/crypto';
import { AppError } from '../lib/errors';
import type { KeyValidationFailure, ProviderAdapter } from '../providers/adapter';

export function toApiKeyDto(row: ApiKey): ApiKeyDto {
  return apiKeyDtoSchema.parse(row);
}

const FAILURE_CODES: Record<KeyValidationFailure, ErrorCode> = {
  invalid: 'LSE-KEY-011',
  permission: 'LSE-KEY-004',
  rate_limited: 'LSE-KEY-005',
  overloaded: 'LSE-KEY-006',
  server_error: 'LSE-KEY-009',
  timeout: 'LSE-KEY-010',
  network: 'LSE-KEY-010',
};

function adapterFor(ctx: AppContext, provider: string): ProviderAdapter {
  if (provider === 'anthropic') return ctx.providers.anthropic;
  throw new AppError('LSE-KEY-013', { devMessage: `Unsupported provider ${provider}` });
}

/** Map a failed validation to an error; `mode` decides the code for 401. */
function validationError(
  reason: KeyValidationFailure,
  devMessage: string,
  mode: 'create' | 'revalidate',
): AppError {
  const code =
    reason === 'invalid' && mode === 'revalidate' ? 'LSE-KEY-003' : FAILURE_CODES[reason];
  return new AppError(code, { devMessage });
}

export async function listApiKeys(ctx: AppContext, userId: string): Promise<ApiKeyDto[]> {
  const rows = await ctx.prisma.apiKey.findMany({
    where: { userId, orgId: null },
    orderBy: { createdAt: 'desc' },
  });
  return rows.map(toApiKeyDto);
}

export async function createApiKey(
  ctx: AppContext,
  userId: string,
  body: CreateApiKeyBody,
  ip?: string,
): Promise<ApiKeyDto> {
  const adapter = adapterFor(ctx, body.provider);
  const result = await adapter.validateKey(body.key);
  if (!result.ok) throw validationError(result.reason, result.devMessage, 'create');

  const enc = await ctx.crypto.encrypt(body.key, 'api-key');
  // P10-SEC-011: a stored key never exists without its audit row.
  const row = await ctx.prisma.$transaction(
    async (tx) => {
      const created = await tx.apiKey.create({
        data: {
          userId,
          provider: body.provider,
          label: body.label ?? null,
          keyEnc: bytes(enc.ciphertext),
          dataKeyEnc: bytes(enc.wrappedKey),
          iv: bytes(enc.iv),
          last4: last4(body.key),
          status: 'ACTIVE',
          lastValidatedAt: new Date(),
        },
      });
      await ctx.audit.record(
        {
          actorId: userId,
          action: 'api_key.create',
          target: created.id,
          meta: { provider: created.provider, last4: created.last4, label: created.label },
          ip,
        },
        tx,
      );
      return created;
    },
    { maxWait: 10_000, timeout: 15_000 },
  );
  return toApiKeyDto(row);
}

async function findOwnKey(ctx: AppContext, userId: string, id: string): Promise<ApiKey> {
  const row = await ctx.prisma.apiKey.findFirst({ where: { id, userId } });
  if (!row) throw new AppError('LSE-NF-001', { devMessage: 'API key not found' });
  return row;
}

/** Decrypt a stored key. Only for handing to the agent runtime — never return it. */
export async function decryptApiKey(ctx: AppContext, row: ApiKey): Promise<string> {
  return ctx.crypto.decryptString(
    {
      ciphertext: Buffer.from(row.keyEnc),
      wrappedKey: Buffer.from(row.dataKeyEnc),
      iv: Buffer.from(row.iv),
    },
    'api-key',
  );
}

export async function revalidateApiKey(
  ctx: AppContext,
  userId: string,
  id: string,
  ip?: string,
): Promise<ApiKeyDto> {
  const row = await findOwnKey(ctx, userId, id);
  const key = await decryptApiKey(ctx, row);
  const result = await adapterFor(ctx, row.provider).validateKey(key);
  if (result.ok) {
    const updated = await ctx.prisma.apiKey.update({
      where: { id: row.id },
      data: { status: 'ACTIVE', lastValidatedAt: new Date() },
    });
    await ctx.audit.record({
      actorId: userId,
      action: 'api_key.revalidate',
      target: row.id,
      meta: { status: 'ACTIVE' },
      ip,
    });
    return toApiKeyDto(updated);
  }
  if (result.reason === 'invalid') {
    await ctx.prisma.apiKey.update({
      where: { id: row.id },
      data: { status: 'INVALID', lastValidatedAt: new Date() },
    });
    await ctx.audit.record({
      actorId: userId,
      action: 'api_key.revalidate',
      target: row.id,
      meta: { status: 'INVALID' },
      ip,
    });
  }
  // Transient failures (429/5xx/timeout) leave the stored status untouched.
  throw validationError(result.reason, result.devMessage, 'revalidate');
}

export async function deleteApiKey(
  ctx: AppContext,
  userId: string,
  id: string,
  ip?: string,
): Promise<void> {
  const row = await findOwnKey(ctx, userId, id);
  await ctx.prisma.$transaction(
    async (tx) => {
      await tx.apiKey.delete({ where: { id: row.id } });
      await ctx.audit.record(
        {
          actorId: userId,
          action: 'api_key.delete',
          target: row.id,
          meta: { provider: row.provider, last4: row.last4 },
          ip,
        },
        tx,
      );
    },
    { maxWait: 10_000, timeout: 15_000 },
  );
}
