/**
 * Idempotency-Key support for resource-creating POSTs (spec §10, §16.4).
 * Scope: user + exact path + key, 24h. Same key + same body → stored response
 * is replayed (header `Idempotent-Replayed: true`); same key + different body
 * (or a still-running original) → LSE-VAL-004. Only 2xx responses are kept.
 * Stored responses are envelope-encrypted (they may contain one-time tokens).
 */
import type { RequestHandler } from 'express';
import { IDEMPOTENCY_HEADER, IDEMPOTENCY_TTL_SECONDS } from '@loose/shared';
import type { AppContext } from '../context';
import { sha256Hex } from '../lib/crypto';
import { AppError } from '../lib/errors';

const KEY_REGEX = /^[A-Za-z0-9_\-:.]{1,255}$/;

interface PendingRecord {
  state: 'pending';
  bodyHash: string;
}
interface DoneRecord {
  state: 'done';
  bodyHash: string;
  status: number;
  /** base64 of the encrypted packed JSON body */
  body: string;
}
type StoredRecord = PendingRecord | DoneRecord;

export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`).join(',')}}`;
}

export function idempotency(ctx: AppContext): RequestHandler {
  return async (req, res, next) => {
    const key = req.get(IDEMPOTENCY_HEADER);
    if (key === undefined) return next();
    if (!KEY_REGEX.test(key)) {
      throw new AppError('LSE-VAL-001', {
        fields: { [`headers.${IDEMPOTENCY_HEADER}`]: ['Use 1-255 letters, digits, - _ : .'] },
        devMessage: 'Invalid Idempotency-Key',
      });
    }
    const userId = req.auth?.user.id ?? 'anonymous';
    const path = req.originalUrl.split('?')[0] ?? '';
    const storeKey = `idem:${sha256Hex(`${userId}|${req.method}|${path}|${key}`)}`;
    const bodyHash = sha256Hex(stableStringify(req.body ?? null));

    let existingRaw: string | null;
    try {
      existingRaw = await ctx.kv.get(storeKey);
    } catch (err) {
      ctx.logger.warn({ err }, 'idempotency store unavailable; proceeding without it');
      return next();
    }

    if (existingRaw) {
      const rec = JSON.parse(existingRaw) as StoredRecord;
      if (rec.bodyHash !== bodyHash) {
        throw new AppError('LSE-VAL-004', {
          devMessage: 'Idempotency-Key reused with a different body',
        });
      }
      if (rec.state === 'pending') {
        throw new AppError('LSE-VAL-004', {
          devMessage: 'A request with this Idempotency-Key is still in progress',
          retryable: true,
        });
      }
      const body = JSON.parse(
        await ctx.crypto.decryptPackedString(Buffer.from(rec.body, 'base64'), 'generic'),
      ) as unknown;
      res.setHeader('Idempotent-Replayed', 'true');
      res.status(rec.status).json(body);
      return;
    }

    const pending: PendingRecord = { state: 'pending', bodyHash };
    const acquired = await ctx.kv.setIfAbsent(
      storeKey,
      JSON.stringify(pending),
      IDEMPOTENCY_TTL_SECONDS,
    );
    if (!acquired) {
      throw new AppError('LSE-VAL-004', {
        devMessage: 'A request with this Idempotency-Key is still in progress',
        retryable: true,
      });
    }

    let settled = false;
    const release = () => {
      if (settled) return;
      settled = true;
      void ctx.kv.del(storeKey).catch(() => undefined);
    };
    const originalJson = res.json.bind(res);
    res.json = (body: unknown) => {
      if (settled) return originalJson(body);
      settled = true;
      const status = res.statusCode;
      if (status < 200 || status >= 300) {
        void ctx.kv.del(storeKey).catch(() => undefined);
        return originalJson(body);
      }
      // Persist before responding so an immediate retry is replayed, not rejected.
      void (async () => {
        const enc = await ctx.crypto.encryptPacked(JSON.stringify(body), 'generic');
        const done: DoneRecord = {
          state: 'done',
          bodyHash,
          status,
          body: Buffer.from(enc).toString('base64'),
        };
        await ctx.kv.set(storeKey, JSON.stringify(done), IDEMPOTENCY_TTL_SECONDS);
      })()
        .catch((err: unknown) => {
          ctx.logger.warn({ err }, 'failed to store idempotent response');
          void ctx.kv.del(storeKey).catch(() => undefined);
        })
        .finally(() => originalJson(body));
      return res;
    };
    res.on('close', release);
    next();
  };
}
