/**
 * Anthropic adapter. Key validation uses `GET /v1/models?limit=1`, which is
 * free (no tokens consumed).
 */
import { ANTHROPIC_API_VERSION, API_KEY_VALIDATION_TIMEOUT_MS } from '@loose/shared';
import type { KeyValidationResult, ModelInfo, ProviderAdapter, TokenUsage } from './adapter';

export const ANTHROPIC_API_BASE = 'https://api.anthropic.com';

/** Static pricing table (USD / MTok). Approximate; refreshed manually. */
export const ANTHROPIC_MODELS: readonly ModelInfo[] = Object.freeze([
  {
    id: 'claude-opus-4-1',
    displayName: 'Claude Opus 4.1',
    contextWindow: 200_000,
    inputPerMTokUsd: 15,
    outputPerMTokUsd: 75,
    cacheReadPerMTokUsd: 1.5,
  },
  {
    id: 'claude-sonnet-4-5',
    displayName: 'Claude Sonnet 4.5',
    contextWindow: 200_000,
    inputPerMTokUsd: 3,
    outputPerMTokUsd: 15,
    cacheReadPerMTokUsd: 0.3,
  },
  {
    id: 'claude-haiku-4-5',
    displayName: 'Claude Haiku 4.5',
    contextWindow: 200_000,
    inputPerMTokUsd: 1,
    outputPerMTokUsd: 5,
    cacheReadPerMTokUsd: 0.1,
  },
]);

export interface AnthropicAdapterOptions {
  fetch?: typeof fetch;
  baseUrl?: string;
  timeoutMs?: number;
}

export class AnthropicAdapter implements ProviderAdapter {
  readonly id = 'anthropic' as const;
  readonly #fetch: typeof fetch;
  readonly #baseUrl: string;
  readonly #timeoutMs: number;

  constructor(opts: AnthropicAdapterOptions = {}) {
    this.#fetch = opts.fetch ?? globalThis.fetch;
    this.#baseUrl = opts.baseUrl ?? ANTHROPIC_API_BASE;
    this.#timeoutMs = opts.timeoutMs ?? API_KEY_VALIDATION_TIMEOUT_MS;
  }

  listModels(): readonly ModelInfo[] {
    return ANTHROPIC_MODELS;
  }

  async validateKey(apiKey: string): Promise<KeyValidationResult> {
    let res: Response;
    try {
      res = await this.#fetch(`${this.#baseUrl}/v1/models?limit=1`, {
        method: 'GET',
        headers: {
          'x-api-key': apiKey,
          'anthropic-version': ANTHROPIC_API_VERSION,
          accept: 'application/json',
        },
        signal: AbortSignal.timeout(this.#timeoutMs),
      });
    } catch (err) {
      const name = (err as { name?: string } | null)?.name;
      if (name === 'TimeoutError' || name === 'AbortError') {
        return {
          ok: false,
          reason: 'timeout',
          devMessage: `Anthropic did not answer within ${this.#timeoutMs}ms`,
        };
      }
      return { ok: false, reason: 'network', devMessage: 'Network error reaching Anthropic' };
    }
    // Drain the body; only the provider's error *type* is reported, never echoed content.
    const errorType = await readErrorType(res);
    const status = res.status;
    const detail = `Anthropic ${status}${errorType ? ` ${errorType}` : ''}`;
    if (res.ok) return { ok: true };
    if (status === 401)
      return { ok: false, reason: 'invalid', httpStatus: status, devMessage: detail };
    if (status === 403)
      return { ok: false, reason: 'permission', httpStatus: status, devMessage: detail };
    if (status === 429)
      return { ok: false, reason: 'rate_limited', httpStatus: status, devMessage: detail };
    if (status === 529 || status === 503) {
      return { ok: false, reason: 'overloaded', httpStatus: status, devMessage: detail };
    }
    return { ok: false, reason: 'server_error', httpStatus: status, devMessage: detail };
  }

  estimateCost(model: string, usage: TokenUsage): number {
    const m =
      ANTHROPIC_MODELS.find((x) => model === x.id || model.startsWith(`${x.id}-`)) ??
      ANTHROPIC_MODELS.reduce((a, b) => (b.outputPerMTokUsd > a.outputPerMTokUsd ? b : a));
    const cost =
      (usage.tokensIn * m.inputPerMTokUsd +
        usage.tokensOut * m.outputPerMTokUsd +
        (usage.cacheRead ?? 0) * m.cacheReadPerMTokUsd) /
      1_000_000;
    return Math.round(cost * 1_000_000) / 1_000_000;
  }

  toAgentEnv(apiKey: string): Record<string, string> {
    return { ANTHROPIC_API_KEY: apiKey };
  }
}

async function readErrorType(res: Response): Promise<string | undefined> {
  try {
    const text = await res.text();
    if (res.ok || !text) return undefined;
    const json = JSON.parse(text) as { error?: { type?: unknown } };
    const t = json.error?.type;
    return typeof t === 'string' && /^[a-z_]{1,64}$/.test(t) ? t : undefined;
  } catch {
    return undefined;
  }
}
