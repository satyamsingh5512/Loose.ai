/**
 * Model provider adapter (spec §8.1). BYOK only: adapters validate a user's key
 * and translate it for the agent runtime, but never persist or log it.
 */
import type { ModelProvider } from '@loose/shared';

export interface ModelInfo {
  id: string;
  displayName: string;
  contextWindow: number;
  /** USD per million input tokens. */
  inputPerMTokUsd: number;
  /** USD per million output tokens. */
  outputPerMTokUsd: number;
  /** USD per million cache-read tokens. */
  cacheReadPerMTokUsd: number;
}

export interface TokenUsage {
  tokensIn: number;
  tokensOut: number;
  cacheRead?: number;
}

export type KeyValidationFailure =
  | 'invalid' // 401
  | 'permission' // 403
  | 'rate_limited' // 429
  | 'overloaded' // 529 / 503
  | 'server_error' // other 5xx / unexpected
  | 'timeout'
  | 'network';

export type KeyValidationResult =
  | { ok: true }
  | { ok: false; reason: KeyValidationFailure; httpStatus?: number; devMessage: string };

export interface ProviderAdapter {
  readonly id: ModelProvider;
  listModels(): readonly ModelInfo[];
  /** Live check that costs no tokens. Must never include the key in devMessage. */
  validateKey(apiKey: string): Promise<KeyValidationResult>;
  /** Estimated cost in USD; unknown models use the most expensive known price. */
  estimateCost(model: string, usage: TokenUsage): number;
  /** Environment variables the agent runner needs to use this key. */
  toAgentEnv(apiKey: string): Record<string, string>;
}
