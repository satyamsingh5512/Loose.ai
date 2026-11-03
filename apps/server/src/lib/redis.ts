/**
 * Redis connection + a tiny key/value abstraction used by idempotency.
 * In tests an in-memory store is used so suites don't need Redis.
 */
import { Redis } from 'ioredis';
import type { Logger } from './logger';

export type { Redis };

export function createRedis(url: string, logger: Logger): Redis {
  const redis = new Redis(url, {
    lazyConnect: false,
    maxRetriesPerRequest: 2,
    enableOfflineQueue: true,
  });
  // ioredis emits 'error' on every reconnect attempt; log without crashing.
  redis.on('error', (err) => logger.warn({ err: { message: err.message } }, 'redis error'));
  return redis;
}

export interface KvStore {
  get(key: string): Promise<string | null>;
  /** SET key value EX ttl NX — resolves true when the key was set. */
  setIfAbsent(key: string, value: string, ttlSeconds: number): Promise<boolean>;
  set(key: string, value: string, ttlSeconds: number): Promise<void>;
  del(key: string): Promise<void>;
}

export class RedisKvStore implements KvStore {
  constructor(private readonly redis: Redis) {}
  get(key: string) {
    return this.redis.get(key);
  }
  async setIfAbsent(key: string, value: string, ttlSeconds: number) {
    return (await this.redis.set(key, value, 'EX', ttlSeconds, 'NX')) === 'OK';
  }
  async set(key: string, value: string, ttlSeconds: number) {
    await this.redis.set(key, value, 'EX', ttlSeconds);
  }
  async del(key: string) {
    await this.redis.del(key);
  }
}

export class MemoryKvStore implements KvStore {
  readonly #map = new Map<string, { value: string; expiresAt: number }>();

  #live(key: string) {
    const e = this.#map.get(key);
    if (e && e.expiresAt <= Date.now()) {
      this.#map.delete(key);
      return undefined;
    }
    return e;
  }
  async get(key: string) {
    return this.#live(key)?.value ?? null;
  }
  async setIfAbsent(key: string, value: string, ttlSeconds: number) {
    if (this.#live(key)) return false;
    this.#map.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
    return true;
  }
  async set(key: string, value: string, ttlSeconds: number) {
    this.#map.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
  }
  async del(key: string) {
    this.#map.delete(key);
  }
}
