/**
 * Artifact object storage (screenshots, logs, diffs). Content is only ever served
 * through auth-checked API routes; keys are never exposed to clients.
 * - LocalObjectStorage: files under ARTIFACT_DIR (default ./.data/artifacts, gitignored)
 * - S3ObjectStorage: S3 / MinIO (Phase 10, spec §19; `ARTIFACT_STORAGE=s3`). AWS SDK v3, loaded
 *   lazily so the local backend never pays for it. Storage failures surface as LSE-SYS-008.
 */
import { createReadStream } from 'node:fs';
import { mkdir, rm, stat, writeFile } from 'node:fs/promises';
import { dirname, join, resolve, sep } from 'node:path';
import type { Readable } from 'node:stream';
import type { S3Client } from '@aws-sdk/client-s3';
import type * as S3ClientModule from '@aws-sdk/client-s3';
import type { Env } from '../config/env';
import { AppError } from './errors';

export interface StoredObject {
  stream: Readable;
  bytes: number;
}

export interface PutOptions {
  /** Stored as the object's Content-Type where the backend supports it (S3). */
  contentType?: string;
}

export interface SignedUrlOptions {
  /** Link lifetime in seconds (S3 backend clamps to 30–3600; default `S3_SIGNED_URL_TTL_SEC`). */
  ttlSec?: number;
  /** Forces `Content-Disposition: attachment; filename=…` on the download. */
  filename?: string;
  contentType?: string;
}

export interface ObjectStorage {
  put(key: string, data: Uint8Array | string, opts?: PutOptions): Promise<{ bytes: number }>;
  get(key: string): Promise<StoredObject | null>;
  delete(key: string): Promise<void>;
  /**
   * Short-lived direct-download URL, or null when the backend can't offer one (local disk): callers
   * then stream through the API. Never log or persist the returned URL.
   */
  signedUrl?(key: string, opts?: SignedUrlOptions): Promise<string | null>;
  /** Cheap reachability probe (readiness checks). Throws LSE-SYS-008 when storage is down. */
  ping?(): Promise<void>;
}

function storageUnavailable(op: string, err: unknown): AppError {
  const name = err instanceof Error ? err.name : 'Error';
  const code = (err as { code?: unknown } | null)?.code;
  return new AppError('LSE-SYS-008', {
    devMessage: `Object storage ${op} failed (${typeof code === 'string' ? code : name})`,
    cause: err,
  });
}

/** Keys look like `sessions/<sessionId>/<artifactId>.png`. */
const KEY_RE = /^[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_.-]+)*$/;

export function assertSafeKey(key: string): void {
  if (!KEY_RE.test(key) || key.split('/').some((s) => s === '..' || s === '.')) {
    throw new AppError('LSE-SYS-001', { devMessage: 'Invalid storage key' });
  }
}

export class LocalObjectStorage implements ObjectStorage {
  readonly root: string;

  constructor(dir: string) {
    this.root = resolve(dir);
  }

  #path(key: string) {
    assertSafeKey(key);
    const p = resolve(join(this.root, key));
    if (!p.startsWith(this.root + sep)) {
      throw new AppError('LSE-SYS-001', { devMessage: 'Storage key escapes the root' });
    }
    return p;
  }

  async put(key: string, data: Uint8Array | string) {
    const p = this.#path(key);
    try {
      await mkdir(dirname(p), { recursive: true });
      await writeFile(p, data, { mode: 0o600 });
    } catch (err) {
      throw storageUnavailable('put', err);
    }
    return { bytes: typeof data === 'string' ? Buffer.byteLength(data) : data.byteLength };
  }

  async get(key: string): Promise<StoredObject | null> {
    const p = this.#path(key);
    try {
      const s = await stat(p);
      if (!s.isFile()) return null;
      return { stream: createReadStream(p), bytes: s.size };
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'ENOENT' || code === 'ENOTDIR') return null;
      throw storageUnavailable('get', err);
    }
  }

  async delete(key: string) {
    try {
      await rm(this.#path(key), { force: true });
    } catch (err) {
      throw storageUnavailable('delete', err);
    }
  }

  async ping() {
    try {
      await mkdir(this.root, { recursive: true });
    } catch (err) {
      throw storageUnavailable('ping', err);
    }
  }
}

/** S3 / MinIO settings (from env `S3_*`, see config/env.ts). */
export interface S3StorageConfig {
  bucket: string;
  region: string;
  endpoint?: string | undefined;
  accessKeyId?: string | undefined;
  secretAccessKey?: string | undefined;
  forcePathStyle: boolean;
  /** Key prefix inside the bucket ('' or ending with '/'). */
  prefix: string;
  signedUrlTtlSec: number;
}

export function s3ConfigFromEnv(env: Env): S3StorageConfig {
  const prefix = env.S3_PREFIX
    ? env.S3_PREFIX.endsWith('/')
      ? env.S3_PREFIX
      : `${env.S3_PREFIX}/`
    : '';
  return {
    bucket: env.S3_BUCKET ?? '',
    region: env.S3_REGION,
    endpoint: env.S3_ENDPOINT,
    accessKeyId: env.S3_ACCESS_KEY_ID,
    secretAccessKey: env.S3_SECRET_ACCESS_KEY,
    forcePathStyle: env.S3_FORCE_PATH_STYLE,
    prefix,
    signedUrlTtlSec: env.S3_SIGNED_URL_TTL_SEC,
  };
}

type S3Sdk = typeof S3ClientModule;
type S3ClientLike = S3Client;

/** Configured default TTLs are clamped to [30, 3600]; an explicit shorter request is honoured (min 1 s). */
const SIGNED_URL_MIN_SEC = 30;
const SIGNED_URL_ABSOLUTE_MIN_SEC = 1;
const SIGNED_URL_MAX_SEC = 3600;
const S3_CONNECT_TIMEOUT_MS = 5_000;
const S3_REQUEST_TIMEOUT_MS = 60_000;

function isNotFound(err: unknown): boolean {
  const e = err as { name?: string; $metadata?: { httpStatusCode?: number } } | null;
  return e?.name === 'NoSuchKey' || e?.name === 'NotFound' || e?.$metadata?.httpStatusCode === 404;
}

/** `Content-Disposition` value that is safe in a header (no quotes, CR/LF or path separators). */
export function attachmentDisposition(filename: string): string {
  const safe = filename.replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 120) || 'download';
  return `attachment; filename="${safe}"`;
}

export class S3ObjectStorage implements ObjectStorage {
  #sdk: S3Sdk | undefined;
  #client: S3ClientLike | undefined;

  /** `deps.client` lets tests inject a pre-configured client (e.g. one pointed at a fake S3). */
  constructor(
    readonly config: S3StorageConfig,
    deps: { client?: S3ClientLike } = {},
  ) {
    this.#client = deps.client;
  }

  async #sdkAndClient(): Promise<{ sdk: S3Sdk; client: S3ClientLike }> {
    this.#sdk ??= await import('@aws-sdk/client-s3');
    if (!this.#client) {
      const c = this.config;
      this.#client = new this.#sdk.S3Client({
        region: c.region,
        ...(c.endpoint ? { endpoint: c.endpoint } : {}),
        forcePathStyle: c.forcePathStyle,
        ...(c.accessKeyId && c.secretAccessKey
          ? { credentials: { accessKeyId: c.accessKeyId, secretAccessKey: c.secretAccessKey } }
          : {}),
        maxAttempts: 3,
        // S3-compatible stores (MinIO, R2, …) reject the default CRC32 trailer on some versions.
        requestChecksumCalculation: 'WHEN_REQUIRED',
        responseChecksumValidation: 'WHEN_REQUIRED',
        requestHandler: {
          connectionTimeout: S3_CONNECT_TIMEOUT_MS,
          requestTimeout: S3_REQUEST_TIMEOUT_MS,
        },
      });
    }
    return { sdk: this.#sdk, client: this.#client };
  }

  #objectKey(key: string): string {
    assertSafeKey(key);
    return `${this.config.prefix}${key}`;
  }

  async put(key: string, data: Uint8Array | string, opts: PutOptions = {}) {
    const Key = this.#objectKey(key);
    const body = typeof data === 'string' ? Buffer.from(data) : data;
    try {
      const { sdk, client } = await this.#sdkAndClient();
      await client.send(
        new sdk.PutObjectCommand({
          Bucket: this.config.bucket,
          Key,
          Body: body,
          ContentLength: body.byteLength,
          ...(opts.contentType ? { ContentType: opts.contentType } : {}),
        }),
      );
    } catch (err) {
      throw storageUnavailable('put', err);
    }
    return { bytes: body.byteLength };
  }

  async get(key: string): Promise<StoredObject | null> {
    const Key = this.#objectKey(key);
    try {
      const { sdk, client } = await this.#sdkAndClient();
      const res = await client.send(new sdk.GetObjectCommand({ Bucket: this.config.bucket, Key }));
      const body = res.Body as Readable | undefined;
      if (!body || typeof body.pipe !== 'function') return null;
      return { stream: body, bytes: res.ContentLength ?? 0 };
    } catch (err) {
      if (isNotFound(err)) return null;
      throw storageUnavailable('get', err);
    }
  }

  async delete(key: string): Promise<void> {
    const Key = this.#objectKey(key);
    try {
      const { sdk, client } = await this.#sdkAndClient();
      // S3 answers 204 for missing keys, so this is idempotent.
      await client.send(new sdk.DeleteObjectCommand({ Bucket: this.config.bucket, Key }));
    } catch (err) {
      if (isNotFound(err)) return;
      throw storageUnavailable('delete', err);
    }
  }

  async signedUrl(key: string, opts: SignedUrlOptions = {}): Promise<string | null> {
    const Key = this.#objectKey(key);
    const requested =
      opts.ttlSec === undefined
        ? Math.max(SIGNED_URL_MIN_SEC, Math.floor(this.config.signedUrlTtlSec))
        : Math.max(SIGNED_URL_ABSOLUTE_MIN_SEC, Math.floor(opts.ttlSec));
    const ttl = Math.min(SIGNED_URL_MAX_SEC, requested);
    try {
      const { sdk, client } = await this.#sdkAndClient();
      const { getSignedUrl } = await import('@aws-sdk/s3-request-presigner');
      return await getSignedUrl(
        client,
        new sdk.GetObjectCommand({
          Bucket: this.config.bucket,
          Key,
          ...(opts.filename
            ? { ResponseContentDisposition: attachmentDisposition(opts.filename) }
            : {}),
          ...(opts.contentType ? { ResponseContentType: opts.contentType } : {}),
        }),
        { expiresIn: ttl },
      );
    } catch (err) {
      throw storageUnavailable('sign', err);
    }
  }

  async ping(): Promise<void> {
    try {
      const { sdk, client } = await this.#sdkAndClient();
      await client.send(new sdk.HeadBucketCommand({ Bucket: this.config.bucket }));
    } catch (err) {
      throw storageUnavailable('ping', err);
    }
  }
}
