/**
 * KMS abstraction for envelope encryption (spec §8.1, §15). Data keys are
 * generated per record and wrapped by a KmsProvider; only wrapped keys are
 * persisted. Every failure surfaces as LSE-SYS-006.
 */
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { AppError } from './errors';

export interface KmsProvider {
  readonly name: string;
  wrapKey(dataKey: Buffer): Promise<Buffer>;
  unwrapKey(wrapped: Buffer): Promise<Buffer>;
}

const LOCAL_FORMAT_VERSION = 1;
const IV_BYTES = 12;
const TAG_BYTES = 16;

/**
 * Local provider: wraps data keys with AES-256-GCM under a 32-byte master key
 * from the environment. Format: [version(1) | iv(12) | tag(16) | ciphertext].
 */
export class LocalKmsProvider implements KmsProvider {
  readonly name = 'local';
  readonly #masterKey: Buffer;

  constructor(masterKeyBase64: string) {
    const key = Buffer.from(masterKeyBase64, 'base64');
    if (key.length !== 32) {
      throw new AppError('LSE-SYS-006', { devMessage: 'LOCAL_KMS_MASTER_KEY must be 32 bytes' });
    }
    this.#masterKey = key;
  }

  async wrapKey(dataKey: Buffer): Promise<Buffer> {
    try {
      const iv = randomBytes(IV_BYTES);
      const cipher = createCipheriv('aes-256-gcm', this.#masterKey, iv);
      const ct = Buffer.concat([cipher.update(dataKey), cipher.final()]);
      return Buffer.concat([Buffer.from([LOCAL_FORMAT_VERSION]), iv, cipher.getAuthTag(), ct]);
    } catch (cause) {
      throw new AppError('LSE-SYS-006', { devMessage: 'local KMS wrap failed', cause });
    }
  }

  async unwrapKey(wrapped: Buffer): Promise<Buffer> {
    try {
      if (wrapped.length < 1 + IV_BYTES + TAG_BYTES + 1 || wrapped[0] !== LOCAL_FORMAT_VERSION) {
        throw new Error('unknown wrapped key format');
      }
      const iv = wrapped.subarray(1, 1 + IV_BYTES);
      const tag = wrapped.subarray(1 + IV_BYTES, 1 + IV_BYTES + TAG_BYTES);
      const ct = wrapped.subarray(1 + IV_BYTES + TAG_BYTES);
      const decipher = createDecipheriv('aes-256-gcm', this.#masterKey, iv);
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(ct), decipher.final()]);
    } catch (cause) {
      throw new AppError('LSE-SYS-006', { devMessage: 'local KMS unwrap failed', cause });
    }
  }
}

/** AWS KMS — not implemented in v1; selecting it fails loudly. */
export class AwsKmsProvider implements KmsProvider {
  readonly name = 'aws';
  async wrapKey(): Promise<Buffer> {
    throw new AppError('LSE-SYS-006', { devMessage: 'AWS KMS provider is not configured' });
  }
  async unwrapKey(): Promise<Buffer> {
    throw new AppError('LSE-SYS-006', { devMessage: 'AWS KMS provider is not configured' });
  }
}

export function createKmsProvider(env: {
  KMS_PROVIDER: 'local' | 'aws';
  LOCAL_KMS_MASTER_KEY?: string | undefined;
}): KmsProvider {
  if (env.KMS_PROVIDER === 'aws') return new AwsKmsProvider();
  if (!env.LOCAL_KMS_MASTER_KEY) {
    throw new AppError('LSE-SYS-006', { devMessage: 'LOCAL_KMS_MASTER_KEY is not set' });
  }
  return new LocalKmsProvider(env.LOCAL_KMS_MASTER_KEY);
}
