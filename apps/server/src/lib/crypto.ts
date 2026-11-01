/**
 * Envelope encryption + token helpers.
 *
 * Each record gets a fresh random 32-byte data key; the plaintext is encrypted
 * with AES-256-GCM (random 12-byte IV, 16-byte auth tag appended to the
 * ciphertext) and the data key is wrapped by the KmsProvider. `aad` binds a
 * ciphertext to its purpose so blobs can't be swapped between columns.
 */
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';
import { AppError } from './errors';
import type { KmsProvider } from './kms';

const DATA_KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const PACKED_VERSION = 1;

export interface EncryptedRecord {
  /** ciphertext || authTag */
  ciphertext: Buffer;
  /** KMS-wrapped data key */
  wrappedKey: Buffer;
  iv: Buffer;
}

export type CryptoPurpose = 'api-key' | 'oauth-token' | 'project-env' | 'generic';

export class EnvelopeCrypto {
  constructor(private readonly kms: KmsProvider) {}

  async encrypt(plaintext: string | Buffer, purpose: CryptoPurpose): Promise<EncryptedRecord> {
    const dataKey = randomBytes(DATA_KEY_BYTES);
    try {
      const iv = randomBytes(IV_BYTES);
      const cipher = createCipheriv('aes-256-gcm', dataKey, iv);
      cipher.setAAD(Buffer.from(purpose));
      const data = typeof plaintext === 'string' ? Buffer.from(plaintext, 'utf8') : plaintext;
      const ct = Buffer.concat([cipher.update(data), cipher.final(), cipher.getAuthTag()]);
      const wrappedKey = await this.kms.wrapKey(dataKey);
      return { ciphertext: ct, wrappedKey, iv };
    } finally {
      dataKey.fill(0);
    }
  }

  async decrypt(rec: EncryptedRecord, purpose: CryptoPurpose): Promise<Buffer> {
    const dataKey = await this.kms.unwrapKey(Buffer.from(rec.wrappedKey));
    try {
      const ct = Buffer.from(rec.ciphertext);
      if (ct.length < TAG_BYTES) throw new Error('ciphertext too short');
      const decipher = createDecipheriv('aes-256-gcm', dataKey, Buffer.from(rec.iv));
      decipher.setAAD(Buffer.from(purpose));
      decipher.setAuthTag(ct.subarray(ct.length - TAG_BYTES));
      return Buffer.concat([
        decipher.update(ct.subarray(0, ct.length - TAG_BYTES)),
        decipher.final(),
      ]);
    } catch (cause) {
      throw new AppError('LSE-SYS-006', {
        devMessage: 'decryption failed (tampered or wrong key)',
        cause,
      });
    } finally {
      dataKey.fill(0);
    }
  }

  async decryptString(rec: EncryptedRecord, purpose: CryptoPurpose): Promise<string> {
    return (await this.decrypt(rec, purpose)).toString('utf8');
  }

  /** Encrypt into a single self-describing blob (for single-column storage). */
  async encryptPacked(
    plaintext: string | Buffer,
    purpose: CryptoPurpose,
  ): Promise<Uint8Array<ArrayBuffer>> {
    return bytes(packRecord(await this.encrypt(plaintext, purpose)));
  }

  async decryptPacked(blob: Uint8Array, purpose: CryptoPurpose): Promise<Buffer> {
    return this.decrypt(unpackRecord(blob), purpose);
  }

  async decryptPackedString(blob: Uint8Array, purpose: CryptoPurpose): Promise<string> {
    return (await this.decryptPacked(blob, purpose)).toString('utf8');
  }
}

/** Packed format: [version(1) | wrappedKeyLen(uint16 BE) | wrappedKey | iv(12) | ciphertext||tag]. */
export function packRecord(rec: EncryptedRecord): Buffer {
  const len = Buffer.alloc(2);
  len.writeUInt16BE(rec.wrappedKey.length);
  return Buffer.concat([
    Buffer.from([PACKED_VERSION]),
    len,
    rec.wrappedKey,
    rec.iv,
    rec.ciphertext,
  ]);
}

export function unpackRecord(blob: Uint8Array): EncryptedRecord {
  const buf = Buffer.from(blob);
  if (buf.length < 3 || buf[0] !== PACKED_VERSION) {
    throw new AppError('LSE-SYS-006', { devMessage: 'unknown encrypted blob format' });
  }
  const keyLen = buf.readUInt16BE(1);
  const keyEnd = 3 + keyLen;
  if (buf.length < keyEnd + IV_BYTES + TAG_BYTES) {
    throw new AppError('LSE-SYS-006', { devMessage: 'truncated encrypted blob' });
  }
  return {
    wrappedKey: buf.subarray(3, keyEnd),
    iv: buf.subarray(keyEnd, keyEnd + IV_BYTES),
    ciphertext: buf.subarray(keyEnd + IV_BYTES),
  };
}

/** Copy into a plain ArrayBuffer-backed Uint8Array (the type Prisma's Bytes columns expect). */
export function bytes(b: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(b);
}

// ---- hashing & tokens ---------------------------------------------------------

export function sha256Hex(input: string | Buffer): string {
  return createHash('sha256').update(input).digest('hex');
}

/** Cryptographically random token, base64url encoded. */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

export function hmacSha256(secret: string, data: string): string {
  return createHmac('sha256', secret).update(data).digest('base64url');
}

/** Constant-time string comparison (false on length mismatch). */
export function safeEqual(a: string | undefined | null, b: string | undefined | null): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length || ab.length === 0) return false;
  return timingSafeEqual(ab, bb);
}
