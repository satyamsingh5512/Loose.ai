import { describe, expect, it } from 'vitest';
import { EnvelopeCrypto, packRecord, safeEqual, sha256Hex, unpackRecord } from '../src/lib/crypto';
import { AppError } from '../src/lib/errors';
import { AwsKmsProvider, createKmsProvider, LocalKmsProvider } from '../src/lib/kms';

const MASTER = Buffer.alloc(32, 1).toString('base64');
const OTHER_MASTER = Buffer.alloc(32, 2).toString('base64');

async function expectSys006(p: Promise<unknown>) {
  await expect(p).rejects.toBeInstanceOf(AppError);
  await expect(p).rejects.toMatchObject({ code: 'LSE-SYS-006' });
}

describe('envelope encryption', () => {
  const crypto = new EnvelopeCrypto(new LocalKmsProvider(MASTER));

  it('round-trips plaintext', async () => {
    const rec = await crypto.encrypt('sk-ant-api03-secret-value', 'api-key');
    expect(rec.iv).toHaveLength(12);
    expect(rec.ciphertext.toString('utf8')).not.toContain('secret');
    expect(await crypto.decryptString(rec, 'api-key')).toBe('sk-ant-api03-secret-value');
  });

  it('uses a distinct IV and data key per record', async () => {
    const a = await crypto.encrypt('same', 'api-key');
    const b = await crypto.encrypt('same', 'api-key');
    expect(a.iv.equals(b.iv)).toBe(false);
    expect(a.wrappedKey.equals(b.wrappedKey)).toBe(false);
    expect(a.ciphertext.equals(b.ciphertext)).toBe(false);
  });

  it('detects tampering of ciphertext, tag, iv and wrapped key (LSE-SYS-006)', async () => {
    const rec = await crypto.encrypt('hello world', 'api-key');
    const flip = (b: Buffer, i: number) => {
      const c = Buffer.from(b);
      c[i] = (c[i] ?? 0) ^ 0xff;
      return c;
    };
    await expectSys006(crypto.decrypt({ ...rec, ciphertext: flip(rec.ciphertext, 0) }, 'api-key'));
    await expectSys006(
      crypto.decrypt(
        { ...rec, ciphertext: flip(rec.ciphertext, rec.ciphertext.length - 1) },
        'api-key',
      ),
    );
    await expectSys006(crypto.decrypt({ ...rec, iv: flip(rec.iv, 3) }, 'api-key'));
    await expectSys006(crypto.decrypt({ ...rec, wrappedKey: flip(rec.wrappedKey, 20) }, 'api-key'));
  });

  it('binds ciphertext to its purpose (AAD)', async () => {
    const rec = await crypto.encrypt('token', 'oauth-token');
    await expectSys006(crypto.decrypt(rec, 'api-key'));
  });

  it('fails with a different master key', async () => {
    const rec = await crypto.encrypt('x', 'generic');
    const other = new EnvelopeCrypto(new LocalKmsProvider(OTHER_MASTER));
    await expectSys006(other.decrypt(rec, 'generic'));
  });

  it('packs into a single blob and back', async () => {
    const blob = await crypto.encryptPacked('{"A":"1"}', 'project-env');
    expect(await crypto.decryptPackedString(blob, 'project-env')).toBe('{"A":"1"}');
    const rec = unpackRecord(blob);
    expect(packRecord(rec).equals(Buffer.from(blob))).toBe(true);
    expect(() => unpackRecord(Buffer.from([9, 9, 9]))).toThrow(AppError);
  });

  it('aws provider is a stub that throws LSE-SYS-006', async () => {
    const kms = createKmsProvider({ KMS_PROVIDER: 'aws' });
    expect(kms).toBeInstanceOf(AwsKmsProvider);
    await expectSys006(new EnvelopeCrypto(kms).encrypt('x', 'generic'));
  });

  it('rejects a master key that is not 32 bytes', () => {
    expect(() => new LocalKmsProvider(Buffer.alloc(16).toString('base64'))).toThrow(AppError);
  });

  it('helpers', () => {
    expect(sha256Hex('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
    expect(safeEqual('a', 'a')).toBe(true);
    expect(safeEqual('a', 'b')).toBe(false);
    expect(safeEqual('a', 'ab')).toBe(false);
    expect(safeEqual(undefined, 'a')).toBe(false);
  });
});
