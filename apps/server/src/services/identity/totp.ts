/**
 * TOTP (RFC 6238) + recovery codes, implemented with `node:crypto` (spec §8.20 "enforced 2FA").
 *
 * - HMAC-SHA1, 6 digits, 30 s period, ±1 step tolerance (`TOTP_WINDOW`).
 * - Replay protection: a step that is not strictly greater than `User.totpLastStep` is refused,
 *   so a shoulder-surfed code cannot be used twice.
 * - Every code comparison is constant time.
 * - Recovery codes are random base32 (`abcde-12345`); only sha256(normalized) is stored.
 */
import { createHmac, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';
import {
  RECOVERY_CODE_COUNT,
  TOTP_DIGITS,
  TOTP_PERIOD_SEC,
  TOTP_SECRET_BYTES,
  TOTP_WINDOW,
} from '@loose/shared';
import { sha256Hex } from '../../lib/crypto';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(data: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of data) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

/** Decode base32 (padding and whitespace tolerated); null when a character is invalid. */
export function base32Decode(input: string): Buffer | null {
  const clean = input.replace(/[\s=]/g, '').toUpperCase();
  if (clean.length === 0) return null;
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx < 0) return null;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function generateTotpSecret(): Buffer {
  return randomBytes(TOTP_SECRET_BYTES);
}

/** Current 30-second time step. */
export function totpStep(now: number = Date.now()): number {
  return Math.floor(now / 1000 / TOTP_PERIOD_SEC);
}

/** The 6-digit code of `secret` at `step` (HOTP truncation, RFC 4226 §5.3). */
export function totpCode(secret: Uint8Array, step: number): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.max(0, Math.floor(step))));
  const mac = createHmac('sha1', secret).update(counter).digest();
  const offset = (mac[mac.length - 1] as number) & 0x0f;
  const bin =
    (((mac[offset] as number) & 0x7f) << 24) |
    ((mac[offset + 1] as number) << 16) |
    ((mac[offset + 2] as number) << 8) |
    (mac[offset + 3] as number);
  return String(bin % 10 ** TOTP_DIGITS).padStart(TOTP_DIGITS, '0');
}

function constantTimeEquals(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length || ab.length === 0) return false;
  return timingSafeEqual(ab, bb);
}

export interface VerifyTotpOptions {
  now?: number;
  window?: number;
  /** Last accepted step (replay protection); only strictly newer steps are accepted. */
  lastStep?: number | null | undefined;
}

export interface VerifyTotpResult {
  ok: boolean;
  /** The accepted step (store it as `totpLastStep`). */
  step?: number;
  /** The code was valid but already used (replay). */
  replayed?: boolean;
}

/**
 * Verify `code` against `secret`. Every candidate step is compared in constant time and the
 * loop always runs to completion so the result does not leak which step matched.
 */
export function verifyTotp(
  secret: Uint8Array,
  code: string,
  opts: VerifyTotpOptions = {},
): VerifyTotpResult {
  const window = opts.window ?? TOTP_WINDOW;
  const current = totpStep(opts.now ?? Date.now());
  const normalized = code.trim();
  if (!new RegExp(`^\\d{${TOTP_DIGITS}}$`).test(normalized)) return { ok: false };
  let matched: number | undefined;
  for (let delta = -window; delta <= window; delta++) {
    const step = current + delta;
    if (step < 0) continue;
    if (constantTimeEquals(totpCode(secret, step), normalized) && matched === undefined) {
      matched = step;
    }
  }
  if (matched === undefined) return { ok: false };
  const last = opts.lastStep ?? null;
  if (last !== null && matched <= last) return { ok: false, replayed: true, step: matched };
  return { ok: true, step: matched };
}

export interface OtpauthUrlInput {
  issuer: string;
  account: string;
  secret: Uint8Array;
}

/** `otpauth://totp/<issuer>:<account>?secret=…` (the QR payload). */
export function otpauthUrl({ issuer, account, secret }: OtpauthUrlInput): string {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
  const params = new URLSearchParams({
    secret: base32Encode(secret),
    issuer,
    algorithm: 'SHA1',
    digits: String(TOTP_DIGITS),
    period: String(TOTP_PERIOD_SEC),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

// ---- recovery codes --------------------------------------------------------------------------

const RECOVERY_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

function recoveryChunk(length: number): string {
  let out = '';
  for (let i = 0; i < length; i++) out += RECOVERY_ALPHABET[randomInt(RECOVERY_ALPHABET.length)];
  return out;
}

/** `RECOVERY_CODE_COUNT` single-use codes shaped `abcde-12345`. */
export function generateRecoveryCodes(count = RECOVERY_CODE_COUNT): string[] {
  return Array.from({ length: count }, () => `${recoveryChunk(5)}-${recoveryChunk(5)}`);
}

/** Lower-case, strip the dash and whitespace → the form that is hashed. */
export function normalizeRecoveryCode(raw: string): string {
  return raw.trim().toLowerCase().replace(/-/g, '');
}

export function hashRecoveryCode(raw: string): string {
  return sha256Hex(`recovery:${normalizeRecoveryCode(raw)}`);
}
