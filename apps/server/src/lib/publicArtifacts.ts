/**
 * Signed, expiring public links to screenshot artifacts (embedded in PR bodies, where
 * reviewers have no loose.ai session). Token = `<artifactId>.<expiresEpochSec>.<sig>`,
 * sig = base64url(HMAC-SHA256(SESSION_SECRET-derived key, "public-artifact:<id>.<exp>")).
 * Unguessable (256-bit MAC), tamper-proof, and limited to PUBLIC_ARTIFACT_TTL_DAYS.
 */
import { createHmac, timingSafeEqual } from 'node:crypto';
import { API_PREFIX, PUBLIC_ARTIFACT_TTL_DAYS } from '@loose/shared';

const DAY_SEC = 86_400;
const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

function mac(secret: string, payload: string): string {
  return createHmac('sha256', `${secret}:public-artifact`)
    .update(`public-artifact:${payload}`)
    .digest('base64url');
}

export function signArtifactToken(
  secret: string,
  artifactId: string,
  now = Date.now(),
  ttlDays = PUBLIC_ARTIFACT_TTL_DAYS,
): string {
  const exp = Math.floor(now / 1000) + ttlDays * DAY_SEC;
  const payload = `${artifactId}.${exp}`;
  return `${payload}.${mac(secret, payload)}`;
}

/** Artifact id for a valid, unexpired token; otherwise null. */
export function verifyArtifactToken(
  secret: string,
  token: string,
  now = Date.now(),
): string | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [id, expRaw, sig] = parts as [string, string, string];
  if (!ID_RE.test(id) || !/^\d{1,12}$/.test(expRaw)) return null;
  const expected = Buffer.from(mac(secret, `${id}.${expRaw}`));
  const given = Buffer.from(sig);
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return null;
  if (Number(expRaw) * 1000 <= now) return null;
  return id;
}

export function publicArtifactUrl(apiUrl: string, token: string): string {
  return `${apiUrl.replace(/\/+$/, '')}${API_PREFIX}/public-artifacts/${token}`;
}
