/**
 * Client IP resolution (FOUNDATION; OWNED BY W3 afterwards).
 *
 * HTTP requests use Express' `req.ip` (honours `app.set('trust proxy', TRUST_PROXY)`). WebSocket
 * upgrades bypass Express, so `clientIpFromUpgrade` applies the same rule: with `trustProxy = N`
 * the client is the N-th address from the right of `X-Forwarded-For` + socket address chain.
 * Addresses are normalized (`::ffff:1.2.3.4` → `1.2.3.4`).
 */
import type { IncomingMessage } from 'node:http';
import { normalizeIp } from '@loose/shared';

/** Normalize an address string; unparsable input is returned unchanged (trimmed). */
export function normalizeClientIp(ip: string | undefined | null): string | undefined {
  if (!ip) return undefined;
  const trimmed = ip.trim();
  return normalizeIp(trimmed) ?? trimmed;
}

/**
 * Same semantics as Express `trust proxy` with a hop count: addresses = [...xff, remote];
 * the client is `addresses[len - 1 - trustProxy]` (clamped to the left-most entry).
 */
export function clientIpFromChain(
  remoteAddress: string | undefined,
  forwardedFor: string | string[] | undefined,
  trustProxy: number,
): string | undefined {
  const xff = (Array.isArray(forwardedFor) ? forwardedFor.join(',') : (forwardedFor ?? ''))
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const chain = [...xff, ...(remoteAddress ? [remoteAddress] : [])];
  if (chain.length === 0) return undefined;
  const hops = Math.max(0, Math.floor(trustProxy));
  const idx = Math.max(0, chain.length - 1 - hops);
  return normalizeClientIp(chain[idx]);
}

export function clientIpFromUpgrade(req: IncomingMessage, trustProxy: number): string | undefined {
  return clientIpFromChain(req.socket.remoteAddress, req.headers['x-forwarded-for'], trustProxy);
}
