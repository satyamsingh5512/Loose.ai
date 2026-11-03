import http from 'node:http';
import https from 'node:https';
import type { ErrorCode } from '@loose/shared';
import type { AppContext } from '../../context';
import type { ResolvedAddress } from './dns';
import { AppError } from '../errors';
import { canonicalIpLiteral, isNonPublicAddress } from './ip';

export interface SafeFetchInit extends Omit<RequestInit, 'redirect'> {
  errorCode?: ErrorCode;
  timeoutMs?: number;
  maxResponseBytes?: number;
  allowHttp?: boolean;
  redirect?: 'manual';
  /**
   * Resolve as soon as the status line and headers arrive, with an empty body, and close the
   * connection (for endless streams such as an SSE reachability probe).
   */
  headersOnly?: boolean;
}
export const SAFE_FETCH_DEFAULT_TIMEOUT_MS = 10_000;
export const SAFE_FETCH_DEFAULT_MAX_BYTES = 1024 * 1024;

function blocked(ctx: AppContext, code: ErrorCode, reason: string): never {
  ctx.metrics
    .counter('loose_ssrf_blocked_total', 'Blocked SSRF targets', ['reason'])
    .inc({ reason });
  throw new AppError(code, { devMessage: 'Outbound URL is not publicly reachable' });
}
/**
 * True for anything that is not a publicly routable unicast address: RFC1918, loopback, link-local,
 * site-local, CGNAT, documentation, multicast/reserved, IPv4-mapped/compatible/NAT64/6to4 forms
 * (see `./ip.ts`; classification is numeric, not textual) and anything unparseable.
 */
export function isPrivateAddress(raw: string): boolean {
  return isNonPublicAddress(raw);
}
export async function resolvePublicAddresses(
  ctx: AppContext,
  host: string,
  code: ErrorCode,
): Promise<ResolvedAddress[]> {
  if (!host || host.length > 253) blocked(ctx, code, 'invalid_host');
  // IP literals in any spelling (`[::1]`, `0x7f.1`, `2130706433`, `0177.0.0.1`) are classified
  // directly and never reach DNS.
  const literal = canonicalIpLiteral(host);
  let rows: ResolvedAddress[];
  try {
    rows = literal ? [literal] : await ctx.dns.lookup(host);
  } catch (cause) {
    throw new AppError('LSE-SYS-005', { devMessage: 'Outbound DNS lookup failed', cause });
  }
  if (!rows.length)
    throw new AppError('LSE-SYS-005', { devMessage: 'Outbound DNS lookup returned no addresses' });
  if (rows.some((r) => isPrivateAddress(r.address))) blocked(ctx, code, 'private_address');
  return rows;
}
function bodyBytes(body: unknown): Buffer | undefined {
  if (body == null) return undefined;
  if (typeof body === 'string') return Buffer.from(body);
  if (body instanceof URLSearchParams) return Buffer.from(body.toString());
  if (body instanceof Uint8Array) return Buffer.from(body);
  if (body instanceof ArrayBuffer) return Buffer.from(body);
  throw new AppError('LSE-VAL-001', { devMessage: 'Unsupported outbound request body' });
}
type PinnedLookupCallback = (
  err: NodeJS.ErrnoException | null,
  address: string | { address: string; family: number }[],
  family?: number,
) => void;

/** Resolves exactly once, validates every answer, then pins the connection to that address. */
export async function safeFetch(
  ctx: AppContext,
  raw: string | URL,
  init: SafeFetchInit = {},
): Promise<Response> {
  const {
    errorCode = 'LSE-VAL-001',
    timeoutMs = SAFE_FETCH_DEFAULT_TIMEOUT_MS,
    maxResponseBytes = SAFE_FETCH_DEFAULT_MAX_BYTES,
    allowHttp = ctx.env.NODE_ENV !== 'production',
    headersOnly = false,
    signal: externalSignal,
    headers,
    body,
    ...rest
  } = init;
  let target: URL;
  try {
    target = new URL(String(raw));
  } catch {
    blocked(ctx, errorCode, 'invalid_url');
  }
  if (!['http:', 'https:'].includes(target.protocol)) blocked(ctx, errorCode, 'scheme');
  if (target.username || target.password) blocked(ctx, errorCode, 'credentials');
  if (target.protocol === 'http:' && !allowHttp) blocked(ctx, errorCode, 'http');
  const addresses = await resolvePublicAddresses(ctx, target.hostname, errorCode);
  const pinned = addresses[0]!;
  // Existing integration tests inject an MSW-compatible fetch. DNS is still resolved and
  // validated above; production always uses the low-level pinned connection below.
  if (ctx.env.NODE_ENV === 'test') {
    try {
      const res = await ctx.fetch(target, {
        ...rest,
        headers,
        body,
        redirect: 'manual',
        signal: externalSignal ?? AbortSignal.timeout(timeoutMs),
      });
      if (Number(res.headers.get('content-length') ?? '0') > maxResponseBytes)
        throw new Error('response exceeds byte limit');
      return res;
    } catch (cause) {
      if (cause instanceof AppError) throw cause;
      throw new AppError('LSE-SYS-005', {
        devMessage: `Outbound request failed: ${target.hostname}`,
        cause,
      });
    }
  }
  const requestHeaders = new Headers(headers);
  if (!requestHeaders.has('host')) requestHeaders.set('host', target.host);
  const bytes = bodyBytes(body);
  if (bytes && !requestHeaders.has('content-length'))
    requestHeaders.set('content-length', String(bytes.length));
  const client = target.protocol === 'https:' ? https : http;
  return await new Promise<Response>((resolve, reject) => {
    let done = false;
    const fail = (cause: unknown) => {
      if (!done) {
        done = true;
        reject(
          new AppError('LSE-SYS-005', {
            devMessage: `Outbound request failed: ${target.hostname}`,
            cause,
          }),
        );
      }
    };
    const req = client.request(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port || undefined,
        path: `${target.pathname}${target.search}`,
        method: rest.method ?? 'GET',
        headers: Object.fromEntries(requestHeaders),
        servername: target.hostname,
        // Node 22 and Bun pass `{ all: true }` (happy-eyeballs) and then require an array; a
        // bare (address, family) answer fails every request with "Invalid IP address".
        lookup: ((_host: string, opts: { all?: boolean } | undefined, cb: PinnedLookupCallback) =>
          opts?.all
            ? cb(null, [{ address: pinned.address, family: pinned.family }])
            : cb(null, pinned.address, pinned.family)) as unknown as http.RequestOptions['lookup'],
      },
      (res) => {
        const responseHeaders = () =>
          Object.fromEntries(
            Object.entries(res.headers).flatMap(([name, value]) =>
              value === undefined ? [] : [[name, Array.isArray(value) ? value.join(', ') : value]],
            ),
          );
        if (headersOnly) {
          done = true;
          res.destroy();
          req.destroy();
          resolve(
            new Response(null, {
              status: res.statusCode ?? 502,
              statusText: res.statusMessage,
              headers: responseHeaders(),
            }),
          );
          return;
        }
        const chunks: Buffer[] = [];
        let size = 0;
        res.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size > maxResponseBytes) {
            req.destroy();
            res.destroy();
            fail(new Error('response exceeds byte limit'));
          } else chunks.push(chunk);
        });
        res.on('error', fail);
        res.on('end', () => {
          if (done) return;
          done = true;
          resolve(
            new Response(Buffer.concat(chunks), {
              status: res.statusCode ?? 502,
              statusText: res.statusMessage,
              headers: responseHeaders(),
            }),
          );
        });
      },
    );
    req.setTimeout(timeoutMs, () => req.destroy(new Error('timeout')));
    req.on('error', fail);
    if (externalSignal)
      externalSignal.addEventListener('abort', () => req.destroy(externalSignal.reason), {
        once: true,
      });
    req.end(bytes);
  });
}
