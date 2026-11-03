/**
 * Injectable DNS resolver (FOUNDATION; OWNED BY W3). Used by the SSRF guard (`safeFetch`, pinned
 * connections) and domain verification (TXT records). Tests pass a fake through
 * `buildContext({ dns })`.
 */
import { lookup, resolveTxt } from 'node:dns/promises';

export interface ResolvedAddress {
  address: string;
  family: 4 | 6;
}

export interface DnsResolver {
  /** All A/AAAA addresses of `host`. */
  lookup(host: string): Promise<ResolvedAddress[]>;
  /** TXT records (each record = array of chunks). */
  resolveTxt(host: string): Promise<string[][]>;
}

export const systemDns: DnsResolver = {
  async lookup(host) {
    const rows = await lookup(host, { all: true, verbatim: true });
    return rows.map((r) => ({ address: r.address, family: r.family === 6 ? 6 : 4 }));
  },
  resolveTxt: (host) => resolveTxt(host),
};
