/**
 * Numeric IP parsing and special-use classification for the SSRF guard (P10-SEC-012).
 *
 * Addresses are parsed into numbers (IPv4: uint32, IPv6: 128-bit bigint) and matched against CIDR
 * blocks, so every textual spelling of one address (expanded, compressed, IPv4-mapped / -compatible,
 * NAT64, 6to4, bracketed, zone-suffixed, decimal / octal / hex IPv4) is classified identically.
 * Anything that cannot be parsed is treated as non-public.
 */

/** Strip IPv6 brackets and a zone id (`fe80::1%eth0`). */
export function stripHostBrackets(raw: string): string {
  let host = raw.trim();
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  const zone = host.indexOf('%');
  if (zone !== -1) host = host.slice(0, zone);
  return host;
}

function parseIntPart(part: string): number | null {
  if (part === '') return null;
  if (/^0x[0-9a-f]*$/i.test(part)) return part.length > 2 ? Number.parseInt(part, 16) : null;
  if (/^0[0-7]*$/.test(part)) return part.length > 1 ? Number.parseInt(part, 8) : 0;
  if (/^[1-9][0-9]*$/.test(part)) return Number.parseInt(part, 10);
  return null;
}

/**
 * `inet_aton` semantics: 1–4 parts, each decimal / octal (`017`) / hex (`0x7f`); the last part fills
 * the remaining bytes (`127.1`, `2130706433`, `0x7f000001`). Returns the uint32 or null.
 */
export function parseIpv4Loose(raw: string): number | null {
  const parts = raw.split('.');
  if (parts.length < 1 || parts.length > 4) return null;
  const nums: number[] = [];
  for (const p of parts) {
    const n = parseIntPart(p);
    if (n === null || !Number.isFinite(n)) return null;
    nums.push(n);
  }
  const last = nums.pop()!;
  if (nums.some((n) => n > 255)) return null;
  if (last >= 256 ** (4 - nums.length)) return null;
  let value = last;
  nums.forEach((n, i) => {
    value += n * 256 ** (3 - i);
  });
  return value;
}

/** Strict dotted quad (decimal parts only), used for IPv6-embedded IPv4. */
function parseDottedQuad(raw: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(raw);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((n) => n > 255)) return null;
  return ((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0;
}

/** Parse any textual IPv6 address into its 128-bit value, or null. */
export function parseIpv6(raw: string): bigint | null {
  const text = stripHostBrackets(raw);
  if (!text.includes(':')) return null;
  let head = text;
  let tail4: number[] = [];
  const lastColon = text.lastIndexOf(':');
  const trailing = text.slice(lastColon + 1);
  if (trailing.includes('.')) {
    const v4 = parseDottedQuad(trailing);
    if (v4 === null) return null;
    tail4 = [v4 >>> 16, v4 & 0xffff];
    head = text.slice(0, lastColon + 1);
    // `::1.2.3.4` leaves a trailing `::` or `:` that the group split below understands.
    if (!head.endsWith('::')) head = head.slice(0, -1);
  }
  const doubleAt = head.indexOf('::');
  if (doubleAt !== head.lastIndexOf('::')) return null;
  const toGroups = (s: string): number[] | null => {
    if (s === '') return [];
    const out: number[] = [];
    for (const g of s.split(':')) {
      if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
      out.push(Number.parseInt(g, 16));
    }
    return out;
  };
  let groups: number[];
  if (doubleAt === -1) {
    const g = toGroups(head);
    if (!g) return null;
    groups = g;
  } else {
    const left = toGroups(head.slice(0, doubleAt));
    const right = toGroups(head.slice(doubleAt + 2));
    if (!left || !right) return null;
    const missing = 8 - tail4.length - left.length - right.length;
    if (missing < 1) return null;
    groups = [...left, ...Array<number>(missing).fill(0), ...right];
  }
  groups = [...groups, ...tail4];
  if (groups.length !== 8) return null;
  return groups.reduce((acc, g) => (acc << 16n) | BigInt(g), 0n);
}

// ---- classification -------------------------------------------------------------------------

/** [network uint32, prefix length] of IPv4 special-use blocks that are never public targets. */
const V4_BLOCKED: readonly (readonly [string, number])[] = [
  ['0.0.0.0', 8], // "this" network
  ['10.0.0.0', 8],
  ['100.64.0.0', 10], // CGNAT
  ['127.0.0.0', 8],
  ['169.254.0.0', 16], // link-local / cloud metadata
  ['172.16.0.0', 12],
  ['192.0.0.0', 24], // IETF protocol assignments
  ['192.0.2.0', 24], // documentation
  ['192.88.99.0', 24], // 6to4 relay anycast
  ['192.168.0.0', 16],
  ['198.18.0.0', 15], // benchmarking
  ['198.51.100.0', 24], // documentation
  ['203.0.113.0', 24], // documentation
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reserved + broadcast
];

const V4_BLOCK_RANGES = V4_BLOCKED.map(([net, bits]) => {
  const base = parseDottedQuad(net)!;
  const size = 2 ** (32 - bits);
  return [base, base + size - 1] as const;
});

export function isPrivateIpv4Number(value: number): boolean {
  return V4_BLOCK_RANGES.some(([lo, hi]) => value >= lo && value <= hi);
}

const mask = (bits: number, width = 128): bigint =>
  ((1n << BigInt(bits)) - 1n) << BigInt(width - bits);
const inV6 = (ip: bigint, prefix: bigint, bits: number): boolean =>
  (ip & mask(bits)) === (prefix & mask(bits));

/**
 * IPv6 is allow-listed: only global unicast `2000::/3` can be public. Within it the IETF protocol
 * block (Teredo etc.), documentation, 6to4 and NAT64-like translators are refused as well.
 * IPv4-mapped (`::ffff:0:0/96`) addresses are classified by the IPv4 they embed; every other
 * address outside `2000::/3` (`::`, `::1`, v4-compatible `::a.b.c.d`, `64:ff9b::/96` NAT64,
 * `fc00::/7`, `fe80::/10`, deprecated site-local `fec0::/10`, `ff00::/8` multicast, …) is refused.
 */
export function isPrivateIpv6Number(ip: bigint): boolean {
  if (inV6(ip, 0xffffn << 32n, 96)) return isPrivateIpv4Number(Number(ip & 0xffffffffn));
  if (!inV6(ip, 0x2000n << 112n, 3)) return true;
  return (
    inV6(ip, 0x2001n << 112n, 23) || // 2001::/23 IETF protocol assignments (Teredo, ORCHID, …)
    inV6(ip, 0x20010db8n << 96n, 32) || // documentation
    inV6(ip, 0x2002n << 112n, 16) || // 6to4 (embeds an arbitrary IPv4)
    inV6(ip, 0x3fffn << 112n, 20) // documentation (RFC 9637)
  );
}

/** True when `raw` is not a publicly routable unicast address (or cannot be parsed at all). */
export function isNonPublicAddress(raw: string): boolean {
  const text = stripHostBrackets(raw).toLowerCase();
  if (text.includes(':')) {
    const v6 = parseIpv6(text);
    return v6 === null ? true : isPrivateIpv6Number(v6);
  }
  const v4 = parseIpv4Loose(text);
  return v4 === null ? true : isPrivateIpv4Number(v4);
}

/**
 * If `host` is spelled as an IP literal in any form (bracketed IPv6, `0x7f.1`, `2130706433`,
 * `0177.0.0.1`), return its canonical text; otherwise null (a DNS name).
 */
export function canonicalIpLiteral(host: string): { address: string; family: 4 | 6 } | null {
  const text = stripHostBrackets(host).toLowerCase();
  if (text.includes(':')) {
    return { address: text, family: 6 };
  }
  const v4 = parseIpv4Loose(text);
  if (v4 === null) return null;
  return {
    address: [v4 >>> 24, (v4 >>> 16) & 255, (v4 >>> 8) & 255, v4 & 255].join('.'),
    family: 4,
  };
}

/** Loopback bind targets (`127.0.0.0/8`, `::1`, `localhost`). */
export function isLoopbackHost(host: string): boolean {
  const text = stripHostBrackets(host).toLowerCase();
  if (text === 'localhost') return true;
  if (text.includes(':')) {
    const v6 = parseIpv6(text);
    if (v6 === null) return false;
    if (v6 === 1n) return true;
    return inV6(v6, 0xffffn << 32n, 96) && (v6 & 0xffffffffn) >> 24n === 127n;
  }
  const v4 = parseIpv4Loose(text);
  return v4 !== null && v4 >>> 24 === 127;
}
