/**
 * P10-SEC-012 follow-up: the extensions / hooks / outbound-webhook SSRF guard (`assertPublicUrl`)
 * uses the shared numeric classifier in `lib/net/ip.ts` instead of its own textual prefix checks,
 * so the IPv6 / mapped / special-use forms the audit found are blocked there too.
 */
import type * as DnsPromises from 'node:dns/promises';
import { describe, expect, it, vi } from 'vitest';
import { isAppError } from '../src/lib/errors';

const resolved: { current: Array<{ address: string; family: number }> } = { current: [] };
vi.mock('node:dns/promises', async (orig) => ({
  ...(await orig<typeof DnsPromises>()),
  lookup: vi.fn(async () => resolved.current),
}));

const { assertPublicUrl } = await import('../src/services/extensionsCommon');

async function codeOf(url: string, code?: 'LSE-EXT-006'): Promise<string | null> {
  try {
    await assertPublicUrl(url, code);
    return null;
  } catch (err) {
    if (isAppError(err)) return err.code;
    throw err;
  }
}

describe('assertPublicUrl uses lib/net/ip.ts', () => {
  it.each([
    'http://[0:0:0:0:0:ffff:127.0.0.1]/',
    'http://[::ffff:10.0.0.1]/',
    'http://[ff02::1]/',
    'http://[fec0::1]/',
    'http://[fd00::1]/',
    'http://[::1]/',
    'http://[2001:db8::1]/',
    'http://0x7f.1/',
    'http://2130706433/',
    'http://127.1/',
    'http://100.64.0.1/',
    'http://203.0.113.5/',
    'http://198.18.0.1/',
    'http://224.0.0.1/',
    'http://0.0.0.0/',
  ])('blocks the non-public literal %s', async (url) => {
    expect(await codeOf(url)).toBe('LSE-MCP-004');
    expect(await codeOf(url, 'LSE-EXT-006')).toBe('LSE-EXT-006');
  });

  it.each(['https://93.184.216.34/mcp', 'https://[2606:4700:4700::1111]/hook'])(
    'allows the public literal %s',
    async (url) => {
      expect(await codeOf(url)).toBeNull();
    },
  );

  it('blocks a host name that resolves to a non-public address in any form', async () => {
    for (const address of ['::ffff:169.254.169.254', 'fec0::1', 'ff02::1', '10.1.2.3']) {
      resolved.current = [
        { address: '93.184.216.34', family: 4 },
        { address, family: address.includes(':') ? 6 : 4 },
      ];
      expect(await codeOf('https://mcp.example.com/'), address).toBe('LSE-MCP-004');
    }
    resolved.current = [{ address: '93.184.216.34', family: 4 }];
    expect(await codeOf('https://mcp.example.com/')).toBeNull();
  });

  it('still refuses non-http(s) schemes and local names', async () => {
    resolved.current = [{ address: '93.184.216.34', family: 4 }];
    for (const url of ['ftp://93.184.216.34/', 'http://localhost/', 'http://db.internal/']) {
      expect(await codeOf(url), url).toBe('LSE-MCP-004');
    }
  });
});
