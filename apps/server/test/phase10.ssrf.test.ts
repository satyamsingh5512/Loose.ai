import { describe, expect, it } from 'vitest';
import type { AppError } from '../src/lib/errors';
import { createMetricsRegistry } from '../src/lib/metrics';
import { isPrivateAddress, resolvePublicAddresses } from '../src/lib/net/safeFetch';

const base = (lookup: (host: string) => Promise<{ address: string; family: 4 | 6 }[]>) =>
  ({
    env: { NODE_ENV: 'test' },
    dns: { lookup, resolveTxt: async () => [] },
    metrics: createMetricsRegistry(),
  }) as unknown as Parameters<typeof resolvePublicAddresses>[0];

describe('Phase 10 DNS-pinned SSRF protection', () => {
  it('blocks private, mapped and link-local addresses', () => {
    for (const address of [
      '127.0.0.1',
      '10.1.2.3',
      '169.254.1.1',
      '100.64.0.1',
      '198.18.0.1',
      '224.0.0.1',
      '::1',
      'fc00::1',
      'fe80::1',
      '::ffff:127.0.0.1',
    ])
      expect(isPrivateAddress(address)).toBe(true);
    expect(isPrivateAddress('8.8.8.8')).toBe(false);
  });
  it('rejects a rebinding answer when one DNS answer becomes private', async () => {
    const ctx = base(async () => [
      { address: '93.184.216.34', family: 4 },
      { address: '127.0.0.1', family: 4 },
    ]);
    await expect(
      resolvePublicAddresses(ctx, 'rebind.example', 'LSE-VAL-001'),
    ).rejects.toMatchObject({ code: 'LSE-VAL-001' } satisfies Partial<AppError>);
    expect(await ctx.metrics.render()).toContain(
      'loose_ssrf_blocked_total{reason="private_address"} 1',
    );
  });
});
