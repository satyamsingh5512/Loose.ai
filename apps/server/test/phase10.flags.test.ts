import { describe, expect, it } from 'vitest';
import type { Organization } from '@prisma/client';
import { FeatureFlags } from '../src/lib/featureFlags';

describe('Phase 10 feature flags', () => {
  it('applies an org override over environment defaults', () => {
    const flags = new FeatureFlags({ plugins: false, shared_sessions: true });
    expect(flags.isEnabled('plugins')).toBe(false);
    expect(
      flags.isEnabled('plugins', { featureFlags: { plugins: true } } as Pick<
        Organization,
        'featureFlags'
      >),
    ).toBe(true);
  });
  it('throws the catalogued feature-off error', () => {
    try {
      new FeatureFlags({ scim: false }).assertEnabled('scim');
    } catch (err) {
      expect(err).toMatchObject({ code: 'LSE-SYS-007' });
    }
  });
});
