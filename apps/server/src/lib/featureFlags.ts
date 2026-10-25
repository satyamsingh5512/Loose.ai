/**
 * Feature flags (spec §19; phase10-design.md §6.5) — implemented by the FOUNDATION, OWNED BY W3.
 * Precedence: org override (`Organization.featureFlags`) > env (`FEATURE_FLAGS`) > default.
 */
import type { RequestHandler } from 'express';
import {
  parseOrgFeatureFlags,
  resolveFeatureFlags,
  type FeatureFlag,
  type FeatureFlagOverrides,
} from '@loose/shared';
import type { Organization } from '@prisma/client';
import type { AppContext } from '../context';
import { AppError } from './errors';

type OrgFlags = Pick<Organization, 'featureFlags'> | null | undefined;

export class FeatureFlags {
  constructor(private readonly envOverrides: FeatureFlagOverrides = {}) {}

  /** Effective flags (for an org when given). */
  all(org?: OrgFlags): Record<FeatureFlag, boolean> {
    return resolveFeatureFlags(
      this.envOverrides,
      org ? parseOrgFeatureFlags(org.featureFlags) : {},
    );
  }

  isEnabled(flag: FeatureFlag, org?: OrgFlags): boolean {
    return this.all(org)[flag];
  }

  /** Throws LSE-SYS-007 when the flag is off. */
  assertEnabled(flag: FeatureFlag, org?: OrgFlags): void {
    if (!this.isEnabled(flag, org)) {
      throw new AppError('LSE-SYS-007', { devMessage: `Feature "${flag}" is disabled` });
    }
  }
}

/** Route guard: uses `req.org` when mounted behind requireOrg. */
export function requireFeature(ctx: AppContext, flag: FeatureFlag): RequestHandler {
  return (req, _res, next) => {
    ctx.featureFlags.assertEnabled(flag, req.org);
    next();
  };
}
