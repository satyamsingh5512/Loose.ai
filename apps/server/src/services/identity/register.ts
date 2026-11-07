/** Identity background wiring (W1). FOUNDATION stub; called from platform/register.ts. */
import type { AppContext } from '../../context';
import type { PlatformRole } from '../../platform/register';

export function registerIdentity(_ctx: AppContext, _role: PlatformRole): void {
  // Nothing to register yet (no identity jobs). Keep idempotent per context.
}
