import { IpBlockedScreen } from '@/components/auth/AccessBlockedScreens';
import { Skeleton } from '@/components/ui/skeleton';
import { ApiError, presentationFor } from '@/lib/errors';
import { ErrorBanner } from './ErrorBanner';
import { FullPageError } from './FullPageError';

/** Render a failed page query: 403/404/maintenance as a page, others as a banner with retry. */
export function QueryError({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const e = ApiError.from(error);
  if (e.code === 'LSE-AUTH-001') return null; // global redirect handles it
  if (e.code === 'LSE-ORG-010') return <IpBlockedScreen {...(onRetry ? { onRetry } : {})} />;
  if (presentationFor(e) === 'page')
    return <FullPageError error={e} onRetry={onRetry} headingLevel="h2" />;
  return <ErrorBanner error={e} onRetry={onRetry} />;
}

/** Generic loading placeholder with an accessible status. */
export function LoadingBlock({ label = 'Loading…', rows = 3 }: { label?: string; rows?: number }) {
  return (
    <div role="status" aria-live="polite" className="grid gap-3">
      <span className="sr-only">{label}</span>
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-16 w-full" />
      ))}
    </div>
  );
}
