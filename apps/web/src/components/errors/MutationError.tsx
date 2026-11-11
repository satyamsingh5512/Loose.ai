import { ApiError, presentationForAction } from '@/lib/errors';
import { ErrorBanner } from './ErrorBanner';

/**
 * Renders a mutation error in-place when it is inline/banner class. Toast-class
 * errors are shown by `useErrorHandler` and signed-out errors redirect, so they
 * render nothing here. `hideCodes` lets a form render specific codes itself
 * (e.g. LSE-KEY-011 under the key field).
 */
export function MutationError({
  error,
  onRetry,
  hideCodes,
  className,
}: {
  error: unknown;
  onRetry?: () => void;
  hideCodes?: readonly string[];
  className?: string;
}) {
  if (!error) return null;
  const e = ApiError.from(error);
  if (e.code === 'LSE-AUTH-001') return null;
  if (hideCodes?.includes(e.code)) return null;
  if (presentationForAction(e) === 'toast') return null;
  return <ErrorBanner error={e} onRetry={onRetry} className={className} />;
}

/** First server-side field error for `path` (LSE-VAL-001 `fields`). */
export function fieldErrorOf(error: unknown, path: string): string | undefined {
  if (!error) return undefined;
  return ApiError.from(error).fieldError(path);
}
