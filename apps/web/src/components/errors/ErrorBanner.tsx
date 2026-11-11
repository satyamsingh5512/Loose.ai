import { AlertTriangle, X } from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { ApiError } from '@/lib/errors';
import { cn } from '@/lib/utils';
import { CopyDebugInfoButton } from './CopyDebugInfo';
import { ErrorActionButton } from './ErrorAction';

interface ErrorBannerProps {
  error: unknown;
  onRetry?: () => void;
  onDismiss?: () => void;
  className?: string;
  /** Hide the title line (for compact in-form errors). */
  compact?: boolean;
}

/**
 * The single banner used for every error shown in-page (spec §12 UX, §16.6):
 * catalog title + plain-English userMessage + primary action from `error.action`
 * + the request id for support.
 */
export function ErrorBanner({ error, onRetry, onDismiss, className, compact }: ErrorBannerProps) {
  if (!error) return null;
  const e = ApiError.from(error);
  return (
    <Alert
      variant={e.retryable ? 'warning' : 'destructive'}
      className={cn('pr-10', className)}
      data-error-code={e.code}
    >
      <AlertTriangle aria-hidden="true" />
      {compact ? null : <AlertTitle>{e.title}</AlertTitle>}
      <AlertDescription>
        <p>{e.userMessage}</p>
        <div className="mt-1 flex flex-wrap items-center gap-3">
          <ErrorActionButton action={e.action} onRetry={onRetry} />
          {e.requestId && e.requestId !== 'client' ? (
            <span className="text-xs text-muted-foreground">
              Error {e.code} · Reference {e.requestId}
            </span>
          ) : (
            <span className="text-xs text-muted-foreground">Error {e.code}</span>
          )}
          <CopyDebugInfoButton error={e} />
        </div>
      </AlertDescription>
      {onDismiss ? (
        <Button
          variant="ghost"
          size="icon"
          className="absolute top-2 right-2 size-7"
          onClick={onDismiss}
          aria-label="Dismiss"
        >
          <X aria-hidden="true" />
        </Button>
      ) : null}
    </Alert>
  );
}
