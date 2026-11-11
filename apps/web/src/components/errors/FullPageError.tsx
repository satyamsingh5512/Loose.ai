import { Construction, Lock, SearchX, ServerCrash, WifiOff } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { ApiError } from '@/lib/errors';
import { CopyDebugInfoButton } from './CopyDebugInfo';
import { ErrorActionButton } from './ErrorAction';

function iconFor(e: ApiError) {
  if (e.code === 'LSE-SYS-004') return Construction;
  if (e.isNetworkError) return WifiOff;
  if (e.status === 403) return Lock;
  if (e.status === 404) return SearchX;
  return ServerCrash;
}

/** Full-page error (403 / 404 / maintenance, spec §16.6). */
export function FullPageError({
  error,
  onRetry,
  headingLevel = 'h1',
}: {
  error: unknown;
  onRetry?: () => void;
  headingLevel?: 'h1' | 'h2';
}) {
  const e = ApiError.from(error);
  const Icon = iconFor(e);
  const Heading = headingLevel;
  const showHome = !e.action || e.action.type === 'retry';
  return (
    <section
      className="mx-auto flex max-w-md flex-col items-center gap-4 px-4 py-16 text-center"
      aria-labelledby="full-page-error-title"
      data-error-code={e.code}
    >
      <Icon className="size-10 text-muted-foreground" aria-hidden="true" />
      <Heading id="full-page-error-title" className="text-xl font-semibold">
        {e.title}
      </Heading>
      <p className="text-muted-foreground">{e.userMessage}</p>
      <div className="flex flex-wrap justify-center gap-2">
        <ErrorActionButton action={e.action} onRetry={onRetry} variant="default" size="default" />
        {showHome ? (
          <Button variant="outline" asChild>
            <Link to="/">Go home</Link>
          </Button>
        ) : null}
      </div>
      <div className="flex flex-wrap items-center justify-center gap-2">
        <p className="text-xs text-muted-foreground">
          Error {e.code}
          {e.requestId && e.requestId !== 'client' ? ` · Reference ${e.requestId}` : ''}
        </p>
        <CopyDebugInfoButton error={e} />
      </div>
    </section>
  );
}

export function NotFoundPage() {
  return <FullPageError error={ApiError.fromCode('LSE-NF-001')} />;
}
