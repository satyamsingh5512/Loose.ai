import { QueryErrorResetBoundary } from '@tanstack/react-query';
import { RotateCw } from 'lucide-react';
import * as React from 'react';
import { isRouteErrorResponse, useRouteError } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { ApiError } from '@/lib/errors';
import { FullPageError } from './FullPageError';

interface BoundaryProps {
  /** Shown in the fallback ("Dashboard couldn't load"). */
  section: string;
  children: React.ReactNode;
  onReset?: () => void;
  /** Reset automatically when any of these change (e.g. route params). */
  resetKeys?: readonly unknown[];
}

interface BoundaryState {
  error: unknown;
}

class SectionBoundary extends React.Component<BoundaryProps, BoundaryState> {
  override state: BoundaryState = { error: null };

  static getDerivedStateFromError(error: unknown): BoundaryState {
    return { error: error ?? new Error('Unknown error') };
  }

  override componentDidCatch(error: unknown, info: React.ErrorInfo): void {
    // Sentry hook point (spec §16.6). Never log secrets: ApiError carries none.
    if (import.meta.env.DEV) console.error(`[${this.props.section}]`, error, info.componentStack);
  }

  override componentDidUpdate(prev: BoundaryProps): void {
    if (this.state.error === null) return;
    const a = prev.resetKeys ?? [];
    const b = this.props.resetKeys ?? [];
    if (a.length !== b.length || a.some((v, i) => !Object.is(v, b[i]))) this.reset();
  }

  reset = (): void => {
    this.props.onReset?.();
    this.setState({ error: null });
  };

  override render(): React.ReactNode {
    if (this.state.error === null) return this.props.children;
    const e = ApiError.from(this.state.error);
    return (
      <div
        role="alert"
        className="flex flex-col items-start gap-3 rounded-lg border border-destructive/40 bg-destructive/5 p-4"
      >
        <div>
          <p className="font-medium">{this.props.section} couldn&apos;t load</p>
          <p className="text-sm text-muted-foreground">{e.userMessage}</p>
          <p className="mt-1 text-xs text-muted-foreground">Error {e.code}</p>
        </div>
        <Button size="sm" variant="outline" onClick={this.reset}>
          <RotateCw aria-hidden="true" />
          Reload section
        </Button>
      </div>
    );
  }
}

/** Error boundary with "Reload section" that also resets failed queries. */
export function ErrorBoundary(props: BoundaryProps) {
  return (
    <QueryErrorResetBoundary>
      {({ reset }) => (
        <SectionBoundary
          {...props}
          onReset={() => {
            reset();
            props.onReset?.();
          }}
        />
      )}
    </QueryErrorResetBoundary>
  );
}

/** `errorElement` for the router: renders thrown errors as a full page. */
export function RouteErrorPage() {
  const err = useRouteError();
  if (isRouteErrorResponse(err)) {
    const code = err.status === 404 ? 'LSE-NF-001' : 'LSE-SYS-001';
    return (
      <FullPageError error={ApiError.fromCode(code)} onRetry={() => window.location.reload()} />
    );
  }
  return <FullPageError error={err} onRetry={() => window.location.reload()} />;
}
