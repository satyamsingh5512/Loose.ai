import { ExternalLink, RotateCw } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { API_PREFIX } from '@loose/shared';
import type { ApiErrorAction } from '@/lib/errors';
import { currentPath } from '@/lib/utils';

/**
 * Where an error action should go. API auth links (e.g. "Reconnect GitHub" →
 * /api/v1/auth/github?link=1) get a `returnTo` so the user lands back here.
 */
export function resolveActionHref(action: ApiErrorAction, returnTo = currentPath()): string | null {
  if (!action.href) return null;
  if (action.href.startsWith(`${API_PREFIX}/auth/`) && !action.href.includes('returnTo=')) {
    const sep = action.href.includes('?') ? '&' : '?';
    return `${action.href}${sep}returnTo=${encodeURIComponent(returnTo)}`;
  }
  if (
    action.href === '/signin' &&
    returnTo &&
    returnTo !== '/' &&
    !returnTo.startsWith('/signin')
  ) {
    return `/signin?returnTo=${encodeURIComponent(returnTo)}`;
  }
  return action.href;
}

function isExternal(href: string): boolean {
  return /^https?:\/\//i.test(href);
}

/** The primary action button for an error (from `error.action`). */
export function ErrorActionButton({
  action,
  onRetry,
  size = 'sm',
  variant = 'outline',
}: {
  action: ApiErrorAction | undefined;
  onRetry?: (() => void) | undefined;
  size?: 'sm' | 'default';
  variant?: 'outline' | 'default';
}) {
  if (!action) return null;
  if (action.type === 'retry') {
    if (!onRetry) return null;
    return (
      <Button size={size} variant={variant} onClick={onRetry}>
        <RotateCw aria-hidden="true" />
        {action.label}
      </Button>
    );
  }
  const href = resolveActionHref(action);
  if (!href) return null;
  if (isExternal(href)) {
    return (
      <Button size={size} variant={variant} asChild>
        <a href={href} target="_blank" rel="noopener noreferrer">
          {action.label}
          <ExternalLink aria-hidden="true" />
          <span className="sr-only">(opens in a new tab)</span>
        </a>
      </Button>
    );
  }
  // API routes (OAuth starts) need a full-page navigation, not client routing.
  if (action.type === 'link' || href.startsWith(API_PREFIX)) {
    return (
      <Button size={size} variant={variant} asChild>
        <a href={href}>{action.label}</a>
      </Button>
    );
  }
  return (
    <Button size={size} variant={variant} asChild>
      <Link to={href}>{action.label}</Link>
    </Button>
  );
}
