import { useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'sonner';
import { API_PREFIX } from '@loose/shared';
import { ApiError, presentationForAction } from '@/lib/errors';
import { browser } from '@/lib/utils';
import { resolveActionHref } from './ErrorAction';

export interface NotifyOptions {
  onRetry?: () => void;
}

/**
 * Toast an error, keyed by error code so repeats replace rather than stack.
 * Uses the catalog's plain-English userMessage and the action from the envelope.
 */
export function toastError(
  error: unknown,
  navigate: (to: string) => void,
  opts: NotifyOptions = {},
): void {
  const e = ApiError.from(error);
  const a = e.action;
  let action: { label: string; onClick: () => void } | undefined;
  if (a?.type === 'retry') {
    if (opts.onRetry) action = { label: a.label, onClick: opts.onRetry };
  } else if (a) {
    const href = resolveActionHref(a);
    if (href) {
      action = {
        label: a.label,
        onClick: () => {
          if (/^https?:\/\//i.test(href)) window.open(href, '_blank', 'noopener,noreferrer');
          else if (a.type === 'link' || href.startsWith(API_PREFIX)) browser.assign(href);
          else navigate(href);
        },
      };
    }
  }
  const description = e.retryable ? 'This usually clears up on its own.' : undefined;
  toast.error(e.userMessage, {
    id: e.code,
    ...(description ? { description } : {}),
    ...(action ? { action } : {}),
  });
}

/**
 * Hook returning a handler for errors from user actions. Inline/banner errors
 * are rendered by the caller (form / page); everything else becomes a toast.
 * Returns the presentation so callers know whether they must render it.
 */
export function useErrorHandler() {
  const navigate = useNavigate();
  return useCallback(
    (error: unknown, opts: NotifyOptions & { forceToast?: boolean } = {}) => {
      const e = ApiError.from(error);
      // Signed-out errors are handled globally by the sign-in redirect.
      if (e.code === 'LSE-AUTH-001') return 'redirect' as const;
      const p = presentationForAction(e);
      if (p === 'toast' || opts.forceToast) toastError(e, navigate, opts);
      return p;
    },
    [navigate],
  );
}

export function toastSuccess(message: string, description?: string): void {
  toast.success(message, description ? { description } : undefined);
}
