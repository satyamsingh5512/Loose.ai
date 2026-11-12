import { isSafeReturnTo } from '@loose/shared';
import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { Navigate, Outlet, useLocation, useNavigate } from 'react-router-dom';
import { FullPageError } from '@/components/errors/FullPageError';
import { Skeleton } from '@/components/ui/skeleton';
import { useMeQuery } from '@/hooks/api/auth';
import { onMfaRequired, onUnauthorized } from '@/lib/authEvents';
import { queryKeys } from '@/lib/queryKeys';
import { useAuthStore } from '@/stores/authStore';

const PUBLIC_PREFIXES = [
  '/signin',
  '/signup',
  '/auth/callback/',
  '/auth/2fa',
  '/invite/',
  '/docs/',
];

/** Pages that must never be a post-sign-in destination (would loop). */
const NO_RETURN_PREFIXES = ['/signin', '/signup', '/auth/callback/', '/auth/2fa'];

export function isPublicPath(pathname: string): boolean {
  return PUBLIC_PREFIXES.some((p) => pathname === p || pathname.startsWith(p));
}

function isReturnableTo(path: string): boolean {
  return isSafeReturnTo(path) && !NO_RETURN_PREFIXES.some((p) => path === p || path.startsWith(p));
}

export function signInPath(returnTo: string): string {
  if (returnTo === '/' || !isReturnableTo(returnTo)) return '/signin';
  return `/signin?returnTo=${encodeURIComponent(returnTo)}`;
}

/** Two-step challenge / enrollment screen, remembering where the user was heading. */
export function twoFactorPath(returnTo: string): string {
  if (returnTo === '/' || !isReturnableTo(returnTo)) return '/auth/2fa';
  return `/auth/2fa?returnTo=${encodeURIComponent(returnTo)}`;
}

/** Validated `returnTo` from a query string, defaulting to `/`. */
export function safeReturnTo(value: string | null | undefined): string {
  return value && isReturnableTo(value) ? value : '/';
}

/**
 * Listens for LSE-AUTH-001 from any API call and sends the user to
 * /signin?returnTo=<where they were>. Mounted once at the router root.
 */
export function AuthRedirector() {
  const navigate = useNavigate();
  const location = useLocation();
  const qc = useQueryClient();
  const markSessionExpired = useAuthStore((s) => s.markSessionExpired);
  const locRef = useRef(location);
  locRef.current = location;

  useEffect(
    () =>
      onUnauthorized(() => {
        const loc = locRef.current;
        if (isPublicPath(loc.pathname)) return;
        markSessionExpired();
        qc.setQueryData(queryKeys.me, null);
        navigate(signInPath(`${loc.pathname}${loc.search}${loc.hash}`), { replace: true });
      }),
    [navigate, qc, markSessionExpired],
  );

  // LSE-AUTH-012 from any API call → the two-step challenge (or enrollment, when required).
  useEffect(
    () =>
      onMfaRequired(() => {
        const loc = locRef.current;
        if (isPublicPath(loc.pathname)) return;
        navigate(twoFactorPath(`${loc.pathname}${loc.search}${loc.hash}`), { replace: true });
      }),
    [navigate],
  );
  return null;
}

/** Root route element: global listeners + the matched page. */
export function RootLayout() {
  return (
    <>
      <AuthRedirector />
      <Outlet />
    </>
  );
}

export function FullScreenLoader({ label }: { label?: string }) {
  const { t } = useTranslation();
  return (
    <div role="status" aria-live="polite" className="flex min-h-screen items-center justify-center">
      <span className="sr-only">{label ?? t('shell.loading')}</span>
      <div className="grid w-64 gap-3" aria-hidden="true">
        <Skeleton className="h-6 w-32" />
        <Skeleton className="h-4 w-full" />
        <Skeleton className="h-4 w-3/4" />
      </div>
    </div>
  );
}

/** Guard for authenticated routes. */
export function RequireAuth() {
  const me = useMeQuery();
  const location = useLocation();
  if (me.isPending) return <FullScreenLoader />;
  if (me.isError) return <FullPageError error={me.error} onRetry={() => void me.refetch()} />;
  const here = `${location.pathname}${location.search}${location.hash}`;
  if (!me.data) return <Navigate to={signInPath(here)} replace />;
  // The session still has to pass the two-step challenge before anything else works.
  if (me.data.mfaRequired) return <Navigate to={twoFactorPath(here)} replace />;
  return <Outlet />;
}
