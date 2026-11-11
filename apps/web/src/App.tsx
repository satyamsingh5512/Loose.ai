import { QueryClientProvider, type QueryClient } from '@tanstack/react-query';
import { useEffect, type ReactNode } from 'react';
import { RouterProvider, type createBrowserRouter } from 'react-router-dom';
import { Toaster } from '@/components/ui/sonner';
import { TooltipProvider } from '@/components/ui/tooltip';
import { ensureCsrfToken } from '@/lib/api';
import '@/i18n';
import { applyTheme, useUiStore } from '@/stores/uiStore';

function ThemeSync() {
  const theme = useUiStore((s) => s.theme);
  useEffect(() => {
    applyTheme(theme);
    if (theme !== 'system' || typeof window.matchMedia !== 'function') return;
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const onChange = () => applyTheme('system');
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, [theme]);
  return null;
}

/** Providers shared by the app and tests. */
export function AppProviders({
  queryClient,
  children,
}: {
  queryClient: QueryClient;
  children: ReactNode;
}) {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider delayDuration={300}>
        <ThemeSync />
        {children}
        <Toaster />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export function App({
  router,
  queryClient,
}: {
  router: ReturnType<typeof createBrowserRouter>;
  queryClient: QueryClient;
}) {
  // Make sure the CSRF double-submit cookie exists before the first mutation.
  useEffect(() => {
    void ensureCsrfToken();
  }, []);
  return (
    <AppProviders queryClient={queryClient}>
      <RouterProvider router={router} />
    </AppProviders>
  );
}
