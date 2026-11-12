import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { Outlet, useLocation, useMatch } from 'react-router-dom';
import { ErrorBoundary } from '@/components/errors/ErrorBoundary';
import { cn } from '@/lib/utils';
import { useUiStore } from '@/stores/uiStore';
import { DeletionBanner } from './DeletionBanner';
import { Header } from './Header';
import { OrgDeletionBanner } from './OrgDeletionBanner';
import { Sidebar } from './Sidebar';

/** Org id in the URL (`/orgs/:orgId/...`), excluding `/orgs/new`. */
export function useRouteOrgId(): string | null {
  const match = useMatch('/orgs/:orgId/*');
  const id = match?.params.orgId;
  return id && id !== 'new' ? id : null;
}

export function AppLayout() {
  const { t } = useTranslation();
  const orgId = useRouteOrgId();
  const location = useLocation();
  const mobileNavOpen = useUiStore((s) => s.mobileNavOpen);
  const setMobileNavOpen = useUiStore((s) => s.setMobileNavOpen);

  // Close the mobile drawer on navigation.
  useEffect(() => {
    setMobileNavOpen(false);
  }, [location.pathname, setMobileNavOpen]);

  return (
    <div className="flex min-h-screen bg-background">
      <a
        href="#main-content"
        className="sr-only z-50 rounded-md bg-primary px-3 py-2 text-primary-foreground focus:not-sr-only focus:fixed focus:top-2 focus:left-2"
      >
        {t('shell.skipToContent')}
      </a>
      {mobileNavOpen ? (
        <div
          className="fixed inset-0 z-30 bg-black/40 md:hidden"
          aria-hidden="true"
          onClick={() => setMobileNavOpen(false)}
        />
      ) : null}
      <aside
        id="app-sidebar"
        aria-label="Sidebar"
        className={cn(
          'fixed inset-y-0 left-0 z-40 w-64 border-r bg-sidebar text-sidebar-foreground transition-transform md:sticky md:top-0 md:h-screen md:translate-x-0',
          // `invisible` keeps the off-canvas drawer out of the tab order on mobile.
          mobileNavOpen ? 'translate-x-0' : 'invisible -translate-x-full md:visible',
        )}
      >
        <Sidebar orgId={orgId} />
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <Header />
        <main id="main-content" tabIndex={-1} className="flex-1 px-4 py-6 outline-none md:px-8">
          <DeletionBanner />
          <OrgDeletionBanner orgId={orgId} />
          <ErrorBoundary section="This page" resetKeys={[location.pathname]}>
            <Outlet />
          </ErrorBoundary>
        </main>
      </div>
    </div>
  );
}
