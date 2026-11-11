import { Globe, KeyRound } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Link, useLocation } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { useOrgs } from '@/hooks/api/orgs';
import { ssoStartUrl } from '@/lib/api';

/**
 * LSE-ORG-010: the organization only accepts connections from approved IP addresses, so
 * nothing inside it can load. A dedicated screen beats a generic 403 — the user needs to know
 * it is the network, not their role.
 */
export function IpBlockedScreen({ onRetry }: { onRetry?: () => void }) {
  const { t } = useTranslation();
  return (
    <section
      aria-labelledby="ip-blocked-title"
      className="mx-auto flex max-w-md flex-col items-center gap-4 px-4 py-16 text-center"
      data-error-code="LSE-ORG-010"
    >
      <Globe className="size-10 text-muted-foreground" aria-hidden="true" />
      <h1 id="ip-blocked-title" className="text-xl font-semibold">
        {t('ipBlocked.title')}
      </h1>
      <p className="text-muted-foreground">{t('ipBlocked.body')}</p>
      <p className="text-sm text-muted-foreground">{t('ipBlocked.help')}</p>
      <div className="flex flex-wrap justify-center gap-2">
        {onRetry ? <Button onClick={onRetry}>{t('ipBlocked.retry')}</Button> : null}
        <Button variant="outline" asChild>
          <Link to="/orgs">{t('ipBlocked.switchOrg')}</Link>
        </Button>
      </div>
      <p className="text-xs text-muted-foreground">Error LSE-ORG-010</p>
    </section>
  );
}

/**
 * LSE-AUTH-006: this organization requires single sign-on. We know the org id from the URL;
 * the org list (which isn't SSO-gated) gives us the slug the SSO start route needs.
 */
export function SsoRequiredScreen({ orgId }: { orgId: string }) {
  const { t } = useTranslation();
  const orgs = useOrgs();
  const location = useLocation();
  const slug = orgs.data?.find((o) => o.id === orgId)?.slug;
  return (
    <section
      aria-labelledby="sso-required-title"
      className="mx-auto flex max-w-md flex-col items-center gap-4 px-4 py-16 text-center"
      data-error-code="LSE-AUTH-006"
    >
      <KeyRound className="size-10 text-muted-foreground" aria-hidden="true" />
      <h1 id="sso-required-title" className="text-xl font-semibold">
        {t('ssoRequired.title')}
      </h1>
      <p className="text-muted-foreground">{t('ssoRequired.body')}</p>
      {slug ? (
        <Button asChild>
          <a href={ssoStartUrl(slug, { returnTo: `${location.pathname}${location.search}` })}>
            {t('ssoRequired.action')}
          </a>
        </Button>
      ) : (
        <p className="text-sm text-muted-foreground">{t('ssoRequired.noSlug')}</p>
      )}
      <p className="text-xs text-muted-foreground">Error LSE-AUTH-006</p>
    </section>
  );
}
