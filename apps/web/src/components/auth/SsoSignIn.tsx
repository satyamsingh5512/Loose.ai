import { ssoDiscoverQuerySchema } from '@loose/shared';
import { KeyRound } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Field } from '@/components/ui/field';
import { Input } from '@/components/ui/input';
import { useSsoDiscover } from '@/hooks/api/identity';
import { ssoStartUrl } from '@/lib/api';

/**
 * "Single sign-on" entry on the sign-in page: the user types their work email, we ask the
 * server whether the domain belongs to an org with SSO, and offer a plain link (full-page
 * navigation — the start route sets the state cookies and redirects to the IdP).
 */
export function SsoSignIn({ returnTo }: { returnTo: string }) {
  const { t } = useTranslation();
  const [email, setEmail] = useState('');
  const [submitted, setSubmitted] = useState('');
  const [fieldError, setFieldError] = useState<string | undefined>();
  const discover = useSsoDiscover(submitted);

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    const parsed = ssoDiscoverQuerySchema.safeParse({ email });
    if (!parsed.success) {
      setFieldError(t('signIn.sso.invalidEmail'));
      setSubmitted('');
      return;
    }
    setFieldError(undefined);
    setSubmitted(parsed.data.email);
  };

  const result = discover.data;
  const org = result?.orgName ?? result?.orgSlug ?? '';

  return (
    <form
      onSubmit={onSubmit}
      className="grid gap-3"
      aria-labelledby="sso-signin-title"
      noValidate
      data-testid="sso-signin"
    >
      <div>
        <h2 id="sso-signin-title" className="text-sm font-medium">
          {t('signIn.sso.heading')}
        </h2>
        <p className="text-xs text-muted-foreground">{t('signIn.sso.description')}</p>
      </div>
      <Field id="sso-email" label={t('signIn.sso.emailLabel')} error={fieldError}>
        {(aria) => (
          <Input
            {...aria}
            type="email"
            autoComplete="email"
            value={email}
            onChange={(e) => {
              setEmail(e.target.value);
              if (submitted) setSubmitted('');
            }}
          />
        )}
      </Field>
      <Button type="submit" variant="secondary" loading={discover.isFetching}>
        <KeyRound aria-hidden="true" />
        {discover.isFetching ? t('signIn.sso.checking') : t('signIn.sso.submit')}
      </Button>
      <div aria-live="polite" className="grid gap-2">
        {submitted && discover.isError ? (
          <Alert variant="warning" role="status">
            <AlertDescription>{t('signIn.sso.unavailable')}</AlertDescription>
          </Alert>
        ) : null}
        {result && !result.sso ? (
          <p className="text-xs text-muted-foreground" role="status">
            {t('signIn.sso.none')}
          </p>
        ) : null}
        {result?.sso && result.orgSlug ? (
          <>
            <p className="text-xs text-muted-foreground" role="status">
              {result.enforced
                ? t('signIn.sso.foundEnforced', { org })
                : t('signIn.sso.found', { org })}
            </p>
            <Button asChild>
              <a href={ssoStartUrl(result.orgSlug, { returnTo })}>
                {t('signIn.sso.start', { org })}
              </a>
            </Button>
          </>
        ) : null}
      </div>
    </form>
  );
}
