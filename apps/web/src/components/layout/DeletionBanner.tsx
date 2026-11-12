import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { useAuth } from '@/hooks/useAuth';
import { formatDateTime } from '@/lib/utils';

/** Persistent notice while the signed-in account is inside its deletion grace period. */
export function DeletionBanner() {
  const { t } = useTranslation();
  const { user } = useAuth();
  if (!user?.deletionScheduledAt) return null;
  return (
    <Alert variant="warning" role="status" className="mb-4" data-testid="deletion-banner">
      <AlertDescription>
        <p>
          {t('deletion.banner', { when: formatDateTime(user.deletionScheduledAt) })}{' '}
          <Link className="font-medium underline" to="/settings#privacy">
            {t('deletion.bannerAction')}
          </Link>
        </p>
      </AlertDescription>
    </Alert>
  );
}
