import { useTranslation } from 'react-i18next';
import { DataExportCard } from '@/components/governance/DataExportCard';
import { DeletionCard } from '@/components/governance/DeletionCard';
import {
  useCancelMyDeletion,
  useMyDataExports,
  useMyDeletion,
  useRequestMyDataExport,
  useScheduleMyDeletion,
} from '@/hooks/api/governance';
import { useFeatureFlags } from '@/hooks/api/featureFlags';
import { useAuth } from '@/hooks/useAuth';

/** Account settings → Privacy (`/settings#privacy`): export my data, delete my account. */
export function PrivacySection() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const flags = useFeatureFlags();
  const exports = useMyDataExports({ enabled: flags.isEnabled('data_export') });
  const request = useRequestMyDataExport();
  const deletion = useMyDeletion();
  const schedule = useScheduleMyDeletion();
  const cancel = useCancelMyDeletion();

  return (
    <div id="privacy" className="grid gap-6">
      {flags.isEnabled('data_export') ? (
        <DataExportCard
          id="my-export"
          title={t('dataExport.myTitle')}
          description={t('dataExport.myDescription')}
          exports={{
            data: exports.data,
            isPending: exports.isPending,
            isError: exports.isError,
            error: exports.error,
            refetch: () => void exports.refetch(),
          }}
          request={request}
        />
      ) : null}
      <DeletionCard
        id="my-deletion"
        kind="user"
        confirmValue={user?.email ?? ''}
        query={{
          data: deletion.data,
          isPending: deletion.isPending,
          isError: deletion.isError,
          error: deletion.error,
          refetch: () => void deletion.refetch(),
        }}
        schedule={schedule}
        cancel={cancel}
      />
    </div>
  );
}
