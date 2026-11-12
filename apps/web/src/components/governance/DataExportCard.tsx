import type { DataExportDto } from '@loose/shared';
import { Download } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { MutationError } from '@/components/errors/MutationError';
import { toastSuccess } from '@/components/errors/notify';
import { LoadingBlock, QueryError } from '@/components/errors/QueryError';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { FeatureOff, isFeatureOffError } from '@/components/ui/feature-off';
import { isExportActive } from '@/hooks/api/governance';
import { formatDateTime } from '@/lib/utils';

export function formatBytes(bytes: number | null): string {
  if (bytes === null) return '—';
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let n = bytes / 1024;
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(n < 10 ? 1 : 0)} ${units[i]}`;
}

const STATUS_VARIANT = {
  PENDING: 'secondary',
  RUNNING: 'secondary',
  SUCCEEDED: 'success',
  FAILED: 'destructive',
  EXPIRED: 'outline',
} as const;

/** Request + list GDPR/DPDP data exports (org or personal). Status is polled by the hook. */
export function DataExportCard({
  id,
  title,
  description,
  exports,
  request,
  canRequest = true,
}: {
  id: string;
  title: string;
  description: string;
  exports: {
    data: DataExportDto[] | undefined;
    isPending: boolean;
    isError: boolean;
    error: unknown;
    refetch: () => void;
  };
  request: {
    isPending: boolean;
    error: unknown;
    mutate: (v: undefined, o: { onSuccess: () => void }) => void;
  };
  canRequest?: boolean;
}) {
  const { t } = useTranslation();
  const list = exports.data ?? [];
  const busy = list.some(isExportActive);

  return (
    <Card id={id} aria-labelledby={`${id}-title`}>
      <CardHeader>
        <CardTitle id={`${id}-title`} as="h2">
          {title}
        </CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent className="grid gap-3 text-sm">
        {isFeatureOffError(exports.error) ? (
          <FeatureOff name={title} />
        ) : exports.isPending ? (
          <LoadingBlock rows={1} label={t('common.loading')} />
        ) : exports.isError ? (
          <QueryError error={exports.error} onRetry={exports.refetch} />
        ) : list.length === 0 ? (
          <p className="text-muted-foreground">{t('dataExport.none')}</p>
        ) : (
          <ul aria-label={t('dataExport.list')} className="grid gap-2">
            {list.map((e) => (
              <li key={e.id} className="flex flex-wrap items-center gap-2 rounded-md border p-2">
                <Badge variant={STATUS_VARIANT[e.status]}>
                  {t(`dataExport.status.${e.status}`)}
                </Badge>
                <span className="text-muted-foreground">
                  {t('dataExport.created', { when: formatDateTime(e.createdAt) })}
                </span>
                {e.status === 'SUCCEEDED' && e.bytes !== null ? (
                  <span className="text-muted-foreground">{formatBytes(e.bytes)}</span>
                ) : null}
                {e.status === 'SUCCEEDED' && e.expiresAt ? (
                  <span className="text-muted-foreground">
                    {t('dataExport.expires', { when: formatDateTime(e.expiresAt) })}
                  </span>
                ) : null}
                {e.status === 'FAILED' ? (
                  <span className="text-destructive">{t('dataExport.failed')}</span>
                ) : null}
                {e.downloadUrl ? (
                  <Button size="sm" variant="outline" className="ml-auto" asChild>
                    <a href={e.downloadUrl} download>
                      <Download aria-hidden="true" />
                      {t('dataExport.download')}
                      <span className="sr-only"> ({formatDateTime(e.createdAt)})</span>
                    </a>
                  </Button>
                ) : null}
              </li>
            ))}
          </ul>
        )}
        <MutationError error={request.error} />
        {busy ? (
          <p role="status" className="text-muted-foreground">
            {t('dataExport.inProgress')}
          </p>
        ) : null}
      </CardContent>
      <CardFooter>
        <Button
          variant="outline"
          disabled={!canRequest || busy || isFeatureOffError(exports.error)}
          loading={request.isPending}
          onClick={() =>
            request.mutate(undefined, { onSuccess: () => toastSuccess(t('dataExport.requested')) })
          }
        >
          {t('dataExport.request')}
        </Button>
      </CardFooter>
    </Card>
  );
}
