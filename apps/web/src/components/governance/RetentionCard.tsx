import {
  RETENTION_KINDS,
  RETENTION_LIMITS,
  retentionSettingsSchema,
  zodIssuesToFieldErrors,
  type RetentionKind,
  type RetentionSettings,
} from '@loose/shared';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { fieldErrorOf, MutationError } from '@/components/errors/MutationError';
import { toastSuccess } from '@/components/errors/notify';
import { LoadingBlock, QueryError } from '@/components/errors/QueryError';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Field } from '@/components/ui/field';
import { Input } from '@/components/ui/input';
import { useRetention, useUpdateRetention } from '@/hooks/api/governance';
import { formatDateTime } from '@/lib/utils';

function RetentionForm({
  orgId,
  settings,
  canEdit,
}: {
  orgId: string;
  settings: RetentionSettings;
  canEdit: boolean;
}) {
  const { t } = useTranslation();
  const update = useUpdateRetention(orgId);
  const [values, setValues] = useState<Record<RetentionKind, string>>(
    () =>
      Object.fromEntries(RETENTION_KINDS.map((k) => [k, String(settings[k])])) as Record<
        RetentionKind,
        string
      >,
  );
  const [localErrors, setLocalErrors] = useState<Record<string, string[]>>({});
  const err = (k: RetentionKind) => localErrors[k]?.[0] ?? fieldErrorOf(update.error, k);

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    const parsed = retentionSettingsSchema.safeParse(
      Object.fromEntries(
        RETENTION_KINDS.map((k) => [k, values[k] === '' ? NaN : Number(values[k])]),
      ),
    );
    if (!parsed.success) {
      const fields = zodIssuesToFieldErrors(parsed.error.issues);
      // Replace zod's generic text with the allowed range.
      for (const k of RETENTION_KINDS) {
        if (fields[k]) {
          fields[k] = [
            t('retention.range', { min: RETENTION_LIMITS[k].min, max: RETENTION_LIMITS[k].max }),
          ];
        }
      }
      setLocalErrors(fields);
      return;
    }
    setLocalErrors({});
    update.mutate(parsed.data, { onSuccess: () => toastSuccess(t('retention.saved')) });
  };

  return (
    <form onSubmit={onSubmit} noValidate aria-label={t('retention.title')}>
      <CardContent className="grid gap-4 sm:grid-cols-2">
        {RETENTION_KINDS.map((k) => (
          <Field
            key={k}
            id={`retention-${k}`}
            label={`${t(`retention.${k}`)} (${t('retention.days')})`}
            description={t(`retention.${k}Help`)}
            error={err(k)}
          >
            {(aria) => (
              <Input
                {...aria}
                type="number"
                inputMode="numeric"
                min={RETENTION_LIMITS[k].min}
                max={RETENTION_LIMITS[k].max}
                value={values[k]}
                disabled={!canEdit}
                onChange={(e) => setValues((v) => ({ ...v, [k]: e.target.value }))}
              />
            )}
          </Field>
        ))}
        <div className="sm:col-span-2">
          <MutationError error={update.error} />
        </div>
      </CardContent>
      <CardFooter className="flex flex-wrap items-center gap-2">
        <Button type="submit" disabled={!canEdit} loading={update.isPending}>
          {t('retention.save')}
        </Button>
        {!canEdit ? (
          <span className="text-xs text-muted-foreground">{t('retention.ownerOnly')}</span>
        ) : null}
      </CardFooter>
    </form>
  );
}

export function RetentionCard({ orgId, canEdit }: { orgId: string; canEdit: boolean }) {
  const { t } = useTranslation();
  const query = useRetention(orgId);
  const counts = query.data?.lastPurgeCounts;
  return (
    <Card id="retention" aria-labelledby="retention-title">
      <CardHeader>
        <CardTitle id="retention-title" as="h2">
          {t('retention.title')}
        </CardTitle>
        <CardDescription>{t('retention.description')}</CardDescription>
      </CardHeader>
      {query.isPending ? (
        <CardContent>
          <LoadingBlock rows={2} label={t('common.loading')} />
        </CardContent>
      ) : query.isError ? (
        <CardContent>
          <QueryError error={query.error} onRetry={() => void query.refetch()} />
        </CardContent>
      ) : (
        <>
          <RetentionForm
            key={JSON.stringify(query.data.settings)}
            orgId={orgId}
            settings={query.data.settings}
            canEdit={canEdit}
          />
          <CardContent className="pt-0 text-xs text-muted-foreground">
            <p>
              {query.data.lastPurgeAt
                ? t('retention.lastPurge', { when: formatDateTime(query.data.lastPurgeAt) })
                : t('retention.neverPurged')}
            </p>
            {counts ? <p>{t('retention.purged', counts)}</p> : null}
          </CardContent>
        </>
      )}
    </Card>
  );
}
