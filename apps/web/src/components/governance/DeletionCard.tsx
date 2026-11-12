import type { DeletionRequestDto } from '@loose/shared';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { MutationError } from '@/components/errors/MutationError';
import { toastSuccess } from '@/components/errors/notify';
import { LoadingBlock, QueryError } from '@/components/errors/QueryError';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Field } from '@/components/ui/field';
import { Input } from '@/components/ui/input';
import { DisabledReason } from '@/components/ui/tooltip';
import { formatDateTime } from '@/lib/utils';

interface MutationLike<V> {
  isPending: boolean;
  error: unknown;
  reset: () => void;
  mutate: (v: V, o: { onSuccess?: () => void }) => void;
}

/**
 * Schedule / cancel deletion with a grace period (org or account). The user must type the
 * org's URL name or their own email; once scheduled the card explains the deadline and offers
 * the only action that is still safe: cancelling.
 */
export function DeletionCard({
  id,
  kind,
  subject,
  confirmValue,
  query,
  schedule,
  cancel,
  disabledReason,
}: {
  id: string;
  kind: 'org' | 'user';
  /** Org name (org) — shown in the dialog title. */
  subject?: string;
  /** What must be typed to confirm: org slug, or the user's email. */
  confirmValue: string;
  query: {
    data: DeletionRequestDto | null | undefined;
    isPending: boolean;
    isError: boolean;
    error: unknown;
    refetch: () => void;
  };
  schedule: MutationLike<string>;
  cancel: MutationLike<void>;
  /** Why the action is unavailable for this viewer (e.g. not an owner). */
  disabledReason?: string | null;
}) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [typed, setTyped] = useState('');
  const pending = query.data ?? null;
  const title = kind === 'org' ? t('deletion.orgTitle') : t('deletion.myTitle');
  const description = kind === 'org' ? t('deletion.orgDescription') : t('deletion.myDescription');

  return (
    <Card id={id} aria-labelledby={`${id}-title`} className="border-destructive/40">
      <CardHeader>
        <CardTitle id={`${id}-title`} as="h2">
          {title}
        </CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent className="grid gap-3">
        {query.isPending ? (
          <LoadingBlock rows={1} label={t('common.loading')} />
        ) : query.isError ? (
          <QueryError error={query.error} onRetry={query.refetch} />
        ) : pending ? (
          <Alert variant="warning" role="status" data-testid="deletion-scheduled">
            <AlertTitle>{t('deletion.graceTitle')}</AlertTitle>
            <AlertDescription>
              <p>{t('deletion.graceBody', { when: formatDateTime(pending.scheduledFor) })}</p>
              {kind === 'org' ? <p>{t('deletion.orgFrozen')}</p> : null}
            </AlertDescription>
          </Alert>
        ) : null}
        <MutationError error={cancel.error} />
      </CardContent>
      <CardFooter>
        {pending ? (
          <Button
            variant="outline"
            loading={cancel.isPending}
            onClick={() =>
              cancel.mutate(undefined, { onSuccess: () => toastSuccess(t('deletion.cancelled')) })
            }
          >
            {t('deletion.cancel')}
          </Button>
        ) : (
          <DisabledReason reason={disabledReason ?? null}>
            <Button
              variant="destructive"
              disabled={Boolean(disabledReason) || query.isPending || query.isError}
              onClick={() => setOpen(true)}
            >
              {t('deletion.schedule')}
            </Button>
          </DisabledReason>
        )}
      </CardFooter>
      <ConfirmDialog
        open={open}
        onOpenChange={(o) => {
          setOpen(o);
          if (!o) {
            setTyped('');
            schedule.reset();
          }
        }}
        title={
          kind === 'org'
            ? t('deletion.confirmTitle', { context: 'org', name: subject ?? '' })
            : t('deletion.confirmTitle', { context: 'user' })
        }
        description={t('deletion.confirmBody')}
        confirmLabel={t('deletion.schedule')}
        destructive
        loading={schedule.isPending}
        error={schedule.error}
        confirmDisabled={typed.trim() !== confirmValue}
        onConfirm={() =>
          schedule.mutate(typed.trim(), {
            onSuccess: () => {
              setOpen(false);
              setTyped('');
              toastSuccess(t('deletion.graceTitle'));
            },
          })
        }
      >
        <Field
          id={`${id}-confirm`}
          label={t('deletion.typeToConfirm', { context: kind, value: confirmValue })}
        >
          {(aria) => (
            <Input
              {...aria}
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
          )}
        </Field>
      </ConfirmDialog>
    </Card>
  );
}
