import { totpCodeSchema } from '@loose/shared';
import { ShieldCheck, ShieldOff } from 'lucide-react';
import { useState, type FormEvent } from 'react';
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { FeatureOff, isFeatureOffError } from '@/components/ui/feature-off';
import { Field } from '@/components/ui/field';
import { Input } from '@/components/ui/input';
import { useFeatureFlags } from '@/hooks/api/featureFlags';
import {
  useDisableTwoFactor,
  useRegenerateRecoveryCodes,
  useTwoFactorStatus,
} from '@/hooks/api/identity';
import { ApiError } from '@/lib/errors';
import { formatDateTime } from '@/lib/utils';
import { RecoveryCodes } from './RecoveryCodes';
import { TwoFactorEnrollment } from './TwoFactorEnrollment';

/** Asks for a current authenticator code, then runs `onSubmit`. */
function CodeDialog({
  open,
  onOpenChange,
  title,
  description,
  destructive,
  pending,
  error,
  onSubmit,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: string;
  destructive?: boolean;
  pending: boolean;
  error: unknown;
  onSubmit: (code: string) => void;
}) {
  const { t } = useTranslation();
  const [code, setCode] = useState('');
  const [fieldError, setFieldError] = useState<string | undefined>();
  const apiError = error ? ApiError.from(error) : null;
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const parsed = totpCodeSchema.safeParse(code);
    if (!parsed.success) {
      setFieldError(t('twoFactor.invalidCode'));
      return;
    }
    setFieldError(undefined);
    onSubmit(parsed.data);
  };
  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o) {
          setCode('');
          setFieldError(undefined);
        }
        onOpenChange(o);
      }}
    >
      <DialogContent>
        <form onSubmit={submit} noValidate className="grid gap-4">
          <DialogHeader>
            <DialogTitle>{title}</DialogTitle>
            <DialogDescription>{description}</DialogDescription>
          </DialogHeader>
          <Field
            id="2fa-confirm-code"
            label={t('twoFactor.code')}
            description={t('twoFactor.codeHelp')}
            error={
              fieldError ?? (apiError?.code === 'LSE-AUTH-010' ? apiError.userMessage : undefined)
            }
          >
            {(aria) => (
              <Input
                {...aria}
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                className="max-w-40 font-mono tracking-widest"
              />
            )}
          </Field>
          <MutationError error={error} hideCodes={['LSE-AUTH-010']} />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              {t('common.cancel')}
            </Button>
            <Button
              type="submit"
              variant={destructive ? 'destructive' : 'default'}
              loading={pending}
            >
              {t('twoFactor.section.confirm')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/** Account settings → Two-step verification (`/settings#security`). */
export function TwoFactorSection() {
  const { t } = useTranslation();
  const flags = useFeatureFlags();
  const status = useTwoFactorStatus({ enabled: flags.isEnabled('admin_2fa') });
  const disable = useDisableTwoFactor();
  const regenerate = useRegenerateRecoveryCodes();
  const [enrolling, setEnrolling] = useState(false);
  const [disableOpen, setDisableOpen] = useState(false);
  const [regenOpen, setRegenOpen] = useState(false);
  const [newCodes, setNewCodes] = useState<string[] | null>(null);

  const title = t('twoFactor.section.title');
  const off = !flags.isEnabled('admin_2fa') || isFeatureOffError(status.error);

  return (
    <Card id="security" aria-labelledby="two-factor-title">
      <CardHeader>
        <CardTitle id="two-factor-title" as="h2">
          {title}
        </CardTitle>
        <CardDescription>{t('twoFactor.section.description')}</CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4 text-sm">
        {off ? (
          <FeatureOff name={title} />
        ) : status.isPending ? (
          <LoadingBlock rows={1} label={t('common.loading')} />
        ) : status.isError ? (
          <QueryError error={status.error} onRetry={() => void status.refetch()} />
        ) : newCodes ? (
          <RecoveryCodes codes={newCodes} onDone={() => setNewCodes(null)} />
        ) : enrolling ? (
          <TwoFactorEnrollment
            onFinished={() => {
              setEnrolling(false);
              toastSuccess(t('twoFactor.section.statusOn'));
            }}
            onCancel={() => setEnrolling(false)}
          />
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-2">
              {status.data.enabled ? (
                <Badge variant="success">
                  <ShieldCheck aria-hidden="true" className="size-3" />
                  {t('twoFactor.section.statusOn')}
                </Badge>
              ) : (
                <Badge variant="outline">
                  <ShieldOff aria-hidden="true" className="size-3" />
                  {t('twoFactor.section.statusOff')}
                </Badge>
              )}
              {status.data.enabled && status.data.enabledAt ? (
                <span className="text-muted-foreground">
                  {t('twoFactor.section.enabledOn', {
                    when: formatDateTime(status.data.enabledAt),
                  })}
                </span>
              ) : null}
            </div>
            {status.data.enabled ? (
              <p className="text-muted-foreground">
                {t('twoFactor.section.recoveryRemaining', {
                  count: status.data.recoveryCodesRemaining,
                })}
              </p>
            ) : null}
            {status.data.requiredByOrg ? (
              <p className="text-muted-foreground">{t('twoFactor.section.requiredByOrg')}</p>
            ) : null}
          </>
        )}
      </CardContent>
      {!off && status.data && !enrolling && !newCodes ? (
        <CardFooter className="flex flex-wrap gap-2">
          {status.data.enabled ? (
            <>
              <Button variant="outline" onClick={() => setRegenOpen(true)}>
                {t('twoFactor.section.regenerate')}
              </Button>
              <Button
                variant="outline"
                disabled={status.data.requiredByOrg}
                onClick={() => setDisableOpen(true)}
              >
                {t('twoFactor.section.disable')}
              </Button>
            </>
          ) : (
            <Button onClick={() => setEnrolling(true)}>{t('twoFactor.section.enable')}</Button>
          )}
        </CardFooter>
      ) : null}
      <CodeDialog
        open={disableOpen}
        onOpenChange={(o) => {
          setDisableOpen(o);
          if (!o) disable.reset();
        }}
        title={t('twoFactor.section.disableTitle')}
        description={t('twoFactor.section.disableDescription')}
        destructive
        pending={disable.isPending}
        error={disable.error}
        onSubmit={(code) =>
          disable.mutate(code, {
            onSuccess: () => {
              setDisableOpen(false);
              toastSuccess(t('twoFactor.section.statusOff'));
            },
          })
        }
      />
      <CodeDialog
        open={regenOpen}
        onOpenChange={(o) => {
          setRegenOpen(o);
          if (!o) regenerate.reset();
        }}
        title={t('twoFactor.section.regenerateTitle')}
        description={t('twoFactor.section.regenerateDescription')}
        pending={regenerate.isPending}
        error={regenerate.error}
        onSubmit={(code) =>
          regenerate.mutate(code, {
            onSuccess: (res) => {
              setRegenOpen(false);
              setNewCodes(res.recoveryCodes);
            },
          })
        }
      />
    </Card>
  );
}
