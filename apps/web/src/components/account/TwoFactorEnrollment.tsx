import { totpCodeSchema } from '@loose/shared';
import { Copy } from 'lucide-react';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { MutationError } from '@/components/errors/MutationError';
import { Button } from '@/components/ui/button';
import { Field } from '@/components/ui/field';
import { Input } from '@/components/ui/input';
import { QrCode } from '@/components/ui/qr-code';
import { useActivateTwoFactor, useEnrollTwoFactor } from '@/hooks/api/identity';
import { ApiError } from '@/lib/errors';
import { copyToClipboard } from '@/lib/utils';
import { RecoveryCodes } from './RecoveryCodes';

type Step = 'idle' | 'scan' | 'codes';

/** Split a base32 secret into groups of four so it is easy to read and type. */
export function formatSecret(secret: string): string {
  return secret.replace(/(.{4})/g, '$1 ').trim();
}

/**
 * Enrolment wizard: start → QR + setup key + confirm code → recovery codes (once). The QR is
 * drawn locally from the `otpauth://` URL; the secret and codes never leave component state and
 * are cleared when the flow ends or is cancelled.
 */
export function TwoFactorEnrollment({
  onFinished,
  onCancel,
  autoStart = false,
}: {
  /** Called after the user confirms they saved the recovery codes. */
  onFinished: () => void;
  onCancel?: () => void;
  autoStart?: boolean;
}) {
  const { t } = useTranslation();
  const enroll = useEnrollTwoFactor();
  const activate = useActivateTwoFactor();
  const [step, setStep] = useState<Step>('idle');
  const [secret, setSecret] = useState<{ secret: string; otpauthUrl: string } | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [code, setCode] = useState('');
  const [fieldError, setFieldError] = useState<string | undefined>();
  const [copied, setCopied] = useState(false);
  const startedRef = useRef(false);

  const start = () => {
    enroll.mutate(undefined, {
      onSuccess: (res) => {
        setSecret(res);
        setStep('scan');
      },
    });
  };

  // Used by the sign-in-time screen, where the only thing to do is enrol. The ref keeps
  // StrictMode's double effect from minting two secrets (the server keeps only the last).
  useEffect(() => {
    if (!autoStart || startedRef.current) return;
    startedRef.current = true;
    enroll.mutate(undefined, {
      onSuccess: (res) => {
        setSecret(res);
        setStep('scan');
      },
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoStart]);

  const reset = () => {
    setSecret(null);
    setCodes(null);
    setCode('');
    setFieldError(undefined);
    setStep('idle');
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const parsed = totpCodeSchema.safeParse(code);
    if (!parsed.success) {
      setFieldError(t('twoFactor.invalidCode'));
      return;
    }
    setFieldError(undefined);
    activate.mutate(parsed.data, {
      onSuccess: (res) => {
        // The setup key is no longer needed (or safe to keep around).
        setSecret(null);
        setCode('');
        setCodes(res.recoveryCodes);
        setStep('codes');
      },
    });
  };

  if (step === 'codes' && codes) {
    return (
      <RecoveryCodes
        codes={codes}
        onDone={() => {
          reset();
          onFinished();
        }}
      />
    );
  }

  if (step === 'scan' && secret) {
    const activateError = activate.error ? ApiError.from(activate.error) : null;
    return (
      <form onSubmit={submit} className="grid gap-4" noValidate data-testid="enroll-form">
        <div className="grid gap-2">
          <p className="text-sm font-medium">{t('twoFactor.section.scan')}</p>
          <QrCode value={secret.otpauthUrl} label={t('twoFactor.section.qrLabel')} />
        </div>
        <div className="grid gap-1 text-sm">
          <p className="text-muted-foreground">{t('twoFactor.section.manual')}</p>
          <div className="flex flex-wrap items-center gap-2">
            <code
              aria-label={t('twoFactor.section.secretLabel')}
              className="rounded bg-muted px-2 py-1 font-mono text-sm tracking-wider break-all"
            >
              {formatSecret(secret.secret)}
            </code>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => {
                void copyToClipboard(secret.secret).then(setCopied);
              }}
            >
              <Copy aria-hidden="true" />
              {copied ? t('twoFactor.section.copied') : t('twoFactor.section.copySecret')}
            </Button>
          </div>
        </div>
        <Field
          id="enroll-code"
          label={t('twoFactor.section.confirmCode')}
          description={t('twoFactor.codeHelp')}
          error={
            fieldError ??
            (activateError?.code === 'LSE-AUTH-010' ? activateError.userMessage : undefined)
          }
          required
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
        <MutationError error={activate.error} hideCodes={['LSE-AUTH-010']} />
        <div className="flex flex-wrap gap-2">
          <Button type="submit" loading={activate.isPending}>
            {t('twoFactor.section.activate')}
          </Button>
          <Button
            type="button"
            variant="outline"
            onClick={() => {
              reset();
              onCancel?.();
            }}
          >
            {t('twoFactor.section.cancel')}
          </Button>
        </div>
      </form>
    );
  }

  return (
    <div className="grid gap-2">
      <MutationError error={enroll.error} />
      <div>
        <Button type="button" onClick={start} loading={enroll.isPending}>
          {t('twoFactor.section.enable')}
        </Button>
      </div>
    </div>
  );
}
