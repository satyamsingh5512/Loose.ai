import { Check, Copy } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Button } from '@/components/ui/button';
import { buildDebugInfo, type ApiError } from '@/lib/errors';
import { copyToClipboard } from '@/lib/utils';

/** "Copy debug info" (spec §16.9): copies code, request id, session id and timestamp. */
export function CopyDebugInfoButton({ error }: { error: ApiError }) {
  const { t } = useTranslation();
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle');

  useEffect(() => {
    if (state === 'idle') return;
    const timer = setTimeout(() => setState('idle'), 2000);
    return () => clearTimeout(timer);
  }, [state]);

  return (
    <Button
      type="button"
      variant="ghost"
      size="sm"
      className="h-6 px-1.5 text-xs text-muted-foreground"
      onClick={() => {
        void copyToClipboard(buildDebugInfo(error)).then((ok) =>
          setState(ok ? 'copied' : 'failed'),
        );
      }}
    >
      {state === 'copied' ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
      <span aria-live="polite">
        {state === 'copied'
          ? t('errors.debugInfoCopied')
          : state === 'failed'
            ? t('errors.debugInfoCopyFailed')
            : t('errors.copyDebugInfo')}
      </span>
    </Button>
  );
}
