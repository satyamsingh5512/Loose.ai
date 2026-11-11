import { Check, Copy, Download } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/input';
import { saveFile } from '@/lib/api';
import { copyToClipboard } from '@/lib/utils';

/**
 * The one-time recovery code list. The codes live only in this component's props; the parent
 * drops them as soon as `onDone` fires, and "Done" stays disabled until the user confirms they
 * saved them (copy / download / tick the box).
 */
export function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);
  const [saved, setSaved] = useState(false);

  const text = `${codes.join('\n')}\n`;

  const copy = async () => {
    if (await copyToClipboard(text)) {
      setCopied(true);
      setSaved(true);
    }
  };
  const download = () => {
    saveFile({
      blob: new Blob([text], { type: 'text/plain' }),
      filename: 'loose-ai-recovery-codes.txt',
    });
    setSaved(true);
  };

  return (
    <section aria-labelledby="recovery-title" className="grid gap-3" data-testid="recovery-codes">
      <h3 id="recovery-title" className="text-sm font-semibold">
        {t('twoFactor.section.recoveryTitle')}
      </h3>
      <Alert variant="warning" role="note">
        <AlertTitle>{t('twoFactor.section.recoveryList')}</AlertTitle>
        <AlertDescription>{t('twoFactor.section.recoveryWarning')}</AlertDescription>
      </Alert>
      <ul
        aria-label={t('twoFactor.section.recoveryList')}
        className="grid grid-cols-2 gap-1 rounded-md border bg-muted/40 p-3 font-mono text-sm"
      >
        {codes.map((c) => (
          <li key={c}>{c}</li>
        ))}
      </ul>
      <div className="flex flex-wrap gap-2">
        <Button type="button" variant="outline" size="sm" onClick={() => void copy()}>
          {copied ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
          {copied ? t('twoFactor.section.copied') : t('twoFactor.section.copyCodes')}
        </Button>
        <Button type="button" variant="outline" size="sm" onClick={download}>
          <Download aria-hidden="true" />
          {t('twoFactor.section.downloadCodes')}
        </Button>
      </div>
      <label className="flex items-center gap-2 text-sm">
        <Checkbox checked={saved} onChange={(e) => setSaved(e.target.checked)} />
        {t('twoFactor.section.savedConfirm')}
      </label>
      <div>
        <Button type="button" onClick={onDone} disabled={!saved}>
          {t('twoFactor.section.done')}
        </Button>
      </div>
    </section>
  );
}
