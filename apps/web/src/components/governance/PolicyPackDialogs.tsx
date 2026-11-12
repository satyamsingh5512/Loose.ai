import {
  createPolicyPackBodySchema,
  policyPackRulesSchema,
  type ApplyPolicyPackResultDto,
  type PolicyPackDto,
} from '@loose/shared';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { fieldErrorOf, MutationError } from '@/components/errors/MutationError';
import { toastSuccess } from '@/components/errors/notify';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Field } from '@/components/ui/field';
import { Checkbox, Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import {
  useApplyPolicyPack,
  useCreatePolicyPack,
  useUpdatePolicyPack,
} from '@/hooks/api/governance';
import { useProjects } from '@/hooks/api/projects';

/** Create / edit a custom pack. Rules are edited as JSON and validated with the shared schema. */
export function PolicyPackEditorDialog({
  orgId,
  pack,
  open,
  onOpenChange,
}: {
  orgId: string;
  /** Existing custom pack to edit; omit to create. */
  pack?: PolicyPackDto;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const { t } = useTranslation();
  const create = useCreatePolicyPack(orgId);
  const update = useUpdatePolicyPack(orgId);
  const mutation = pack ? update : create;
  const [name, setName] = useState(pack?.name ?? '');
  const [description, setDescription] = useState(pack?.description ?? '');
  const [rulesText, setRulesText] = useState(pack ? JSON.stringify(pack.rules, null, 2) : '');
  const [errors, setErrors] = useState<{ name?: string; rules?: string }>({});

  const submit = (e: FormEvent) => {
    e.preventDefault();
    let rulesJson: unknown;
    try {
      rulesJson = JSON.parse(rulesText);
    } catch {
      setErrors({ rules: t('policyPacks.invalidJson') });
      return;
    }
    const rules = policyPackRulesSchema.safeParse(rulesJson);
    if (!rules.success) {
      setErrors({ rules: rules.error.issues[0]?.message ?? t('policyPacks.invalidJson') });
      return;
    }
    const base = createPolicyPackBodySchema.safeParse({ name, description, rules: rules.data });
    if (!base.success) {
      setErrors({ name: base.error.issues[0]?.message });
      return;
    }
    setErrors({});
    const done = () => {
      toastSuccess(t('policyPacks.saved'));
      onOpenChange(false);
    };
    if (pack) {
      update.mutate(
        {
          id: pack.id,
          body: {
            name: base.data.name,
            description: base.data.description,
            rules: base.data.rules,
          },
        },
        { onSuccess: done },
      );
    } else {
      create.mutate(base.data, { onSuccess: done });
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-xl">
        <form onSubmit={submit} noValidate className="grid gap-4">
          <DialogHeader>
            <DialogTitle>
              {pack ? `${t('policyPacks.edit')} ${pack.name}` : t('policyPacks.create')}
            </DialogTitle>
            <DialogDescription>{t('policyPacks.description')}</DialogDescription>
          </DialogHeader>
          <Field
            id="pack-name"
            label={t('policyPacks.name')}
            // The server derives the slug from the name, so a taken/invalid slug is a problem with the name.
            error={
              errors.name ??
              fieldErrorOf(mutation.error, 'name') ??
              fieldErrorOf(mutation.error, 'slug')
            }
            required
          >
            {(aria) => <Input {...aria} value={name} onChange={(e) => setName(e.target.value)} />}
          </Field>
          <Field id="pack-description" label={t('policyPacks.descriptionLabel')}>
            {(aria) => (
              <Textarea
                {...aria}
                rows={2}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            )}
          </Field>
          <Field
            id="pack-rules"
            label={t('policyPacks.rulesJson')}
            description={t('policyPacks.rulesHelp')}
            error={errors.rules ?? fieldErrorOf(mutation.error, 'rules')}
            required
          >
            {(aria) => (
              <Textarea
                {...aria}
                rows={8}
                spellCheck={false}
                className="font-mono text-xs"
                value={rulesText}
                onChange={(e) => setRulesText(e.target.value)}
              />
            )}
          </Field>
          <MutationError error={mutation.error} hideCodes={['LSE-VAL-001']} />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" loading={mutation.isPending}>
              {t('policyPacks.save')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/** Choose projects to apply a pack to; shows which guardrails changed per project afterwards. */
export function ApplyPolicyPackDialog({
  orgId,
  pack,
  open,
  onOpenChange,
}: {
  orgId: string;
  pack: PolicyPackDto;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const { t } = useTranslation();
  const projects = useProjects(orgId);
  const apply = useApplyPolicyPack(orgId);
  const [selected, setSelected] = useState<string[]>([]);
  const [result, setResult] = useState<ApplyPolicyPackResultDto | null>(null);

  const toggle = (id: string, on: boolean) =>
    setSelected((s) => (on ? [...s, id] : s.filter((x) => x !== id)));
  const nameOf = (id: string) => projects.data?.find((p) => p.id === id)?.name ?? id;

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o) {
          setSelected([]);
          setResult(null);
          apply.reset();
        }
        onOpenChange(o);
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('policyPacks.applyTitle', { name: pack.name })}</DialogTitle>
          <DialogDescription>{t('policyPacks.applyDescription')}</DialogDescription>
        </DialogHeader>
        {result ? (
          <Alert variant="success" role="status" data-testid="apply-result">
            <AlertDescription>
              <p>{t('policyPacks.applied', { count: result.applied.length })}</p>
              <ul className="list-disc pl-4">
                {result.applied.map((a) => (
                  <li key={a.projectId}>
                    <span className="font-medium">{nameOf(a.projectId)}</span>:{' '}
                    {a.changed.length === 0
                      ? t('policyPacks.unchanged')
                      : t('policyPacks.changed', {
                          fields: a.changed.map((f) => t(`policyPacks.fields.${f}`)).join(', '),
                        })}
                  </li>
                ))}
              </ul>
            </AlertDescription>
          </Alert>
        ) : (
          <fieldset className="grid gap-2">
            <legend className="mb-1 text-sm font-medium">{t('policyPacks.projects')}</legend>
            {projects.data?.length === 0 ? (
              <p className="text-sm text-muted-foreground">{t('policyPacks.noProjects')}</p>
            ) : null}
            {(projects.data ?? []).map((p) => (
              <label key={p.id} className="flex items-center gap-2 text-sm">
                <Checkbox
                  checked={selected.includes(p.id)}
                  onChange={(e) => toggle(p.id, e.target.checked)}
                />
                {p.name}
              </label>
            ))}
          </fieldset>
        )}
        <MutationError error={apply.error} />
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {result ? t('common.close') : t('common.cancel')}
          </Button>
          {result ? null : (
            <Button
              disabled={selected.length === 0}
              loading={apply.isPending}
              onClick={() =>
                apply.mutate(
                  { id: pack.id, body: { projectIds: selected } },
                  { onSuccess: setResult },
                )
              }
            >
              {t('policyPacks.applyConfirm')}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
