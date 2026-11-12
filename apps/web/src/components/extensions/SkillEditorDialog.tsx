/**
 * Create / edit an Agent Skill bundle (spec §8.6): a `SKILL.md` Markdown editor with live
 * frontmatter validation (`validateSkillBundle`), optional extra bundle files, and
 * "Try this skill" (`POST …/skills/dry-run`) showing issues, warnings and the listing the
 * agent would see. Nothing is saved until the admin submits.
 */
import {
  BUILTIN_SKILLS,
  SKILL_ENTRY_FILE,
  validateSkillBundle,
  type SkillDto,
  type SkillDryRunDto,
  type SkillFile,
  type WritableExtScope,
} from '@loose/shared';
import { AlertTriangle, CheckCircle2, Plus, Trash2 } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { MutationError } from '@/components/errors/MutationError';
import { toastSuccess, useErrorHandler } from '@/components/errors/notify';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
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
import { Input, NativeSelect } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { useCreateSkill, useDryRunSkill, useUpdateSkill } from '@/hooks/api/extensions';
import { ScopePicker } from './common';

const BLANK_SKILL = `---
name: my-skill
description: What this skill does and when the AI should use it.
---

# My skill

1. First step…
`;

export interface SkillEditorProps {
  orgId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Absent = create a new skill. */
  skill?: (SkillDto & { files: SkillFile[] }) | undefined;
  projects: { id: string; name: string }[];
  canManageShared: boolean;
  canCreatePersonal: boolean;
}

function filesOf(entry: string, extra: SkillFile[]): SkillFile[] {
  return [{ path: SKILL_ENTRY_FILE, content: entry }, ...extra.filter((f) => f.path.trim())];
}

function DryRunResult({ result }: { result: SkillDryRunDto }) {
  return (
    <Alert variant={result.valid ? 'success' : 'destructive'} data-testid="skill-dry-run">
      {result.valid ? <CheckCircle2 aria-hidden="true" /> : <AlertTriangle aria-hidden="true" />}
      <AlertTitle>{result.valid ? 'This skill is valid' : 'This skill has problems'}</AlertTitle>
      <AlertDescription>
        {result.issues.length > 0 ? (
          <ul className="list-disc pl-4">
            {result.issues.map((i) => (
              <li key={`${i.code}-${i.path ?? ''}-${i.message}`}>
                {i.path ? `${i.path}: ` : ''}
                {i.message}
              </li>
            ))}
          </ul>
        ) : null}
        {result.warnings.length > 0 ? (
          <ul className="list-disc pl-4">
            {result.warnings.map((w) => (
              <li key={w}>{w}</li>
            ))}
          </ul>
        ) : null}
        {result.valid ? (
          <>
            <span className="font-medium">The agent sees:</span>
            <pre className="max-h-32 w-full overflow-auto rounded bg-muted p-2 font-mono text-xs whitespace-pre-wrap">
              {result.listingPreview}
            </pre>
          </>
        ) : null}
      </AlertDescription>
    </Alert>
  );
}

export function SkillEditorDialog({
  orgId,
  open,
  onOpenChange,
  skill,
  projects,
  canManageShared,
  canCreatePersonal,
}: SkillEditorProps) {
  const editing = Boolean(skill);
  const [scope, setScope] = useState<WritableExtScope>(canManageShared ? 'ORG' : 'USER');
  const [projectId, setProjectId] = useState('');
  const [template, setTemplate] = useState('');
  const [entry, setEntry] = useState(
    () => skill?.files.find((f) => f.path === SKILL_ENTRY_FILE)?.content ?? BLANK_SKILL,
  );
  const [extra, setExtra] = useState<SkillFile[]>(
    () => skill?.files.filter((f) => f.path !== SKILL_ENTRY_FILE) ?? [],
  );
  const [dryRun, setDryRun] = useState<SkillDryRunDto | null>(null);
  const [scopeError, setScopeError] = useState<string | undefined>();

  const create = useCreateSkill(orgId);
  const update = useUpdateSkill(orgId);
  const tryIt = useDryRunSkill(orgId);
  const handleError = useErrorHandler();

  const files = filesOf(entry, extra);
  const validation = validateSkillBundle(files);
  const saving = create.isPending || update.isPending;

  const applyTemplate = (name: string) => {
    setTemplate(name);
    const b = BUILTIN_SKILLS.find((s) => s.name === name);
    setEntry(b ? b.skillMd : BLANK_SKILL);
    setDryRun(null);
  };

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!validation.ok) return;
    if (!editing && scope === 'PROJECT' && !projectId) {
      setScopeError('Choose a project.');
      return;
    }
    setScopeError(undefined);
    if (skill) {
      update.mutate(
        { id: skill.id, body: { files } },
        {
          onSuccess: () => {
            toastSuccess(`${skill.name} saved`);
            onOpenChange(false);
          },
          onError: (err) => handleError(err),
        },
      );
      return;
    }
    create.mutate(
      {
        scope,
        ...(scope === 'PROJECT' ? { projectId } : {}),
        files,
        enabled: true,
      },
      {
        onSuccess: (dto) => {
          toastSuccess(`${dto.name} added`);
          onOpenChange(false);
        },
        onError: (err) => handleError(err),
      },
    );
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl">
        <form onSubmit={onSubmit} noValidate className="grid gap-4">
          <DialogHeader>
            <DialogTitle>{editing ? `Edit ${skill?.name}` : 'New skill'}</DialogTitle>
            <DialogDescription>
              A skill is a Markdown file with <code>name</code> and <code>description</code>{' '}
              frontmatter. The AI loads it when the description matches the request.
            </DialogDescription>
          </DialogHeader>

          {editing ? null : (
            <>
              <ScopePicker
                idPrefix="skill"
                scope={scope}
                onScopeChange={setScope}
                projectId={projectId}
                onProjectChange={setProjectId}
                projects={projects}
                canManageShared={canManageShared}
                canCreatePersonal={canCreatePersonal}
                personalHint="Only loaded in your own sessions."
                error={scopeError}
              />
              <Field
                id="skill-template"
                label="Start from a template"
                description="Copies a built-in skill you can adapt. Rename it in the frontmatter."
              >
                {(aria) => (
                  <NativeSelect
                    {...aria}
                    value={template}
                    onChange={(e) => applyTemplate(e.target.value)}
                  >
                    <option value="">Blank skill</option>
                    {BUILTIN_SKILLS.map((b) => (
                      <option key={b.name} value={b.name}>
                        {b.name}
                      </option>
                    ))}
                  </NativeSelect>
                )}
              </Field>
            </>
          )}

          <Field
            id="skill-md"
            label={SKILL_ENTRY_FILE}
            description="Markdown with YAML frontmatter. Add an optional quick-action label to show it as a Simple-mode button."
            error={
              validation.issues[0]
                ? `${validation.issues[0].path ? `${validation.issues[0].path}: ` : ''}${validation.issues[0].message}`
                : undefined
            }
            required
          >
            {(aria) => (
              <Textarea
                {...aria}
                rows={16}
                className="font-mono text-xs"
                value={entry}
                onChange={(e) => {
                  setEntry(e.target.value);
                  setDryRun(null);
                }}
                spellCheck={false}
              />
            )}
          </Field>

          {validation.ok ? (
            <p className="flex items-center gap-2 text-xs text-success" data-testid="skill-valid">
              <CheckCircle2 className="size-4" aria-hidden="true" />
              Valid skill: {validation.name}
              {validation.quickAction ? ` · quick action "${validation.quickAction}"` : ''}
            </p>
          ) : null}
          {validation.warnings.length > 0 ? (
            <ul className="list-disc pl-5 text-xs text-muted-foreground">
              {validation.warnings.map((w) => (
                <li key={w}>{w}</li>
              ))}
            </ul>
          ) : null}

          <fieldset className="grid gap-2">
            <legend className="text-sm font-medium">Extra files (optional)</legend>
            <p className="text-xs text-muted-foreground">
              Reference material or scripts the skill uses, e.g. <code>reference/style.md</code>.
            </p>
            {extra.map((f, i) => (
              <div key={i} className="grid gap-2 sm:grid-cols-[14rem_1fr_auto] sm:items-start">
                <Field id={`skill-file-${i}-path`} label="Path" className="sm:col-span-1">
                  {(aria) => (
                    <Input
                      {...aria}
                      value={f.path}
                      placeholder="reference/notes.md"
                      onChange={(e) =>
                        setExtra(
                          extra.map((x, j) => (j === i ? { ...x, path: e.target.value } : x)),
                        )
                      }
                    />
                  )}
                </Field>
                <Field id={`skill-file-${i}-content`} label="Content">
                  {(aria) => (
                    <Textarea
                      {...aria}
                      rows={3}
                      className="font-mono text-xs"
                      value={f.content}
                      onChange={(e) =>
                        setExtra(
                          extra.map((x, j) => (j === i ? { ...x, content: e.target.value } : x)),
                        )
                      }
                    />
                  )}
                </Field>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="sm:mt-6"
                  onClick={() => setExtra(extra.filter((_x, j) => j !== i))}
                >
                  <Trash2 aria-hidden="true" />
                  <span className="sr-only">Remove file {f.path || i + 1}</span>
                </Button>
              </div>
            ))}
            <div>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setExtra([...extra, { path: '', content: '' }])}
              >
                <Plus aria-hidden="true" />
                Add file
              </Button>
            </div>
          </fieldset>

          {dryRun ? <DryRunResult result={dryRun} /> : null}
          <MutationError error={create.error ?? update.error ?? tryIt.error} />

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              loading={tryIt.isPending}
              onClick={() =>
                tryIt.mutate(files, {
                  onSuccess: (r) => setDryRun(r),
                  onError: (err) => handleError(err),
                })
              }
            >
              Try this skill
            </Button>
            <Button type="submit" loading={saving} disabled={!validation.ok}>
              {editing ? 'Save new version' : 'Add skill'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
