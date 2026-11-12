/**
 * Create / edit a subagent (spec §8.8): a Markdown definition with YAML frontmatter
 * (`name`, `description`, `tools`, `model`, `permissionMode`) validated live with the
 * shared `validateSubagentDefinition`. Built-ins can be used as a starting template.
 */
import {
  BUILTIN_SUBAGENTS,
  validateSubagentDefinition,
  type SubagentDto,
  type WritableExtScope,
} from '@loose/shared';
import { AlertTriangle, CheckCircle2 } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { MutationError } from '@/components/errors/MutationError';
import { toastSuccess, useErrorHandler } from '@/components/errors/notify';
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
import { NativeSelect } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { useCreateSubagent, useUpdateSubagent } from '@/hooks/api/extensions';
import { ScopePicker } from './common';

const BLANK_SUBAGENT = `---
name: my-subagent
description: What this subagent is good at and when to hand work to it.
tools: [Read, Grep, Glob]
---

You are a focused helper. Do one thing well:

1. First step…
`;

export function SubagentEditorDialog({
  orgId,
  subagent,
  onClose,
  projects,
  canManageShared,
  canCreatePersonal,
}: {
  orgId: string;
  /** Absent = create a new subagent. */
  subagent?: SubagentDto | undefined;
  onClose: () => void;
  projects: { id: string; name: string }[];
  canManageShared: boolean;
  canCreatePersonal: boolean;
}) {
  const editing = Boolean(subagent);
  const [scope, setScope] = useState<WritableExtScope>(canManageShared ? 'ORG' : 'USER');
  const [projectId, setProjectId] = useState('');
  const [template, setTemplate] = useState('');
  const [definition, setDefinition] = useState(() => subagent?.definition ?? BLANK_SUBAGENT);
  const [scopeError, setScopeError] = useState<string | undefined>();

  const create = useCreateSubagent(orgId);
  const update = useUpdateSubagent(orgId);
  const handleError = useErrorHandler();

  const validation = validateSubagentDefinition(definition);
  const firstIssue = validation.issues[0];

  const applyTemplate = (name: string) => {
    setTemplate(name);
    const b = BUILTIN_SUBAGENTS.find((s) => s.name === name);
    setDefinition(b ? b.definition : BLANK_SUBAGENT);
  };

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!validation.ok) return;
    if (!editing && scope === 'PROJECT' && !projectId) {
      setScopeError('Choose a project.');
      return;
    }
    setScopeError(undefined);
    if (subagent) {
      update.mutate(
        { id: subagent.id, body: { definition } },
        {
          onSuccess: () => {
            toastSuccess(`${subagent.name} saved`);
            onClose();
          },
          onError: (err) => handleError(err),
        },
      );
      return;
    }
    create.mutate(
      { scope, ...(scope === 'PROJECT' ? { projectId } : {}), definition },
      {
        onSuccess: (dto) => {
          toastSuccess(`${dto.name} added`);
          onClose();
        },
        onError: (err) => handleError(err),
      },
    );
  };

  return (
    <Dialog open onOpenChange={(o) => (o ? undefined : onClose())}>
      <DialogContent className="max-w-3xl">
        <form onSubmit={onSubmit} noValidate className="grid gap-4">
          <DialogHeader>
            <DialogTitle>{editing ? `Edit ${subagent?.name}` : 'New subagent'}</DialogTitle>
            <DialogDescription>
              A subagent is a specialist with its own instructions and tools. The AI hands work to
              it on its own, or you mention it with <code>@name</code>.
            </DialogDescription>
          </DialogHeader>

          {editing ? null : (
            <>
              <ScopePicker
                idPrefix="subagent"
                scope={scope}
                onScopeChange={setScope}
                projectId={projectId}
                onProjectChange={setProjectId}
                projects={projects}
                canManageShared={canManageShared}
                canCreatePersonal={canCreatePersonal}
                personalHint="Only available in your own sessions."
                error={scopeError}
              />
              <Field
                id="subagent-template"
                label="Start from a template"
                description="Copies a built-in subagent you can adapt. Rename it in the frontmatter."
              >
                {(aria) => (
                  <NativeSelect
                    {...aria}
                    value={template}
                    onChange={(e) => applyTemplate(e.target.value)}
                  >
                    <option value="">Blank subagent</option>
                    {BUILTIN_SUBAGENTS.map((b) => (
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
            id="subagent-definition"
            label="Definition"
            description="Markdown with YAML frontmatter: name, description and optional tools, model, permissionMode."
            error={
              firstIssue
                ? `${firstIssue.path ? `${firstIssue.path}: ` : ''}${firstIssue.message}`
                : undefined
            }
            required
          >
            {(aria) => (
              <Textarea
                {...aria}
                rows={16}
                className="font-mono text-xs"
                value={definition}
                onChange={(e) => setDefinition(e.target.value)}
                spellCheck={false}
              />
            )}
          </Field>

          {validation.ok ? (
            <p
              className="flex items-center gap-2 text-xs text-success"
              data-testid="subagent-valid"
            >
              <CheckCircle2 className="size-4" aria-hidden="true" />
              Valid subagent: {validation.name}
              {validation.tools.length > 0 ? ` · tools: ${validation.tools.join(', ')}` : ''}
            </p>
          ) : null}
          {validation.warnings.length > 0 ? (
            <ul className="list-disc pl-5 text-xs text-muted-foreground">
              {validation.warnings.map((w) => (
                <li key={w} className="flex items-start gap-1">
                  <AlertTriangle className="mt-0.5 size-3 shrink-0" aria-hidden="true" />
                  {w}
                </li>
              ))}
            </ul>
          ) : null}

          <MutationError error={create.error ?? update.error} />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button
              type="submit"
              loading={create.isPending || update.isPending}
              disabled={!validation.ok}
            >
              {editing ? 'Save subagent' : 'Add subagent'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
