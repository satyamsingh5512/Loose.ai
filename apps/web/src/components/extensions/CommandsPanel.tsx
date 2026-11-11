/**
 * Slash commands tab (spec §8.6.1): list built-in and custom commands, create / edit /
 * delete Markdown commands with frontmatter (description, argument-hint, allowed-tools,
 * model) and the template syntax help ($ARGUMENTS, @file, !`cmd`).
 */
import {
  BUILTIN_COMMANDS,
  MAX_SLASH_COMMAND_BODY,
  parseCommandMeta,
  slashCommandNameSchema,
  type CommandDto,
  type WritableExtScope,
} from '@loose/shared';
import { Pencil, Plus, Trash2 } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { MutationError } from '@/components/errors/MutationError';
import { toastSuccess, useErrorHandler } from '@/components/errors/notify';
import { LoadingBlock, QueryError } from '@/components/errors/QueryError';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Field } from '@/components/ui/field';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import {
  useCommands,
  useCreateCommand,
  useDeleteCommand,
  useUpdateCommand,
} from '@/hooks/api/extensions';
import {
  EmptyState,
  ExtensionList,
  ExtensionRow,
  PanelHeader,
  ScopeBadge,
  ScopePicker,
} from './common';

const BLANK_COMMAND = `---
description: What this command does
argument-hint: <issue number>
---

Fix issue #$ARGUMENTS. Start from @README.md and run the project's tests when you are done.
`;

interface CommandsPanelProps {
  orgId: string;
  isAdmin: boolean;
  /** Viewers may not create anything (the server enforces this too). */
  canCreatePersonal: boolean;
  projects: { id: string; name: string }[];
}

function SyntaxHelp() {
  return (
    <div className="rounded-md bg-muted p-3 text-xs text-muted-foreground">
      <p className="font-medium text-foreground">Template syntax</p>
      <ul className="mt-1 grid gap-0.5">
        <li>
          <code>$ARGUMENTS</code> — everything typed after the command (<code>$1</code>…
          <code>$9</code> for single words).
        </li>
        <li>
          <code>@path/to/file</code> — includes that repository file.
        </li>
        <li>
          <code>!`npm test`</code> — runs the command in the sandbox first and includes its output.
        </li>
        <li>
          Frontmatter: <code>description</code>, <code>argument-hint</code>,{' '}
          <code>allowed-tools</code>, <code>model</code>.
        </li>
      </ul>
    </div>
  );
}

function CommandDialog({
  orgId,
  command,
  onClose,
  isAdmin,
  projects,
}: {
  orgId: string;
  /** Absent = create. */
  command?: CommandDto | undefined;
  onClose: () => void;
  isAdmin: boolean;
  projects: { id: string; name: string }[];
}) {
  const editing = Boolean(command);
  const [scope, setScope] = useState<WritableExtScope>(isAdmin ? 'ORG' : 'USER');
  const [projectId, setProjectId] = useState('');
  const [name, setName] = useState(command?.name ?? '');
  const [body, setBody] = useState(command?.body ?? BLANK_COMMAND);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const create = useCreateCommand(orgId);
  const update = useUpdateCommand(orgId);
  const handleError = useErrorHandler();
  const meta = parseCommandMeta(body);

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    const next: Record<string, string> = {};
    const parsedName = slashCommandNameSchema.safeParse(name);
    if (!parsedName.success) {
      next.name = parsedName.error.issues[0]?.message ?? 'Invalid name';
    }
    if (!body.trim()) next.body = 'Enter the command instructions.';
    if (body.length > MAX_SLASH_COMMAND_BODY) next.body = 'The command is too long.';
    if (!editing && scope === 'PROJECT' && !projectId) next.projectId = 'Choose a project.';
    setErrors(next);
    if (Object.keys(next).length > 0) return;
    const done = (verb: string) => () => {
      toastSuccess(`/${name} ${verb}`);
      onClose();
    };
    if (command) {
      update.mutate(
        { id: command.id, body: { name: name.trim(), body } },
        { onSuccess: done('saved'), onError: (err) => handleError(err) },
      );
      return;
    }
    create.mutate(
      {
        scope,
        ...(scope === 'PROJECT' ? { projectId } : {}),
        name: name.trim(),
        body,
      },
      { onSuccess: done('created'), onError: (err) => handleError(err) },
    );
  };

  return (
    <Dialog open onOpenChange={(o) => (o ? undefined : onClose())}>
      <DialogContent className="max-w-2xl">
        <form onSubmit={onSubmit} noValidate className="grid gap-4">
          <DialogHeader>
            <DialogTitle>{editing ? `Edit /${command?.name}` : 'New slash command'}</DialogTitle>
            <DialogDescription>
              A command is a Markdown prompt template members can run with{' '}
              <code>/name arguments</code> in the chat.
            </DialogDescription>
          </DialogHeader>
          {editing ? null : (
            <ScopePicker
              idPrefix="command"
              scope={scope}
              onScopeChange={setScope}
              projectId={projectId}
              onProjectChange={setProjectId}
              projects={projects}
              canManageShared={isAdmin}
              canCreatePersonal
              personalHint="Only available in your own sessions."
              error={errors.projectId}
            />
          )}
          <Field
            id="command-name"
            label="Command name"
            description="Lowercase letters, numbers and hyphens. Members type /name."
            error={errors.name}
            required
          >
            {(aria) => (
              <Input
                {...aria}
                value={name}
                placeholder="fix-issue"
                onChange={(e) => setName(e.target.value.toLowerCase())}
              />
            )}
          </Field>
          <Field
            id="command-body"
            label="Command (Markdown)"
            error={errors.body}
            description={
              meta.description
                ? `Shown in the palette as: ${meta.description}`
                : 'Add a description in the frontmatter to label it in the palette.'
            }
            required
          >
            {(aria) => (
              <Textarea
                {...aria}
                rows={12}
                className="font-mono text-xs"
                value={body}
                spellCheck={false}
                onChange={(e) => setBody(e.target.value)}
              />
            )}
          </Field>
          <SyntaxHelp />
          <MutationError error={create.error ?? update.error} />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={create.isPending || update.isPending}>
              {editing ? 'Save command' : 'Create command'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function CommandsPanel({ orgId, isAdmin, canCreatePersonal, projects }: CommandsPanelProps) {
  const commands = useCommands(orgId);
  const del = useDeleteCommand(orgId);
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<CommandDto | null>(null);
  const [deleting, setDeleting] = useState<CommandDto | null>(null);

  if (commands.isPending) return <LoadingBlock label="Loading commands…" />;
  if (commands.isError)
    return <QueryError error={commands.error} onRetry={() => void commands.refetch()} />;

  const custom = commands.data.filter((c) => !c.builtin);
  const canWrite = (c: CommandDto) => isAdmin || c.scope === 'USER';

  return (
    <div className="grid gap-4">
      <PanelHeader
        title="Slash commands"
        description="Prompt templates members run with / in the chat."
        actions={
          isAdmin || canCreatePersonal ? (
            <Button onClick={() => setCreating(true)}>
              <Plus aria-hidden="true" />
              New command
            </Button>
          ) : undefined
        }
      />

      {custom.length === 0 ? (
        <EmptyState>No custom commands yet. The built-ins below always work.</EmptyState>
      ) : (
        <ExtensionList label="Custom commands">
          {custom.map((c) => (
            <ExtensionRow
              key={c.id}
              title={`/${c.name}`}
              badges={
                <>
                  <ScopeBadge scope={c.scope} />
                  {c.model ? <Badge variant="outline">{c.model}</Badge> : null}
                </>
              }
              description={c.description ?? 'No description'}
              details={
                <p className="text-xs text-muted-foreground">
                  {c.argumentHint ? `Arguments: ${c.argumentHint}` : 'No arguments'}
                  {c.allowedTools.length > 0 ? ` · tools: ${c.allowedTools.join(', ')}` : ''}
                </p>
              }
              actions={
                canWrite(c) ? (
                  <>
                    <Button size="sm" variant="ghost" onClick={() => setEditing(c)}>
                      <Pencil aria-hidden="true" />
                      <span className="sr-only">Edit /{c.name}</span>
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => setDeleting(c)}>
                      <Trash2 aria-hidden="true" />
                      <span className="sr-only">Delete /{c.name}</span>
                    </Button>
                  </>
                ) : null
              }
            />
          ))}
        </ExtensionList>
      )}

      <section aria-labelledby="builtin-commands-title" className="grid gap-2">
        <h3 id="builtin-commands-title" className="text-sm font-medium">
          Built-in commands
        </h3>
        <ul className="grid gap-1 text-sm sm:grid-cols-2">
          {BUILTIN_COMMANDS.map((c) => (
            <li key={c.name} className="flex flex-wrap items-baseline gap-2">
              <code className="font-medium">/{c.name}</code>
              <span className="text-muted-foreground">{c.description}</span>
              {c.adminOnly ? <Badge variant="outline">Admins</Badge> : null}
            </li>
          ))}
        </ul>
      </section>

      {creating ? (
        <CommandDialog
          orgId={orgId}
          onClose={() => setCreating(false)}
          isAdmin={isAdmin}
          projects={projects}
        />
      ) : null}
      {editing ? (
        <CommandDialog
          orgId={orgId}
          command={editing}
          onClose={() => setEditing(null)}
          isAdmin={isAdmin}
          projects={projects}
        />
      ) : null}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(o) => {
          if (!o) {
            setDeleting(null);
            del.reset();
          }
        }}
        title={`Delete /${deleting?.name ?? ''}?`}
        description="Members will no longer see this command in the palette."
        confirmLabel="Delete command"
        destructive
        loading={del.isPending}
        error={del.error}
        onConfirm={() => {
          const target = deleting;
          if (!target) return;
          del.mutate(target.id, {
            onSuccess: () => {
              toastSuccess(`/${target.name} deleted`);
              setDeleting(null);
            },
          });
        }}
      />
    </div>
  );
}
