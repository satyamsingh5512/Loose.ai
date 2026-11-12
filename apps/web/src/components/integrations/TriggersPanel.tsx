/**
 * Integrations tab of the organization settings (spec §8.15, admin only): triggers that
 * start sessions from outside the app.
 *
 * - GitHub issue label per project (turn on / change the label / turn off),
 * - status of the Slack, Linear and Jira connections with the URL to paste into them,
 * - every other trigger (PR comment, Slack, Linear, Jira, schedules) with run-now and
 *   recent runs; schedules show a plain-English timetable and the next run.
 */
import type { RunDto, TriggerDto, TriggerKind } from '@loose/shared';
import { ExternalLink, Pencil, Play, Plus, Trash2 } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { MutationError } from '@/components/errors/MutationError';
import { toastSuccess, useErrorHandler } from '@/components/errors/notify';
import { LoadingBlock, QueryError } from '@/components/errors/QueryError';
import {
  EmptyState,
  ExtensionList,
  ExtensionRow,
  PanelHeader,
} from '@/components/extensions/common';
import { CopyField } from '@/components/org/InviteModal';
import { Badge, type BadgeProps } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Field } from '@/components/ui/field';
import { Checkbox, Input } from '@/components/ui/input';
import { useProjects } from '@/hooks/api/projects';
import {
  useCreateTrigger,
  useDeleteTrigger,
  useFireTrigger,
  useTriggerRuns,
  useTriggers,
  useUpdateTrigger,
} from '@/hooks/api/platform';
import { describeCron, formatInZone } from '@/lib/cron';
import { formatRelative } from '@/lib/utils';
import { TRIGGER_KIND_LABEL, TriggerEditorDialog } from './TriggerEditorDialog';

const RUN_VARIANT: Record<RunDto['status'], BadgeProps['variant']> = {
  QUEUED: 'secondary',
  PROVISIONING: 'secondary',
  RUNNING: 'secondary',
  WAITING_APPROVAL: 'warning',
  CREATING_PR: 'secondary',
  SUCCEEDED: 'success',
  FAILED: 'destructive',
  CANCELLED: 'outline',
};
const RUN_LABEL: Record<RunDto['status'], string> = {
  QUEUED: 'Queued',
  PROVISIONING: 'Starting',
  RUNNING: 'Running',
  WAITING_APPROVAL: 'Waiting for approval',
  CREATING_PR: 'Opening pull request',
  SUCCEEDED: 'Succeeded',
  FAILED: 'Failed',
  CANCELLED: 'Cancelled',
};

// ---- GitHub label per project ------------------------------------------------------------

function GithubLabelRow({
  orgId,
  project,
  trigger,
}: {
  orgId: string;
  project: { id: string; name: string };
  trigger: TriggerDto | undefined;
}) {
  const create = useCreateTrigger(orgId);
  const update = useUpdateTrigger(orgId);
  const del = useDeleteTrigger(orgId);
  const handleError = useErrorHandler();
  const saved = typeof trigger?.config.label === 'string' ? trigger.config.label : 'loose';
  const [label, setLabel] = useState(saved);
  const [error, setError] = useState('');
  const inputId = `label-${project.id}`;

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    const next = label.trim();
    if (!next) {
      setError('Enter a label.');
      return;
    }
    setError('');
    if (trigger) {
      update.mutate(
        { id: trigger.id, body: { config: { label: next } } },
        {
          onSuccess: () => toastSuccess(`Label for ${project.name} saved`),
          onError: (err) => handleError(err),
        },
      );
      return;
    }
    create.mutate(
      {
        kind: 'GITHUB_ISSUE_LABEL',
        projectId: project.id,
        name: `Issue label · ${project.name}`,
        enabled: true,
        promptTemplate: '',
        createPr: true,
        mode: 'PRO',
        config: { label: next },
      },
      {
        onSuccess: () => toastSuccess(`Issues labelled “${next}” now start sessions`),
        onError: (err) => handleError(err),
      },
    );
  };

  const busy = create.isPending || update.isPending;
  return (
    <li className="grid gap-2 p-4 sm:grid-cols-[1fr_auto] sm:items-end">
      <form onSubmit={onSubmit} noValidate className="flex flex-wrap items-end gap-3">
        <div className="min-w-40">
          <p className="text-sm font-medium">{project.name}</p>
          {trigger ? (
            <Badge variant={trigger.enabled ? 'success' : 'outline'} data-testid="label-state">
              {trigger.enabled ? 'On' : 'Paused'}
            </Badge>
          ) : (
            <Badge variant="outline" data-testid="label-state">
              Off
            </Badge>
          )}
        </div>
        <Field id={inputId} label="Issue label" error={error} className="w-48">
          {(aria) => (
            <Input
              {...aria}
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              autoComplete="off"
            />
          )}
        </Field>
        <Button
          type="submit"
          size="sm"
          variant={trigger ? 'outline' : 'default'}
          loading={busy}
          disabled={trigger ? label.trim() === saved : false}
        >
          {trigger ? 'Save label' : 'Turn on'}
          <span className="sr-only"> for {project.name}</span>
        </Button>
      </form>
      {trigger ? (
        <div className="flex flex-wrap items-center gap-2">
          <label className="flex items-center gap-2 text-sm">
            <Checkbox
              checked={trigger.enabled}
              aria-label={`${trigger.enabled ? 'Pause' : 'Resume'} issue label for ${project.name}`}
              onChange={(e) =>
                update.mutate(
                  { id: trigger.id, body: { enabled: e.target.checked } },
                  { onError: (err) => handleError(err) },
                )
              }
            />
            Enabled
          </label>
          <Button
            size="sm"
            variant="ghost"
            loading={del.isPending}
            onClick={() =>
              del.mutate(trigger.id, {
                onSuccess: () => toastSuccess(`Issue label for ${project.name} turned off`),
                onError: (err) => handleError(err),
              })
            }
          >
            <Trash2 aria-hidden="true" />
            <span className="sr-only">Turn off issue label for {project.name}</span>
          </Button>
        </div>
      ) : null}
    </li>
  );
}

// ---- Slack / Linear / Jira status --------------------------------------------------------

/** Trigger kinds whose inbound webhook URL and signing secret are unique per trigger. */
const PER_TRIGGER_KINDS: ReadonlySet<TriggerKind> = new Set<TriggerKind>(['LINEAR', 'JIRA']);

const CONNECTIONS: { kind: TriggerKind; name: string; hint: string }[] = [
  {
    kind: 'SLACK_COMMAND',
    name: 'Slack',
    hint: 'Paste this URL as the request URL of your /loose slash command.',
  },
  {
    kind: 'LINEAR',
    name: 'Linear',
    hint: 'Each Linear trigger below has its own webhook URL and signing secret. Add both as a webhook in Linear (Issues events).',
  },
  {
    kind: 'JIRA',
    name: 'Jira',
    hint: 'Each Jira trigger below has its own webhook URL and secret. Add both as a webhook in Jira (issue created / updated).',
  },
];

function ConnectionCard({
  name,
  hint,
  triggers,
}: {
  name: string;
  hint: string;
  triggers: TriggerDto[];
}) {
  const first = triggers[0];
  const state = !first
    ? { label: 'Not set up', variant: 'outline' as const }
    : triggers.every((t) => !t.configured)
      ? { label: 'Needs server setup', variant: 'warning' as const }
      : { label: 'Connected', variant: 'success' as const };
  // Linear and Jira are credentialed per trigger (URL + secret shown on each trigger row).
  const url = PER_TRIGGER_KINDS.has(first?.kind ?? 'SLACK_COMMAND')
    ? null
    : (triggers.find((t) => t.webhookUrl)?.webhookUrl ?? null);
  return (
    <Card data-testid={`connection-${name.toLowerCase()}`}>
      <CardHeader>
        <CardTitle as="h3" className="flex items-center gap-2 text-base">
          {name}
          <Badge variant={state.variant}>{state.label}</Badge>
        </CardTitle>
        <CardDescription>
          {first
            ? triggers.every((t) => !t.configured)
              ? `The server has no ${name} signing secret yet, so incoming requests are refused. Ask the person who runs loose.ai to set it.`
              : hint
            : `Create a ${name} trigger below to get the URL.`}
        </CardDescription>
      </CardHeader>
      {url ? (
        <CardContent>
          <CopyField id={`${name.toLowerCase()}-url`} label={`${name} URL`} value={url} />
        </CardContent>
      ) : null}
    </Card>
  );
}

// ---- trigger rows ------------------------------------------------------------------------

function TriggerRuns({ orgId, triggerId }: { orgId: string; triggerId: string }) {
  const runs = useTriggerRuns(orgId, triggerId);
  if (runs.isPending) return <LoadingBlock label="Loading runs…" rows={1} />;
  if (runs.isError) return <QueryError error={runs.error} onRetry={() => void runs.refetch()} />;
  if (runs.data.length === 0) {
    return <p className="text-xs text-muted-foreground">No runs yet.</p>;
  }
  return (
    <ul aria-label="Recent runs" className="grid gap-1 text-xs">
      {runs.data.map((r) => (
        <li key={r.id} className="flex flex-wrap items-center gap-2">
          <Badge variant={RUN_VARIANT[r.status]}>{RUN_LABEL[r.status]}</Badge>
          <span className="text-muted-foreground">{formatRelative(r.createdAt)}</span>
          {r.prUrl ? (
            <a
              href={r.prUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 underline-offset-4 hover:underline"
            >
              Pull request #{r.prNumber ?? ''}
              <ExternalLink className="size-3" aria-hidden="true" />
              <span className="sr-only">(opens in a new tab)</span>
            </a>
          ) : null}
          {r.errorCode ? <code className="text-destructive">{r.errorCode}</code> : null}
        </li>
      ))}
    </ul>
  );
}

function TriggerRow({
  orgId,
  trigger,
  onEdit,
  onDelete,
}: {
  orgId: string;
  trigger: TriggerDto;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const update = useUpdateTrigger(orgId);
  const fire = useFireTrigger(orgId);
  const handleError = useErrorHandler();
  const [showRuns, setShowRuns] = useState(false);
  const cron = typeof trigger.config.cron === 'string' ? trigger.config.cron : null;
  const zone = typeof trigger.config.timezone === 'string' ? trigger.config.timezone : 'UTC';

  return (
    <ExtensionRow
      title={trigger.name}
      badges={
        <>
          <Badge variant="outline">{TRIGGER_KIND_LABEL[trigger.kind]}</Badge>
          <Badge variant="secondary">{trigger.projectName}</Badge>
          {trigger.enabled ? null : <Badge variant="outline">Off</Badge>}
          {trigger.kind !== 'SCHEDULE' &&
          trigger.kind !== 'GITHUB_PR_COMMENT' &&
          !trigger.configured ? (
            <Badge variant="warning">Needs server setup</Badge>
          ) : null}
        </>
      }
      description={
        cron ? (
          <span>
            {describeCron(cron)} ({zone})
          </span>
        ) : undefined
      }
      details={
        <div className="grid gap-1 text-xs text-muted-foreground">
          {cron ? (
            <p data-testid="next-run">
              {trigger.enabled && trigger.nextRunAt
                ? `Next run: ${formatInZone(trigger.nextRunAt, zone)}`
                : 'Not scheduled while it is off.'}
            </p>
          ) : null}
          <p>
            Runs as {trigger.runAsUserName ?? 'a teammate'}
            {trigger.lastFiredAt ? ` · last fired ${formatRelative(trigger.lastFiredAt)}` : ''}
          </p>
          {trigger.lastError ? (
            <p className="text-destructive" role="note">
              Last problem: {trigger.lastError}
            </p>
          ) : null}
          {PER_TRIGGER_KINDS.has(trigger.kind) && trigger.webhookUrl ? (
            <div className="grid gap-2 pt-1" data-testid={`trigger-credentials-${trigger.id}`}>
              <CopyField
                id={`${trigger.id}-webhook-url`}
                label="Webhook URL"
                value={trigger.webhookUrl}
              />
              {trigger.webhookSecret ? (
                <CopyField
                  id={`${trigger.id}-webhook-secret`}
                  label="Signing secret"
                  value={trigger.webhookSecret}
                />
              ) : null}
            </div>
          ) : null}
          {showRuns ? <TriggerRuns orgId={orgId} triggerId={trigger.id} /> : null}
          <MutationError error={update.error ?? fire.error} />
        </div>
      }
      actions={
        <>
          <label className="flex items-center gap-2 text-sm">
            <Checkbox
              checked={trigger.enabled}
              aria-label={`${trigger.enabled ? 'Disable' : 'Enable'} ${trigger.name}`}
              onChange={(e) =>
                update.mutate(
                  { id: trigger.id, body: { enabled: e.target.checked } },
                  { onError: (err) => handleError(err) },
                )
              }
            />
            Enabled
          </label>
          <Button
            size="sm"
            variant="outline"
            loading={fire.isPending}
            onClick={() =>
              fire.mutate(
                { id: trigger.id },
                {
                  onSuccess: (r) =>
                    toastSuccess(
                      r.duplicate ? 'Already started' : 'Run started',
                      r.duplicate ? 'This was already fired a moment ago.' : undefined,
                    ),
                  onError: (err) => handleError(err),
                },
              )
            }
          >
            <Play aria-hidden="true" />
            Run now
            <span className="sr-only"> {trigger.name}</span>
          </Button>
          <Button
            size="sm"
            variant="ghost"
            aria-expanded={showRuns}
            onClick={() => setShowRuns((v) => !v)}
          >
            {showRuns ? 'Hide runs' : 'Recent runs'}
            <span className="sr-only"> of {trigger.name}</span>
          </Button>
          <Button size="sm" variant="ghost" onClick={onEdit}>
            <Pencil aria-hidden="true" />
            <span className="sr-only">Edit {trigger.name}</span>
          </Button>
          <Button size="sm" variant="ghost" onClick={onDelete}>
            <Trash2 aria-hidden="true" />
            <span className="sr-only">Delete {trigger.name}</span>
          </Button>
        </>
      }
    />
  );
}

export function TriggersPanel({ orgId }: { orgId: string }) {
  const triggers = useTriggers(orgId);
  const projects = useProjects(orgId);
  const del = useDeleteTrigger(orgId);
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<TriggerDto | null>(null);
  const [deleting, setDeleting] = useState<TriggerDto | null>(null);

  if (triggers.isPending || projects.isPending)
    return <LoadingBlock label="Loading integrations…" />;
  if (triggers.isError) {
    return <QueryError error={triggers.error} onRetry={() => void triggers.refetch()} />;
  }
  if (projects.isError) {
    return <QueryError error={projects.error} onRetry={() => void projects.refetch()} />;
  }

  const projectOptions = projects.data.map((p) => ({ id: p.id, name: p.name }));
  // The first issue-label trigger of each project is edited inline above.
  const inline = new Map<string, TriggerDto>();
  for (const t of triggers.data) {
    if (t.kind === 'GITHUB_ISSUE_LABEL' && !inline.has(t.projectId)) inline.set(t.projectId, t);
  }
  const inlineIds = new Set([...inline.values()].map((t) => t.id));
  const others = triggers.data.filter((t) => !inlineIds.has(t.id));

  return (
    <div className="grid gap-6">
      <PanelHeader
        title="Integrations"
        description="Start sessions from GitHub issues, pull request comments, Slack, Linear, Jira or a schedule. Each one runs with a teammate’s key and opens a pull request for review."
        actions={
          <Button onClick={() => setCreating(true)} disabled={projectOptions.length === 0}>
            <Plus aria-hidden="true" />
            New trigger
          </Button>
        }
      />

      <section aria-labelledby="gh-label-title" className="grid gap-2">
        <h3 id="gh-label-title" className="text-base font-semibold">
          GitHub issue label
        </h3>
        <p className="text-sm text-muted-foreground">
          When someone adds this label to an issue, loose.ai works on it and opens a pull request
          that closes the issue.
        </p>
        {projectOptions.length === 0 ? (
          <EmptyState>Create a project first.</EmptyState>
        ) : (
          <ul aria-label="Issue label per project" className="divide-y rounded-lg border">
            {projectOptions.map((p) => (
              <GithubLabelRow
                key={`${p.id}:${inline.get(p.id)?.updatedAt ?? ''}`}
                orgId={orgId}
                project={p}
                trigger={inline.get(p.id)}
              />
            ))}
          </ul>
        )}
      </section>

      <section aria-labelledby="connections-title" className="grid gap-2">
        <h3 id="connections-title" className="text-base font-semibold">
          Connections
        </h3>
        <div className="grid gap-3 md:grid-cols-3">
          {CONNECTIONS.map((c) => (
            <ConnectionCard
              key={c.kind}
              name={c.name}
              hint={c.hint}
              triggers={triggers.data.filter((t) => t.kind === c.kind)}
            />
          ))}
        </div>
      </section>

      <section aria-labelledby="triggers-title" className="grid gap-2">
        <h3 id="triggers-title" className="text-base font-semibold">
          Triggers and schedules
        </h3>
        {others.length === 0 ? (
          <EmptyState>No other triggers yet.</EmptyState>
        ) : (
          <ExtensionList label="Triggers">
            {others.map((t) => (
              <TriggerRow
                key={t.id}
                orgId={orgId}
                trigger={t}
                onEdit={() => setEditing(t)}
                onDelete={() => setDeleting(t)}
              />
            ))}
          </ExtensionList>
        )}
      </section>

      {creating || editing ? (
        <TriggerEditorDialog
          orgId={orgId}
          {...(editing ? { trigger: editing } : {})}
          projects={projectOptions}
          defaultProjectId={projectOptions[0]?.id}
          onClose={() => {
            setCreating(false);
            setEditing(null);
          }}
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
        title={`Delete ${deleting?.name ?? 'trigger'}?`}
        description="It stops starting sessions. Runs it already started are kept."
        confirmLabel="Delete trigger"
        destructive
        loading={del.isPending}
        error={del.error}
        onConfirm={() => {
          const target = deleting;
          if (!target) return;
          del.mutate(target.id, {
            onSuccess: () => {
              toastSuccess(`${target.name} deleted`);
              setDeleting(null);
            },
          });
        }}
      />
    </div>
  );
}
