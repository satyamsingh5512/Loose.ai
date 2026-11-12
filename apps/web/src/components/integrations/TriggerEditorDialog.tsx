/**
 * Create / edit an automation trigger (spec §8.15). Per-kind configuration:
 * GitHub issue label, GitHub PR comment mention, Slack command, Linear / Jira label and a
 * cron schedule with a plain-English summary and a preview of the next runs.
 *
 * The request is validated with the shared Zod schemas before it is sent.
 */
import {
  createTriggerBodySchema,
  DEFAULT_TRIGGER_LABEL,
  DEFAULT_TRIGGER_MENTION,
  DEFAULT_TRIGGER_PROMPTS,
  GithubAuthorAssociationSchema,
  isValidCron,
  isValidTimeZone,
  MIN_SCHEDULE_INTERVAL_MIN,
  minCronGapMinutes,
  TRIGGER_KINDS,
  TRIGGER_PROMPT_VARIABLES,
  zodIssuesToFieldErrors,
  type GithubAuthorAssociation,
  type TriggerDto,
  type TriggerKind,
  type UpdateTriggerBody,
} from '@loose/shared';
import { useState, type FormEvent } from 'react';
import { fieldErrorOf, MutationError } from '@/components/errors/MutationError';
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
import { Checkbox, Input, NativeSelect } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { useCreateTrigger, useUpdateTrigger } from '@/hooks/api/platform';
import { describeCron, formatInZone, previewRuns } from '@/lib/cron';

export const TRIGGER_KIND_LABEL: Record<TriggerKind, string> = {
  GITHUB_ISSUE_LABEL: 'GitHub issue label',
  GITHUB_PR_COMMENT: 'GitHub pull request comment',
  SLACK_COMMAND: 'Slack slash command',
  LINEAR: 'Linear issue label',
  JIRA: 'Jira issue label',
  SCHEDULE: 'Schedule',
};

const KIND_HELP: Record<TriggerKind, string> = {
  GITHUB_ISSUE_LABEL: 'Adding the label to an issue starts a session that opens a pull request.',
  GITHUB_PR_COMMENT: 'A teammate comments the mention on a pull request and the AI pushes a fix.',
  SLACK_COMMAND: 'Run /loose in Slack with a request; the result is posted back to the channel.',
  LINEAR: 'Labelling a Linear issue starts a session that opens a pull request.',
  JIRA: 'Labelling a Jira issue starts a session that opens a pull request.',
  SCHEDULE: 'Run a prompt on a timetable, for example a weekly dependency check.',
};

const ASSOCIATION_LABEL: Record<GithubAuthorAssociation, string> = {
  OWNER: 'Repository owner',
  MEMBER: 'Organization member',
  COLLABORATOR: 'Collaborator',
  CONTRIBUTOR: 'Past contributor',
  FIRST_TIME_CONTRIBUTOR: 'First-time contributor',
  FIRST_TIMER: 'First-timer',
  NONE: 'Anyone else',
};

const commaList = (s: string) =>
  s
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean);

interface TriggerForm {
  kind: TriggerKind;
  projectId: string;
  name: string;
  enabled: boolean;
  createPr: boolean;
  mode: 'SIMPLE' | 'PRO';
  promptTemplate: string;
  label: string;
  mention: string;
  associations: GithubAuthorAssociation[];
  teamId: string;
  channelIds: string;
  projectKey: string;
  cron: string;
  timezone: string;
}

function blankForm(kind: TriggerKind, projectId: string): TriggerForm {
  return {
    kind,
    projectId,
    name: '',
    enabled: true,
    createPr: true,
    mode: 'PRO',
    promptTemplate: '',
    label: DEFAULT_TRIGGER_LABEL,
    mention: DEFAULT_TRIGGER_MENTION,
    associations: ['OWNER', 'MEMBER', 'COLLABORATOR'],
    teamId: '',
    channelIds: '',
    projectKey: '',
    cron: '0 9 * * 1',
    timezone: 'UTC',
  };
}

function formFromTrigger(t: TriggerDto): TriggerForm {
  const f = blankForm(t.kind, t.projectId);
  const c = t.config;
  f.name = t.name;
  f.enabled = t.enabled;
  f.createPr = t.createPr;
  f.mode = t.mode;
  f.promptTemplate = t.promptTemplate;
  if (typeof c.label === 'string') f.label = c.label;
  if (typeof c.mention === 'string') f.mention = c.mention;
  if (Array.isArray(c.allowedAssociations)) {
    f.associations = c.allowedAssociations.filter(
      (a): a is GithubAuthorAssociation => GithubAuthorAssociationSchema.safeParse(a).success,
    );
  }
  if (typeof c.teamId === 'string') f.teamId = c.teamId;
  if (Array.isArray(c.channelIds)) f.channelIds = c.channelIds.join(', ');
  if (typeof c.projectKey === 'string') f.projectKey = c.projectKey;
  if (typeof c.cron === 'string') f.cron = c.cron;
  if (typeof c.timezone === 'string') f.timezone = c.timezone;
  return f;
}

function configOf(f: TriggerForm): Record<string, unknown> {
  switch (f.kind) {
    case 'GITHUB_ISSUE_LABEL':
      return { label: f.label.trim() };
    case 'GITHUB_PR_COMMENT':
      return { mention: f.mention.trim(), allowedAssociations: f.associations };
    case 'SLACK_COMMAND': {
      const channels = commaList(f.channelIds);
      return { teamId: f.teamId.trim(), ...(channels.length > 0 ? { channelIds: channels } : {}) };
    }
    case 'LINEAR':
      return { label: f.label.trim(), ...(f.teamId.trim() ? { teamId: f.teamId.trim() } : {}) };
    case 'JIRA':
      return {
        label: f.label.trim(),
        ...(f.projectKey.trim() ? { projectKey: f.projectKey.trim().toUpperCase() } : {}),
      };
    case 'SCHEDULE':
      return { cron: f.cron.trim(), timezone: f.timezone.trim() || 'UTC' };
  }
}

/** Plain-English summary + next runs of a schedule form (or the reason it is not valid). */
export function SchedulePreview({ cron, timezone }: { cron: string; timezone: string }) {
  const zone = timezone.trim() || 'UTC';
  if (!isValidCron(cron)) {
    return (
      <p className="text-xs text-muted-foreground" data-testid="schedule-preview">
        Enter five fields: minute, hour, day of month, month, weekday.
      </p>
    );
  }
  if (!isValidTimeZone(zone)) {
    return (
      <p className="text-xs text-destructive" data-testid="schedule-preview">
        Unknown time zone.
      </p>
    );
  }
  const runs = previewRuns(cron, zone, 3);
  const gap = minCronGapMinutes(cron, zone);
  return (
    <div className="grid gap-1 text-xs" data-testid="schedule-preview">
      <p className="font-medium">
        {describeCron(cron)} ({zone})
      </p>
      {gap < MIN_SCHEDULE_INTERVAL_MIN ? (
        <p className="text-destructive">
          Schedules can run at most every {MIN_SCHEDULE_INTERVAL_MIN} minutes.
        </p>
      ) : null}
      {runs.length > 0 ? (
        <>
          <p className="text-muted-foreground">Next runs:</p>
          <ul className="list-disc pl-5 text-muted-foreground">
            {runs.map((r) => (
              <li key={r.toISOString()}>{formatInZone(r, zone)}</li>
            ))}
          </ul>
        </>
      ) : (
        <p className="text-muted-foreground">This schedule never runs.</p>
      )}
    </div>
  );
}

export function TriggerEditorDialog({
  orgId,
  trigger,
  projects,
  defaultProjectId,
  defaultKind = 'SCHEDULE',
  onClose,
}: {
  orgId: string;
  /** Absent = create. */
  trigger?: TriggerDto | undefined;
  projects: { id: string; name: string }[];
  defaultProjectId?: string | undefined;
  defaultKind?: TriggerKind | undefined;
  onClose: () => void;
}) {
  const editing = Boolean(trigger);
  const [form, setForm] = useState<TriggerForm>(() =>
    trigger ? formFromTrigger(trigger) : blankForm(defaultKind, defaultProjectId ?? ''),
  );
  const [errors, setErrors] = useState<Record<string, string[]>>({});
  const create = useCreateTrigger(orgId);
  const update = useUpdateTrigger(orgId);
  const handleError = useErrorHandler();
  const err = (p: string) =>
    errors[p]?.[0] ?? fieldErrorOf(create.error, p) ?? fieldErrorOf(update.error, p);
  const set = <K extends keyof TriggerForm>(key: K, value: TriggerForm[K]) =>
    setForm((prev) => ({ ...prev, [key]: value }));

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    const name = form.name.trim() || `${TRIGGER_KIND_LABEL[form.kind]}`;
    if (trigger) {
      const body: UpdateTriggerBody = {
        name,
        enabled: form.enabled,
        promptTemplate: form.promptTemplate,
        createPr: form.createPr,
        mode: form.mode,
        config: configOf(form),
      };
      update.mutate(
        { id: trigger.id, body },
        {
          onSuccess: () => {
            toastSuccess(`${name} saved`);
            onClose();
          },
          onError: (error) => handleError(error),
        },
      );
      return;
    }
    const parsed = createTriggerBodySchema.safeParse({
      kind: form.kind,
      projectId: form.projectId,
      name,
      enabled: form.enabled,
      promptTemplate: form.promptTemplate,
      createPr: form.createPr,
      mode: form.mode,
      config: configOf(form),
    });
    if (!parsed.success) {
      const fields = zodIssuesToFieldErrors(parsed.error.issues);
      // The project picker has no `Field` error of its own for an empty id.
      setErrors(fields);
      return;
    }
    setErrors({});
    create.mutate(parsed.data, {
      onSuccess: () => {
        toastSuccess(`${name} added`);
        onClose();
      },
      onError: (error) => handleError(error),
    });
  };

  const kind = form.kind;
  const usesLabel = kind === 'GITHUB_ISSUE_LABEL' || kind === 'LINEAR' || kind === 'JIRA';

  return (
    <Dialog open onOpenChange={(o) => (o ? undefined : onClose())}>
      <DialogContent className="max-w-2xl">
        <form onSubmit={onSubmit} noValidate className="grid gap-4">
          <DialogHeader>
            <DialogTitle>{editing ? `Edit ${trigger?.name}` : 'New trigger'}</DialogTitle>
            <DialogDescription>{KIND_HELP[kind]}</DialogDescription>
          </DialogHeader>

          {editing ? null : (
            <div className="grid gap-3 sm:grid-cols-2">
              <Field id="trigger-kind" label="Starts from">
                {(aria) => (
                  <NativeSelect
                    {...aria}
                    value={form.kind}
                    onChange={(e) => set('kind', e.target.value as TriggerKind)}
                  >
                    {TRIGGER_KINDS.map((k) => (
                      <option key={k} value={k}>
                        {TRIGGER_KIND_LABEL[k]}
                      </option>
                    ))}
                  </NativeSelect>
                )}
              </Field>
              <Field id="trigger-project" label="Project" error={err('projectId')} required>
                {(aria) => (
                  <NativeSelect
                    {...aria}
                    value={form.projectId}
                    onChange={(e) => set('projectId', e.target.value)}
                  >
                    <option value="">Select a project…</option>
                    {projects.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.name}
                      </option>
                    ))}
                  </NativeSelect>
                )}
              </Field>
            </div>
          )}

          <Field id="trigger-name" label="Name" error={err('name')}>
            {(aria) => (
              <Input
                {...aria}
                value={form.name}
                placeholder={TRIGGER_KIND_LABEL[kind]}
                onChange={(e) => set('name', e.target.value)}
              />
            )}
          </Field>

          {usesLabel ? (
            <Field id="trigger-label" label="Label" error={err('config.label')} required>
              {(aria) => (
                <Input
                  {...aria}
                  value={form.label}
                  onChange={(e) => set('label', e.target.value)}
                />
              )}
            </Field>
          ) : null}

          {kind === 'GITHUB_PR_COMMENT' ? (
            <>
              <Field
                id="trigger-mention"
                label="Mention"
                description="Comment this on a pull request, followed by what to fix."
                error={err('config.mention')}
                required
              >
                {(aria) => (
                  <Input
                    {...aria}
                    value={form.mention}
                    onChange={(e) => set('mention', e.target.value)}
                  />
                )}
              </Field>
              <fieldset className="grid gap-2">
                <legend className="mb-1 text-sm font-medium">Who can trigger it</legend>
                <div className="grid gap-2 sm:grid-cols-2">
                  {GithubAuthorAssociationSchema.options.map((a) => (
                    <label key={a} className="flex items-center gap-2 text-sm">
                      <Checkbox
                        checked={form.associations.includes(a)}
                        onChange={(e) =>
                          set(
                            'associations',
                            e.target.checked
                              ? [...form.associations, a]
                              : form.associations.filter((x) => x !== a),
                          )
                        }
                      />
                      {ASSOCIATION_LABEL[a]}
                    </label>
                  ))}
                </div>
                {err('config.allowedAssociations') ? (
                  <p className="text-xs font-medium text-destructive" role="alert">
                    {err('config.allowedAssociations')}
                  </p>
                ) : null}
              </fieldset>
            </>
          ) : null}

          {kind === 'SLACK_COMMAND' ? (
            <>
              <Field
                id="trigger-team"
                label="Slack workspace ID"
                description="Starts with T. Only requests from this workspace are accepted."
                error={err('config.teamId')}
                required
              >
                {(aria) => (
                  <Input
                    {...aria}
                    value={form.teamId}
                    placeholder="T0123456789"
                    onChange={(e) => set('teamId', e.target.value)}
                  />
                )}
              </Field>
              <Field
                id="trigger-channels"
                label="Channel IDs (optional)"
                description="Separate with commas. Empty = every channel."
                error={err('config.channelIds')}
              >
                {(aria) => (
                  <Input
                    {...aria}
                    value={form.channelIds}
                    placeholder="C0123456789, C0987654321"
                    onChange={(e) => set('channelIds', e.target.value)}
                  />
                )}
              </Field>
            </>
          ) : null}

          {kind === 'LINEAR' ? (
            <Field
              id="trigger-linear-team"
              label="Linear team ID (optional)"
              error={err('config.teamId')}
            >
              {(aria) => (
                <Input
                  {...aria}
                  value={form.teamId}
                  onChange={(e) => set('teamId', e.target.value)}
                />
              )}
            </Field>
          ) : null}

          {kind === 'JIRA' ? (
            <Field
              id="trigger-jira-key"
              label="Jira project key (optional)"
              error={err('config.projectKey')}
            >
              {(aria) => (
                <Input
                  {...aria}
                  value={form.projectKey}
                  placeholder="WEB"
                  onChange={(e) => set('projectKey', e.target.value)}
                />
              )}
            </Field>
          ) : null}

          {kind === 'SCHEDULE' ? (
            <fieldset className="grid gap-3 rounded-md border p-3">
              <legend className="px-1 text-sm font-medium">Timetable</legend>
              <div className="grid gap-3 sm:grid-cols-2">
                <Field
                  id="trigger-cron"
                  label="Cron expression"
                  description="minute hour day month weekday — for example 0 9 * * 1 for Mondays at 9:00."
                  error={err('config.cron')}
                  required
                >
                  {(aria) => (
                    <Input
                      {...aria}
                      className="font-mono"
                      value={form.cron}
                      onChange={(e) => set('cron', e.target.value)}
                    />
                  )}
                </Field>
                <Field
                  id="trigger-timezone"
                  label="Time zone"
                  description="An IANA name such as Europe/London."
                  error={err('config.timezone')}
                >
                  {(aria) => (
                    <Input
                      {...aria}
                      value={form.timezone}
                      onChange={(e) => set('timezone', e.target.value)}
                    />
                  )}
                </Field>
              </div>
              <div aria-live="polite">
                <SchedulePreview cron={form.cron} timezone={form.timezone} />
              </div>
            </fieldset>
          ) : null}

          <Field
            id="trigger-prompt"
            label={kind === 'SCHEDULE' ? 'Prompt' : 'Prompt template (optional)'}
            description={
              kind === 'SCHEDULE'
                ? 'What the AI should do on every run.'
                : `Leave empty to use the default. You can use ${TRIGGER_PROMPT_VARIABLES.map((v) => `{{${v}}}`).join(', ')}.`
            }
            error={err('promptTemplate')}
            required={kind === 'SCHEDULE'}
          >
            {(aria) => (
              <Textarea
                {...aria}
                rows={4}
                value={form.promptTemplate}
                placeholder={DEFAULT_TRIGGER_PROMPTS[kind] || undefined}
                onChange={(e) => set('promptTemplate', e.target.value)}
              />
            )}
          </Field>

          <div className="grid gap-3 sm:grid-cols-2">
            <Field id="trigger-mode" label="Mode">
              {(aria) => (
                <NativeSelect
                  {...aria}
                  value={form.mode}
                  onChange={(e) => set('mode', e.target.value as 'SIMPLE' | 'PRO')}
                >
                  <option value="PRO">Pro</option>
                  <option value="SIMPLE">Simple</option>
                </NativeSelect>
              )}
            </Field>
            <div className="grid content-end gap-2">
              <label className="flex items-center gap-2 text-sm">
                <Checkbox
                  checked={form.createPr}
                  onChange={(e) => set('createPr', e.target.checked)}
                />
                Open a pull request with the changes
              </label>
              <label className="flex items-center gap-2 text-sm">
                <Checkbox
                  checked={form.enabled}
                  onChange={(e) => set('enabled', e.target.checked)}
                />
                Enabled
              </label>
            </div>
          </div>

          <MutationError error={create.error ?? update.error} hideCodes={['LSE-VAL-001']} />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={create.isPending || update.isPending}>
              {editing ? 'Save trigger' : 'Add trigger'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
