/**
 * Per-project extension overrides (spec §10.4.1): every org/project skill, MCP server and
 * subagent with its inherited state and a three-way override (inherit / on / off), plus
 * the plugins installed in this project and the hooks that apply to it.
 *
 * Saving sends only the rows that changed (`null` clears the override). Plugins are
 * toggled one by one (`PUT /orgs/:orgId/plugins/:id/install`), hooks are org policy and
 * only shown for reference.
 */
import {
  HOOK_EVENT_LABELS,
  type ProjectExtensionsDto,
  type UpdateProjectExtensionsBody,
} from '@loose/shared';
import { useState } from 'react';
import { MutationError } from '@/components/errors/MutationError';
import { toastSuccess, useErrorHandler } from '@/components/errors/notify';
import { LoadingBlock, QueryError } from '@/components/errors/QueryError';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Field } from '@/components/ui/field';
import { Checkbox, NativeSelect } from '@/components/ui/input';
import {
  useProjectExtensions,
  useUpdateProjectExtensions,
  useUpdatePluginInstall,
} from '@/hooks/api/extensions';
import { EmptyState, ScopeBadge } from './common';

type Choice = 'inherit' | 'on' | 'off';
type Kind = 'skills' | 'mcpServers' | 'subagents';

const CHOICES: { value: Choice; label: string }[] = [
  { value: 'inherit', label: 'Inherit' },
  { value: 'on', label: 'On' },
  { value: 'off', label: 'Off' },
];

const toChoice = (override: boolean | null): Choice =>
  override === null ? 'inherit' : override ? 'on' : 'off';
const toOverride = (c: Choice): boolean | null => (c === 'inherit' ? null : c === 'on');

function keyOf(kind: Kind, row: { id: string; name: string }) {
  return kind === 'mcpServers' ? row.id : row.name;
}

function rowsOf(data: ProjectExtensionsDto) {
  return {
    skills: data.skills.map((s) => ({
      id: s.id,
      name: s.name,
      scope: s.scope,
      description: s.description,
      inherited: s.inherited,
      override: s.override,
    })),
    mcpServers: data.mcpServers.map((s) => ({
      id: s.id,
      name: s.name,
      scope: s.scope,
      description: s.url ?? [s.command, ...s.args].filter(Boolean).join(' '),
      inherited: s.inherited,
      override: s.override,
    })),
    subagents: data.subagents.map((s) => ({
      id: s.id,
      name: s.name,
      scope: s.scope,
      description: s.description,
      inherited: s.inherited,
      override: s.override,
    })),
  };
}

type Rows = ReturnType<typeof rowsOf>;
type Choices = Record<Kind, Record<string, Choice>>;

function initialChoices(rows: Rows): Choices {
  const of = (kind: Kind) =>
    Object.fromEntries(rows[kind].map((r) => [keyOf(kind, r), toChoice(r.override)]));
  return { skills: of('skills'), mcpServers: of('mcpServers'), subagents: of('subagents') };
}

function OverrideList({
  legend,
  emptyLabel,
  kind,
  rows,
  choices,
  onChange,
}: {
  legend: string;
  emptyLabel: string;
  kind: Kind;
  rows: Rows[Kind];
  choices: Record<string, Choice>;
  onChange: (key: string, c: Choice) => void;
}) {
  return (
    <fieldset className="grid gap-2">
      <legend className="mb-1 text-sm font-medium">{legend}</legend>
      {rows.length === 0 ? (
        <EmptyState>{emptyLabel}</EmptyState>
      ) : (
        <ul aria-label={legend} className="divide-y rounded-lg border">
          {rows.map((r) => {
            const key = keyOf(kind, r);
            const choice = choices[key] ?? 'inherit';
            return (
              <li key={r.id} className="grid gap-2 p-3 sm:grid-cols-[1fr_12rem] sm:items-center">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-sm font-medium break-all">{r.name}</span>
                    <ScopeBadge scope={r.scope} />
                  </div>
                  <p className="text-sm text-muted-foreground">{r.description}</p>
                  <p className="text-xs text-muted-foreground">
                    {r.inherited ? 'On by default' : 'Off by default'}
                    {choice !== 'inherit'
                      ? ` · overridden ${choice === 'on' ? 'on' : 'off'} for this project`
                      : ''}
                  </p>
                </div>
                <Field id={`ext-${kind}-${key}`} label={`${r.name} in this project`}>
                  {(aria) => (
                    <NativeSelect
                      {...aria}
                      value={choice}
                      onChange={(e) => onChange(key, e.target.value as Choice)}
                    >
                      {CHOICES.map((c) => (
                        <option key={c.value} value={c.value}>
                          {c.label}
                          {c.value === 'inherit' ? (r.inherited ? ' (on)' : ' (off)') : ''}
                        </option>
                      ))}
                    </NativeSelect>
                  )}
                </Field>
              </li>
            );
          })}
        </ul>
      )}
    </fieldset>
  );
}

/** Installed plugins: an on/off switch per install (saved immediately). */
function PluginList({
  orgId,
  projectId,
  plugins,
}: {
  orgId: string;
  projectId: string;
  plugins: ProjectExtensionsDto['plugins'];
}) {
  const update = useUpdatePluginInstall(orgId);
  const handleError = useErrorHandler();
  return (
    <fieldset className="grid gap-2">
      <legend className="mb-1 text-sm font-medium">Plugins</legend>
      {plugins.length === 0 ? (
        <EmptyState>No plugins installed in this project.</EmptyState>
      ) : (
        <ul aria-label="Plugins" className="divide-y rounded-lg border">
          {plugins.map((p) => (
            <li key={p.id} className="grid gap-2 p-3 sm:grid-cols-[1fr_auto] sm:items-center">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-sm font-medium break-all">{p.pluginName}</span>
                  <Badge variant="outline">v{p.version}</Badge>
                  {p.updateAvailable ? (
                    <Badge variant="warning">v{p.latestVersion} available</Badge>
                  ) : null}
                </div>
                <p className="text-xs text-muted-foreground">
                  {p.contents.skills.length} skills · {p.contents.commands.length} commands ·{' '}
                  {p.contents.subagents.length} subagents · {p.contents.hooks} hooks ·{' '}
                  {p.contents.mcpServers.length} connections
                </p>
                {p.warnings.map((w) => (
                  <p key={w} className="text-xs text-warning-foreground dark:text-warning">
                    {w}
                  </p>
                ))}
              </div>
              <label className="flex items-center gap-2 text-sm">
                <Checkbox
                  checked={p.enabled}
                  aria-label={`${p.enabled ? 'Disable' : 'Enable'} ${p.pluginName}`}
                  onChange={(e) =>
                    update.mutate(
                      { id: p.pluginId, body: { projectId, enabled: e.target.checked } },
                      {
                        onSuccess: () =>
                          toastSuccess(
                            e.target.checked
                              ? `${p.pluginName} enabled`
                              : `${p.pluginName} disabled`,
                          ),
                        onError: (err) => handleError(err),
                      },
                    )
                  }
                />
                Active
              </label>
            </li>
          ))}
        </ul>
      )}
      <MutationError error={update.error} />
      <p className="text-xs text-muted-foreground">
        Install, update or roll back plugins on the organization&apos;s Extensions page.
      </p>
    </fieldset>
  );
}

/** Hooks that apply here (org policy, read-only in project settings). */
function HookList({ hooks }: { hooks: ProjectExtensionsDto['hooks'] }) {
  if (hooks.length === 0) return null;
  return (
    <section className="grid gap-2">
      <h3 className="text-sm font-medium">Hooks that apply here</h3>
      <ul aria-label="Hooks that apply here" className="divide-y rounded-lg border">
        {hooks.map((h) => (
          <li key={h.id} className="flex flex-wrap items-center gap-2 p-3 text-sm">
            <span className="font-medium">{h.name}</span>
            <ScopeBadge scope={h.scope} />
            <Badge variant="outline">{HOOK_EVENT_LABELS[h.event]}</Badge>
            {!h.enabled ? <Badge variant="outline">Off</Badge> : null}
          </li>
        ))}
      </ul>
      <p className="text-xs text-muted-foreground">
        Hooks are organization policy and can only be changed on the Extensions page.
      </p>
    </section>
  );
}

function Editor({
  orgId,
  projectId,
  data,
}: {
  orgId: string;
  projectId: string;
  data: ProjectExtensionsDto;
}) {
  const rows = rowsOf(data);
  const [choices, setChoices] = useState<Choices>(() => initialChoices(rows));
  const update = useUpdateProjectExtensions(orgId, projectId);
  const handleError = useErrorHandler();
  const saved = initialChoices(rows);

  const dirty = (['skills', 'mcpServers', 'subagents'] as const).some(
    (k) => JSON.stringify(choices[k]) !== JSON.stringify(saved[k]),
  );

  const patch = (): UpdateProjectExtensionsBody => {
    const diff = (kind: Kind) => {
      const out: Record<string, boolean | null> = {};
      for (const [key, choice] of Object.entries(choices[kind])) {
        if (choice !== saved[kind][key]) out[key] = toOverride(choice);
      }
      return out;
    };
    const skills = diff('skills');
    const mcpServers = diff('mcpServers');
    const subagents = diff('subagents');
    return {
      ...(Object.keys(skills).length > 0 ? { skills } : {}),
      ...(Object.keys(mcpServers).length > 0 ? { mcpServers } : {}),
      ...(Object.keys(subagents).length > 0 ? { subagents } : {}),
    };
  };

  const onChange = (kind: Kind) => (key: string, c: Choice) =>
    setChoices((p) => ({ ...p, [kind]: { ...p[kind], [key]: c } }));

  return (
    <div className="grid gap-4">
      <OverrideList
        legend="Skills"
        emptyLabel="No organization or project skills yet."
        kind="skills"
        rows={rows.skills}
        choices={choices.skills}
        onChange={onChange('skills')}
      />
      <OverrideList
        legend="MCP servers"
        emptyLabel="No organization or project tools yet."
        kind="mcpServers"
        rows={rows.mcpServers}
        choices={choices.mcpServers}
        onChange={onChange('mcpServers')}
      />
      <OverrideList
        legend="Subagents"
        emptyLabel="No subagents available yet."
        kind="subagents"
        rows={rows.subagents}
        choices={choices.subagents}
        onChange={onChange('subagents')}
      />
      <PluginList orgId={orgId} projectId={projectId} plugins={data.plugins} />
      <HookList hooks={data.hooks} />
      <p className="text-xs text-muted-foreground">
        Personal skills, tools and subagents stay under each member&apos;s own control.
      </p>
      <MutationError error={update.error} />
      <div>
        <Button
          type="button"
          disabled={!dirty}
          loading={update.isPending}
          onClick={() =>
            update.mutate(patch(), {
              onSuccess: () => toastSuccess('Project extensions saved'),
              onError: (err) => handleError(err),
            })
          }
        >
          Save extensions
        </Button>
      </div>
    </div>
  );
}

/** Loader + editor; `key` on the editor resets local state after a successful save. */
export function ProjectExtensionToggles({
  orgId,
  projectId,
}: {
  orgId: string;
  projectId: string;
}) {
  const query = useProjectExtensions(orgId, projectId);
  if (query.isPending) return <LoadingBlock rows={2} label="Loading extensions…" />;
  if (query.isError) return <QueryError error={query.error} onRetry={() => void query.refetch()} />;
  const d = query.data;
  if (
    d.skills.length === 0 &&
    d.mcpServers.length === 0 &&
    d.subagents.length === 0 &&
    d.plugins.length === 0 &&
    d.hooks.length === 0
  ) {
    return (
      <EmptyState>
        This organization has no shared skills, tools, subagents, hooks or plugins yet. Add them on
        the Extensions page.
      </EmptyState>
    );
  }
  return <Editor key={JSON.stringify(rowsOf(d))} orgId={orgId} projectId={projectId} data={d} />;
}
