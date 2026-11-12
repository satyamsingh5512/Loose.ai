/**
 * Plugin dialogs (spec §8.16): publish a manifest (create or a new version), inspect the
 * version history, and install / update / roll back / uninstall a plugin for one project.
 *
 * A manifest is validated locally with the shared `validatePluginManifest` and, before
 * installing, against the project with `POST /orgs/:orgId/plugins/validate` so name,
 * version, dependency and credential conflicts (LSE-EXT-007) are shown up front.
 */
import {
  pluginVersionChange,
  validatePluginManifest,
  type PluginDetailDto,
  type PluginManifestInput,
  type PluginValidationDto,
} from '@loose/shared';
import { AlertTriangle, CheckCircle2 } from 'lucide-react';
import { useEffect, useState, type FormEvent } from 'react';
import { MutationError } from '@/components/errors/MutationError';
import { toastSuccess, useErrorHandler } from '@/components/errors/notify';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
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
import {
  useCreatePlugin,
  useInstallPlugin,
  usePublishPluginVersion,
  useUpdatePluginInstall,
  useValidatePlugin,
} from '@/hooks/api/extensions';
import { formatDateTime } from '@/lib/utils';
import { EmptyState } from './common';

const BLANK_MANIFEST = `{
  "manifestVersion": 1,
  "name": "my-plugin",
  "version": "1.0.0",
  "title": "My plugin",
  "description": "What this plugin bundles.",
  "commands": [{ "name": "ship-it", "body": "Ship the current branch." }]
}
`;

function parseManifest(text: string): { manifest?: unknown; error?: string } {
  try {
    return { manifest: JSON.parse(text) };
  } catch {
    return { error: 'That is not valid JSON.' };
  }
}

/** Issues / conflicts / warnings of a server-side validation. */
export function PluginValidationResult({ result }: { result: PluginValidationDto }) {
  const conflicts = result.conflicts;
  return (
    <Alert
      variant={result.valid && conflicts.length === 0 ? 'success' : 'destructive'}
      data-testid="plugin-validation"
    >
      {result.valid && conflicts.length === 0 ? (
        <CheckCircle2 aria-hidden="true" />
      ) : (
        <AlertTriangle aria-hidden="true" />
      )}
      <AlertTitle>
        {result.valid && conflicts.length === 0
          ? `${result.name ?? 'The plugin'} ${result.version ?? ''} is ready`
          : 'This plugin has problems'}
      </AlertTitle>
      <AlertDescription>
        {result.issues.length > 0 ? (
          <ul className="list-disc pl-4">
            {result.issues.map((i) => (
              <li key={`${i.code}-${i.path ?? ''}-${i.message}`}>
                {i.code}: {i.path ? `${i.path}: ` : ''}
                {i.message}
              </li>
            ))}
          </ul>
        ) : null}
        {conflicts.length > 0 ? (
          <ul className="list-disc pl-4" data-testid="plugin-conflicts">
            {conflicts.map((c) => (
              <li key={`${c.kind}-${c.name}`}>
                {c.code}: {c.message}
              </li>
            ))}
          </ul>
        ) : null}
        {result.warnings.length > 0 ? (
          <ul className="list-disc pl-4 text-muted-foreground">
            {result.warnings.map((w) => (
              <li key={w}>{w}</li>
            ))}
          </ul>
        ) : null}
        <span className="text-muted-foreground">
          {result.contents.skills.length} skills · {result.contents.commands.length} commands ·{' '}
          {result.contents.subagents.length} subagents · {result.contents.hooks} hooks ·{' '}
          {result.contents.mcpServers.length} connections
        </span>
      </AlertDescription>
    </Alert>
  );
}

/** Create a plugin or publish a new version of one, from a manifest JSON. */
export function PluginManifestDialog({
  orgId,
  plugin,
  onClose,
}: {
  orgId: string;
  /** Absent = create a new plugin; present = publish a new version of it. */
  plugin?: PluginDetailDto | undefined;
  onClose: () => void;
}) {
  const publishing = Boolean(plugin);
  const [text, setText] = useState(() =>
    plugin ? `${JSON.stringify(plugin.manifest, null, 2)}\n` : BLANK_MANIFEST,
  );
  const [jsonError, setJsonError] = useState<string | undefined>();
  const [checked, setChecked] = useState<PluginValidationDto | null>(null);
  const create = useCreatePlugin(orgId);
  const publish = usePublishPluginVersion(orgId);
  const validate = useValidatePlugin(orgId);
  const handleError = useErrorHandler();

  const parsed = parseManifest(text);
  const local = parsed.manifest ? validatePluginManifest(parsed.manifest) : null;
  const firstIssue = local?.issues[0];
  const canSubmit = Boolean(local?.ok);

  const onUpload = async (file: File | undefined) => {
    if (!file) return;
    setText(await file.text());
    setChecked(null);
  };

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (parsed.error) {
      setJsonError(parsed.error);
      return;
    }
    setJsonError(undefined);
    if (!local?.ok || !local.manifest) return;
    const manifest = local.manifest as PluginManifestInput;
    if (plugin) {
      publish.mutate(
        { id: plugin.id, body: { manifest: local.manifest } },
        {
          onSuccess: (v) => {
            toastSuccess(`${plugin.name} ${v.version} published`);
            onClose();
          },
          onError: (err) => handleError(err),
        },
      );
      return;
    }
    create.mutate(
      { manifest },
      {
        onSuccess: (dto) => {
          toastSuccess(`${dto.name} ${dto.version} published`);
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
            <DialogTitle>
              {publishing ? `Publish a new version of ${plugin?.name}` : 'New plugin'}
            </DialogTitle>
            <DialogDescription>
              A plugin bundles skills, slash commands, subagents, hooks and tool connections under
              one semantic version. It stays private to this organization.
            </DialogDescription>
          </DialogHeader>

          <Field
            id="plugin-file"
            label="Upload a manifest file (optional)"
            description="Replaces the editor content with the file's JSON."
          >
            {(aria) => (
              <Input
                {...aria}
                type="file"
                accept="application/json,.json"
                onChange={(e) => void onUpload(e.target.files?.[0])}
              />
            )}
          </Field>

          <Field
            id="plugin-manifest"
            label="Manifest (JSON)"
            error={jsonError ?? parsed.error ?? (firstIssue ? firstIssue.message : undefined)}
            required
          >
            {(aria) => (
              <Textarea
                {...aria}
                rows={16}
                className="font-mono text-xs"
                value={text}
                spellCheck={false}
                onChange={(e) => {
                  setText(e.target.value);
                  setChecked(null);
                  setJsonError(undefined);
                }}
              />
            )}
          </Field>

          {local?.ok ? (
            <p className="flex items-center gap-2 text-xs text-success" data-testid="plugin-valid">
              <CheckCircle2 className="size-4" aria-hidden="true" />
              {local.manifest?.name} {local.manifest?.version} · {local.counts.skills} skills,{' '}
              {local.counts.commands} commands, {local.counts.subagents} subagents,{' '}
              {local.counts.hooks} hooks, {local.counts.mcpServers} connections
            </p>
          ) : null}
          {checked ? <PluginValidationResult result={checked} /> : null}
          <MutationError error={create.error ?? publish.error ?? validate.error} />

          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button
              type="button"
              variant="outline"
              loading={validate.isPending}
              onClick={() => {
                if (!parsed.manifest) {
                  setJsonError(parsed.error);
                  return;
                }
                validate.mutate(
                  { manifest: parsed.manifest },
                  { onSuccess: (r) => setChecked(r), onError: (err) => handleError(err) },
                );
              }}
            >
              Check manifest
            </Button>
            <Button
              type="submit"
              loading={create.isPending || publish.isPending}
              disabled={!canSubmit}
            >
              {publishing ? 'Publish version' : 'Add plugin'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/** Version history of a plugin, with "publish a new version". */
export function PluginVersionsDialog({
  plugin,
  onClose,
  onPublish,
  canPublish,
}: {
  plugin: PluginDetailDto;
  onClose: () => void;
  onPublish: () => void;
  canPublish: boolean;
}) {
  return (
    <Dialog open onOpenChange={(o) => (o ? undefined : onClose())}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Versions of {plugin.name}</DialogTitle>
          <DialogDescription>
            Published versions stay available, so a project can roll back to an older one.
          </DialogDescription>
        </DialogHeader>
        {plugin.versions.length === 0 ? (
          <EmptyState>No versions yet.</EmptyState>
        ) : (
          <ul aria-label={`Versions of ${plugin.name}`} className="divide-y rounded-md border">
            {plugin.versions.map((v) => (
              <li key={v.version} className="flex flex-wrap items-center gap-2 p-3 text-sm">
                <span className="font-medium">{v.version}</span>
                {v.version === plugin.version ? <Badge variant="secondary">Latest</Badge> : null}
                <span className="text-muted-foreground">
                  {formatDateTime(v.createdAt)}
                  {v.createdByName ? ` · ${v.createdByName}` : ''}
                </span>
              </li>
            ))}
          </ul>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
          {canPublish ? <Button onClick={onPublish}>Publish new version</Button> : null}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** Install a plugin into a project, or move an existing install to another version. */
export function PluginInstallDialog({
  orgId,
  plugin,
  projectId,
  projectName,
  installedVersion,
  installedEnabled,
  onClose,
}: {
  orgId: string;
  plugin: PluginDetailDto;
  projectId: string;
  projectName: string;
  /** Null = not installed in this project yet. */
  installedVersion: string | null;
  installedEnabled?: boolean | undefined;
  onClose: () => void;
}) {
  const versions =
    plugin.versions.length > 0 ? plugin.versions.map((v) => v.version) : [plugin.version];
  const [version, setVersion] = useState(installedVersion ?? plugin.version);
  const [enabled, setEnabled] = useState(installedEnabled ?? true);
  const [credentials, setCredentials] = useState<Record<string, Record<string, string>>>({});
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [checked, setChecked] = useState<PluginValidationDto | null>(null);
  const install = useInstallPlugin(orgId);
  const updateInstall = useUpdatePluginInstall(orgId);
  const validate = useValidatePlugin(orgId);
  const handleError = useErrorHandler();

  // Check the manifest against the project as soon as the dialog opens.
  useEffect(() => {
    validate.mutate({ manifest: plugin.manifest, projectId }, { onSuccess: (r) => setChecked(r) });
    // eslint-disable-next-line react-hooks/exhaustive-deps -- run once per dialog
  }, []);

  const change = pluginVersionChange(installedVersion, version);
  const label =
    change === 'install'
      ? 'Install'
      : change === 'update'
        ? 'Update'
        : change === 'rollback'
          ? 'Roll back'
          : 'Save';

  const setCredential = (server: string, key: string, value: string) =>
    setCredentials((prev) => ({ ...prev, [server]: { ...(prev[server] ?? {}), [key]: value } }));

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    const next: Record<string, string> = {};
    for (const group of plugin.credentials) {
      for (const f of group.fields) {
        const value = credentials[group.server]?.[f.key] ?? '';
        if (f.required && !value && installedVersion === null) {
          next[`${group.server}.${f.key}`] = `${f.label} is required.`;
        }
      }
    }
    setErrors(next);
    if (Object.keys(next).length > 0) return;

    const filled = Object.fromEntries(
      Object.entries(credentials)
        .map(([server, values]) => [
          server,
          Object.fromEntries(Object.entries(values).filter(([, v]) => v !== '')),
        ])
        .filter(([, values]) => Object.keys(values as object).length > 0),
    ) as Record<string, Record<string, string>>;

    if (installedVersion === null) {
      install.mutate(
        { id: plugin.id, body: { projectId, version, credentials: filled, enabled } },
        {
          onSuccess: (dto) => {
            toastSuccess(`${plugin.name} ${dto.version} installed in ${projectName}`);
            onClose();
          },
          onError: (err) => handleError(err),
        },
      );
      return;
    }
    updateInstall.mutate(
      {
        id: plugin.id,
        body: {
          projectId,
          version,
          enabled,
          ...(Object.keys(filled).length > 0 ? { credentials: filled } : {}),
        },
      },
      {
        onSuccess: (dto) => {
          toastSuccess(
            change === 'rollback'
              ? `${plugin.name} rolled back to ${dto.version}`
              : `${plugin.name} is now on ${dto.version}`,
          );
          onClose();
        },
        onError: (err) => handleError(err),
      },
    );
  };

  return (
    <Dialog open onOpenChange={(o) => (o ? undefined : onClose())}>
      <DialogContent className="max-w-2xl">
        <form onSubmit={onSubmit} noValidate className="grid gap-4">
          <DialogHeader>
            <DialogTitle>
              {installedVersion === null
                ? `Install ${plugin.title} in ${projectName}`
                : `${plugin.title} in ${projectName}`}
            </DialogTitle>
            <DialogDescription>
              {plugin.description ||
                'Everything the plugin bundles becomes available in this project.'}
            </DialogDescription>
          </DialogHeader>

          <Field
            id="plugin-install-version"
            label="Version"
            description={
              installedVersion === null
                ? undefined
                : `Currently installed: ${installedVersion}. Pick an older version to roll back.`
            }
          >
            {(aria) => (
              <NativeSelect {...aria} value={version} onChange={(e) => setVersion(e.target.value)}>
                {versions.map((v) => (
                  <option key={v} value={v}>
                    {v}
                    {v === plugin.version ? ' (latest)' : ''}
                    {v === installedVersion ? ' (installed)' : ''}
                  </option>
                ))}
              </NativeSelect>
            )}
          </Field>

          {plugin.credentials.length > 0 ? (
            <fieldset className="grid gap-3 rounded-md border p-3">
              <legend className="px-1 text-sm font-medium">Connection credentials</legend>
              <p className="text-xs text-muted-foreground">
                The plugin only declares which credentials its tools need. Values are encrypted and
                never shown again; a connection without its credentials is skipped.
              </p>
              {plugin.credentials.map((group) =>
                group.fields.map((f) => (
                  <Field
                    key={`${group.server}.${f.key}`}
                    id={`plugin-cred-${group.server}-${f.key}`}
                    label={`${group.server}: ${f.label}`}
                    error={errors[`${group.server}.${f.key}`]}
                    required={f.required}
                  >
                    {(aria) => (
                      <Input
                        {...aria}
                        type="password"
                        autoComplete="off"
                        value={credentials[group.server]?.[f.key] ?? ''}
                        placeholder={f.placeholder ?? '••••••••'}
                        onChange={(e) => setCredential(group.server, f.key, e.target.value)}
                      />
                    )}
                  </Field>
                )),
              )}
            </fieldset>
          ) : null}

          <label className="flex items-center gap-2 text-sm">
            <Checkbox checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
            Active in this project
          </label>

          {checked ? <PluginValidationResult result={checked} /> : null}
          <MutationError error={install.error ?? updateInstall.error} />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={install.isPending || updateInstall.isPending}>
              {label}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
