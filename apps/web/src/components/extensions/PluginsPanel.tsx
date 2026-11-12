/**
 * Plugins tab of the Extensions page (spec §8.16): the organization's private
 * marketplace. Admins publish manifests and new versions; with a project selected each
 * row shows its install state and can install, update, roll back or uninstall.
 */
import type { PluginDto } from '@loose/shared';
import { Download, History, Plus, Trash2 } from 'lucide-react';
import { useState } from 'react';
import { toastSuccess } from '@/components/errors/notify';
import { LoadingBlock, QueryError } from '@/components/errors/QueryError';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Field } from '@/components/ui/field';
import { NativeSelect } from '@/components/ui/input';
import { useDeletePlugin, usePlugin, usePlugins, useUninstallPlugin } from '@/hooks/api/extensions';
import { EmptyState, ExtensionList, ExtensionRow, PanelHeader } from './common';
import { PluginInstallDialog, PluginManifestDialog, PluginVersionsDialog } from './PluginDialogs';

type DialogKind = 'install' | 'versions' | 'publish';

/** Loads the plugin detail (manifest, versions, credential requirements) for a dialog. */
function PluginDetailDialog({
  orgId,
  plugin,
  kind,
  projectId,
  projectName,
  isAdmin,
  onKind,
  onClose,
}: {
  orgId: string;
  plugin: PluginDto;
  kind: DialogKind;
  projectId: string;
  projectName: string;
  isAdmin: boolean;
  onKind: (k: DialogKind) => void;
  onClose: () => void;
}) {
  const detail = usePlugin(orgId, plugin.id);
  if (detail.isPending) return <LoadingBlock rows={1} label="Loading plugin…" />;
  if (detail.isError)
    return <QueryError error={detail.error} onRetry={() => void detail.refetch()} />;
  if (kind === 'publish') {
    return <PluginManifestDialog orgId={orgId} plugin={detail.data} onClose={onClose} />;
  }
  if (kind === 'versions') {
    return (
      <PluginVersionsDialog
        plugin={detail.data}
        canPublish={isAdmin}
        onPublish={() => onKind('publish')}
        onClose={onClose}
      />
    );
  }
  return (
    <PluginInstallDialog
      orgId={orgId}
      plugin={detail.data}
      projectId={projectId}
      projectName={projectName}
      installedVersion={plugin.install?.version ?? null}
      installedEnabled={plugin.install?.enabled}
      onClose={onClose}
    />
  );
}

export function PluginsPanel({
  orgId,
  isAdmin,
  projects,
}: {
  orgId: string;
  isAdmin: boolean;
  projects: { id: string; name: string }[];
}) {
  const [projectId, setProjectId] = useState('');
  const plugins = usePlugins(orgId, projectId ? { projectId } : {});
  const del = useDeletePlugin(orgId);
  const uninstall = useUninstallPlugin(orgId);
  const [creating, setCreating] = useState(false);
  const [open, setOpen] = useState<{ plugin: PluginDto; kind: DialogKind } | null>(null);
  const [deleting, setDeleting] = useState<PluginDto | null>(null);
  const [uninstalling, setUninstalling] = useState<PluginDto | null>(null);

  if (plugins.isPending) return <LoadingBlock label="Loading plugins…" />;
  if (plugins.isError)
    return <QueryError error={plugins.error} onRetry={() => void plugins.refetch()} />;

  const projectName = projects.find((p) => p.id === projectId)?.name ?? '';

  return (
    <div className="grid gap-4">
      <PanelHeader
        title="Plugins"
        description="Bundles of skills, commands, subagents, hooks and tool connections, versioned and installed per project."
        actions={
          isAdmin ? (
            <Button onClick={() => setCreating(true)}>
              <Plus aria-hidden="true" />
              New plugin
            </Button>
          ) : undefined
        }
      />

      {projects.length > 0 ? (
        <Field
          id="plugin-project"
          label="Project"
          description="Choose a project to see and change what is installed there."
          className="max-w-sm"
        >
          {(aria) => (
            <NativeSelect
              {...aria}
              value={projectId}
              onChange={(e) => setProjectId(e.target.value)}
            >
              <option value="">No project selected</option>
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </NativeSelect>
          )}
        </Field>
      ) : null}

      {plugins.data.length === 0 ? (
        <EmptyState>No plugins published yet.</EmptyState>
      ) : (
        <ExtensionList label="Plugins">
          {plugins.data.map((p) => {
            const installed = p.install ?? null;
            return (
              <ExtensionRow
                key={p.id}
                title={p.name}
                badges={
                  <>
                    <Badge variant="outline">v{p.version}</Badge>
                    {installed ? (
                      <Badge variant="success" data-testid={`plugin-installed-${p.name}`}>
                        Installed v{installed.version}
                      </Badge>
                    ) : null}
                    {installed?.updateAvailable ? (
                      <Badge variant="warning">Update available</Badge>
                    ) : null}
                    {installed && !installed.enabled ? <Badge variant="outline">Off</Badge> : null}
                  </>
                }
                description={p.description}
                details={
                  <p className="text-xs text-muted-foreground">
                    {p.contents.skills.length} skills · {p.contents.commands.length} commands ·{' '}
                    {p.contents.subagents.length} subagents · {p.contents.hooks} hooks ·{' '}
                    {p.contents.mcpServers.length} connections
                    {p.author ? ` · by ${p.author}` : ''} · installed in {p.installCount} project
                    {p.installCount === 1 ? '' : 's'}
                  </p>
                }
                actions={
                  <>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => setOpen({ plugin: p, kind: 'versions' })}
                    >
                      <History aria-hidden="true" />
                      <span className="sr-only">Versions of {p.name}</span>
                    </Button>
                    {isAdmin && projectId ? (
                      <Button
                        size="sm"
                        variant={installed ? 'outline' : 'default'}
                        onClick={() => setOpen({ plugin: p, kind: 'install' })}
                      >
                        <Download aria-hidden="true" />
                        {installed ? 'Change version' : 'Install'}
                        <span className="sr-only"> {p.name}</span>
                      </Button>
                    ) : null}
                    {isAdmin && projectId && installed ? (
                      <Button size="sm" variant="ghost" onClick={() => setUninstalling(p)}>
                        Uninstall
                        <span className="sr-only"> {p.name}</span>
                      </Button>
                    ) : null}
                    {isAdmin ? (
                      <Button size="sm" variant="ghost" onClick={() => setDeleting(p)}>
                        <Trash2 aria-hidden="true" />
                        <span className="sr-only">Delete {p.name}</span>
                      </Button>
                    ) : null}
                  </>
                }
              />
            );
          })}
        </ExtensionList>
      )}
      {isAdmin && !projectId && projects.length > 0 ? (
        <p className="text-xs text-muted-foreground">
          Select a project above to install, update or roll back a plugin.
        </p>
      ) : null}

      {creating ? <PluginManifestDialog orgId={orgId} onClose={() => setCreating(false)} /> : null}
      {open ? (
        <PluginDetailDialog
          orgId={orgId}
          plugin={open.plugin}
          kind={open.kind}
          projectId={projectId}
          projectName={projectName}
          isAdmin={isAdmin}
          onKind={(kind) => setOpen({ plugin: open.plugin, kind })}
          onClose={() => setOpen(null)}
        />
      ) : null}
      <ConfirmDialog
        open={uninstalling !== null}
        onOpenChange={(o) => {
          if (!o) {
            setUninstalling(null);
            uninstall.reset();
          }
        }}
        title={`Remove ${uninstalling?.name ?? 'plugin'} from ${projectName}?`}
        description="Everything it added to this project is removed, including its stored credentials."
        confirmLabel="Uninstall"
        destructive
        loading={uninstall.isPending}
        error={uninstall.error}
        onConfirm={() => {
          const target = uninstalling;
          if (!target) return;
          uninstall.mutate(
            { id: target.id, projectId },
            {
              onSuccess: () => {
                toastSuccess(`${target.name} uninstalled`);
                setUninstalling(null);
              },
            },
          );
        }}
      />
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(o) => {
          if (!o) {
            setDeleting(null);
            del.reset();
          }
        }}
        title={`Delete ${deleting?.name ?? 'plugin'}?`}
        description="The plugin and all of its versions are removed from this organization."
        confirmLabel="Delete plugin"
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
