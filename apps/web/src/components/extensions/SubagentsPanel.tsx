/**
 * Subagents tab of the Extensions page (spec §8.8): the resolved list (built-in → org →
 * project → personal) with its tools, create / edit from Markdown and delete.
 *
 * Built-ins are read-only. Turning a subagent off for one project happens in the
 * project's settings (`extensions.subagents` override), not here.
 */
import type { SubagentDto } from '@loose/shared';
import { Pencil, Plus, Trash2 } from 'lucide-react';
import { useState } from 'react';
import { toastSuccess } from '@/components/errors/notify';
import { LoadingBlock, QueryError } from '@/components/errors/QueryError';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { useDeleteSubagent, useSubagents } from '@/hooks/api/extensions';
import { EmptyState, ExtensionList, ExtensionRow, PanelHeader, ScopeBadge } from './common';
import { SubagentEditorDialog } from './SubagentEditorDialog';

export function SubagentsPanel({
  orgId,
  isAdmin,
  canCreatePersonal,
  projects,
}: {
  orgId: string;
  isAdmin: boolean;
  canCreatePersonal: boolean;
  projects: { id: string; name: string }[];
}) {
  const subagents = useSubagents(orgId);
  const del = useDeleteSubagent(orgId);
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<SubagentDto | null>(null);
  const [deleting, setDeleting] = useState<SubagentDto | null>(null);

  if (subagents.isPending) return <LoadingBlock label="Loading subagents…" />;
  if (subagents.isError)
    return <QueryError error={subagents.error} onRetry={() => void subagents.refetch()} />;

  const canWrite = (s: SubagentDto) => !s.builtin && (isAdmin || s.scope === 'USER');

  return (
    <div className="grid gap-4">
      <PanelHeader
        title="Subagents"
        description="Specialists with their own instructions and tools. The AI delegates to them, or you mention one with @name."
        actions={
          isAdmin || canCreatePersonal ? (
            <Button onClick={() => setCreating(true)}>
              <Plus aria-hidden="true" />
              New subagent
            </Button>
          ) : undefined
        }
      />

      {subagents.data.length === 0 ? (
        <EmptyState>No subagents yet.</EmptyState>
      ) : (
        <ExtensionList label="Subagents">
          {subagents.data.map((s) => (
            <ExtensionRow
              key={s.id}
              title={`@${s.name}`}
              badges={
                <>
                  <ScopeBadge scope={s.scope} />
                  {s.pluginName ? <Badge variant="secondary">Plugin: {s.pluginName}</Badge> : null}
                  {s.model ? <Badge variant="outline">{s.model}</Badge> : null}
                  {s.permissionMode ? <Badge variant="outline">{s.permissionMode}</Badge> : null}
                </>
              }
              description={s.description}
              details={
                <p className="text-xs text-muted-foreground">
                  {s.tools.length > 0
                    ? `Tools: ${s.tools.join(', ')}`
                    : 'Tools: inherits the session’s tools'}
                </p>
              }
              actions={
                canWrite(s) ? (
                  <>
                    <Button size="sm" variant="ghost" onClick={() => setEditing(s)}>
                      <Pencil aria-hidden="true" />
                      <span className="sr-only">Edit {s.name}</span>
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => setDeleting(s)}>
                      <Trash2 aria-hidden="true" />
                      <span className="sr-only">Delete {s.name}</span>
                    </Button>
                  </>
                ) : (
                  <span className="text-xs text-muted-foreground">
                    {s.builtin ? 'Read-only' : ''}
                  </span>
                )
              }
            />
          ))}
        </ExtensionList>
      )}
      <p className="text-xs text-muted-foreground">
        Turn a subagent off for a single project in that project&apos;s settings.
      </p>

      {creating ? (
        <SubagentEditorDialog
          orgId={orgId}
          onClose={() => setCreating(false)}
          projects={projects}
          canManageShared={isAdmin}
          canCreatePersonal={canCreatePersonal}
        />
      ) : null}
      {editing ? (
        <SubagentEditorDialog
          orgId={orgId}
          subagent={editing}
          onClose={() => setEditing(null)}
          projects={projects}
          canManageShared={isAdmin}
          canCreatePersonal={canCreatePersonal}
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
        title={`Delete ${deleting?.name ?? 'subagent'}?`}
        description="Sessions will stop offering this specialist."
        confirmLabel="Delete subagent"
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
