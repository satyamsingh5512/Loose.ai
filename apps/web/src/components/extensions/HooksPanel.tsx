/**
 * Hooks tab of the Extensions page (spec §8.9): the org's and projects' hooks with their
 * event, matcher and handler, one-click recipes, a custom editor, the "test with a sample
 * payload" dialog, an enable toggle and delete.
 *
 * Only admins change hooks (they are policy); members see them read-only.
 */
import { HOOK_EVENT_LABELS, type HookDto, type HookRecipe } from '@loose/shared';
import { FlaskConical, Pencil, Plus, Trash2 } from 'lucide-react';
import { useState } from 'react';
import { MutationError } from '@/components/errors/MutationError';
import { toastSuccess, useErrorHandler } from '@/components/errors/notify';
import { LoadingBlock, QueryError } from '@/components/errors/QueryError';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Checkbox } from '@/components/ui/input';
import { useDeleteHook, useHookRecipes, useHooks, useUpdateHook } from '@/hooks/api/extensions';
import { EmptyState, ExtensionList, ExtensionRow, PanelHeader, ScopeBadge } from './common';
import { HookEditorDialog } from './HookEditorDialog';
import { HookTestDialog } from './HookTestDialog';

function handlerSummary(hook: HookDto): string {
  const h = hook.handler;
  if (h.type === 'command') return `Runs ${h.command} in the sandbox`;
  if (h.type === 'http') return `Asks ${h.url}${h.hasSecret ? ' (signed)' : ''}`;
  const parts: string[] = [h.action.replace(/_/g, ' ')];
  if (h.config.paths?.length) parts.push(h.config.paths.join(', '));
  if (h.config.commands?.length) parts.push(h.config.commands.join(' && '));
  if (h.config.command) parts.push(h.config.command);
  if (h.config.hasWebhookUrl) parts.push('webhook stored');
  return parts.join(' · ');
}

function RecipeList({
  recipes,
  onPick,
}: {
  recipes: HookRecipe[];
  onPick: (r: HookRecipe) => void;
}) {
  return (
    <Card data-testid="hook-recipes">
      <CardHeader>
        <CardTitle as="h3" className="text-base">
          Start from a recipe
        </CardTitle>
        <CardDescription>
          Common policies, ready to use. You can change every detail before saving.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ul aria-label="Hook recipes" className="grid gap-2 sm:grid-cols-2">
          {recipes.map((r) => (
            <li key={r.id} className="flex items-start justify-between gap-2 rounded-md border p-3">
              <div className="min-w-0">
                <p className="text-sm font-medium">{r.name}</p>
                <p className="text-xs text-muted-foreground">{r.description}</p>
              </div>
              <Button size="sm" variant="outline" onClick={() => onPick(r)}>
                Use
              </Button>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}

export function HooksPanel({
  orgId,
  isAdmin,
  projects,
}: {
  orgId: string;
  isAdmin: boolean;
  projects: { id: string; name: string }[];
}) {
  const hooks = useHooks(orgId);
  const recipes = useHookRecipes(orgId, { enabled: isAdmin });
  const update = useUpdateHook(orgId);
  const del = useDeleteHook(orgId);
  const handleError = useErrorHandler();
  const [creating, setCreating] = useState(false);
  const [fromRecipe, setFromRecipe] = useState<HookRecipe | null>(null);
  const [editing, setEditing] = useState<HookDto | null>(null);
  const [testing, setTesting] = useState<HookDto | null>(null);
  const [deleting, setDeleting] = useState<HookDto | null>(null);

  if (hooks.isPending) return <LoadingBlock label="Loading hooks…" />;
  if (hooks.isError) return <QueryError error={hooks.error} onRetry={() => void hooks.refetch()} />;

  const closeEditor = () => {
    setCreating(false);
    setFromRecipe(null);
    setEditing(null);
  };

  return (
    <div className="grid gap-4">
      <PanelHeader
        title="Hooks"
        description="Automatic checks that run before or after the AI acts. They can block, ask for approval or rewrite an action — enforced by the server."
        actions={
          isAdmin ? (
            <Button onClick={() => setCreating(true)}>
              <Plus aria-hidden="true" />
              New hook
            </Button>
          ) : undefined
        }
      />
      <MutationError error={update.error} />

      {isAdmin && recipes.data && recipes.data.length > 0 ? (
        <RecipeList
          recipes={[...recipes.data]}
          onPick={(r) => {
            setFromRecipe(r);
            setCreating(true);
          }}
        />
      ) : null}

      {hooks.data.length === 0 ? (
        <EmptyState>No hooks yet.</EmptyState>
      ) : (
        <ExtensionList label="Hooks">
          {hooks.data.map((h) => (
            <ExtensionRow
              key={h.id}
              title={h.name}
              badges={
                <>
                  <ScopeBadge scope={h.scope} />
                  <Badge variant="outline">{HOOK_EVENT_LABELS[h.event]}</Badge>
                  {h.matcher ? <Badge variant="secondary">{h.matcher}</Badge> : null}
                  {h.pluginName ? <Badge variant="secondary">Plugin: {h.pluginName}</Badge> : null}
                  {!h.enabled ? <Badge variant="outline">Off</Badge> : null}
                </>
              }
              description={handlerSummary(h)}
              details={
                <p className="text-xs text-muted-foreground">
                  {h.failMode === 'closed'
                    ? 'If it fails, the action is blocked'
                    : 'If it fails, the action is allowed'}{' '}
                  · timeout {h.timeoutSec}s{h.recipe ? ` · recipe ${h.recipe}` : ''}
                </p>
              }
              actions={
                isAdmin ? (
                  <>
                    <label className="flex items-center gap-2 text-sm">
                      <Checkbox
                        checked={h.enabled}
                        aria-label={`${h.enabled ? 'Disable' : 'Enable'} ${h.name}`}
                        onChange={(e) =>
                          update.mutate(
                            { id: h.id, body: { enabled: e.target.checked } },
                            {
                              onSuccess: () =>
                                toastSuccess(
                                  e.target.checked ? `${h.name} enabled` : `${h.name} disabled`,
                                ),
                              onError: (err) => handleError(err),
                            },
                          )
                        }
                      />
                      Enabled
                    </label>
                    <Button size="sm" variant="outline" onClick={() => setTesting(h)}>
                      <FlaskConical aria-hidden="true" />
                      Test
                      <span className="sr-only"> {h.name}</span>
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => setEditing(h)}>
                      <Pencil aria-hidden="true" />
                      <span className="sr-only">Edit {h.name}</span>
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => setDeleting(h)}>
                      <Trash2 aria-hidden="true" />
                      <span className="sr-only">Delete {h.name}</span>
                    </Button>
                  </>
                ) : undefined
              }
            />
          ))}
        </ExtensionList>
      )}

      {creating || editing ? (
        <HookEditorDialog
          orgId={orgId}
          {...(editing ? { hook: editing } : {})}
          {...(!editing && fromRecipe ? { recipe: fromRecipe } : {})}
          onClose={closeEditor}
          projects={projects}
          canManageShared={isAdmin}
        />
      ) : null}
      {testing ? (
        <HookTestDialog orgId={orgId} hook={testing} onClose={() => setTesting(null)} />
      ) : null}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(o) => {
          if (!o) {
            setDeleting(null);
            del.reset();
          }
        }}
        title={`Delete ${deleting?.name ?? 'hook'}?`}
        description="Sessions will no longer run this check."
        confirmLabel="Delete hook"
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
