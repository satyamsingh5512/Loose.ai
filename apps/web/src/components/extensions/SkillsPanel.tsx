/**
 * Skills tab of the Extensions page (spec §8.6): the resolved list (built-in → org →
 * project → personal) with enable toggles and quick-action labels, create / edit from
 * Markdown, "Try this skill", version history with restore, GitHub import and delete.
 *
 * Built-in skills are read-only; turning one off stores it in the org policy
 * (`extensions.disabledBuiltinSkills`), so only admins see that toggle.
 */
import {
  githubRepoFullNameSchema,
  type OrgPolicy,
  type SkillDto,
  type WritableExtScope,
} from '@loose/shared';
import { Download, FlaskConical, History, Pencil, Plus, Trash2 } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { MutationError } from '@/components/errors/MutationError';
import { toastSuccess, useErrorHandler } from '@/components/errors/notify';
import { LoadingBlock, QueryError } from '@/components/errors/QueryError';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
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
import { Checkbox, Input } from '@/components/ui/input';
import {
  useDeleteSkill,
  useDryRunSavedSkill,
  useImportSkill,
  useRestoreSkillVersion,
  useSkill,
  useSkills,
  useSkillVersions,
  useUpdateSkill,
} from '@/hooks/api/extensions';
import { usePolicy, useUpdatePolicy } from '@/hooks/api/orgs';
import { formatDateTime } from '@/lib/utils';
import {
  EmptyState,
  ExtensionList,
  ExtensionRow,
  PanelHeader,
  ScopeBadge,
  ScopePicker,
} from './common';
import { SkillEditorDialog } from './SkillEditorDialog';

interface PanelProps {
  orgId: string;
  isAdmin: boolean;
  canCreatePersonal: boolean;
  projects: { id: string; name: string }[];
}

// ---- GitHub import ----------------------------------------------------------------

function ImportDialog({
  orgId,
  open,
  onOpenChange,
  isAdmin,
  canCreatePersonal,
  projects,
}: PanelProps & { open: boolean; onOpenChange: (open: boolean) => void }) {
  const [scope, setScope] = useState<WritableExtScope>(isAdmin ? 'ORG' : 'USER');
  const [projectId, setProjectId] = useState('');
  const [repo, setRepo] = useState('');
  const [path, setPath] = useState('');
  const [ref, setRef] = useState('');
  const [errors, setErrors] = useState<Record<string, string>>({});
  const importSkill = useImportSkill(orgId);
  const handleError = useErrorHandler();

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    const next: Record<string, string> = {};
    if (!githubRepoFullNameSchema.safeParse(repo.trim()).success) {
      next.repo = 'Use owner/repository.';
    }
    if (!path.trim()) next.path = 'Enter the folder that holds SKILL.md.';
    if (scope === 'PROJECT' && !projectId) next.projectId = 'Choose a project.';
    setErrors(next);
    if (Object.keys(next).length > 0) return;
    importSkill.mutate(
      {
        scope,
        ...(scope === 'PROJECT' ? { projectId } : {}),
        source: 'github',
        repo: repo.trim(),
        path: path.trim(),
        ...(ref.trim() ? { ref: ref.trim() } : {}),
      },
      {
        onSuccess: (dto) => {
          toastSuccess(`${dto.name} imported`);
          onOpenChange(false);
        },
        onError: (err) => handleError(err),
      },
    );
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <form onSubmit={onSubmit} noValidate className="grid gap-4">
          <DialogHeader>
            <DialogTitle>Import a skill from GitHub</DialogTitle>
            <DialogDescription>
              Reads the folder that contains <code>SKILL.md</code> from a repository you can access.
            </DialogDescription>
          </DialogHeader>
          <ScopePicker
            idPrefix="import"
            scope={scope}
            onScopeChange={setScope}
            projectId={projectId}
            onProjectChange={setProjectId}
            projects={projects}
            canManageShared={isAdmin}
            canCreatePersonal={canCreatePersonal}
            error={errors.projectId}
          />
          <Field id="import-repo" label="Repository" error={errors.repo} required>
            {(aria) => (
              <Input
                {...aria}
                value={repo}
                placeholder="acme/skills"
                onChange={(e) => setRepo(e.target.value)}
              />
            )}
          </Field>
          <Field
            id="import-path"
            label="Folder"
            description="The directory holding SKILL.md, e.g. .claude/skills/pdf"
            error={errors.path}
            required
          >
            {(aria) => (
              <Input
                {...aria}
                value={path}
                placeholder=".claude/skills/pdf"
                onChange={(e) => setPath(e.target.value)}
              />
            )}
          </Field>
          <Field id="import-ref" label="Branch or tag (optional)">
            {(aria) => (
              <Input
                {...aria}
                value={ref}
                placeholder="main"
                onChange={(e) => setRef(e.target.value)}
              />
            )}
          </Field>
          <MutationError error={importSkill.error} />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" loading={importSkill.isPending}>
              Import skill
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

// ---- version history ---------------------------------------------------------------

function VersionsDialog({
  orgId,
  skill,
  onClose,
}: {
  orgId: string;
  skill: SkillDto;
  onClose: () => void;
}) {
  const versions = useSkillVersions(orgId, skill.id);
  const restore = useRestoreSkillVersion(orgId);
  const handleError = useErrorHandler();
  return (
    <Dialog open onOpenChange={(o) => (o ? undefined : onClose())}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>History of {skill.name}</DialogTitle>
          <DialogDescription>
            Restoring a version saves it as a new version — nothing is lost.
          </DialogDescription>
        </DialogHeader>
        {versions.isPending ? <LoadingBlock rows={2} label="Loading history…" /> : null}
        {versions.isError ? (
          <QueryError error={versions.error} onRetry={() => void versions.refetch()} />
        ) : null}
        {versions.data?.length === 0 ? <EmptyState>No earlier versions.</EmptyState> : null}
        {versions.data && versions.data.length > 0 ? (
          <ul aria-label={`Versions of ${skill.name}`} className="divide-y rounded-md border">
            {versions.data.map((v) => (
              <li key={v.version} className="flex flex-wrap items-center gap-2 p-3 text-sm">
                <span className="font-medium">v{v.version}</span>
                <span className="text-muted-foreground">
                  {formatDateTime(v.createdAt)}
                  {v.createdByName ? ` · ${v.createdByName}` : ''} · {v.fileCount} file
                  {v.fileCount === 1 ? '' : 's'}
                </span>
                <Button
                  size="sm"
                  variant="outline"
                  className="ml-auto"
                  disabled={v.version === skill.version}
                  loading={restore.isPending && restore.variables?.version === v.version}
                  onClick={() =>
                    restore.mutate(
                      { id: skill.id, version: v.version },
                      {
                        onSuccess: () => {
                          toastSuccess(`Restored v${v.version}`);
                          onClose();
                        },
                        onError: (err) => handleError(err),
                      },
                    )
                  }
                >
                  {v.version === skill.version ? 'Current' : 'Restore'}
                </Button>
              </li>
            ))}
          </ul>
        ) : null}
        <MutationError error={restore.error} />
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---- edit (needs the bundle files) -------------------------------------------------

function EditSkillDialog({
  orgId,
  skill,
  onClose,
  projects,
  isAdmin,
  canCreatePersonal,
}: {
  orgId: string;
  skill: SkillDto;
  onClose: () => void;
  projects: { id: string; name: string }[];
  isAdmin: boolean;
  canCreatePersonal: boolean;
}) {
  const detail = useSkill(orgId, skill.id);
  if (detail.isPending) return <LoadingBlock rows={1} label="Loading skill…" />;
  if (detail.isError)
    return <QueryError error={detail.error} onRetry={() => void detail.refetch()} />;
  return (
    <SkillEditorDialog
      orgId={orgId}
      open
      onOpenChange={(o) => (o ? undefined : onClose())}
      skill={detail.data}
      projects={projects}
      canManageShared={isAdmin}
      canCreatePersonal={canCreatePersonal}
    />
  );
}

// ---- panel -------------------------------------------------------------------------

export function SkillsPanel({ orgId, isAdmin, canCreatePersonal, projects }: PanelProps) {
  const skills = useSkills(orgId);
  const policy = usePolicy(orgId, { enabled: isAdmin });
  const updatePolicy = useUpdatePolicy(orgId);
  const update = useUpdateSkill(orgId);
  const del = useDeleteSkill(orgId);
  const tryIt = useDryRunSavedSkill(orgId);
  const handleError = useErrorHandler();

  const [creating, setCreating] = useState(false);
  const [importing, setImporting] = useState(false);
  const [editing, setEditing] = useState<SkillDto | null>(null);
  const [versionsOf, setVersionsOf] = useState<SkillDto | null>(null);
  const [deleting, setDeleting] = useState<SkillDto | null>(null);
  const [tried, setTried] = useState<{ name: string; text: string; valid: boolean } | null>(null);

  if (skills.isPending) return <LoadingBlock label="Loading skills…" />;
  if (skills.isError)
    return <QueryError error={skills.error} onRetry={() => void skills.refetch()} />;

  const canWrite = (s: SkillDto) => !s.builtin && (isAdmin || s.scope === 'USER');

  const toggleBuiltin = (s: SkillDto, enabled: boolean) => {
    const current: OrgPolicy | undefined = policy.data;
    if (!current) return;
    const disabled = new Set(current.extensions.disabledBuiltinSkills);
    if (enabled) disabled.delete(s.name);
    else disabled.add(s.name);
    updatePolicy.mutate(
      {
        ...current,
        extensions: { ...current.extensions, disabledBuiltinSkills: [...disabled] },
      },
      {
        onSuccess: () => {
          void skills.refetch();
          toastSuccess(enabled ? `${s.name} enabled` : `${s.name} turned off`);
        },
        onError: (err) => handleError(err),
      },
    );
  };

  const toggle = (s: SkillDto, enabled: boolean) => {
    if (s.builtin) {
      toggleBuiltin(s, enabled);
      return;
    }
    update.mutate(
      { id: s.id, body: { enabled } },
      {
        onSuccess: () => toastSuccess(enabled ? `${s.name} enabled` : `${s.name} disabled`),
        onError: (err) => handleError(err),
      },
    );
  };

  return (
    <div className="grid gap-4">
      <PanelHeader
        title="Skills"
        description="Reusable instructions the AI loads when a request matches. Built-ins ship with loose.ai."
        actions={
          isAdmin || canCreatePersonal ? (
            <>
              <Button variant="outline" onClick={() => setImporting(true)}>
                <Download aria-hidden="true" />
                Import from GitHub
              </Button>
              <Button onClick={() => setCreating(true)}>
                <Plus aria-hidden="true" />
                New skill
              </Button>
            </>
          ) : undefined
        }
      />

      <MutationError error={update.error ?? updatePolicy.error ?? tryIt.error} />
      {tried ? (
        <Alert variant={tried.valid ? 'success' : 'destructive'} data-testid="skill-try-result">
          <AlertTitle>
            {tried.valid ? `${tried.name} is valid` : `${tried.name} has problems`}
          </AlertTitle>
          <AlertDescription>
            <pre className="max-h-40 w-full overflow-auto rounded bg-muted p-2 font-mono text-xs whitespace-pre-wrap">
              {tried.text}
            </pre>
            <Button variant="link" size="sm" className="h-auto p-0" onClick={() => setTried(null)}>
              Dismiss
            </Button>
          </AlertDescription>
        </Alert>
      ) : null}

      {skills.data.length === 0 ? (
        <EmptyState>No skills yet.</EmptyState>
      ) : (
        <ExtensionList label="Skills">
          {skills.data.map((s) => (
            <ExtensionRow
              key={s.id}
              title={s.name}
              badges={
                <>
                  <ScopeBadge scope={s.scope} />
                  {s.quickAction ? (
                    <Badge variant="secondary">Quick action: {s.quickAction}</Badge>
                  ) : null}
                  {!s.enabled ? <Badge variant="outline">Off</Badge> : null}
                </>
              }
              description={s.description}
              details={
                s.builtin ? null : (
                  <p className="text-xs text-muted-foreground">
                    Version {s.version} · updated {formatDateTime(s.updatedAt)}
                  </p>
                )
              }
              actions={
                <>
                  <label className="flex items-center gap-2 text-sm">
                    <Checkbox
                      checked={s.enabled}
                      disabled={s.builtin ? !isAdmin || !policy.data : !canWrite(s)}
                      onChange={(e) => toggle(s, e.target.checked)}
                      aria-label={`${s.enabled ? 'Disable' : 'Enable'} ${s.name}`}
                    />
                    Enabled
                  </label>
                  <Button
                    size="sm"
                    variant="ghost"
                    loading={tryIt.isPending && tryIt.variables === s.id}
                    onClick={() =>
                      tryIt.mutate(s.id, {
                        onSuccess: (r) =>
                          setTried({
                            name: s.name,
                            valid: r.valid,
                            text: r.valid
                              ? r.listingPreview
                              : [
                                  ...r.issues.map((i) =>
                                    i.path ? `${i.path}: ${i.message}` : i.message,
                                  ),
                                  ...r.warnings,
                                ].join('\n'),
                          }),
                        onError: (err) => handleError(err),
                      })
                    }
                  >
                    <FlaskConical aria-hidden="true" />
                    <span className="sr-only">Try </span>Try
                  </Button>
                  {canWrite(s) ? (
                    <>
                      <Button size="sm" variant="ghost" onClick={() => setEditing(s)}>
                        <Pencil aria-hidden="true" />
                        <span className="sr-only">Edit {s.name}</span>
                      </Button>
                      <Button size="sm" variant="ghost" onClick={() => setVersionsOf(s)}>
                        <History aria-hidden="true" />
                        <span className="sr-only">History of {s.name}</span>
                      </Button>
                      <Button size="sm" variant="ghost" onClick={() => setDeleting(s)}>
                        <Trash2 aria-hidden="true" />
                        <span className="sr-only">Delete {s.name}</span>
                      </Button>
                    </>
                  ) : null}
                </>
              }
            />
          ))}
        </ExtensionList>
      )}

      {creating ? (
        <SkillEditorDialog
          orgId={orgId}
          open
          onOpenChange={(o) => setCreating(o)}
          projects={projects}
          canManageShared={isAdmin}
          canCreatePersonal={canCreatePersonal}
        />
      ) : null}
      {importing ? (
        <ImportDialog
          orgId={orgId}
          open
          onOpenChange={setImporting}
          isAdmin={isAdmin}
          canCreatePersonal={canCreatePersonal}
          projects={projects}
        />
      ) : null}
      {editing ? (
        <EditSkillDialog
          orgId={orgId}
          skill={editing}
          onClose={() => setEditing(null)}
          projects={projects}
          isAdmin={isAdmin}
          canCreatePersonal={canCreatePersonal}
        />
      ) : null}
      {versionsOf ? (
        <VersionsDialog orgId={orgId} skill={versionsOf} onClose={() => setVersionsOf(null)} />
      ) : null}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(o) => {
          if (!o) {
            setDeleting(null);
            del.reset();
          }
        }}
        title={`Delete ${deleting?.name ?? 'skill'}?`}
        description="Sessions will stop loading this skill. Its version history is removed too."
        confirmLabel="Delete skill"
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
