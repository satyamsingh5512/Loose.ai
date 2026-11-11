/**
 * Shared chrome for the Extensions screens (spec §8.6, §8.6.1, §8.7, §8.8–§8.9): scope
 * badges and pickers, the panel header, empty states, the MCP status badge and the hook
 * decision badge.
 *
 * UI strings stay in this module (the extensions screens are English-only for now).
 */
import type { ExtScope, HookDecisionKind, McpStatus, WritableExtScope } from '@loose/shared';
import type { ReactNode } from 'react';
import { Badge } from '@/components/ui/badge';
import { Field } from '@/components/ui/field';
import { NativeSelect } from '@/components/ui/input';
import { cn } from '@/lib/utils';

export const SCOPE_LABEL: Record<ExtScope, string> = {
  BUILTIN: 'Built-in',
  ORG: 'Organization',
  PROJECT: 'Project',
  USER: 'Personal',
};

const SCOPE_VARIANT: Record<ExtScope, 'secondary' | 'outline' | 'default'> = {
  BUILTIN: 'secondary',
  ORG: 'outline',
  PROJECT: 'outline',
  USER: 'default',
};

export function ScopeBadge({ scope }: { scope: ExtScope }) {
  return <Badge variant={SCOPE_VARIANT[scope]}>{SCOPE_LABEL[scope]}</Badge>;
}

/** Scope + project picker for the create forms. */
export function ScopePicker({
  idPrefix,
  scope,
  onScopeChange,
  projectId,
  onProjectChange,
  projects,
  canManageShared,
  canCreatePersonal,
  hidePersonal = false,
  personalHint,
  error,
}: {
  idPrefix: string;
  scope: WritableExtScope;
  onScopeChange: (s: WritableExtScope) => void;
  projectId: string;
  onProjectChange: (id: string) => void;
  projects: { id: string; name: string }[];
  canManageShared: boolean;
  canCreatePersonal: boolean;
  /** Hooks are org policy: they have no personal scope. */
  hidePersonal?: boolean;
  personalHint?: string | undefined;
  error?: string | undefined;
}) {
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      <Field
        id={`${idPrefix}-scope`}
        label="Available to"
        description={scope === 'USER' ? (personalHint ?? 'Only your own sessions.') : undefined}
      >
        {(aria) => (
          <NativeSelect
            {...aria}
            value={scope}
            onChange={(e) => onScopeChange(e.target.value as WritableExtScope)}
          >
            <option value="ORG" disabled={!canManageShared}>
              Everyone in the organization
            </option>
            <option value="PROJECT" disabled={!canManageShared}>
              One project
            </option>
            {hidePersonal ? null : (
              <option value="USER" disabled={!canCreatePersonal}>
                Only me (personal)
              </option>
            )}
          </NativeSelect>
        )}
      </Field>
      {scope === 'PROJECT' ? (
        <Field id={`${idPrefix}-project`} label="Project" error={error} required>
          {(aria) => (
            <NativeSelect
              {...aria}
              value={projectId}
              onChange={(e) => onProjectChange(e.target.value)}
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
      ) : null}
    </div>
  );
}

/** Panel header: title, description and the primary actions of a tab. */
export function PanelHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description: string;
  actions?: ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        <h2 className="text-lg font-semibold tracking-tight">{title}</h2>
        <p className="text-sm text-muted-foreground">{description}</p>
      </div>
      {actions ? <div className="flex flex-wrap gap-2">{actions}</div> : null}
    </div>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return (
    <p className="rounded-md border border-dashed p-6 text-center text-sm text-muted-foreground">
      {children}
    </p>
  );
}

/** A list row for one extension (skill, command, MCP server). */
export function ExtensionRow({
  title,
  badges,
  description,
  details,
  actions,
  className,
}: {
  title: ReactNode;
  badges?: ReactNode;
  description?: ReactNode;
  details?: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <li className={cn('grid gap-2 p-4 sm:grid-cols-[1fr_auto] sm:items-start', className)}>
      <div className="min-w-0 grid gap-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-sm font-medium break-all">{title}</span>
          {badges}
        </div>
        {description ? <p className="text-sm text-muted-foreground">{description}</p> : null}
        {details}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </li>
  );
}

export function ExtensionList({ label, children }: { label: string; children: ReactNode }) {
  return (
    <ul aria-label={label} className="divide-y rounded-lg border">
      {children}
    </ul>
  );
}

const MCP_STATUS: Record<
  McpStatus,
  { label: string; variant: 'success' | 'destructive' | 'warning' | 'secondary' | 'outline' }
> = {
  connected: { label: 'Connected', variant: 'success' },
  failed: { label: 'Failed', variant: 'destructive' },
  needs_auth: { label: 'Needs auth', variant: 'warning' },
  pending: { label: 'Checking…', variant: 'secondary' },
  disabled: { label: 'Disabled', variant: 'secondary' },
  untested: { label: 'Not tested', variant: 'outline' },
};

export function McpStatusBadge({ status }: { status: McpStatus }) {
  const s = MCP_STATUS[status];
  return (
    <Badge variant={s.variant} data-testid="mcp-status">
      {s.label}
    </Badge>
  );
}

/** Decision of a hook run (`allow` / `deny` / `ask` / `modify`, spec §8.9). */
const HOOK_DECISION: Record<
  HookDecisionKind,
  { label: string; variant: 'success' | 'destructive' | 'warning' | 'secondary' }
> = {
  allow: { label: 'Allowed', variant: 'success' },
  deny: { label: 'Denied', variant: 'destructive' },
  ask: { label: 'Asks for approval', variant: 'warning' },
  modify: { label: 'Rewritten', variant: 'secondary' },
};

export function HookDecisionBadge({ decision }: { decision: HookDecisionKind }) {
  const d = HOOK_DECISION[decision];
  return (
    <Badge variant={d.variant} data-testid="hook-decision" data-decision={decision}>
      {d.label}
    </Badge>
  );
}
