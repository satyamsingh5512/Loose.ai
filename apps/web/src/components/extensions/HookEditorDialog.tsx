/**
 * Create / edit a hook (spec §8.9). One-click recipes prefill everything; the custom form
 * exposes the event, the tool matcher, the handler (`command` in the sandbox, an `http`
 * webhook the server calls, or a `builtin` action), the fail mode and the timeout.
 *
 * The definition is validated live with the shared `validateHookDefinition`
 * (LSE-EXT-006). Secrets are write-only: the HMAC signing secret and the Slack webhook
 * URL are sent once and never returned by the API, so the form only shows whether one is
 * stored.
 */
import {
  defaultHookFailMode,
  DEFAULT_HOOK_TIMEOUT_SEC,
  HOOK_BUILTIN_ACTIONS,
  HOOK_BUILTIN_EVENTS,
  HOOK_EVENT_LABELS,
  HOOK_EVENTS,
  HOOK_TIMEOUT_SEC_MAX,
  HOOK_TIMEOUT_SEC_MIN,
  isToolHookEvent,
  validateHookDefinition,
  type HookBuiltinAction,
  type HookBuiltinConfig,
  type HookDto,
  type HookEvent,
  type HookFailMode,
  type HookHandler,
  type HookHandlerType,
  type HookRecipe,
  type HookScope,
  type WritableExtScope,
} from '@loose/shared';
import { CheckCircle2 } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { MutationError } from '@/components/errors/MutationError';
import { toastSuccess, useErrorHandler } from '@/components/errors/notify';
import { fromLines, LinesField, toLines } from '@/components/project/LinesField';
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
import { useCreateHook, useUpdateHook } from '@/hooks/api/extensions';
import { ScopePicker } from './common';

const HANDLER_LABEL: Record<HookHandlerType, string> = {
  builtin: 'Built-in action',
  command: 'Command in the sandbox',
  http: 'Call our own endpoint (webhook)',
};

const ACTION_LABEL: Record<HookBuiltinAction, string> = {
  block_paths: 'Block changes to certain paths',
  block_dangerous_commands: 'Block dangerous commands',
  redact_secrets: 'Block secrets in changes',
  auto_format: 'Run a formatter',
  run_checks: 'Run checks (lint, tests)',
  notify_slack: 'Post to Slack',
};

/** Local form state; mirrors the handler union without secrets. */
interface HookForm {
  name: string;
  event: HookEvent;
  matcher: string;
  handlerType: HookHandlerType;
  command: string;
  url: string;
  secret: string;
  action: HookBuiltinAction;
  paths: string;
  patterns: string;
  commands: string;
  formatCommand: string;
  webhookUrl: string;
  text: string;
  message: string;
  failMode: HookFailMode;
  timeoutSec: string;
  enabled: boolean;
}

function blankForm(): HookForm {
  return {
    name: '',
    event: 'PreToolUse',
    matcher: '',
    handlerType: 'builtin',
    command: '',
    url: '',
    secret: '',
    action: 'block_paths',
    paths: '',
    patterns: '',
    commands: '',
    formatCommand: '',
    webhookUrl: '',
    text: '',
    message: '',
    failMode: 'closed',
    timeoutSec: String(DEFAULT_HOOK_TIMEOUT_SEC),
    enabled: true,
  };
}

function formFromRecipe(recipe: HookRecipe): HookForm {
  const f = blankForm();
  f.name = recipe.name;
  f.event = recipe.event;
  f.matcher = recipe.matcher ?? '';
  f.handlerType = recipe.handler.type;
  f.failMode = recipe.failMode ?? defaultHookFailMode(recipe.event);
  f.timeoutSec = String(recipe.timeoutSec ?? DEFAULT_HOOK_TIMEOUT_SEC);
  const h = recipe.handler;
  if (h.type === 'command') f.command = h.command;
  if (h.type === 'http') f.url = h.url;
  if (h.type === 'builtin') {
    f.action = h.action;
    const c = h.config ?? {};
    f.paths = fromLines(c.paths ?? []);
    f.patterns = fromLines(c.patterns ?? []);
    f.commands = fromLines(c.commands ?? []);
    f.formatCommand = c.command ?? '';
    // A recipe's webhook URL is only a placeholder — never prefill it.
    f.text = c.text ?? '';
    f.message = c.message ?? '';
  }
  return f;
}

function formFromHook(hook: HookDto): HookForm {
  const f = blankForm();
  f.name = hook.name;
  f.event = hook.event;
  f.matcher = hook.matcher ?? '';
  f.handlerType = hook.handler.type;
  f.failMode = hook.failMode;
  f.timeoutSec = String(hook.timeoutSec);
  f.enabled = hook.enabled;
  const h = hook.handler;
  if (h.type === 'command') f.command = h.command;
  if (h.type === 'http') f.url = h.url;
  if (h.type === 'builtin') {
    f.action = h.action;
    f.paths = fromLines(h.config.paths ?? []);
    f.patterns = fromLines(h.config.patterns ?? []);
    f.commands = fromLines(h.config.commands ?? []);
    f.formatCommand = h.config.command ?? '';
    f.text = h.config.text ?? '';
    f.message = h.config.message ?? '';
  }
  return f;
}

/**
 * The handler as sent to the API. Secrets are write-only: an omitted HMAC secret keeps
 * the stored one, but a `notify_slack` webhook URL is part of the handler the server
 * replaces, so it always has to be entered again (the form requires it).
 */
export function handlerFromForm(f: HookForm): HookHandler {
  if (f.handlerType === 'command') return { type: 'command' as const, command: f.command.trim() };
  if (f.handlerType === 'http') {
    return {
      type: 'http' as const,
      url: f.url.trim(),
      ...(f.secret ? { secret: f.secret } : {}),
    };
  }
  const webhookUrl = f.webhookUrl.trim();
  const config: HookBuiltinConfig = {};
  const paths = toLines(f.paths);
  const patterns = toLines(f.patterns);
  const commands = toLines(f.commands);
  if (f.action === 'block_paths' && paths.length > 0) config.paths = paths;
  if (f.action === 'block_dangerous_commands' && patterns.length > 0) config.patterns = patterns;
  if (f.action === 'run_checks' && commands.length > 0) config.commands = commands;
  if (f.action === 'auto_format' && f.formatCommand.trim()) config.command = f.formatCommand.trim();
  if (f.action === 'notify_slack') {
    if (webhookUrl) config.webhookUrl = webhookUrl;
    if (f.text.trim()) config.text = f.text.trim();
  }
  if (f.message.trim()) config.message = f.message.trim();
  return { type: 'builtin' as const, action: f.action, config };
}

export function HookEditorDialog({
  orgId,
  hook,
  recipe,
  onClose,
  projects,
  canManageShared,
}: {
  orgId: string;
  /** Absent = create a new hook. */
  hook?: HookDto | undefined;
  /** Prefill from a one-click recipe (create only). */
  recipe?: HookRecipe | undefined;
  onClose: () => void;
  projects: { id: string; name: string }[];
  canManageShared: boolean;
}) {
  const editing = Boolean(hook);
  const [scope, setScope] = useState<HookScope>('ORG');
  const [projectId, setProjectId] = useState('');
  const [form, setForm] = useState<HookForm>(() =>
    hook ? formFromHook(hook) : recipe ? formFromRecipe(recipe) : blankForm(),
  );
  const [errors, setErrors] = useState<Record<string, string>>({});
  const create = useCreateHook(orgId);
  const update = useUpdateHook(orgId);
  const handleError = useErrorHandler();

  const set = <K extends keyof HookForm>(key: K, value: HookForm[K]) =>
    setForm((prev) => ({ ...prev, [key]: value }));

  const hasStoredSecret =
    hook?.handler.type === 'http'
      ? hook.handler.hasSecret
      : hook?.handler.type === 'builtin'
        ? Boolean(hook.handler.config.hasWebhookUrl)
        : false;

  const handler = handlerFromForm(form);
  const validation = validateHookDefinition({
    event: form.event,
    matcher: form.matcher,
    handler,
    failMode: form.failMode,
    timeoutSec: Number(form.timeoutSec),
  });
  const firstIssue = validation.issues[0];
  const issueFor = (path: string) =>
    validation.issues.find((i) => i.path === path || i.path?.startsWith(`${path}.`))?.message;

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    const next: Record<string, string> = {};
    if (!form.name.trim()) next.name = 'Give the hook a name.';
    if (!editing && scope === 'PROJECT' && !projectId) next.projectId = 'Choose a project.';
    setErrors(next);
    if (Object.keys(next).length > 0 || !validation.ok) return;

    const body = handlerFromForm(form);
    const timeoutSec = Number(form.timeoutSec);
    if (hook) {
      update.mutate(
        {
          id: hook.id,
          body: {
            name: form.name.trim(),
            event: form.event,
            matcher:
              isToolHookEvent(form.event) && form.matcher.trim() ? form.matcher.trim() : null,
            handler: body,
            failMode: form.failMode,
            timeoutSec,
            enabled: form.enabled,
          },
        },
        {
          onSuccess: () => {
            toastSuccess(`${form.name.trim()} saved`);
            onClose();
          },
          onError: (err) => handleError(err),
        },
      );
      return;
    }
    create.mutate(
      {
        scope,
        ...(scope === 'PROJECT' ? { projectId } : {}),
        name: form.name.trim(),
        event: form.event,
        ...(isToolHookEvent(form.event) && form.matcher.trim()
          ? { matcher: form.matcher.trim() }
          : {}),
        handler: body,
        failMode: form.failMode,
        timeoutSec,
        enabled: form.enabled,
        ...(recipe ? { recipe: recipe.id } : {}),
      },
      {
        onSuccess: (dto) => {
          toastSuccess(`${dto.name} added`);
          onClose();
        },
        onError: (err) => handleError(err),
      },
    );
  };

  const suggestedEvents =
    form.handlerType === 'builtin' ? HOOK_BUILTIN_EVENTS[form.action] : HOOK_EVENTS;

  return (
    <Dialog open onOpenChange={(o) => (o ? undefined : onClose())}>
      <DialogContent className="max-w-2xl">
        <form onSubmit={onSubmit} noValidate className="grid gap-4">
          <DialogHeader>
            <DialogTitle>{editing ? `Edit ${hook?.name}` : 'New hook'}</DialogTitle>
            <DialogDescription>
              Hooks run automatically at fixed moments and can allow, deny, ask for approval or
              rewrite what the AI is about to do. The server always has the final say.
            </DialogDescription>
          </DialogHeader>

          {editing ? null : (
            <ScopePicker
              idPrefix="hook"
              scope={scope as WritableExtScope}
              onScopeChange={(s) => {
                if (s !== 'USER') setScope(s);
              }}
              projectId={projectId}
              onProjectChange={setProjectId}
              projects={projects}
              canManageShared={canManageShared}
              canCreatePersonal={false}
              hidePersonal
              error={errors.projectId}
            />
          )}

          <Field id="hook-name" label="Name" error={errors.name} required>
            {(aria) => (
              <Input
                {...aria}
                value={form.name}
                placeholder="Protect sensitive files"
                onChange={(e) => set('name', e.target.value)}
              />
            )}
          </Field>

          <div className="grid gap-3 sm:grid-cols-2">
            <Field id="hook-event" label="When it runs" error={issueFor('event')} required>
              {(aria) => (
                <NativeSelect
                  {...aria}
                  value={form.event}
                  onChange={(e) => {
                    const event = e.target.value as HookEvent;
                    setForm((prev) => ({
                      ...prev,
                      event,
                      failMode: defaultHookFailMode(event),
                    }));
                  }}
                >
                  {HOOK_EVENTS.map((ev) => (
                    <option key={ev} value={ev}>
                      {HOOK_EVENT_LABELS[ev]}
                    </option>
                  ))}
                </NativeSelect>
              )}
            </Field>
            {isToolHookEvent(form.event) ? (
              <Field
                id="hook-matcher"
                label="Tools it applies to"
                description="A tool name, a list like Edit|Write, or a regex. Empty = every tool."
                error={issueFor('matcher')}
              >
                {(aria) => (
                  <Input
                    {...aria}
                    value={form.matcher}
                    placeholder="Edit|Write"
                    onChange={(e) => set('matcher', e.target.value)}
                  />
                )}
              </Field>
            ) : null}
          </div>

          <Field id="hook-handler-type" label="What it does">
            {(aria) => (
              <NativeSelect
                {...aria}
                value={form.handlerType}
                disabled={editing}
                onChange={(e) => set('handlerType', e.target.value as HookHandlerType)}
              >
                {(['builtin', 'command', 'http'] as const).map((t) => (
                  <option key={t} value={t}>
                    {HANDLER_LABEL[t]}
                  </option>
                ))}
              </NativeSelect>
            )}
          </Field>

          {form.handlerType === 'builtin' ? (
            <fieldset className="grid gap-3 rounded-md border p-3">
              <legend className="px-1 text-sm font-medium">Built-in action</legend>
              <Field id="hook-action" label="Action">
                {(aria) => (
                  <NativeSelect
                    {...aria}
                    value={form.action}
                    onChange={(e) => set('action', e.target.value as HookBuiltinAction)}
                  >
                    {HOOK_BUILTIN_ACTIONS.map((a) => (
                      <option key={a} value={a}>
                        {ACTION_LABEL[a]}
                      </option>
                    ))}
                  </NativeSelect>
                )}
              </Field>
              {form.action === 'block_paths' ? (
                <LinesField
                  id="hook-paths"
                  label="Protected paths"
                  description="Globs, one per line. Any change to them is denied."
                  value={form.paths}
                  onChange={(v) => set('paths', v)}
                  error={issueFor('handler.config.paths')}
                  placeholder={'.github/**\ninfra/**'}
                />
              ) : null}
              {form.action === 'block_dangerous_commands' ? (
                <LinesField
                  id="hook-patterns"
                  label="Extra denied patterns (optional)"
                  description="Regexes, one per line. Known destructive commands are always denied."
                  value={form.patterns}
                  onChange={(v) => set('patterns', v)}
                  error={issueFor('handler.config.patterns')}
                  placeholder="git push --force"
                />
              ) : null}
              {form.action === 'auto_format' ? (
                <Field
                  id="hook-format-command"
                  label="Formatter command"
                  error={issueFor('handler.config.command')}
                  required
                >
                  {(aria) => (
                    <Input
                      {...aria}
                      value={form.formatCommand}
                      placeholder="npm run format"
                      onChange={(e) => set('formatCommand', e.target.value)}
                    />
                  )}
                </Field>
              ) : null}
              {form.action === 'run_checks' ? (
                <LinesField
                  id="hook-commands"
                  label="Commands"
                  description="Run in order in the sandbox, one per line."
                  value={form.commands}
                  onChange={(v) => set('commands', v)}
                  error={issueFor('handler.config.commands')}
                  placeholder={'npm run lint\nnpm test'}
                />
              ) : null}
              {form.action === 'notify_slack' ? (
                <>
                  <Field
                    id="hook-webhook-url"
                    label="Slack incoming webhook URL"
                    description="Stored encrypted and never shown again, so saving this hook needs it again."
                    error={issueFor('handler.config.webhookUrl')}
                    required
                  >
                    {(aria) => (
                      <Input
                        {...aria}
                        type="password"
                        autoComplete="off"
                        value={form.webhookUrl}
                        placeholder="https://hooks.slack.com/…"
                        onChange={(e) => set('webhookUrl', e.target.value)}
                      />
                    )}
                  </Field>
                  <Field
                    id="hook-text"
                    label="Message (optional)"
                    description="{{event}}, {{session}} and {{summary}} are filled in."
                  >
                    {(aria) => (
                      <Input
                        {...aria}
                        value={form.text}
                        onChange={(e) => set('text', e.target.value)}
                      />
                    )}
                  </Field>
                </>
              ) : null}
              {form.action === 'block_paths' ||
              form.action === 'block_dangerous_commands' ||
              form.action === 'redact_secrets' ? (
                <Field
                  id="hook-message"
                  label="Message shown when it blocks (optional)"
                  error={issueFor('handler.config.message')}
                >
                  {(aria) => (
                    <Input
                      {...aria}
                      value={form.message}
                      placeholder="Infrastructure files are managed by the platform team."
                      onChange={(e) => set('message', e.target.value)}
                    />
                  )}
                </Field>
              ) : null}
            </fieldset>
          ) : null}

          {form.handlerType === 'command' ? (
            <Field
              id="hook-command"
              label="Command"
              description="Runs inside the session sandbox with the hook payload as JSON on stdin. Exit code 2 denies."
              error={issueFor('handler.command')}
              required
            >
              {(aria) => (
                <Input
                  {...aria}
                  value={form.command}
                  placeholder="./scripts/check-hook.sh"
                  onChange={(e) => set('command', e.target.value)}
                />
              )}
            </Field>
          ) : null}

          {form.handlerType === 'http' ? (
            <fieldset className="grid gap-3 rounded-md border p-3">
              <legend className="px-1 text-sm font-medium">Webhook</legend>
              <Field
                id="hook-url"
                label="Endpoint URL"
                description="Called by loose.ai (not from the sandbox). It must answer with a hook decision."
                error={issueFor('handler.url')}
                required
              >
                {(aria) => (
                  <Input
                    {...aria}
                    value={form.url}
                    inputMode="url"
                    placeholder="https://example.com/loose/hooks"
                    onChange={(e) => set('url', e.target.value)}
                  />
                )}
              </Field>
              <Field
                id="hook-secret"
                label="Signing secret (optional)"
                description="Used for the x-loose-signature HMAC. Stored encrypted and never shown again."
                error={issueFor('handler.secret')}
              >
                {(aria) => (
                  <Input
                    {...aria}
                    type="password"
                    autoComplete="off"
                    value={form.secret}
                    placeholder={hasStoredSecret ? '•••••••• (stored)' : 'at least 8 characters'}
                    onChange={(e) => set('secret', e.target.value)}
                  />
                )}
              </Field>
              {hasStoredSecret ? (
                <p className="text-xs text-muted-foreground">
                  <Badge variant="outline">Secret stored</Badge> Enter a value only to replace it.
                </p>
              ) : null}
            </fieldset>
          ) : null}

          <div className="grid gap-3 sm:grid-cols-2">
            <Field
              id="hook-fail-mode"
              label="If the hook fails or times out"
              error={issueFor('failMode')}
            >
              {(aria) => (
                <NativeSelect
                  {...aria}
                  value={form.failMode}
                  onChange={(e) => set('failMode', e.target.value as HookFailMode)}
                >
                  <option value="closed">Block the action (fail closed)</option>
                  <option value="open">Let it through (fail open)</option>
                </NativeSelect>
              )}
            </Field>
            <Field id="hook-timeout" label="Timeout (seconds)" error={issueFor('timeoutSec')}>
              {(aria) => (
                <Input
                  {...aria}
                  type="number"
                  inputMode="numeric"
                  min={HOOK_TIMEOUT_SEC_MIN}
                  max={HOOK_TIMEOUT_SEC_MAX}
                  value={form.timeoutSec}
                  onChange={(e) => set('timeoutSec', e.target.value)}
                />
              )}
            </Field>
          </div>

          <label className="flex items-center gap-2 text-sm">
            <Checkbox checked={form.enabled} onChange={(e) => set('enabled', e.target.checked)} />
            Enabled
          </label>

          {validation.ok ? (
            <p className="flex items-center gap-2 text-xs text-success" data-testid="hook-valid">
              <CheckCircle2 className="size-4" aria-hidden="true" />
              This hook is valid.
            </p>
          ) : (
            <p className="text-xs text-destructive" role="alert" data-testid="hook-invalid">
              {firstIssue ? `${firstIssue.code}: ${firstIssue.message}` : 'This hook is invalid.'}
            </p>
          )}
          {validation.warnings.length > 0 ? (
            <ul className="list-disc pl-5 text-xs text-muted-foreground">
              {validation.warnings.map((w) => (
                <li key={w}>{w}</li>
              ))}
            </ul>
          ) : null}
          {form.handlerType === 'builtin' && !suggestedEvents.includes(form.event) ? (
            <p className="text-xs text-muted-foreground">
              This action usually runs on{' '}
              {suggestedEvents.map((ev) => HOOK_EVENT_LABELS[ev]).join(' or ')}.
            </p>
          ) : null}

          <MutationError error={create.error ?? update.error} />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button
              type="submit"
              loading={create.isPending || update.isPending}
              disabled={!validation.ok}
            >
              {editing ? 'Save hook' : 'Add hook'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
