/**
 * Add / edit an MCP server (spec §8.7). Credentials are write-only: entered values are
 * sent once and never returned by the API, so the form only ever shows the stored key
 * NAMES. The catalog picker prefills transport, command/url and the credential fields of
 * a curated entry.
 */
import {
  isAllowedMcpCommand,
  mcpServerNameSchema,
  MCP_STDIO_COMMANDS,
  type McpCatalogEntry,
  type McpServerDto,
  type McpTestResultDto,
  type McpToolDecision,
  type McpToolPolicy,
  type McpTransport,
  type WritableExtScope,
} from '@loose/shared';
import { Plus, Trash2 } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { MutationError } from '@/components/errors/MutationError';
import { toastSuccess, useErrorHandler } from '@/components/errors/notify';
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
import { useCreateMcpServer, useUpdateMcpServer } from '@/hooks/api/extensions';
import { ScopePicker } from './common';

const DECISIONS: { value: McpToolDecision; label: string }[] = [
  { value: 'allow', label: 'Allow' },
  { value: 'approval', label: 'Ask for approval' },
  { value: 'deny', label: 'Deny' },
];

interface CredentialRow {
  key: string;
  value: string;
  kind: 'env' | 'header';
  label?: string | undefined;
  required?: boolean | undefined;
  /** Prepended to the entered value (e.g. `Bearer `). */
  prefix?: string | undefined;
  placeholder?: string | undefined;
}

interface ToolRule {
  tool: string;
  decision: McpToolDecision;
}

function rulesOf(policy: McpToolPolicy): ToolRule[] {
  return Object.entries(policy.tools).map(([tool, decision]) => ({ tool, decision }));
}

function credentialsFrom(entry: McpCatalogEntry): CredentialRow[] {
  return entry.credentials.map((c) => ({
    key: c.key,
    value: '',
    kind: c.kind,
    label: c.label,
    required: c.required,
    prefix: c.prefix,
    placeholder: c.placeholder,
  }));
}

export function McpServerDialog({
  orgId,
  server,
  catalog,
  lastTest,
  onClose,
  isAdmin,
  canCreatePersonal,
  projects,
}: {
  orgId: string;
  /** Absent = create a new server. */
  server?: McpServerDto | undefined;
  catalog: McpCatalogEntry[];
  /** Tools discovered by the most recent "Test connection" (for the policy editor). */
  lastTest?: McpTestResultDto | undefined;
  onClose: () => void;
  isAdmin: boolean;
  canCreatePersonal: boolean;
  projects: { id: string; name: string }[];
}) {
  const editing = Boolean(server);
  const [scope, setScope] = useState<WritableExtScope>(isAdmin ? 'ORG' : 'USER');
  const [projectId, setProjectId] = useState('');
  const [catalogId, setCatalogId] = useState('');
  const [name, setName] = useState(server?.name ?? '');
  const [transport, setTransport] = useState<McpTransport>(server?.transport ?? 'HTTP');
  const [command, setCommand] = useState(server?.command ?? 'npx');
  const [args, setArgs] = useState((server?.args ?? []).join(' '));
  const [url, setUrl] = useState(server?.url ?? '');
  const [credentials, setCredentials] = useState<CredentialRow[]>([]);
  const [toolDefault, setToolDefault] = useState<McpToolDecision>(
    server?.toolPolicy.default ?? 'allow',
  );
  const [rules, setRules] = useState<ToolRule[]>(() => (server ? rulesOf(server.toolPolicy) : []));
  const [enabled, setEnabled] = useState(server?.enabled ?? true);
  const [errors, setErrors] = useState<Record<string, string>>({});

  const create = useCreateMcpServer(orgId);
  const update = useUpdateMcpServer(orgId);
  const handleError = useErrorHandler();

  const storedKeys = [...(server?.envKeys ?? []), ...(server?.headerKeys ?? [])];
  const knownTools = lastTest?.tools.map((t) => t.name) ?? [];

  const applyCatalog = (id: string) => {
    setCatalogId(id);
    const entry = catalog.find((c) => c.id === id);
    if (!entry) {
      setCredentials([]);
      return;
    }
    setName(entry.id);
    setTransport(entry.transport);
    setCommand(entry.command ?? 'npx');
    setArgs((entry.args ?? []).join(' '));
    setUrl(entry.url ?? '');
    setCredentials(credentialsFrom(entry));
    setRules((entry.approvalTools ?? []).map((tool) => ({ tool, decision: 'approval' as const })));
  };

  const credentialMap = (kind: 'env' | 'header') =>
    Object.fromEntries(
      credentials
        .filter((c) => c.kind === kind && c.key.trim() && c.value !== '')
        .map((c) => [c.key.trim(), `${c.prefix ?? ''}${c.value}`]),
    );

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    const next: Record<string, string> = {};
    const trimmedName = name.trim();
    const parsedName = mcpServerNameSchema.safeParse(trimmedName);
    if (!parsedName.success) next.name = parsedName.error.issues[0]?.message ?? 'Invalid name';
    if (transport === 'STDIO') {
      if (!command.trim()) next.command = 'Enter the command that starts the server.';
      else if (!isAllowedMcpCommand(command.trim())) {
        next.command = `Use one of ${MCP_STDIO_COMMANDS.join(', ')}.`;
      }
    } else if (!/^https?:\/\//i.test(url.trim())) {
      next.url = 'Enter an http(s) URL.';
    }
    if (!editing && scope === 'PROJECT' && !projectId) next.projectId = 'Choose a project.';
    for (const c of credentials) {
      if (c.required && !c.value && !storedKeys.includes(c.key)) {
        next[`cred-${c.key}`] = `${c.label ?? c.key} is required.`;
      }
    }
    setErrors(next);
    if (Object.keys(next).length > 0) return;

    const toolPolicy: McpToolPolicy = {
      default: toolDefault,
      tools: Object.fromEntries(
        rules.filter((r) => r.tool.trim()).map((r) => [r.tool.trim(), r.decision]),
      ),
    };
    const argList = args
      .split(/\s+/)
      .map((a) => a.trim())
      .filter(Boolean);
    const env = credentialMap('env');
    const headers = credentialMap('header');

    if (server) {
      update.mutate(
        {
          id: server.id,
          body: {
            name: trimmedName,
            ...(transport === 'STDIO' ? { command: command.trim(), args: argList } : {}),
            ...(transport === 'STDIO' ? {} : { url: url.trim() }),
            ...(Object.keys(env).length > 0 ? { env } : {}),
            ...(Object.keys(headers).length > 0 ? { headers } : {}),
            toolPolicy,
            enabled,
          },
        },
        {
          onSuccess: () => {
            toastSuccess(`${trimmedName} saved`);
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
        name: trimmedName,
        transport,
        ...(transport === 'STDIO'
          ? { command: command.trim(), args: argList }
          : { url: url.trim() }),
        env,
        headers,
        toolPolicy,
        enabled,
        ...(catalogId ? { catalogId } : {}),
      },
      {
        onSuccess: (dto) => {
          toastSuccess(`${dto.name} connected`);
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
            <DialogTitle>{editing ? `Edit ${server?.name}` : 'Connect a tool (MCP)'}</DialogTitle>
            <DialogDescription>
              MCP servers give the AI extra tools. Credentials are encrypted and never shown again
              after you save them.
            </DialogDescription>
          </DialogHeader>

          {editing ? null : (
            <>
              <ScopePicker
                idPrefix="mcp"
                scope={scope}
                onScopeChange={setScope}
                projectId={projectId}
                onProjectChange={setProjectId}
                projects={projects}
                canManageShared={isAdmin}
                canCreatePersonal={canCreatePersonal}
                personalHint="Only used in your own sessions."
                error={errors.projectId}
              />
              <Field
                id="mcp-catalog"
                label="From the catalog"
                description="Prefills the connection details. Choose “Custom” to enter your own."
              >
                {(aria) => (
                  <NativeSelect
                    {...aria}
                    value={catalogId}
                    onChange={(e) => applyCatalog(e.target.value)}
                  >
                    <option value="">Custom server</option>
                    {catalog.map((c) => (
                      <option key={c.id} value={c.id}>
                        {c.name} — {c.description}
                      </option>
                    ))}
                  </NativeSelect>
                )}
              </Field>
            </>
          )}

          <div className="grid gap-3 sm:grid-cols-2">
            <Field
              id="mcp-name"
              label="Name"
              description="Used in tool names (mcp__name__tool)."
              error={errors.name}
              required
            >
              {(aria) => (
                <Input
                  {...aria}
                  value={name}
                  placeholder="linear"
                  onChange={(e) => setName(e.target.value.toLowerCase())}
                />
              )}
            </Field>
            <Field id="mcp-transport" label="Transport">
              {(aria) => (
                <NativeSelect
                  {...aria}
                  value={transport}
                  disabled={editing}
                  onChange={(e) => setTransport(e.target.value as McpTransport)}
                >
                  <option value="HTTP">HTTP (remote)</option>
                  <option value="SSE">SSE (remote)</option>
                  <option value="STDIO">stdio (runs in the sandbox)</option>
                </NativeSelect>
              )}
            </Field>
          </div>

          {transport === 'STDIO' ? (
            <div className="grid gap-3 sm:grid-cols-[10rem_1fr]">
              <Field id="mcp-command" label="Command" error={errors.command} required>
                {(aria) => (
                  <NativeSelect
                    {...aria}
                    value={command}
                    onChange={(e) => setCommand(e.target.value)}
                  >
                    {MCP_STDIO_COMMANDS.map((c) => (
                      <option key={c} value={c}>
                        {c}
                      </option>
                    ))}
                  </NativeSelect>
                )}
              </Field>
              <Field
                id="mcp-args"
                label="Arguments"
                description="Space separated. ${NAME} placeholders are filled from the credentials below."
              >
                {(aria) => (
                  <Input
                    {...aria}
                    value={args}
                    placeholder="-y @modelcontextprotocol/server-slack"
                    onChange={(e) => setArgs(e.target.value)}
                  />
                )}
              </Field>
            </div>
          ) : (
            <Field id="mcp-url" label="Server URL" error={errors.url} required>
              {(aria) => (
                <Input
                  {...aria}
                  value={url}
                  inputMode="url"
                  placeholder="https://mcp.example.com/mcp"
                  onChange={(e) => setUrl(e.target.value)}
                />
              )}
            </Field>
          )}

          <fieldset className="grid gap-2">
            <legend className="text-sm font-medium">Credentials</legend>
            {storedKeys.length > 0 ? (
              <p className="flex flex-wrap items-center gap-1 text-xs text-muted-foreground">
                Stored:
                {storedKeys.map((k) => (
                  <Badge key={k} variant="outline">
                    {k}
                  </Badge>
                ))}
                <span>— enter a value below only to replace it.</span>
              </p>
            ) : null}
            {credentials.map((c, i) => (
              <div key={i} className="grid gap-2 sm:grid-cols-[14rem_1fr_auto] sm:items-start">
                <Field id={`mcp-cred-${i}-key`} label={c.kind === 'env' ? 'Variable' : 'Header'}>
                  {(aria) => (
                    <Input
                      {...aria}
                      value={c.key}
                      readOnly={Boolean(c.label)}
                      placeholder={c.kind === 'env' ? 'API_TOKEN' : 'Authorization'}
                      onChange={(e) =>
                        setCredentials(
                          credentials.map((x, j) => (j === i ? { ...x, key: e.target.value } : x)),
                        )
                      }
                    />
                  )}
                </Field>
                <Field
                  id={`mcp-cred-${i}-value`}
                  label={c.label ?? 'Value'}
                  error={errors[`cred-${c.key}`]}
                >
                  {(aria) => (
                    <Input
                      {...aria}
                      type="password"
                      autoComplete="off"
                      value={c.value}
                      placeholder={c.placeholder ?? '••••••••'}
                      onChange={(e) =>
                        setCredentials(
                          credentials.map((x, j) =>
                            j === i ? { ...x, value: e.target.value } : x,
                          ),
                        )
                      }
                    />
                  )}
                </Field>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="sm:mt-6"
                  onClick={() => setCredentials(credentials.filter((_x, j) => j !== i))}
                >
                  <Trash2 aria-hidden="true" />
                  <span className="sr-only">Remove credential {c.key || i + 1}</span>
                </Button>
              </div>
            ))}
            <div>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() =>
                  setCredentials([
                    ...credentials,
                    { key: '', value: '', kind: transport === 'STDIO' ? 'env' : 'header' },
                  ])
                }
              >
                <Plus aria-hidden="true" />
                Add credential
              </Button>
            </div>
          </fieldset>

          <fieldset className="grid gap-2">
            <legend className="text-sm font-medium">Tool permissions</legend>
            <Field
              id="mcp-tool-default"
              label="Default for every tool"
              description="Per-tool rules below win. Write actions are usually safer behind approval."
            >
              {(aria) => (
                <NativeSelect
                  {...aria}
                  value={toolDefault}
                  onChange={(e) => setToolDefault(e.target.value as McpToolDecision)}
                >
                  {DECISIONS.map((d) => (
                    <option key={d.value} value={d.value}>
                      {d.label}
                    </option>
                  ))}
                </NativeSelect>
              )}
            </Field>
            {rules.map((r, i) => (
              <div key={i} className="grid gap-2 sm:grid-cols-[1fr_12rem_auto] sm:items-start">
                <Field id={`mcp-rule-${i}-tool`} label="Tool">
                  {(aria) => (
                    <Input
                      {...aria}
                      value={r.tool}
                      list={knownTools.length > 0 ? 'mcp-known-tools' : undefined}
                      placeholder="create_issue"
                      onChange={(e) =>
                        setRules(
                          rules.map((x, j) => (j === i ? { ...x, tool: e.target.value } : x)),
                        )
                      }
                    />
                  )}
                </Field>
                <Field id={`mcp-rule-${i}-decision`} label="Decision">
                  {(aria) => (
                    <NativeSelect
                      {...aria}
                      value={r.decision}
                      onChange={(e) =>
                        setRules(
                          rules.map((x, j) =>
                            j === i ? { ...x, decision: e.target.value as McpToolDecision } : x,
                          ),
                        )
                      }
                    >
                      {DECISIONS.map((d) => (
                        <option key={d.value} value={d.value}>
                          {d.label}
                        </option>
                      ))}
                    </NativeSelect>
                  )}
                </Field>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="sm:mt-6"
                  onClick={() => setRules(rules.filter((_x, j) => j !== i))}
                >
                  <Trash2 aria-hidden="true" />
                  <span className="sr-only">Remove rule for {r.tool || i + 1}</span>
                </Button>
              </div>
            ))}
            {knownTools.length > 0 ? (
              <datalist id="mcp-known-tools">
                {knownTools.map((t) => (
                  <option key={t} value={t} />
                ))}
              </datalist>
            ) : null}
            <div>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setRules([...rules, { tool: '', decision: 'approval' }])}
              >
                <Plus aria-hidden="true" />
                Add tool rule
              </Button>
            </div>
            {knownTools.length > 0 ? (
              <p className="text-xs text-muted-foreground">
                Tools from the last connection test: {knownTools.join(', ')}
              </p>
            ) : null}
          </fieldset>

          <label className="flex items-center gap-2 text-sm">
            <Checkbox checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
            Enabled
          </label>

          <MutationError error={create.error ?? update.error} />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={create.isPending || update.isPending}>
              {editing ? 'Save server' : 'Add server'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
