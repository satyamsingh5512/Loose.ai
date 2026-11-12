/**
 * MCP servers tab (spec §8.7): connected tools with their last status, a connection test
 * (status, latency, tools, error), the catalog-backed add dialog and delete.
 */
import type { McpServerDto, McpTestResultDto } from '@loose/shared';
import { Pencil, PlugZap, Plus, Trash2 } from 'lucide-react';
import { useState } from 'react';
import { MutationError } from '@/components/errors/MutationError';
import { toastSuccess, useErrorHandler } from '@/components/errors/notify';
import { LoadingBlock, QueryError } from '@/components/errors/QueryError';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import {
  useDeleteMcpServer,
  useMcpCatalog,
  useMcpServers,
  useTestMcpServer,
} from '@/hooks/api/extensions';
import { formatDateTime } from '@/lib/utils';
import {
  EmptyState,
  ExtensionList,
  ExtensionRow,
  McpStatusBadge,
  PanelHeader,
  ScopeBadge,
} from './common';
import { McpServerDialog } from './McpServerDialog';

function TestResult({ server, result }: { server: McpServerDto; result: McpTestResultDto }) {
  return (
    <Alert
      variant={result.ok ? 'success' : 'destructive'}
      data-testid={`mcp-test-${server.name}`}
      className="mt-2"
    >
      <AlertTitle>
        {result.ok ? 'Connection works' : 'Connection failed'}
        {result.latencyMs !== null ? ` · ${result.latencyMs} ms` : ''}
      </AlertTitle>
      <AlertDescription>
        {result.error ? (
          <span>
            {result.error.code}: {result.error.message}
          </span>
        ) : null}
        {result.tools.length > 0 ? (
          <span>
            {result.tools.length} tool{result.tools.length === 1 ? '' : 's'}:{' '}
            {result.tools.map((t) => t.name).join(', ')}
          </span>
        ) : null}
        {result.note ? <span className="text-muted-foreground">{result.note}</span> : null}
      </AlertDescription>
    </Alert>
  );
}

export function McpPanel({
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
  const servers = useMcpServers(orgId);
  const [adding, setAdding] = useState(false);
  const catalog = useMcpCatalog(orgId, { enabled: adding });
  const test = useTestMcpServer(orgId);
  const del = useDeleteMcpServer(orgId);
  const handleError = useErrorHandler();
  const [editing, setEditing] = useState<McpServerDto | null>(null);
  const [deleting, setDeleting] = useState<McpServerDto | null>(null);
  const [results, setResults] = useState<Record<string, McpTestResultDto>>({});

  if (servers.isPending) return <LoadingBlock label="Loading tools…" />;
  if (servers.isError)
    return <QueryError error={servers.error} onRetry={() => void servers.refetch()} />;

  const canWrite = (s: McpServerDto) => isAdmin || s.scope === 'USER';

  return (
    <div className="grid gap-4">
      <PanelHeader
        title="MCP servers"
        description="Connect external tools (issues, designs, docs, browsers) the AI can call during a session."
        actions={
          isAdmin || canCreatePersonal ? (
            <Button onClick={() => setAdding(true)}>
              <Plus aria-hidden="true" />
              Connect a tool
            </Button>
          ) : undefined
        }
      />
      <MutationError error={test.error} />

      {servers.data.length === 0 ? (
        <EmptyState>No tools connected yet.</EmptyState>
      ) : (
        <ExtensionList label="MCP servers">
          {servers.data.map((s) => (
            <ExtensionRow
              key={s.id}
              title={s.name}
              badges={
                <>
                  <ScopeBadge scope={s.scope} />
                  <Badge variant="outline">{s.transport.toLowerCase()}</Badge>
                  <McpStatusBadge status={s.enabled ? s.lastStatus : 'disabled'} />
                </>
              }
              description={s.url ?? [s.command, ...s.args].filter(Boolean).join(' ')}
              details={
                <>
                  <p className="text-xs text-muted-foreground">
                    Tools: {s.toolPolicy.default}
                    {Object.keys(s.toolPolicy.tools).length > 0
                      ? ` · ${Object.entries(s.toolPolicy.tools)
                          .map(([tool, d]) => `${tool}: ${d}`)
                          .join(', ')}`
                      : ''}
                    {s.envKeys.length + s.headerKeys.length > 0
                      ? ` · credentials: ${[...s.envKeys, ...s.headerKeys].join(', ')}`
                      : ''}
                  </p>
                  {s.lastCheckedAt ? (
                    <p className="text-xs text-muted-foreground">
                      Last checked {formatDateTime(s.lastCheckedAt)}
                      {s.lastError ? ` · ${s.lastError}` : ''}
                    </p>
                  ) : null}
                  {results[s.id] ? <TestResult server={s} result={results[s.id]!} /> : null}
                </>
              }
              actions={
                <>
                  <Button
                    size="sm"
                    variant="outline"
                    loading={test.isPending && test.variables === s.id}
                    onClick={() =>
                      test.mutate(s.id, {
                        onSuccess: (r) => setResults((prev) => ({ ...prev, [s.id]: r })),
                        onError: (err) => handleError(err),
                      })
                    }
                  >
                    <PlugZap aria-hidden="true" />
                    Test connection
                  </Button>
                  {canWrite(s) ? (
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
                  ) : null}
                </>
              }
            />
          ))}
        </ExtensionList>
      )}

      {adding ? (
        catalog.isPending ? (
          <LoadingBlock rows={1} label="Loading catalog…" />
        ) : (
          <McpServerDialog
            orgId={orgId}
            catalog={catalog.data ?? []}
            onClose={() => setAdding(false)}
            isAdmin={isAdmin}
            canCreatePersonal={canCreatePersonal}
            projects={projects}
          />
        )
      ) : null}
      {editing ? (
        <McpServerDialog
          orgId={orgId}
          server={editing}
          catalog={[]}
          lastTest={results[editing.id]}
          onClose={() => setEditing(null)}
          isAdmin={isAdmin}
          canCreatePersonal={canCreatePersonal}
          projects={projects}
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
        title={`Remove ${deleting?.name ?? 'server'}?`}
        description="Its stored credentials are deleted and sessions lose these tools."
        confirmLabel="Remove server"
        destructive
        loading={del.isPending}
        error={del.error}
        onConfirm={() => {
          const target = deleting;
          if (!target) return;
          del.mutate(target.id, {
            onSuccess: () => {
              toastSuccess(`${target.name} removed`);
              setDeleting(null);
            },
          });
        }}
      />
    </div>
  );
}
