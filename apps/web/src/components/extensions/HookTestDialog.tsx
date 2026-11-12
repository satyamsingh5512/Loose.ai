/**
 * "Test with sample payload" for one hook (`POST /orgs/:orgId/hooks/:id/test`, spec §8.9):
 * shows the payload that was sent, the decision, the latency and any error. `command`
 * hooks can only run inside a session sandbox — the API answers with a note saying so.
 */
import { hookSamplePayload, type HookDto, type HookTestResultDto } from '@loose/shared';
import { useState } from 'react';
import { MutationError } from '@/components/errors/MutationError';
import { useErrorHandler } from '@/components/errors/notify';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
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
import { Textarea } from '@/components/ui/textarea';
import { useTestHook } from '@/hooks/api/extensions';
import { HookDecisionBadge } from './common';

function Result({ result }: { result: HookTestResultDto }) {
  return (
    <Alert
      variant={result.ok ? 'success' : 'destructive'}
      data-testid="hook-test-result"
      className="mt-2"
    >
      <AlertTitle className="flex flex-wrap items-center gap-2">
        {result.decision ? (
          <HookDecisionBadge decision={result.decision.decision} />
        ) : (
          <span>{result.ok ? 'Hook ran' : 'Hook could not run'}</span>
        )}
        {result.latencyMs !== null ? <span>{result.latencyMs} ms</span> : null}
        {result.status !== null && result.status !== undefined ? (
          <span>HTTP {result.status}</span>
        ) : null}
      </AlertTitle>
      <AlertDescription>
        {result.decision?.reason ? <span>{result.decision.reason}</span> : null}
        {result.error ? (
          <span data-testid="hook-test-error">
            {result.error.code}: {result.error.message}
          </span>
        ) : null}
        {result.note ? <span className="text-muted-foreground">{result.note}</span> : null}
      </AlertDescription>
    </Alert>
  );
}

export function HookTestDialog({
  orgId,
  hook,
  onClose,
}: {
  orgId: string;
  hook: HookDto;
  onClose: () => void;
}) {
  const test = useTestHook(orgId);
  const handleError = useErrorHandler();
  const [payload, setPayload] = useState(() =>
    JSON.stringify(hookSamplePayload(hook.event, 'ses_example'), null, 2),
  );
  const [parseError, setParseError] = useState<string | undefined>();
  const [result, setResult] = useState<HookTestResultDto | null>(null);

  const run = () => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(payload);
    } catch {
      setParseError('That is not valid JSON.');
      return;
    }
    setParseError(undefined);
    test.mutate(
      { id: hook.id, body: { payload: parsed as never } },
      { onSuccess: (r) => setResult(r), onError: (err) => handleError(err) },
    );
  };

  return (
    <Dialog open onOpenChange={(o) => (o ? undefined : onClose())}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Test {hook.name}</DialogTitle>
          <DialogDescription>
            Runs the hook once with this payload and shows what it would decide. Nothing in a
            session is changed.
          </DialogDescription>
        </DialogHeader>
        <Field
          id="hook-test-payload"
          label="Sample payload"
          description="Edit it to try other tools, prompts or files."
          error={parseError}
        >
          {(aria) => (
            <Textarea
              {...aria}
              rows={12}
              className="font-mono text-xs"
              value={payload}
              spellCheck={false}
              onChange={(e) => setPayload(e.target.value)}
            />
          )}
        </Field>
        {result ? <Result result={result} /> : null}
        <MutationError error={test.error} />
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
          <Button onClick={run} loading={test.isPending}>
            Run test
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
