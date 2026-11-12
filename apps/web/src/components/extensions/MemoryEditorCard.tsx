/**
 * Memory editor card (spec §8.10) used for the organization layer and the personal layer.
 * The AI reads these notes at the start of every session, so the copy is deliberately
 * concrete about what belongs in each layer.
 */
import type { ReactNode } from 'react';
import { useState } from 'react';
import { MutationError } from '@/components/errors/MutationError';
import { toastSuccess, useErrorHandler } from '@/components/errors/notify';
import { LoadingBlock, QueryError } from '@/components/errors/QueryError';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Field } from '@/components/ui/field';
import { Textarea } from '@/components/ui/textarea';
import { formatDateTime } from '@/lib/utils';

export interface MemoryQueryLike {
  isPending: boolean;
  isError: boolean;
  error: unknown;
  data: { memory: string | null; updatedAt: string | null } | undefined;
  refetch: () => void;
}

export interface MemorySaveLike {
  isPending: boolean;
  error: unknown;
  save: (
    memory: string | null,
    handlers: { onSuccess: () => void; onError: (err: unknown) => void },
  ) => void;
}

export function MemoryEditorCard({
  id,
  title,
  description,
  label,
  placeholder,
  maxLength,
  query,
  mutation,
  readOnly = false,
  readOnlyNote,
  footer,
}: {
  id: string;
  title: string;
  description: string;
  label: string;
  placeholder: string;
  maxLength: number;
  query: MemoryQueryLike;
  mutation: MemorySaveLike;
  readOnly?: boolean;
  readOnlyNote?: string;
  /** Extra controls next to the save button (e.g. "Generate draft"). */
  footer?: ReactNode;
}) {
  const [draft, setDraft] = useState<string | null>(null);
  const handleError = useErrorHandler();

  if (query.isPending) {
    return (
      <Card id={id} aria-labelledby={`${id}-title`}>
        <CardHeader>
          <CardTitle id={`${id}-title`} as="h2">
            {title}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <LoadingBlock rows={1} label={`Loading ${label}…`} />
        </CardContent>
      </Card>
    );
  }
  if (query.isError) {
    return (
      <Card id={id} aria-labelledby={`${id}-title`}>
        <CardHeader>
          <CardTitle id={`${id}-title`} as="h2">
            {title}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <QueryError error={query.error} onRetry={() => query.refetch()} />
        </CardContent>
      </Card>
    );
  }

  const value = draft ?? query.data?.memory ?? '';
  const tooLong = value.length > maxLength;

  return (
    <Card id={id} aria-labelledby={`${id}-title`}>
      <CardHeader>
        <CardTitle id={`${id}-title`} as="h2">
          {title}
        </CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent className="grid gap-3">
        <Field
          id={`${id}-text`}
          label={label}
          description={
            readOnly
              ? (readOnlyNote ?? 'Only admins can change this.')
              : `${value.length.toLocaleString()} / ${maxLength.toLocaleString()} characters. Markdown supported.`
          }
          error={tooLong ? 'This is too long.' : undefined}
        >
          {(aria) => (
            <Textarea
              {...aria}
              rows={10}
              className="font-mono text-xs"
              value={value}
              readOnly={readOnly}
              placeholder={placeholder}
              onChange={(e) => setDraft(e.target.value)}
            />
          )}
        </Field>
        {query.data?.updatedAt ? (
          <p className="text-xs text-muted-foreground">
            Last updated {formatDateTime(query.data.updatedAt)}
          </p>
        ) : null}
        <MutationError error={mutation.error} />
      </CardContent>
      {readOnly ? null : (
        <CardFooter className="flex-wrap gap-2">
          <Button
            type="button"
            disabled={tooLong || draft === null}
            loading={mutation.isPending}
            onClick={() =>
              mutation.save(value.trim() ? value : null, {
                onSuccess: () => {
                  setDraft(null);
                  toastSuccess(`${title} saved`);
                },
                onError: (err) => handleError(err),
              })
            }
          >
            Save
          </Button>
          {footer}
        </CardFooter>
      )}
    </Card>
  );
}
