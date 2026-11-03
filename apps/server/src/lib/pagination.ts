/** Cursor pagination helpers (cursor = row id; stable order by createdAt + id). */
import type { PaginationQuery } from '@loose/shared';

export interface Page<T> {
  data: T[];
  nextCursor: string | null;
}

/** Prisma args for `take: limit + 1` cursor pagination. */
export function pageArgs(q: PaginationQuery) {
  return {
    take: q.limit + 1,
    ...(q.cursor ? { cursor: { id: q.cursor }, skip: 1 } : {}),
  };
}

export function toPage<R extends { id: string }, T>(
  rows: R[],
  limit: number,
  map: (r: R) => T,
): Page<T> {
  const hasMore = rows.length > limit;
  const slice = hasMore ? rows.slice(0, limit) : rows;
  return {
    data: slice.map(map),
    nextCursor: hasMore ? (slice[slice.length - 1]?.id ?? null) : null,
  };
}
