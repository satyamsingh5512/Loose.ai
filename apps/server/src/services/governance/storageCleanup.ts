/**
 * Object-storage cleanup for rows that are about to disappear through FK cascades
 * (org deletion, account deletion): collect the keys first, delete the objects after the rows.
 */
import type { AppContext } from '../../context';

const KEY_BATCH = 1000;

async function collect(
  fetchPage: (cursor: string | undefined) => Promise<{ id: string; storageKey: string | null }[]>,
): Promise<string[]> {
  const keys: string[] = [];
  let cursor: string | undefined;
  for (;;) {
    const rows = await fetchPage(cursor);
    for (const r of rows) if (r.storageKey) keys.push(r.storageKey);
    if (rows.length < KEY_BATCH) return keys;
    cursor = rows[rows.length - 1]?.id;
  }
}

const page = (cursor: string | undefined) => ({
  orderBy: { id: 'asc' as const },
  take: KEY_BATCH,
  select: { id: true, storageKey: true },
  ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
});

/** Artifact files and data-export ZIPs that belong to an org. */
export async function collectOrgStorageKeys(ctx: AppContext, orgId: string): Promise<string[]> {
  const artifacts = await collect((c) =>
    ctx.prisma.artifact.findMany({ where: { session: { project: { orgId } } }, ...page(c) }),
  );
  const exports = await collect((c) =>
    ctx.prisma.dataExport.findMany({ where: { orgId }, ...page(c) }),
  );
  return [...artifacts, ...exports];
}

/** Artifact files and data-export ZIPs that belong to a user. */
export async function collectUserStorageKeys(ctx: AppContext, userId: string): Promise<string[]> {
  const artifacts = await collect((c) =>
    ctx.prisma.artifact.findMany({ where: { session: { userId } }, ...page(c) }),
  );
  const exports = await collect((c) =>
    ctx.prisma.dataExport.findMany({ where: { requestedById: userId }, ...page(c) }),
  );
  return [...artifacts, ...exports];
}

/** Best-effort delete (3 attempts per key). Returns the keys that could not be deleted. */
export async function deleteStorageKeys(
  ctx: AppContext,
  keys: readonly string[],
): Promise<string[]> {
  const failed: string[] = [];
  for (const key of keys) {
    let ok = false;
    for (let attempt = 0; attempt < 3 && !ok; attempt++) {
      try {
        await ctx.storage.delete(key);
        ok = true;
      } catch (err) {
        if (attempt === 2) ctx.logger.warn({ err, key }, 'storage cleanup: delete failed');
      }
    }
    if (!ok) failed.push(key);
  }
  return failed;
}
