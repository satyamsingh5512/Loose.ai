import { PrismaClient } from '@prisma/client';

export type { PrismaClient };

export function createPrisma(databaseUrl: string): PrismaClient {
  return new PrismaClient({ datasources: { db: { url: databaseUrl } } });
}
